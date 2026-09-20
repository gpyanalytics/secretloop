#!/usr/bin/env node
/*
 * DISPOSABLE diagnostic. Asserts nothing, always exits 0, never a gate.
 *
 * ONE VARIABLE. The packaged MCP server's helper calls took 30.5 s and 22.4 s, while the very
 * same helper in a plain node process in the SAME job took 4.7 s then 0.4-0.5 s. Bare interpreter
 * startup is 13.7 s cold and ~0.76 s warm, so startup does not account for the difference.
 *
 * The one structural difference between those two parents is their STDIO: the MCP server is a
 * grandchild whose stdin and stdout are pipes, while the cost fixture had inherited stdio. This
 * changes exactly that and nothing else: the same helper source, the same path list, the same
 * spawnSync options, invoked from a child of this process that differs only in its stdio.
 *
 *   node win-helper-cost.js --out <build> --mode compare
 *   node win-helper-cost.js --out <build> --mode measure --tag <label>   (used internally)
 *
 * Paths inspected are ordinary directories that already exist. No consent store is created, no
 * record is read, and the helper's OUTPUT IS NEVER PRINTED -- it is a security descriptor. Only
 * a duration, an exit status and a byte count are reported.
 */
"use strict";
const { spawnSync, spawn } = require("child_process");
const path = require("path");
const os = require("os");

const arg = (n, d) => { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : d; };
const out = arg("--out");
const mode = arg("--mode", "compare");
const tag = arg("--tag", "?");
if (!out) { console.log("HELPERCOST-ERROR: --out is required"); process.exit(0); }
if (process.platform !== "win32") { console.log("HELPERCOST: NOT RUN, win32 only"); process.exit(0); }

const acl = require(path.join(out, "consent-acl-win.js"));
const SCRIPT = acl.HELPER_SCRIPT_FOR_TESTS;
const systemRoot = process.env.SystemRoot || "C:\\Windows";
const exe = path.join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");

// Five ordinary, already-existing directories: the same SHAPE of chain a real store has, without
// creating a store. Nothing here is a consent path.
const profile = process.env.USERPROFILE || os.homedir();
const paths = ["C:\\", "C:\\Users", profile, path.join(profile, "AppData"), path.join(profile, "AppData", "Local")];

function once(list) {
  const use = list || paths;
  const a = process.hrtime.bigint();
  const r = spawnSync(exe, ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(SCRIPT, "utf16le").toString("base64")], {
    input: use.join("\r\n") + "\r\n",
    encoding: "utf8",
    timeout: 120000,
    maxBuffer: 8 * 1024 * 1024,
    windowsHide: true,
  });
  const ms = Number(process.hrtime.bigint() - a) / 1e6;
  // Length only. The output is a security descriptor and must not be logged.
  return { ms, status: r.status, bytes: r.stdout ? r.stdout.length : 0, err: r.error ? r.error.code : "-" };
}

if (mode === "perpath") {
  // THE DISCRIMINATOR. Five paths cost ~22.4 s together. If one of them is pathological, timing
  // each ALONE finds it; if they are all ~4.5 s, the cost is per-path and uniform. Each run also
  // pays one interpreter startup (~0.75 s warm), which is stated rather than subtracted.
  console.log("HELPERCOST perpath: one helper invocation per path, each paying its own startup");
  const empty = once([]);
  console.log(`HELPERCOST perpath [<no paths>]           ${empty.ms.toFixed(0)} ms  outBytes=${empty.bytes}   <- startup + script, no descriptor work`);
  for (const one of paths) {
    const r = once([one]);
    console.log(`HELPERCOST perpath [${one.padEnd(38)}] ${r.ms.toFixed(0)} ms  status=${r.status} outBytes=${r.bytes}`);
  }
  const all = once(paths);
  console.log(`HELPERCOST perpath [all ${paths.length} together]${" ".repeat(22)} ${all.ms.toFixed(0)} ms  outBytes=${all.bytes}`);
  process.exit(0);
}

if (mode === "measure") {
  console.log(`HELPERCOST [${tag}] parent stdio: stdin=${process.stdin.isTTY ? "tty" : "not-tty"} paths=${paths.length}`);
  for (let i = 1; i <= 3; i++) {
    const r = once();
    console.log(`HELPERCOST [${tag}] run ${i}: ${r.ms.toFixed(0)} ms  status=${r.status} err=${r.err} outBytes=${r.bytes}`);
  }
  process.exit(0);
}

// compare: spawn this same script twice, differing ONLY in stdio.
(async () => {
  const self = __filename;
  const run = (label, stdio) => new Promise((resolve) => {
    const c = spawn(process.execPath, [self, "--out", out, "--mode", "measure", "--tag", label], { stdio });
    let buf = "";
    if (stdio[1] === "pipe") { c.stdout.setEncoding("utf8"); c.stdout.on("data", (d) => { buf += d; }); }
    c.on("exit", () => { if (buf) process.stdout.write(buf); resolve(); });
    c.on("error", (e) => { console.log(`HELPERCOST [${label}] spawn error ${e.message}`); resolve(); });
  });
  console.log("HELPERCOST: same helper, same paths, same spawnSync options. Only the PARENT's stdio differs.");
  await run("inherited-stdio", ["inherit", "inherit", "inherit"]);
  await run("piped-stdio", ["pipe", "pipe", "inherit"]);
  console.log("HELPERCOST: done. If the two columns agree, the parent's stdio is NOT the variable.");
  process.exit(0);
})();
