#!/usr/bin/env node
/*
 * DISPOSABLE diagnostic. Asserts nothing, always exits 0, never a gate.
 *
 * The probes showed .NET type resolution is free (767 / 752 ms) while CMDLET invocation costs
 * tens of seconds (ConvertTo-Json 43,141 ms; Get-Item 41,592 ms), and -EncodedCommand is
 * exonerated (743 vs 757 ms). The common property of the slow probes is that each is the first
 * use of a command that PowerShell must DISCOVER.
 *
 * So the variant changes exactly that and nothing else: every cmdlet in the helper is written
 * MODULE-QUALIFIED. It is the same cmdlets, in the same order, with the same arguments, so it
 * cannot change what is inspected or what is reported -- and that is checked here rather than
 * asserted, by comparing the two outputs byte for byte.
 *
 *   node win-helper-variant.js --out <build>
 *
 * Three input sets: empty, an ordinary valid set, and a refusal case (a path that does not
 * exist). Paired and order-swapped so a warm-up effect cannot be mistaken for an improvement.
 * The helper's OUTPUT IS NEVER PRINTED -- it is a security descriptor. Only lengths, a sha256
 * prefix for equality, durations and exit status are reported.
 */
"use strict";
const { spawnSync } = require("child_process");
const crypto = require("crypto");
const path = require("path");
const os = require("os");

const arg = (n, d) => { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : d; };
const out = arg("--out");
if (!out) { console.log("VARIANT-ERROR: --out is required"); process.exit(0); }
if (process.platform !== "win32") { console.log("VARIANT: NOT RUN, win32 only"); process.exit(0); }

const acl = require(path.join(out, "consent-acl-win.js"));
const ORIGINAL = acl.HELPER_SCRIPT_FOR_TESTS;

// Module-qualify each cmdlet the helper uses. Same cmdlet, same module, same arguments.
const QUALIFY = [
  [/\bGet-Item\b/g, "Microsoft.PowerShell.Management\\Get-Item"],
  [/\bTest-Path\b/g, "Microsoft.PowerShell.Management\\Test-Path"],
  [/\bNew-Object\b/g, "Microsoft.PowerShell.Utility\\New-Object"],
  [/\bWhere-Object\b/g, "Microsoft.PowerShell.Core\\Where-Object"],
  [/\bConvertTo-Json\b/g, "Microsoft.PowerShell.Utility\\ConvertTo-Json"],
];
let VARIANT = ORIGINAL;
for (const [re, to] of QUALIFY) VARIANT = VARIANT.replace(re, to);

console.log("VARIANT: cmdlets qualified: " + QUALIFY.map(([re]) => String(re).slice(2, -3)).join(", "));
console.log("VARIANT: original script " + ORIGINAL.length + " chars, variant " + VARIANT.length + " chars");
console.log("VARIANT: the two differ ONLY by module prefixes; no cmdlet, argument or order changed.");

const systemRoot = process.env.SystemRoot || "C:\\Windows";
const exe = path.join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
const profile = process.env.USERPROFILE || os.homedir();

const SETS = {
  empty: [],
  valid: ["C:\\", "C:\\Users", profile, path.join(profile, "AppData")],
  refusal: [path.join(profile, "no-such-directory-" + process.pid)],
};

function run(script, paths) {
  const a = process.hrtime.bigint();
  const r = spawnSync(exe, ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")], {
    input: paths.join("\r\n") + (paths.length ? "\r\n" : ""),
    encoding: "utf8",
    timeout: 180000,
    maxBuffer: 8 * 1024 * 1024,
    windowsHide: true,
  });
  const ms = Number(process.hrtime.bigint() - a) / 1e6;
  const body = r.stdout || "";
  return { ms, status: r.status, bytes: body.length, sha: crypto.createHash("sha256").update(body).digest("hex").slice(0, 16) };
}

console.log("");
for (const [name, paths] of Object.entries(SETS)) {
  // Order swapped per set so a warm-up effect cannot be read as an improvement.
  const firstIsOriginal = name !== "valid";
  const a = firstIsOriginal ? run(ORIGINAL, paths) : run(VARIANT, paths);
  const b = firstIsOriginal ? run(VARIANT, paths) : run(ORIGINAL, paths);
  const orig = firstIsOriginal ? a : b;
  const vari = firstIsOriginal ? b : a;
  console.log(`VARIANT [${name}] ran ${firstIsOriginal ? "original then variant" : "VARIANT FIRST then original"} (${paths.length} path(s))`);
  console.log(`VARIANT [${name}]   original ${orig.ms.toFixed(0).padStart(7)} ms  status=${orig.status} outBytes=${orig.bytes} sha=${orig.sha}`);
  console.log(`VARIANT [${name}]   variant  ${vari.ms.toFixed(0).padStart(7)} ms  status=${vari.status} outBytes=${vari.bytes} sha=${vari.sha}`);
  console.log(`VARIANT [${name}]   output IDENTICAL: ${orig.sha === vari.sha && orig.bytes === vari.bytes ? "YES" : "NO -- NOT an equivalent optimisation"}`);
  console.log("");
}
console.log("VARIANT: a duration difference means nothing unless the output shas match. They are printed above.");
process.exit(0);
