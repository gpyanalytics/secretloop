#!/usr/bin/env node
/*
 * DISPOSABLE diagnostic. Not a test, not a packaging gate, and it always exits 0.
 *
 * It drives the SAME request sequence as scripts/smoke-tarball.sh against the SAME packaged
 * server, with the trace shim preloaded, and a LONGER hard timeout so the operation can be
 * watched to completion instead of being cut off at the smoke's ceiling. The real smoke's
 * 30-second ceiling is untouched and still runs separately; a result here is NOT a passing
 * packaging gate and is never reported as one.
 *
 *   node win-mcp-trace.js --work <dir containing package/> [--limit-ms 180000]
 *
 * The work directory is the smoke's own extracted tarball, so the bytes under test are the
 * packaged bytes. Digests of the three files that matter are printed so the build is identified.
 * Synthetic fixture only; the outbound boundary is never reached because the first verify
 * returns CONSENT_REQUIRED.
 */
"use strict";
const { spawn } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const arg = (n, d) => { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : d; };
const work = arg("--work");
const LIMIT = Number(arg("--limit-ms", "180000"));
if (!work) { console.log("TRACE-ERROR: --work is required"); process.exit(0); }

const pkg = path.join(work, "package");
const entry = path.join(pkg, "out", "mcp.js");
if (!fs.existsSync(entry)) { console.log("TRACE-ERROR: no packaged server at " + entry); process.exit(0); }

const digest = (p) => {
  try { return crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex").slice(0, 16); }
  catch { return "(absent)"; }
};
console.log("TRACE-BUILD entry            " + entry);
for (const f of ["out/mcp.js", "out/mcp-core.js", "out/consent-acl-win.js", "out/consent.js", "out/consent-budget.js"]) {
  console.log("TRACE-BUILD " + f.padEnd(26) + " sha256:" + digest(path.join(pkg, f)));
}
console.log("TRACE-BUILD node             " + process.execPath);
console.log("TRACE-BUILD arch             " + process.arch + "  platform=" + process.platform);
console.log("TRACE-BUILD USERPROFILE      " + (process.env.USERPROFILE || "(unset)"));
console.log("TRACE-BUILD consent store    " + path.join(process.env.USERPROFILE || os.homedir(), ".secretloop") +
            "  exists=" + fs.existsSync(path.join(process.env.USERPROFILE || os.homedir(), ".secretloop")));
console.log("TRACE-BUILD diagnostic hard timeout " + LIMIT + " ms  (the real smoke's ceiling is 30000 ms and is NOT changed)");

const scanDir = fs.mkdtempSync(path.join(os.tmpdir(), "sl-trace-"));
const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
let body = "";
for (let i = 0; i < 36; i++) body += alphabet[(i * 7 + 3) % 36];
fs.writeFileSync(path.join(scanDir, "app.js"), 'const t = "ghp_' + body + '";\n', "utf8");

const shim = path.join(__dirname, "mcp-trace-shim.js");
const t0 = process.hrtime.bigint();
const ms = () => (Number(process.hrtime.bigint() - t0) / 1e6).toFixed(0).padStart(7);
const say = (s) => console.log("TRACE-PARENT " + ms() + "ms " + s);

say("spawning packaged server, args=[" + entry + ", <scanDir>]  cwd=" + work);
const server = spawn(process.execPath, [entry, scanDir], {
  cwd: work,
  stdio: ["pipe", "pipe", "inherit"],
  env: Object.assign({}, process.env, { NODE_OPTIONS: "--require " + shim }),
});
server.on("error", (e) => say("server spawn error: " + e.message));
server.on("exit", (c, sig) => say("server exited code=" + c + " signal=" + sig));

const pending = new Map();
let buffer = "";
server.stdout.setEncoding("utf8");
server.stdout.on("data", (chunk) => {
  buffer += chunk;
  const lines = buffer.split("\n");
  buffer = lines.pop() ?? "";
  for (const line of lines) {
    if (!line.trim()) continue;
    let msg;
    try { msg = JSON.parse(line); } catch { say("non-JSON line on stdout, " + line.length + " bytes"); continue; }
    const r = pending.get(msg.id);
    say("stdout: response id=" + msg.id + (r ? " (matched)" : " (UNMATCHED)"));
    if (r) { pending.delete(msg.id); r(msg); }
  }
});

let nextId = 1;
function send(method, params, label) {
  const id = nextId++;
  const a = process.hrtime.bigint();
  say("-> " + method + " id=" + id + (label ? " " + label : ""));
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      say("!! NO RESPONSE to " + method + " id=" + id + " within " + LIMIT + " ms");
      resolve(null);
    }, LIMIT);
    pending.set(id, (msg) => {
      clearTimeout(timer);
      say("<- " + method + " id=" + id + " after " + (Number(process.hrtime.bigint() - a) / 1e6).toFixed(0) + " ms");
      resolve(msg);
    });
    const ok = server.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    if (!ok) say("   stdin.write returned FALSE: the pipe applied backpressure");
  });
}

(async () => {
  await send("initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "trace", version: "0" } });
  server.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized", params: {} }) + "\n");
  await send("tools/list", {});
  const scan = await send("tools/call", { name: "secretloop_scan", arguments: { path: scanDir } }, "(scan)");
  let fingerprint = null;
  try {
    const parsed = JSON.parse(scan.result.content[0].text);
    fingerprint = parsed.findings[0].fingerprint;
  } catch (e) { say("could not read a fingerprint from the scan result: " + (e && e.message)); }
  say("fingerprint acquired: " + (fingerprint ? "yes" : "no"));
  if (fingerprint) {
    // THE REQUEST THAT TIMES OUT IN THE SMOKE.
    await send("tools/call", { name: "secretloop_verify", arguments: { path: scanDir, fingerprint } }, "(verify - the one that times out)");
  }
  say("sequence complete; killing the server");
  server.kill();
  setTimeout(() => {
    try { fs.rmSync(scanDir, { recursive: true, force: true }); } catch {}
    say("done");
    process.exit(0);
  }, 500);
})().catch((e) => { say("TRACE-ERROR " + (e && e.stack ? e.stack.slice(0, 300) : e)); process.exit(0); });
