/*
 * DISPOSABLE diagnostic preload. Not product code, not a test, and not shipped.
 *
 * Loaded into the PACKAGED MCP server with --require, so the package's own files are never
 * modified: what runs is exactly the built artifact, and there is no patch to forget to remove.
 *
 * It answers one question the library-level timing could not: where does the packaged process
 * spend the 30 s the smoke gives it? Three instruments, all to STDERR only, because stdout is
 * the JSON-RPC transport and writing to it would corrupt the protocol:
 *
 *   1. every subprocess, with a monotonic start and end, so a hanging child is visible;
 *   2. a HEARTBEAT every second, which distinguishes an event loop BLOCKED inside a synchronous
 *      call (heartbeat stops) from something waiting asynchronously (heartbeat continues);
 *   3. exit, uncaught exception and unhandled rejection, so a swallowed error is not invisible.
 *
 * No credential, commitment, consent record, raw helper output or store content is logged: only
 * the executable's basename, durations, and a status code.
 */
"use strict";
const cp = require("child_process");
const path = require("path");

const t0 = process.hrtime.bigint();
const ms = () => Number(process.hrtime.bigint() - t0) / 1e6;
function log(s) {
  try {
    process.stderr.write("TRACE " + ms().toFixed(0).padStart(7) + "ms " + s + "\n");
  } catch (_) {
    /* stderr gone: a diagnostic must never be the thing that breaks the run */
  }
}

log("preload: pid=" + process.pid + " arch=" + process.arch + " node=" + process.version);

for (const fn of ["spawnSync", "execFileSync", "execSync"]) {
  const real = cp[fn];
  if (typeof real !== "function") continue;
  cp[fn] = function (file) {
    const name = path.basename(String(file));
    log(fn + " START " + name);
    const a = process.hrtime.bigint();
    try {
      const r = real.apply(this, arguments);
      const d = Number(process.hrtime.bigint() - a) / 1e6;
      const status = r && typeof r.status !== "undefined" ? r.status : "?";
      const errc = r && r.error ? r.error.code || r.error.message : "-";
      // Sizes only. Never the output itself: it is an access list, and this is a log.
      const outLen = r && r.stdout ? String(r.stdout).length : 0;
      log(fn + " END   " + name + " " + d.toFixed(0) + "ms status=" + status + " err=" + errc + " outBytes=" + outLen);
      return r;
    } catch (e) {
      const d = Number(process.hrtime.bigint() - a) / 1e6;
      log(fn + " THREW " + name + " " + d.toFixed(0) + "ms " + (e && (e.code || e.message)));
      throw e;
    }
  };
}

// The discriminator. If this stops, the event loop is blocked inside a synchronous call.
const beat = setInterval(() => log("heartbeat"), 1000);
if (typeof beat.unref === "function") beat.unref();

process.on("exit", (c) => log("exit code=" + c));
process.on("uncaughtException", (e) => log("uncaughtException " + (e && e.message)));
process.on("unhandledRejection", (e) => log("unhandledRejection " + (e && (e.message || String(e)))));
process.on("SIGTERM", () => log("SIGTERM"));
