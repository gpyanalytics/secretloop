#!/usr/bin/env node
/*
 * Diagnostic fixture: what one consent operation actually COSTS on this machine, broken down
 * by helper. Not a test and not product code; it asserts nothing and always exits 0 so it can
 * never turn a diagnostic into a gate.
 *
 * It exists because "verify timed out" is not a diagnosis. The packaged MCP smoke gives each
 * request 30 s, and on windows-11-arm secretloop_verify exceeded it while the same call took
 * 17.9 s on x64. This says WHERE the time goes: process start, each helper invocation, and the
 * whole operation, using monotonic durations.
 *
 * The outbound boundary is replaced before anything runs: no provider is contacted, the store
 * is disposable, and the credential-shaped value is composed at runtime rather than committed.
 *
 *   node win-consent-cost.js --out <build> --lab <writable dir>
 */
"use strict";
const fs = require("fs");
const path = require("path");
const cp = require("child_process");

const arg = (n) => { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : undefined; };
const out = arg("--out");
const lab = arg("--lab");
if (!out || !lab) { console.log("COST-ERROR: --out and --lab are required"); process.exit(0); }

const t0 = process.hrtime.bigint();
const ms = (a, b) => Number(b - a) / 1e6;

// Count and time every subprocess the product starts, by name, before the product is loaded.
const calls = [];
const realSpawnSync = cp.spawnSync;
cp.spawnSync = function (file, args, opts) {
  const s = process.hrtime.bigint();
  const r = realSpawnSync.apply(this, arguments);
  const e = process.hrtime.bigint();
  calls.push({ exe: path.basename(String(file)), ms: ms(s, e), timeout: opts && opts.timeout });
  return r;
};

(async () => {
  const tLoad = process.hrtime.bigint();
  const consent = require(path.join(out, "consent.js"));
  const mcp = require(path.join(out, "mcp-core.js"));
  const tLoaded = process.hrtime.bigint();

  const repoDir = path.join(lab, "repo");
  const store = path.join(lab, ".secretloop");
  fs.mkdirSync(repoDir, { recursive: true });
  const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let value = "ghp_";
  for (let i = 0; i < 36; i++) value += alphabet[(i * 17 + 9) % alphabet.length];
  fs.writeFileSync(path.join(repoDir, "app.js"), `const t = "${value}";\n`, "utf8");
  const repo = fs.realpathSync(repoDir);

  consent.setConsentRootForTests(store);
  mcp.setAllowedRoots([repo]);
  mcp.resetSessions();
  let outbound = 0;
  mcp.setVerifyFetchForTests(async () => { outbound++; return new Response("{}", { status: 401 }); });

  const mark = (label, fn) => {
    const a = process.hrtime.bigint();
    const before = calls.length;
    let r, err = null;
    try { r = fn(); } catch (e) { err = e; }
    const b = process.hrtime.bigint();
    const mine = calls.slice(before);
    console.log(`COST ${label}: ${ms(a, b).toFixed(0)} ms, ${mine.length} subprocess(es)` +
      (err ? `  -> threw ${String(err && err.problem || err).slice(0, 80)}` : ""));
    for (const c of mine) console.log(`        ${c.exe.padEnd(16)} ${c.ms.toFixed(0)} ms   child timeout=${c.timeout}`);
    return r;
  };

  console.log(`COST node startup to require(): ${ms(t0, tLoad).toFixed(0)} ms`);
  console.log(`COST require(product)         : ${ms(tLoad, tLoaded).toFixed(0)} ms`);

  const scan = mark("scan", () => mcp.toolScan({ path: repo }));
  if (!scan || !scan.ok) { console.log("COST-NOTE: the scan did not succeed; the rest is still timed"); }
  const finding = scan && scan.ok && scan.payload.findings.find((f) => f.ruleId === "github-token");

  if (finding) {
    const a = process.hrtime.bigint();
    const before = calls.length;
    let state = "(threw)";
    try {
      const first = await mcp.toolVerify({ path: repo, fingerprint: finding.fingerprint });
      state = first.ok ? first.payload.state : `refused: ${String(first.error).slice(0, 90)}`;
    } catch (e) { state = `threw: ${String(e && e.problem || e).slice(0, 90)}`; }
    const b = process.hrtime.bigint();
    const mine = calls.slice(before);
    console.log(`COST first verify (the one the smoke times out on): ${ms(a, b).toFixed(0)} ms, ${mine.length} subprocess(es)`);
    for (const c of mine) console.log(`        ${c.exe.padEnd(16)} ${c.ms.toFixed(0)} ms   child timeout=${c.timeout}`);
    console.log(`COST verify outcome: ${state}`);
  }

  const total = {};
  for (const c of calls) {
    total[c.exe] = total[c.exe] || { n: 0, ms: 0 };
    total[c.exe].n++; total[c.exe].ms += c.ms;
  }
  console.log("COST totals by helper:");
  for (const [exe, t] of Object.entries(total)) {
    console.log(`        ${exe.padEnd(16)} ${t.n} call(s), ${t.ms.toFixed(0)} ms total, ${(t.ms / t.n).toFixed(0)} ms mean`);
  }
  console.log(`COST whole fixture: ${ms(t0, process.hrtime.bigint()).toFixed(0)} ms`);
  console.log(`COST outbound attempts (must be 0 for a consent-required first request): ${outbound}`);
  console.log("COST smoke ceiling for ONE request is 30000 ms; the operation budget deadline is 20000 ms.");
})().catch((e) => { console.log("COST-ERROR: " + String(e && e.stack || e).slice(0, 300)); });
