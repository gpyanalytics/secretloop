/*
 * DISPOSABLE diagnostic preload. Not product code, never shipped, stderr only.
 *
 * The post-merge failure showed 51.1 s between a suite heading and a budget refusal, but that
 * span includes fixture setup as well as the consent operation. This separates them, and names
 * the checkpoint that actually refuses, so "the budget refused" stops being the whole story.
 *
 * Logs durations, counts and a checkpoint name. Never a path, record, credential, commitment,
 * helper output or environment dump.
 */
"use strict";
const path = require("path");
const cp = require("child_process");
const t0 = process.hrtime.bigint();
const ms = () => (Number(process.hrtime.bigint() - t0) / 1e6).toFixed(0).padStart(7);
const log = (s) => { try { process.stderr.write("BTRACE " + ms() + "ms " + s + "\n"); } catch (_) {} };

for (const fn of ["spawnSync", "execFileSync"]) {
  const real = cp[fn];
  if (typeof real !== "function") continue;
  cp[fn] = function (file) {
    const name = path.basename(String(file));
    const a = process.hrtime.bigint();
    try {
      const r = real.apply(this, arguments);
      const d = Number(process.hrtime.bigint() - a) / 1e6;
      log(`${fn} ${name} ${d.toFixed(0)}ms status=${r && r.status} outBytes=${r && r.stdout ? String(r.stdout).length : 0}`);
      return r;
    } catch (e) {
      log(`${fn} ${name} THREW ${(e && e.code) || ""}`);
      throw e;
    }
  };
}

// Wrap the budget so each operation's real span, and the refusing checkpoint, are visible.
try {
  const out = path.join(__dirname, "..", "..", "out", "consent-budget.js");
  const b = require(out);
  const realWith = b.withBudget, realDeadline = b.checkBudgetDeadline, realEntry = b.spendDirEntry;
  let op = 0;
  b.withBudget = function (fn) {
    const mine = ++op;
    const a = process.hrtime.bigint();
    log(`operation ${mine} START`);
    try {
      const r = realWith.call(this, fn);
      log(`operation ${mine} END ok ${(Number(process.hrtime.bigint() - a) / 1e6).toFixed(0)}ms`);
      return r;
    } catch (e) {
      log(`operation ${mine} END REFUSED ${(Number(process.hrtime.bigint() - a) / 1e6).toFixed(0)}ms problem=${(e && e.problem) || e.name}`);
      throw e;
    }
  };
  b.checkBudgetDeadline = function () {
    try { return realDeadline.apply(this, arguments); }
    catch (e) { log(`REFUSED AT checkBudgetDeadline  ${e && e.name}`); throw e; }
  };
  b.spendDirEntry = function () {
    try { return realEntry.apply(this, arguments); }
    catch (e) { log(`REFUSED AT spendDirEntry  ${e && e.name}`); throw e; }
  };
  log("budget wrapped: withBudget, checkBudgetDeadline, spendDirEntry");
} catch (e) {
  log("could not wrap the budget: " + (e && e.message));
}
