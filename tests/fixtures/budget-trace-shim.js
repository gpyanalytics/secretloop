/*
 * DISPOSABLE diagnostic preload. Not product code, never shipped, stderr only.
 *
 * The previous shim patched out/consent-budget.js while ts-node loaded src/consent-budget.ts,
 * so it never attached. This hooks Module._load instead, which every require goes through
 * whatever compiles it, and wraps whichever instance is actually returned.
 *
 * Logs monotonic times, counters, a category and a checkpoint name. Never a path, record,
 * credential, commitment, security descriptor or environment value.
 */
"use strict";
const Module = require("module");
const path = require("path");
const cp = require("child_process");

const t0 = process.hrtime.bigint();
const ms = () => (Number(process.hrtime.bigint() - t0) / 1e6).toFixed(0).padStart(7);
const log = (s) => { try { process.stderr.write("BTRACE " + ms() + "ms " + s + "\n"); } catch (_) {} };

// ---- subprocesses -----------------------------------------------------------------
for (const fn of ["spawnSync", "execFileSync"]) {
  const real = cp[fn];
  if (typeof real !== "function") continue;
  cp[fn] = function (file) {
    const name = path.basename(String(file));
    const a = process.hrtime.bigint();
    log(`helper ${name} START`);
    try {
      const r = real.apply(this, arguments);
      log(`helper ${name} ${(Number(process.hrtime.bigint() - a) / 1e6).toFixed(0)}ms status=${r && r.status} outBytes=${r && r.stdout ? String(r.stdout).length : 0}`);
      return r;
    } catch (e) { log(`helper ${name} THREW ${(e && e.code) || ""}`); throw e; }
  };
}

// ---- the budget, whichever instance is really loaded ------------------------------
let budget = null;
function wrapBudget(exp, resolved) {
  if (!exp || exp.__btraced) return exp;
  try { Object.defineProperty(exp, "__btraced", { value: true, enumerable: false }); } catch (_) { return exp; }
  budget = exp;
  log(`INSTRUMENTATION ATTACHED to ${path.basename(resolved)}  (${resolved.endsWith(".ts") ? "TypeScript source via ts-node" : "compiled js"})`);
  const L = exp.LIMITS || {};
  log(`allowance configured: helperCalls=${L.helperCalls} helperBytes=${L.helperBytes} dirEntries=${L.dirEntries} deadlineMs=${L.deadlineMs}`);

  const spend = () => { try { const s = exp.currentSpend && exp.currentSpend(); return s ? `calls=${s.helperCalls} bytes=${s.helperBytes} entries=${s.dirEntries}` : "none"; } catch (_) { return "?"; } };
  const remain = () => {
    try {
      return `msLeft=${exp.remainingMs ? exp.remainingMs(1e9) : "?"} bytesLeft=${exp.remainingBytes ? exp.remainingBytes(1e9) : "?"}`;
    } catch (e) { return `EXHAUSTED(${e && e.name})`; }
  };

  const realWith = exp.withBudget;
  let depth = 0, op = 0;
  exp.withBudget = function (fn) {
    const mine = ++op; const d = ++depth;
    const a = process.hrtime.bigint();
    log(`operation ${mine} START depth=${d}${d > 1 ? " (NESTED: joins the outer allowance)" : ""}`);
    // withBudget clears the allowance in its own finally, which runs BEFORE ours, so the spend
    // has to be read from inside the callback or END can only ever report "none".
    let last = "none";
    let reached = "";
    if (d === 1) resetHits();
    const watched = function () { try { return fn.apply(this, arguments); } finally { last = spend(); reached = hitLine(); } };
    try {
      const r = realWith.call(this, watched);
      log(`operation ${mine} END ok ${(Number(process.hrtime.bigint() - a) / 1e6).toFixed(0)}ms depth=${d} spend[${last}] reached[${reached}]`);
      return r;
    } catch (e) {
      log(`operation ${mine} END REFUSED ${(Number(process.hrtime.bigint() - a) / 1e6).toFixed(0)}ms depth=${d} name=${e && e.name} what=${(e && e.what) || "-"} problem=${(e && e.problem) || "-"} spend[${last}] reached[${reached}]`);
      throw e;
    } finally { depth--; }
  };

  // Each checkpoint names its own CATEGORY when it refuses, and counts how often it was REACHED.
  // The counts matter as much as the refusals: a checkpoint never reached cannot be the one that
  // refused, and that is an observation rather than an argument from reading the source.
  const hits = {};
  const resetHits = () => { for (const k of Object.keys(hits)) hits[k] = 0; };
  const hitLine = () => Object.keys(hits).map((k) => `${k}=${hits[k]}`).join(" ");
  for (const [name, category] of [["checkBudgetDeadline", "DEADLINE"], ["spendDirEntry", "ENTRY-COUNT"],
                                  ["spendHelperCall", "INSPECTION-COUNT"], ["spendHelperBytes", "OUTPUT-BYTES"],
                                  ["remainingMs", "DEADLINE(via remainingMs)"], ["remainingBytes", "OUTPUT-BYTES(via remainingBytes)"]]) {
    const real = exp[name];
    if (typeof real !== "function") continue;
    hits[name] = 0;
    exp[name] = function () {
      hits[name] += 1;
      try { return real.apply(this, arguments); }
      catch (e) { log(`EXHAUSTED category=${category} checkpoint=${name} error=${e && e.name} spend[${spend()}]`); throw e; }
    };
  }
  exp.__btraceHits = hitLine;
  exp.__btraceResetHits = resetHits;
  exp.__btraceRemain = remain;
  return exp;
}

// ---- report the outcome BEFORE the test's assertion runs --------------------------
function wrapMcp(exp, resolved) {
  if (!exp || exp.__btracedMcp || typeof exp.toolVerify !== "function") return exp;
  try { Object.defineProperty(exp, "__btracedMcp", { value: true, enumerable: false }); } catch (_) { return exp; }
  log(`INSTRUMENTATION ATTACHED to ${path.basename(resolved)} (toolVerify)`);
  const real = exp.toolVerify;
  exp.toolVerify = async function () {
    const a = process.hrtime.bigint();
    let r;
    try {
      r = await real.apply(this, arguments);
      return r;
    } finally {
      // Guaranteed: runs before the caller's assertion, and on the throwing path too.
      let out = "?";
      try { out = String(exp.outboundRequestCount ? exp.outboundRequestCount() : "?"); } catch (_) {}
      const state = r && r.ok ? (r.payload && r.payload.state) : (r ? "refused" : "threw");
      log(`toolVerify RETURNED ${(Number(process.hrtime.bigint() - a) / 1e6).toFixed(0)}ms state=${state} outboundRequestCount=${out}`);
    }
  };
  return exp;
}

const realLoad = Module._load;
Module._load = function (request, parent, isMain) {
  const exp = realLoad.apply(this, arguments);
  try {
    const resolved = Module._resolveFilename(request, parent, isMain);
    if (/consent-budget\.(ts|js)$/.test(resolved)) return wrapBudget(exp, resolved);
    if (/mcp-core\.(ts|js)$/.test(resolved)) return wrapMcp(exp, resolved);
  } catch (_) { /* resolution can fail for builtins and virtual ids */ }
  return exp;
};
log("preload installed: Module._load hook armed for consent-budget and mcp-core");
