/*
 * DISPOSABLE diagnostic preload for the paired two-account comparison. Not product code.
 *
 * Passed as `--require` on the child's OWN command line rather than through NODE_OPTIONS,
 * because Start-Process -Credential runs the child as a different user and is not relied on
 * to carry the caller's environment across that boundary.
 *
 * It hooks Module._load, so it attaches to whichever consent-budget.js the chosen out-* build
 * provides. THE BUDGET MODULE IS BYTE-IDENTICAL BETWEEN THE TWO REVISIONS UNDER TEST, so both
 * sides are instrumented by the same code in the same way -- which is the point of a paired
 * comparison.
 *
 * stderr only. Never a credential, commitment, consent record, security descriptor, helper
 * output or environment value. Paths are reduced to a role.
 */
"use strict";
const Module = require("module");
const path = require("path");
const cp = require("child_process");

const t0 = process.hrtime.bigint();
const ms = () => (Number(process.hrtime.bigint() - t0) / 1e6).toFixed(1).padStart(9);
const log = (s) => { try { process.stderr.write("TTRACE " + ms() + "ms " + s + "\n"); } catch (_) {} };

const role = (p) => {
  const s = String(p || "");
  if (/pending/i.test(s)) return "<store/pending>";
  if (/store/i.test(s)) return "<store>";
  if (/repo/i.test(s)) return "<repo>";
  return "<path>";
};

// ---- helpers: invocation, duration, TIMEOUT ARGUMENT, status, captured bytes ----------------
for (const fn of ["spawnSync", "execFileSync"]) {
  const real = cp[fn];
  if (typeof real !== "function") continue;
  cp[fn] = function (file) {
    const name = path.basename(String(file)).toLowerCase();
    const interesting = /^(powershell|pwsh|whoami|icacls|cmd)\.exe$/.test(name);
    let timeoutArg = "none", maxBufferArg = "none";
    for (const a of arguments) {
      if (a && typeof a === "object" && !Array.isArray(a)) {
        if ("timeout" in a) timeoutArg = a.timeout;
        if ("maxBuffer" in a) maxBufferArg = a.maxBuffer;
      }
    }
    if (interesting) log(`helper ${name} START timeoutArg=${timeoutArg} maxBufferArg=${maxBufferArg}`);
    const a0 = process.hrtime.bigint();
    try {
      const r = real.apply(this, arguments);
      if (interesting) {
        const d = (Number(process.hrtime.bigint() - a0) / 1e6).toFixed(1);
        const so = r && r.stdout ? Buffer.byteLength(String(r.stdout), "utf8") : 0;
        const se = r && r.stderr ? Buffer.byteLength(String(r.stderr), "utf8") : 0;
        log(`helper ${name} END ${d}ms status=${r && r.status} signal=${r && r.signal} ` +
            `err=${(r && r.error && r.error.code) || "-"} stdoutBytes=${so} stderrBytes=${se}`);
      }
      return r;
    } catch (e) {
      if (interesting) log(`helper ${name} THREW ${(Number(process.hrtime.bigint() - a0) / 1e6).toFixed(1)}ms code=${(e && e.code) || "?"}`);
      throw e;
    }
  };
}

// ---- the budget ------------------------------------------------------------------------------
function wrapBudget(exp, resolved) {
  if (!exp || exp.__ttraced) return exp;
  try { Object.defineProperty(exp, "__ttraced", { value: true, enumerable: false }); } catch (_) { return exp; }
  const L = exp.LIMITS || {};
  log(`INSTRUMENTATION ATTACHED to ${path.basename(resolved)} from ${/out-main/.test(resolved) ? "out-main (MAIN)" : /out-cand/.test(resolved) ? "out-cand (CANDIDATE)" : "?"} pid=${process.pid}`);
  log(`allowance configured: helperCalls=${L.helperCalls} helperBytes=${L.helperBytes} dirEntries=${L.dirEntries} deadlineMs=${L.deadlineMs}`);

  const spend = () => {
    try {
      const s = exp.currentSpend && exp.currentSpend();
      if (!s) return "none";
      return `calls=${s.helperCalls} bytes=${s.helperBytes} entries=${s.dirEntries} elapsedMs=${s.elapsedMs}` +
        ` remainingMs=${Math.max(0, (L.deadlineMs || 0) - s.elapsedMs)}` +
        ` remainingCalls=${Math.max(0, (L.helperCalls || 0) - s.helperCalls)}` +
        ` remainingBytes=${Math.max(0, (L.helperBytes || 0) - s.helperBytes)}`;
    } catch (_) { return "?"; }
  };
  const hits = {};
  let opStart = process.hrtime.bigint(), when = [], depth = 0, op = 0;
  const reset = () => { for (const k of Object.keys(hits)) hits[k] = 0; opStart = process.hrtime.bigint(); when = []; };
  const hitLine = () => Object.keys(hits).map((k) => `${k}=${hits[k]}`).join(" ");
  const whenLine = () => (when.length ? when.join(" ") : "no checkpoint reached");

  for (const [name, category] of [["checkBudgetDeadline", "DEADLINE"], ["spendDirEntry", "ENTRY-COUNT"],
                                  ["spendHelperCall", "INSPECTION-COUNT"], ["spendHelperBytes", "OUTPUT-BYTES"],
                                  ["remainingMs", "DEADLINE(remainingMs)"], ["remainingBytes", "OUTPUT-BYTES(remainingBytes)"]]) {
    const real = exp[name];
    if (typeof real !== "function") continue;
    hits[name] = 0;
    exp[name] = function () {
      hits[name] += 1;
      if (when.length < 40) when.push(`${name}@${(Number(process.hrtime.bigint() - opStart) / 1e6).toFixed(1)}ms`);
      try { return real.apply(this, arguments); }
      catch (e) {
        log(`EXHAUSTED category=${category} checkpoint=${name} error=${e && e.name} what=${(e && e.what) || "-"} spend[${spend()}]`);
        throw e;
      }
    };
  }

  const realWith = exp.withBudget;
  exp.withBudget = function (fn) {
    if (depth > 0) { depth++; log(`operation ${op} NESTED depth=${depth} (joins the outer allowance)`); try { return realWith.call(this, fn); } finally { depth--; } }
    op++; depth = 1; reset();
    const mine = op, a0 = process.hrtime.bigint();
    log(`operation ${mine} START`);
    let last = "none", reached = "", at = "", outcome = "ok";
    const watched = function () { try { return fn.apply(this, arguments); } finally { last = spend(); reached = hitLine(); at = whenLine(); } };
    try { return realWith.call(this, watched); }
    catch (e) { outcome = `REFUSED name=${e && e.name} what=${(e && e.what) || "-"}`; throw e; }
    finally {
      depth = 0;
      log(`operation ${mine} END ${outcome} ${(Number(process.hrtime.bigint() - a0) / 1e6).toFixed(1)}ms spend[${last}] reached[${reached}] at[${at}]`);
    }
  };

  /*
   * INJECTED CONTROL, run once at attach time, before any request. It proves the hook is live in
   * THIS process. It is injected, it reproduces nothing, and it is excluded from the paired
   * success/failure counts.
   */
  try {
    let refused = "NO REFUSAL - CONTROL FAILED";
    exp.withBudget(() => {
      const past = Date.now() + (L.deadlineMs || 20000) + 1;
      exp.setClockForTests(() => past);
      try { exp.checkBudgetDeadline(); }
      catch (e) { refused = `${e && e.name} what=${(e && e.what) || "-"}`; }
      finally { exp.setClockForTests(undefined); }
    });
    let restored = "unknown";
    exp.withBudget(() => { const s = exp.currentSpend(); restored = s && s.elapsedMs >= 0 && s.elapsedMs < 2000 ? "yes" : "NO"; });
    log(`INJECTED CONTROL (excluded from the counts): forced deadline -> ${refused}; clock restored: ${restored}`);
  } catch (e) {
    log(`INJECTED CONTROL THREW ${e && e.message} - treat budget observations here as ABSENT, not as "nothing refused"`);
  }
  return exp;
}

function wrapMcp(exp, resolved) {
  if (!exp || exp.__ttracedMcp || typeof exp.toolVerify !== "function") return exp;
  try { Object.defineProperty(exp, "__ttracedMcp", { value: true, enumerable: false }); } catch (_) { return exp; }
  log(`INSTRUMENTATION ATTACHED to ${path.basename(resolved)} (toolVerify)`);
  const real = exp.toolVerify;
  const outbound = () => { try { return String(exp.outboundRequestCount ? exp.outboundRequestCount() : "?"); } catch (_) { return "?"; } };
  exp.toolVerify = async function (input) {
    const a0 = process.hrtime.bigint();
    log(`toolVerify REQUEST path=${role(input && input.path)} outboundBefore=${outbound()}`);
    let r, threw;
    try { r = await real.apply(this, arguments); return r; }
    catch (e) { threw = e; throw e; }
    finally {
      // Guaranteed, and BEFORE the fixture's expected-success assertion can stop the observation.
      const state = threw ? `threw ${threw && threw.name}` : (r && r.ok ? (r.payload && r.payload.state) : "refused");
      log(`toolVerify RESPONSE ${(Number(process.hrtime.bigint() - a0) / 1e6).toFixed(1)}ms state=${state} outboundAfter=${outbound()}`);
    }
  };
  return exp;
}

const realLoad = Module._load;
Module._load = function (request, parent, isMain) {
  const exp = realLoad.apply(this, arguments);
  try {
    const resolved = Module._resolveFilename(request, parent, isMain);
    if (/consent-budget\.js$/.test(resolved)) return wrapBudget(exp, resolved);
    if (/mcp-core\.js$/.test(resolved)) return wrapMcp(exp, resolved);
  } catch (_) {}
  return exp;
};
log(`preload installed pid=${process.pid} node=${process.version} ${process.arch}`);
