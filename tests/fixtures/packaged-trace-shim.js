/*
 * DISPOSABLE diagnostic preload for the PACKAGED smoke. Not product code, never shipped.
 *
 * It is loaded through NODE_OPTIONS, so it lands in every node process the smoke starts --
 * npm, the smoke's own driver, and the spawned MCP server. Only the MCP server ever requires
 * the budget, so only that process is wrapped; the rest stay silent on purpose, or the log
 * would be mostly npm.
 *
 * The npm tarball ships tsc output, one CommonJS module per source file: out/consent.js does
 * require("./consent-budget"), so Module._load intercepts it. That was verified before this
 * was written; it is NOT assumed from "it worked under ts-node".
 *
 * stderr only, fixed labels, bounded. Never a credential, commitment, consent record, raw
 * helper output, security descriptor or environment value. Paths are reduced to a ROLE.
 */
"use strict";
const Module = require("module");
const path = require("path");
const cp = require("child_process");

const t0 = process.hrtime.bigint();
const ms = () => (Number(process.hrtime.bigint() - t0) / 1e6).toFixed(0).padStart(7);
// Wall clock too, because the product's own MCP log is wall-clock and the two have to be
// lined up against each other.
const log = (s) => {
  try {
    process.stderr.write("PTRACE " + ms() + "ms " + new Date().toISOString() + " " + s + "\n");
  } catch (_) { }
};

/** A path reduced to a role. Never the path itself. */
function role(p) {
  const s = String(p || "");
  if (/\.secretloop[\\/]pending/i.test(s)) return "<store/pending>";
  if (/\.secretloop/i.test(s)) return "<store>";
  if (/mcp-scan/i.test(s)) return "<scan-fixture>";
  if (/sl-outside-/i.test(s)) return "<outside-root>";
  return "<path>";
}

// ---- subprocesses: start, end, duration, TIMEOUT ARGUMENT, status, output LENGTH ---------
for (const fn of ["spawnSync", "execFileSync", "execSync"]) {
  const real = cp[fn];
  if (typeof real !== "function") continue;
  cp[fn] = function (file) {
    const name = path.basename(String(file)).toLowerCase();
    // Only the helpers matter. Wrapping every subprocess would bury them under npm's own.
    const interesting = /^(powershell|pwsh|whoami|icacls|cmd)\.exe$/.test(name);
    let timeout = "none";
    for (const a of arguments) {
      if (a && typeof a === "object" && !Array.isArray(a) && "timeout" in a) timeout = a.timeout;
    }
    if (interesting) log(`helper ${name} START timeoutArg=${timeout}`);
    const a = process.hrtime.bigint();
    try {
      const r = real.apply(this, arguments);
      if (interesting) {
        const d = (Number(process.hrtime.bigint() - a) / 1e6).toFixed(0);
        const out = r && r.stdout ? String(r.stdout).length : 0;
        log(`helper ${name} END ${d}ms status=${r && r.status} outBytes=${out}`);
      }
      return r;
    } catch (e) {
      if (interesting) {
        const d = (Number(process.hrtime.bigint() - a) / 1e6).toFixed(0);
        log(`helper ${name} THREW ${d}ms code=${(e && e.code) || "?"}`);
      }
      throw e;
    }
  };
}

// ---- the budget, in whichever process actually loads it ----------------------------------
function wrapBudget(exp, resolved) {
  if (!exp || exp.__ptraced) return exp;
  try { Object.defineProperty(exp, "__ptraced", { value: true, enumerable: false }); } catch (_) { return exp; }

  const kind = resolved.endsWith(".ts") ? "TypeScript source" : "compiled js";
  const packaged = /[\\/]package[\\/]out[\\/]/.test(resolved) ? "FROM THE PACKED TARBALL" : "from the working tree";
  log(`INSTRUMENTATION ATTACHED to ${path.basename(resolved)} (${kind}, ${packaged}) pid=${process.pid}`);
  const L = exp.LIMITS || {};
  log(`allowance configured: helperCalls=${L.helperCalls} helperBytes=${L.helperBytes} dirEntries=${L.dirEntries} deadlineMs=${L.deadlineMs}`);

  const spend = () => {
    try {
      const s = exp.currentSpend && exp.currentSpend();
      if (!s) return "none";
      return `calls=${s.helperCalls} bytes=${s.helperBytes} entries=${s.dirEntries} elapsedMs=${s.elapsedMs}` +
        ` remainingMs=${Math.max(0, (L.deadlineMs || 0) - s.elapsedMs)}` +
        ` remainingBytes=${Math.max(0, (L.helperBytes || 0) - s.helperBytes)}` +
        ` remainingCalls=${Math.max(0, (L.helperCalls || 0) - s.helperCalls)}`;
    } catch (_) { return "?"; }
  };

  const hits = {};
  let opStart = process.hrtime.bigint();
  let when = [];
  const resetHits = () => { for (const k of Object.keys(hits)) hits[k] = 0; opStart = process.hrtime.bigint(); when = []; };
  const noteAt = (n) => {
    if (when.length < 24) when.push(`${n}@${(Number(process.hrtime.bigint() - opStart) / 1e6).toFixed(0)}ms`);
  };
  const hitLine = () => Object.keys(hits).map((k) => `${k}=${hits[k]}`).join(" ");
  const whenLine = () => (when.length ? when.join(" ") : "no checkpoint reached");

  const realWith = exp.withBudget;
  let depth = 0, op = 0;
  exp.withBudget = function (fn) {
    const mine = ++op, d = ++depth;
    const a = process.hrtime.bigint();
    log(`operation ${mine} START depth=${d}${d > 1 ? " (NESTED: joins the outer allowance)" : ""}`);
    // withBudget clears the allowance in its own finally, which runs before ours, so the
    // spend has to be read from inside the callback or END can only ever report "none".
    let last = "none", reached = "", at = "";
    const watched = function () {
      try { return fn.apply(this, arguments); }
      finally { last = spend(); reached = hitLine(); at = whenLine(); }
    };
    try {
      const r = realWith.call(this, watched);
      log(`operation ${mine} END ok ${(Number(process.hrtime.bigint() - a) / 1e6).toFixed(0)}ms depth=${d} spend[${last}] reached[${reached}] at[${at}]`);
      return r;
    } catch (e) {
      log(`operation ${mine} END REFUSED ${(Number(process.hrtime.bigint() - a) / 1e6).toFixed(0)}ms depth=${d} name=${e && e.name} what=${(e && e.what) || "-"} problem=${(e && e.problem) || "-"} spend[${last}] reached[${reached}] at[${at}]`);
      throw e;
    } finally { depth--; }
  };

  for (const [name, category] of [["checkBudgetDeadline", "DEADLINE"], ["spendDirEntry", "ENTRY-COUNT"],
                                  ["spendHelperCall", "INSPECTION-COUNT"], ["spendHelperBytes", "OUTPUT-BYTES"],
                                  ["remainingMs", "DEADLINE(via remainingMs)"], ["remainingBytes", "OUTPUT-BYTES(via remainingBytes)"]]) {
    const real = exp[name];
    if (typeof real !== "function") continue;
    hits[name] = 0;
    exp[name] = function () {
      hits[name] += 1;
      noteAt(name);
      try { return real.apply(this, arguments); }
      catch (e) {
        log(`EXHAUSTED category=${category} checkpoint=${name} error=${e && e.name} what=${(e && e.what) || "-"} spend[${spend()}]`);
        throw e;
      }
    };
  }
  const origWith = exp.withBudget;
  exp.withBudget = function (fn) { if (depth === 0) resetHits(); return origWith.call(this, fn); };

  /*
   * THE ATTACHMENT CONTROL, run here, inside the process that will serve the request, at load
   * time and before any request arrives. It INJECTS a deadline that has already passed and
   * requires the refusal and its event. If the two lines below are missing from a log, the
   * hook is not live in that process and nothing else it says about the budget may be used.
   *
   * It is an injected control. It reproduces nothing. It mutates one thing -- the budget's
   * test clock -- and puts it back in a finally, which is then re-checked.
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
    exp.withBudget(() => {
      const s = exp.currentSpend();
      restored = s && s.elapsedMs >= 0 && s.elapsedMs < 1000 ? `yes (elapsedMs=${s.elapsedMs})` : `NO (elapsedMs=${s && s.elapsedMs})`;
    });
    log(`ATTACHMENT CONTROL (INJECTED, reproduces nothing): forced deadline -> ${refused}; clock restored: ${restored}`);
  } catch (e) {
    log(`ATTACHMENT CONTROL THREW ${e && e.message} - treat budget observations in this process as ABSENT, not as "nothing refused"`);
  }
  return exp;
}

// ---- the server boundary: request in, response out, counters before any assertion ---------
function wrapMcp(exp, resolved) {
  if (!exp || exp.__ptracedMcp) return exp;
  try { Object.defineProperty(exp, "__ptracedMcp", { value: true, enumerable: false }); } catch (_) { return exp; }
  const out = () => { try { return String(exp.outboundRequestCount ? exp.outboundRequestCount() : "?"); } catch (_) { return "?"; } };
  for (const name of ["toolVerify", "toolScan"]) {
    const real = exp[name];
    if (typeof real !== "function") continue;
    log(`INSTRUMENTATION ATTACHED to ${path.basename(resolved)} (${name}) pid=${process.pid}`);
    exp[name] = async function (input) {
      const a = process.hrtime.bigint();
      log(`${name} REQUEST RECEIVED path=${role(input && input.path)} outboundBefore=${out()}`);
      let r, threw;
      try { r = await real.apply(this, arguments); return r; }
      catch (e) { threw = e; throw e; }
      finally {
        // Guaranteed, and BEFORE any caller assertion can stop the observation.
        const d = (Number(process.hrtime.bigint() - a) / 1e6).toFixed(0);
        const state = threw ? `threw ${threw && threw.name}` : (r && r.ok ? (r.payload && r.payload.state) : "refused");
        log(`${name} RESPONSE EMITTED ${d}ms state=${state} outboundAfter=${out()}`);
      }
    };
  }
  return exp;
}

const realLoad = Module._load;
Module._load = function (request, parent, isMain) {
  const exp = realLoad.apply(this, arguments);
  try {
    const resolved = Module._resolveFilename(request, parent, isMain);
    if (/consent-budget\.(ts|js)$/.test(resolved)) return wrapBudget(exp, resolved);
    if (/mcp-core\.(ts|js)$/.test(resolved)) return wrapMcp(exp, resolved);
  } catch (_) { /* builtins and virtual ids do not resolve */ }
  return exp;
};

// npm, vsce and the smoke's driver all inherit NODE_OPTIONS. Announcing the preload in every
// one of them would bury the evidence, so only the entry points that can reach the budget say
// so; the ATTACHED line above is what actually proves the hook ran.
if (/[\\/]out[\\/](mcp|cli)\.js$/i.test(String(process.argv[1] || ""))) {
  log(`preload installed in ${path.basename(String(process.argv[1]))} pid=${process.pid} node=${process.version} ${process.arch}`);
}
