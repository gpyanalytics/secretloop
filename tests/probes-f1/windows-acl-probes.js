#!/usr/bin/env node
/*
 * EVIDENCE-ONLY PROTOTYPE for the Windows consent-store ACL policy. Not product code.
 * Runs only on win32. Synthetic stores and records under an explicit lab root only;
 * never touches a real profile store.
 *
 *   node windows-acl-probes.js facts
 *   node windows-acl-probes.js create --root <store>            protected-DACL store creation (the proposed sequence)
 *   node windows-acl-probes.js inspect --path <p> [--owner-sid S]  icacls /save -> SDDL -> policy decision (JSON)
 *   node windows-acl-probes.js owner --path <p>                 owner SID via PowerShell (reliability probe)
 *   node windows-acl-probes.js other-user --store <s> [--target <rec>] [--flip]
 *   node windows-acl-probes.js call1 --out <dir> --root <store> --repo <dir>      real consent path, call 1
 *   node windows-acl-probes.js call2 --out <dir> --root <store> --repo <dir>      real consent path, call 2 (fetch intercepted)
 *   node windows-acl-probes.js unavailable --root <store>       enforcement failure + decision table (tooling absence: run inspect --icacls <missing>)
 *   common: --tmp <dir> for the transient icacls /save file (must be writable by the invoking user)
 *
 * Principals are handled as SIDs only (never localized names). No value or commitment is ever printed.
 * Every icacls/PowerShell child is spawned by absolute path, without a shell, with a timeout; exit status
 * and stderr are captured. A probe that cannot reach its operation prints PROBE-ERROR and exits 2.
 */
"use strict";
const fs = require("fs");
const path = require("path");
const cp = require("child_process");
const crypto = require("crypto");

const args = process.argv.slice(2);
const opt = (n, d) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : d; };
const has = (n) => args.includes(n);
const mode = args[0];
const log = (k, v) => console.log(`${k}: ${typeof v === "string" ? v : JSON.stringify(v)}`);
const code = (e) => (e && e.code) || String(e);
if (process.platform !== "win32") { console.log("PROBE-ERROR: win32 only"); process.exit(3); }

const SYSTEM_ROOT = process.env.SystemRoot || "C:\\Windows";
const ICACLS = opt("--icacls") || path.join(SYSTEM_ROOT, "System32", "icacls.exe"); // --icacls only to simulate absent tooling
const TMP = opt("--tmp", require("os").tmpdir()); // where the transient /save file goes: never inside the store
const POWERSHELL = path.join(SYSTEM_ROOT, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
const SID_SYSTEM = "S-1-5-18", SID_ADMINS = "S-1-5-32-544";
// SDDL string-SID aliases as icacls /save emits them. Closed table; an alias not listed here is refused as unknown.
const SDDL_ALIAS = { BA: "S-1-5-32-544", BU: "S-1-5-32-545", BG: "S-1-5-32-546", PU: "S-1-5-32-547", AO: "S-1-5-32-548", SO: "S-1-5-32-549", PO: "S-1-5-32-550", BO: "S-1-5-32-551", RE: "S-1-5-32-552", RU: "S-1-5-32-554", RD: "S-1-5-32-555", NO: "S-1-5-32-556", SY: "S-1-5-18", LS: "S-1-5-19", NS: "S-1-5-20", WD: "S-1-1-0", AU: "S-1-5-11", IU: "S-1-5-4", NU: "S-1-5-2", AN: "S-1-5-7", RC: "S-1-5-12", CO: "S-1-3-0", CG: "S-1-3-1", OW: "S-1-3-4", AC: "S-1-15-2-1", LW: "S-1-16-4096", ME: "S-1-16-8192", HI: "S-1-16-12288", SI: "S-1-16-16384", ES: "S-1-5-32-573", LU: "S-1-5-32-559", CY: "S-1-5-32-569", MU: "S-1-5-32-558", IS: "S-1-5-17" };
const canonSid = (x) => /^S-1-/.test(x) ? x : (SDDL_ALIAS[x] || `unknown-alias:${x}`);
const WELL_KNOWN = { "S-1-1-0": "Everyone", "S-1-5-11": "Authenticated Users", "S-1-5-32-545": "Users", "S-1-3-0": "CREATOR OWNER", "S-1-5-18": "SYSTEM", "S-1-5-32-544": "Administrators" };

function run(exe, argv, timeoutMs = 15000) {
  if (!fs.existsSync(exe)) return { unavailable: true, exe };
  const r = cp.spawnSync(exe, argv, { encoding: "utf8", timeout: timeoutMs, windowsHide: true });
  return { status: r.status, signal: r.signal, error: r.error ? code(r.error) : null, stdout: r.stdout || "", stderr: r.stderr || "", timedOut: !!(r.error && r.error.code === "ETIMEDOUT") };
}
function currentSid() {
  const r = run(path.join(SYSTEM_ROOT, "System32", "whoami.exe"), ["/user", "/fo", "csv", "/nh"]);
  if (r.unavailable || r.status !== 0) return null;
  const m = /"(S-1-[0-9-]+)"/.exec(r.stdout); return m ? m[1] : null;
}
/** SDDL of an object's DACL through `icacls /save` (SIDs, not names; language-independent). */
function sddlOf(p) {
  const tmp = path.join(TMP, `acl-${process.pid}-${crypto.randomBytes(4).toString("hex")}.txt`);
  const r = run(ICACLS, [p, "/save", tmp, "/q"]);
  if (r.unavailable) return { unavailable: true };
  if (r.status !== 0 || r.timedOut) { return { failed: true, status: r.status, timedOut: r.timedOut, stderrLen: r.stderr.length }; }
  let text;
  try { text = fs.readFileSync(tmp, "utf16le"); } catch (e) { return { failed: true, read: code(e) }; } finally { try { fs.unlinkSync(tmp); } catch {} }
  const lines = text.replace(/^\uFEFF/, "").split(/\r?\n/).filter((l) => l.length);
  // Format: <name line>, <sddl line>, repeated. We saved one object.
  const sddl = lines.length >= 2 ? lines[1] : null;
  if (!sddl || !/^D:/.test(sddl)) return { malformed: true, lines: lines.length };
  return { sddl };
}
/** Parses "D:FLAGS(ace)(ace)..." into flags and ACEs {type, flags, rights, sid}. */
function parseDacl(sddl) {
  const m = /^D:([A-Z]*)((?:\([^)]*\))*)$/.exec(sddl.trim());
  if (!m) return null;
  const aces = [...m[2].matchAll(/\(([^)]*)\)/g)].map((x) => { const f = x[1].split(";"); return { type: f[0], flags: f[1], rights: f[2], sid: canonSid(f[5]), raw: f[5] }; });
  return { flags: m[1], aces };
}
/** THE POLICY DECISION on one object. Refusal reasons are closed; the inheritance flag is advisory only. */
function decide(sddl, ownerSid, isDir) {
  const d = parseDacl(sddl);
  if (!d) return { ok: false, reason: "malformed", sddl };
  const allowed = new Set([ownerSid, SID_SYSTEM, SID_ADMINS]);
  const problems = []; const advisories = [];
  if (isDir && !d.flags.includes("P")) advisories.push("directory-inherits-from-parent");
  for (const a of d.aces) {
    if (a.type !== "A") problems.push(`non-allow-ace:${a.type}:${a.sid}`);
    else if (!allowed.has(a.sid)) problems.push(`foreign-principal:${a.sid}${WELL_KNOWN[a.sid] ? "(" + WELL_KNOWN[a.sid] + ")" : ""}`);
  }
  if (!d.aces.some((a) => a.sid === ownerSid && a.type === "A")) problems.push("owner-not-granted");
  return { ok: problems.length === 0, reason: problems.length ? problems.join(",") : "private", advisories, flags: d.flags, aceCount: d.aces.length, principals: d.aces.map((a) => `${a.type}:${a.flags}:${a.rights}:${a.sid}`) };
}
function inspect(p, ownerSid, isDir) {
  const s = sddlOf(p);
  if (s.unavailable) return { ok: false, reason: "acl-tooling-unavailable" };
  if (s.failed) return { ok: false, reason: "acl-inspection-failed", detail: { status: s.status, timedOut: s.timedOut } };
  if (s.malformed) return { ok: false, reason: "acl-inspection-malformed" };
  return Object.assign(decide(s.sddl, ownerSid, isDir), { sddl: s.sddl });
}
function protect(dir, ownerSid) {
  // One invocation: remove inheritance, replace grants with exactly the allowed set.
  const r = run(ICACLS, [dir, "/inheritance:r", "/grant:r", `*${ownerSid}:(OI)(CI)F`, `*${SID_SYSTEM}:(OI)(CI)F`, `*${SID_ADMINS}:(OI)(CI)F`, "/q"]);
  if (r.unavailable) return { ok: false, reason: "acl-tooling-unavailable" };
  if (r.status !== 0 || r.timedOut) return { ok: false, reason: "acl-enforcement-failed", status: r.status, timedOut: r.timedOut, stderrLen: r.stderr.length };
  return { ok: true };
}
function facts() {
  const os = require("os");
  log("platform", `${process.platform}/${process.arch} ${os.release()}`); log("node", process.version);
  log("user-sid", currentSid() || "unknown");
  const g = run(path.join(SYSTEM_ROOT, "System32", "whoami.exe"), ["/groups", "/fo", "csv", "/nh"]);
  log("elevated", /S-1-16-12288/.test(g.stdout) ? "yes (high integrity)" : /S-1-16-8192/.test(g.stdout) ? "no (medium integrity)" : "unknown");
  log("icacls", fs.existsSync(ICACLS) ? `present at ${ICACLS.replace(/^.*\\System32/, "<SystemRoot>\\System32")}` : "ABSENT");
  const drive = (opt("--root", process.cwd())).slice(0, 2);
  const v = run(path.join(SYSTEM_ROOT, "System32", "fsutil.exe"), ["fsinfo", "volumeinfo", drive]);
  const fsm = /File System Name\s*:\s*(\S+)/.exec(v.stdout || ""); log("filesystem", fsm ? fsm[1] : `unknown (fsutil status ${v.status}; needs elevation on some hosts)`);
  const ps = run(POWERSHELL, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "$PSVersionTable.PSVersion.ToString()"], 30000);
  log("powershell", ps.unavailable ? "absent" : `status ${ps.status}: ${ps.stdout.trim().slice(0, 20)}`);
}
function create() {
  const root = opt("--root"); const sid = currentSid(); if (!root || !sid) throw new Error("--root and a resolvable SID are required");
  fs.rmSync(root, { recursive: true, force: true });
  // Proposed creation sequence: mkdir store -> protect it -> mkdir pending (inherits the protected DACL).
  fs.mkdirSync(root);
  const before = inspect(root, sid, true); log("store.before-protect", { reason: before.reason, principals: before.principals });
  const pr = protect(root, sid); log("store.protect", pr);
  const after = inspect(root, sid, true); log("store.after-protect", { ok: after.ok, reason: after.reason, flags: after.flags, principals: after.principals });
  const pend = path.join(root, "pending"); fs.mkdirSync(pend);
  const pi = inspect(pend, sid, true); log("pending.inherited", { ok: pi.ok, reason: pi.reason, flags: pi.flags, principals: pi.principals });
  // A record written the way the product writes it (temp + rename, mode ignored on win32) -- what does it inherit?
  const rec = path.join(pend, "probe-record.json"); const tmp = rec + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify({ synthetic: true }) + "\n", { mode: 0o600 }); fs.renameSync(tmp, rec);
  const ri = inspect(rec, sid, false); log("record.inherited", { ok: ri.ok, reason: ri.reason, flags: ri.flags, principals: ri.principals });
  fs.unlinkSync(rec); // leave the created store empty for the product to use
  // "pending" created BEFORE protection (the older layout): does protecting the parent later fix it?
  const root2 = root + "-late"; fs.rmSync(root2, { recursive: true, force: true }); fs.mkdirSync(path.join(root2, "pending"), { recursive: true });
  const r2 = path.join(root2, "pending", "old-record.json"); fs.writeFileSync(r2, "{}\n");
  const p2 = protect(root2, sid); const late = inspect(path.join(root2, "pending"), sid, true); const lateRec = inspect(r2, sid, false);
  log("late-protect.parent-only", { protect: p2.ok, pendingAfter: { ok: late.ok, reason: late.reason, principals: late.principals }, oldRecordAfter: { ok: lateRec.ok, reason: lateRec.reason, principals: lateRec.principals } });
  // a planted file with its OWN explicit grant survives parent-only protection?
  const planted = path.join(root2, "pending", "planted.json"); fs.writeFileSync(planted, "{}\n"); run(ICACLS, [planted, "/grant", "*S-1-1-0:F", "/q"]);
  const before2 = inspect(planted, sid, false);
  const p3 = run(ICACLS, [root2, "/inheritance:r", "/grant:r", `*${sid}:(OI)(CI)F`, `*${SID_SYSTEM}:(OI)(CI)F`, `*${SID_ADMINS}:(OI)(CI)F`, "/t", "/q"]);
  const after2 = inspect(planted, sid, false);
  log("late-protect.tree", { treeStatus: p3.status, plantedBefore: { ok: before2.ok, reason: before2.reason }, plantedAfterTree: { ok: after2.ok, reason: after2.reason, principals: after2.principals } });
  fs.rmSync(root2, { recursive: true, force: true });
  console.log("CREATED: " + root);
}
function owner() {
  const p = opt("--path");
  const r = run(POWERSHELL, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", `(Get-Acl -LiteralPath '${p.replace(/'/g, "''")}').GetOwner([System.Security.Principal.SecurityIdentifier]).Value`], 30000);
  if (r.unavailable) { log("owner", "powershell absent"); return; }
  const sid = /^(S-1-[0-9-]+)\s*$/m.exec(r.stdout || "");
  log("owner", { status: r.status, sid: sid ? sid[1] : null, stderrHead: (r.stderr || "").trim().slice(0, 90).replace(/\r?\n/g, " ") });
}
function inspectMode() {
  const p = opt("--path"); const sid = opt("--owner-sid", currentSid()); const st = fs.lstatSync(p);
  const i = inspect(p, sid, st.isDirectory()); log("inspect", { isDir: st.isDirectory(), isLink: st.isSymbolicLink(), ok: i.ok, reason: i.reason, advisories: i.advisories, flags: i.flags, principals: i.principals, detail: i.detail });
}
function otherUser() {
  const store = opt("--store"); const target = opt("--target"); const flip = has("--flip");
  const res = { sid: currentSid() }; const pend = path.join(store, "pending");
  const attempt = (n, fn) => { try { const r = fn(); res[n] = r === undefined ? "ok" : r; } catch (e) { res[n] = "error:" + code(e); } };
  attempt("list.store", () => fs.readdirSync(store).length);
  attempt("list.pending", () => fs.readdirSync(pend).length);
  attempt("plant.pending", () => { const p = path.join(pend, "planted-by-other.json"); fs.writeFileSync(p, "{}\n"); fs.unlinkSync(p); });
  if (target) {
    attempt("read.record", () => { const s = fs.readFileSync(target, "utf8"); const j = JSON.parse(s); return `READ (${j.state || "?"})`; });
    attempt("append.record", () => fs.appendFileSync(target, "\n"));
    if (flip) attempt("flip.record-to-approved", () => {
      // The forgery that needs NO knowledge of the value: a pending record already carries the current
      // value's commitment, so flipping state and adding an expiry is enough if the writer is accepted.
      const j = JSON.parse(fs.readFileSync(target, "utf8"));
      j.state = "approved"; j.approvedAt = new Date().toISOString(); j.expiresAt = new Date(Date.now() + 300000).toISOString();
      fs.writeFileSync(target, JSON.stringify(j, null, 2) + "\n"); return "written";
    });
    attempt("replace.record", () => { const t = target + ".other"; fs.writeFileSync(t, fs.readFileSync(target)); fs.renameSync(t, target); });
    attempt("rename.record", () => { fs.renameSync(target, target + ".moved"); fs.renameSync(target + ".moved", target); });
    attempt("setacl.record", () => { const r = run(ICACLS, [target, "/grant", `*S-1-1-0:F`, "/q"]); return r.status === 0 ? "GRANTED-EVERYONE" : "denied:" + r.status; });
  }
  console.log("OTHER-USER: " + JSON.stringify(res));
}
function loadProduct() {
  const OUT = opt("--out"); if (!OUT) throw new Error("--out required");
  return { consent: require(path.join(OUT, "consent.js")), mcp: require(path.join(OUT, "mcp-core.js")) };
}
function repoFixture(dir) {
  fs.mkdirSync(dir, { recursive: true });
  const a = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"; let v = "ghp_"; for (let i = 0; i < 36; i++) v += a[(i * 23 + 7) % a.length];
  fs.writeFileSync(path.join(dir, "app.js"), `const t = "${v}";\n`);
  return fs.realpathSync(dir);
}
function fpFile(root) { return path.join(path.dirname(root), path.basename(root) + ".fp"); }
async function call1() {
  const { consent, mcp } = loadProduct(); const root = opt("--root"); const repo = repoFixture(opt("--repo"));
  consent.setConsentRootForTests(root); mcp.setAllowedRoots([repo]); mcp.resetSessions();
  let outbound = 0; mcp.setVerifyFetchForTests(async () => { outbound++; return new Response("{}", { status: 401 }); });
  const scan = mcp.toolScan({ path: repo }); if (!scan.ok) throw new Error("scan failed: " + scan.error);
  const f = scan.payload.findings.find((x) => x.ruleId === "github-token"); if (!f) throw new Error("no github finding");
  const r = await mcp.toolVerify({ path: repo, fingerprint: f.fingerprint });
  const id = consent.recordId(f.fingerprint, repo); const rp = path.join(consent.pendingDir(), id + ".json");
  log("call1", { state: r.ok ? r.payload.state : "fail:" + String(r.error).slice(0, 80), outbound, recordExists: fs.existsSync(rp) });
  fs.writeFileSync(fpFile(root), f.fingerprint);
  const sid = currentSid();
  for (const [k, p, d] of [["store", root, true], ["pending", consent.pendingDir(), true], ["record", rp, false]]) { const i = inspect(p, sid, d); log(`call1.acl.${k}`, { ok: i.ok, reason: i.reason, advisories: i.advisories, flags: i.flags, principals: i.principals }); }
  console.log("RECORD-PATH: " + rp);
}
async function call2() {
  const { consent, mcp } = loadProduct(); const root = opt("--root"); const repo = fs.realpathSync(opt("--repo"));
  const fp = fs.readFileSync(fpFile(root), "utf8");
  consent.setConsentRootForTests(root); mcp.setAllowedRoots([repo]); mcp.resetSessions();
  let outbound = 0; mcp.setVerifyFetchForTests(async () => { outbound++; return new Response("{}", { status: 401 }); });
  const id = consent.recordId(fp, repo); let seen; try { const rec = consent.readRecord(id); seen = rec ? rec.state : "absent"; } catch (e) { seen = "store-refused:" + (e.problem || code(e)); }
  const scan = mcp.toolScan({ path: repo }); if (!scan.ok) throw new Error("scan failed: " + scan.error); // the client scans in this session first, as in call 1
  const r = await mcp.toolVerify({ path: repo, fingerprint: fp });
  log("call2", { recordStateSeen: seen, state: r.ok ? r.payload.state : "fail:" + String(r.error).slice(0, 100), outboundAttempted: outbound, externalTransmission: r.ok && r.payload.network ? r.payload.network.externalTransmission : null });
}
function unavailable() {
  const root = opt("--root"); const sid = currentSid();
  // 1. enforcement failure: an invalid SID makes icacls fail; the caller must see a failure, not success.
  fs.mkdirSync(root, { recursive: true });
  const bad = protect(root, "S-1-5-21-0-0-0-99999999");
  log("enforcement-failure.invalid-sid", bad);
  const still = inspect(root, sid, true); log("enforcement-failure.state-after", { ok: still.ok, reason: still.reason, advisories: still.advisories });
  // 2. malformed inspection: parse a non-SDDL string.
  log("decision.malformed", decide("garbage", sid, true).reason);
  // 3. decision table on fixed SDDL inputs (SID-only, language independent).
  log("decision.foreign-users", decide(`D:PAI(A;OICI;FA;;;${sid})(A;OICI;FA;;;S-1-5-18)(A;OICI;FA;;;S-1-5-32-544)(A;OICI;FA;;;S-1-5-32-545)`, sid, true).reason);
  log("decision.foreign-everyone-inherited", decide(`D:AI(A;OICIID;FA;;;S-1-1-0)(A;OICIID;FA;;;${sid})`, sid, true).reason);
  log("decision.deny-ace", decide(`D:PAI(D;OICI;FA;;;S-1-1-0)(A;OICI;FA;;;${sid})(A;OICI;FA;;;S-1-5-18)(A;OICI;FA;;;S-1-5-32-544)`, sid, true).reason);
  const unp = decide(`D:AI(A;OICIID;FA;;;${sid})(A;OICIID;FA;;;S-1-5-18)(A;OICIID;FA;;;S-1-5-32-544)`, sid, true); log("decision.unprotected-but-private", { reason: unp.reason, advisories: unp.advisories });
  log("decision.owner-missing", decide(`D:PAI(A;OICI;FA;;;S-1-5-18)(A;OICI;FA;;;S-1-5-32-544)`, sid, true).reason);
  log("decision.private", decide(`D:PAI(A;OICI;FA;;;${sid})(A;OICI;FA;;;S-1-5-18)(A;OICI;FA;;;S-1-5-32-544)`, sid, true).reason);
  log("decision.record-private", decide(`D:AI(A;ID;FA;;;${sid})(A;ID;FA;;;S-1-5-18)(A;ID;FA;;;S-1-5-32-544)`, sid, false).reason);
  fs.rmSync(root, { recursive: true, force: true });
}
(async () => {
  try {
    if (mode === "facts") facts();
    else if (mode === "create") create();
    else if (mode === "inspect") inspectMode();
    else if (mode === "owner") owner();
    else if (mode === "other-user") otherUser();
    else if (mode === "call1") await call1();
    else if (mode === "call2") await call2();
    else if (mode === "unavailable") unavailable();
    else throw new Error("unknown mode " + mode);
  } catch (e) { console.log("PROBE-ERROR: " + (e && e.stack || e)); process.exit(2); }
})();
