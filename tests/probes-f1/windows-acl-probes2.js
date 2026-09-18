#!/usr/bin/env node
/*
 * EVIDENCE-ONLY ADDENDUM PROBES for the Windows consent-store ACL design. Not product code.
 * Closes the gaps left by windows-acl-probes.js: the creation window, retained handles, object
 * OWNERSHIP versus process identity, DACL semantics (NULL/empty/insufficient rights/inherit-only),
 * and whether a pre-planted record can become trusted.
 *
 * Synthetic records only, in an explicit lab root. Never touches a real profile store. No provider
 * call: the outbound boundary is replaced by a counting interceptor. No value or commitment printed.
 * Every child process is spawned by absolute path, without a shell, with a timeout; exit status kept.
 * A probe that cannot reach its operation prints PROBE-ERROR and exits 2 (a NON-MEASUREMENT, never a pass).
 *
 * modes:
 *   facts                                   environment, privileges, tooling versions
 *   parser                                  offline decision/parser table (runs on any platform)
 *   save-shape   --path P                   exactly what `icacls /save` exposes for one object
 *   owner-of     --path P                   every mechanism for reading an object's OWNER SID
 *   create-open  --root R                   owner: mkdir only -- leaves the creation window OPEN
 *   plant        --store S [--id I] [--repo D] [--out O] [--approved]   attacker: plant inside the window
 *   hold         --file F [--dir D] --ready P --go P [--wait S]         attacker: open handles, retain across the close
 *   create-close --root R                   owner: apply the protected DACL, then inspect store/pending/children
 *   make-repo    --repo D                                                synthetic one-finding repository
 *   inspect      --path P                                                the policy decision on one object
 *   record-id    --out O --repo D                                        the id/fingerprint the product will look for
 *   trust        --out O --root R --repo D                                product: is the pre-planted record trusted?
 *   own-clean    --dir D --owner-sid S      attacker: create a file IT owns whose DACL names only allowed principals
 *   own-regain   --path P                   attacker: re-grant itself through implicit WRITE_DAC, then read/write
 *   rights       --root R                   insufficient rights, inherit-only ACEs, empty DACL, partial success
 *   common: --tmp DIR (writable by the invoking user; holds the transient /save file)
 */
"use strict";
const fs = require("fs");
const path = require("path");
const cp = require("child_process");
const crypto = require("crypto");
const os = require("os");

const args = process.argv.slice(2);
const mode = args[0];
const opt = (n, d) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : d; };
const has = (n) => args.includes(n);
const log = (k, v) => console.log(`${k}: ${typeof v === "string" ? v : JSON.stringify(v)}`);
const code = (e) => (e && e.code) || String(e && e.message || e);
const WIN = process.platform === "win32";
if (!WIN && mode !== "parser") { console.log("PROBE-ERROR: win32 only (except parser)"); process.exit(3); }

const SYSTEM_ROOT = process.env.SystemRoot || "C:\\Windows";
const SYS32 = path.join(SYSTEM_ROOT, "System32");
const ICACLS = opt("--icacls") || path.join(SYS32, "icacls.exe");
const WHOAMI = path.join(SYS32, "whoami.exe");
const POWERSHELL = path.join(SYS32, "WindowsPowerShell", "v1.0", "powershell.exe");
const PWSH = "C:\\Program Files\\PowerShell\\7\\pwsh.exe";
const CMD = path.join(SYS32, "cmd.exe");
const TMP = opt("--tmp", os.tmpdir());
const SID_SYSTEM = "S-1-5-18", SID_ADMINS = "S-1-5-32-544";

// SDDL string-SID aliases (closed table, per the SDDL specification). An alias outside it is REFUSED,
// never accepted: guessing a mapping would silently widen the allowed set.
const SDDL_ALIAS = { BA:"S-1-5-32-544", BU:"S-1-5-32-545", BG:"S-1-5-32-546", PU:"S-1-5-32-547", AO:"S-1-5-32-548", SO:"S-1-5-32-549", PO:"S-1-5-32-550", BO:"S-1-5-32-551", RE:"S-1-5-32-552", RU:"S-1-5-32-554", RD:"S-1-5-32-555", NO:"S-1-5-32-556", MU:"S-1-5-32-558", LU:"S-1-5-32-559", CY:"S-1-5-32-569", ES:"S-1-5-32-573", SY:"S-1-5-18", LS:"S-1-5-19", NS:"S-1-5-20", WD:"S-1-1-0", AU:"S-1-5-11", IU:"S-1-5-4", NU:"S-1-5-2", AN:"S-1-5-7", RC:"S-1-5-12", IS:"S-1-5-17", CO:"S-1-3-0", CG:"S-1-3-1", OW:"S-1-3-4", AC:"S-1-15-2-1", LW:"S-1-16-4096", ME:"S-1-16-8192", HI:"S-1-16-12288", SI:"S-1-16-16384" };
const NAMED = { "S-1-1-0":"Everyone", "S-1-5-11":"Authenticated Users", "S-1-5-32-545":"Users", "S-1-3-0":"CREATOR OWNER", "S-1-5-18":"SYSTEM", "S-1-5-32-544":"Administrators" };
const canonSid = (x) => (x && /^S-1-/.test(x) ? x : (SDDL_ALIAS[x] || `unknown-alias:${x}`));

function run(exe, argv, timeoutMs = 20000) {
  if (!fs.existsSync(exe)) return { unavailable: true, exe };
  const r = cp.spawnSync(exe, argv, { encoding: "utf8", timeout: timeoutMs, windowsHide: true });
  return { status: r.status, error: r.error ? code(r.error) : null, stdout: r.stdout || "", stderr: r.stderr || "",
           timedOut: !!(r.error && (r.error.code === "ETIMEDOUT" || r.error.killed)) };
}
function currentSid() {
  const r = run(WHOAMI, ["/user", "/fo", "csv", "/nh"]);
  if (r.unavailable || r.status !== 0) return null;
  const m = /"(S-1-[0-9-]+)"/.exec(r.stdout); return m ? m[1] : null;
}
/** Raw `icacls /save` result for one object, with the transient file kept OUT of the store. */
function saveRaw(p) {
  const tmp = path.join(TMP, `acl2-${process.pid}-${crypto.randomBytes(4).toString("hex")}.txt`);
  const r = run(ICACLS, [p, "/save", tmp, "/q"]);
  if (r.unavailable) return { unavailable: true };
  let buf = null, readErr = null;
  try { buf = fs.readFileSync(tmp); } catch (e) { readErr = code(e); } finally { try { fs.unlinkSync(tmp); } catch {} }
  return { status: r.status, timedOut: r.timedOut, stderr: r.stderr, buf, readErr };
}
function sddlOf(p) {
  const raw = saveRaw(p);
  if (raw.unavailable) return { unavailable: true };
  if (raw.status !== 0 || raw.timedOut) return { failed: true, status: raw.status, timedOut: raw.timedOut };
  if (raw.buf === null) return { failed: true, read: raw.readErr };
  const lines = raw.buf.toString("utf16le").replace(/^\uFEFF/, "").split(/\r?\n/).filter((l) => l.length);
  const sddl = lines.length >= 2 ? lines[1] : null;
  if (!sddl || !/^D:/.test(sddl)) return { malformed: true, lines: lines.length, first: (lines[0] || "").slice(0, 12) };
  return { sddl, lineCount: lines.length };
}
function parseDacl(sddl) {
  if (typeof sddl !== "string") return null;
  const t = sddl.trim();
  // A NULL DACL is NOT "D:" + ACEs. SDDL spells it D:NO_ACCESS_CONTROL, and a descriptor with no D:
  // component at all is also a NULL DACL. Documented: a NULL DACL grants full access to any user.
  if (/^D:NO_ACCESS_CONTROL$/i.test(t)) return { nullDacl: true };
  // An SDDL-shaped descriptor that carries other components but NO D: component has a NULL DACL.
  // Text that is not a descriptor at all is malformed -- never silently folded into either case.
  if (!/^D:/.test(t)) return /^[OGS]:/.test(t) ? { nullDacl: true, noComponent: true } : null;
  const m = /^D:([A-Z]*)((?:\([^)]*\))*)$/.exec(t);
  if (!m) return null;                                   // truncated / unparsable -> caller refuses
  const aces = [...m[2].matchAll(/\(([^)]*)\)/g)].map((x) => {
    const f = x[1].split(";");
    return { type: f[0], flags: f[1] || "", rights: f[2] || "", sid: canonSid(f[5]), raw: f[5] };
  });
  return { flags: m[1], aces };
}
/** Rights the current user must actually hold on a store DIRECTORY / a RECORD for the product to work. */
function rightsSufficient(ace, isDir) {
  const r = (ace.rights || "").toUpperCase();
  if (r === "FA" || r === "GA") return true;                       // full / generic all
  if (/^0X/.test(r)) { const v = parseInt(r, 16); return Number.isFinite(v) && (v & 0x1F01FF) === 0x1F01FF; } // FILE_ALL_ACCESS
  return false;                                                     // anything narrower is not asserted sufficient
}
/** THE POLICY DECISION on one object's DACL. Closed reasons; inheritance is advisory. */
function decide(sddl, userSid, isDir) {
  const d = parseDacl(sddl);
  if (!d) return { ok: false, reason: "malformed" };
  if (d.nullDacl) return { ok: false, reason: "null-dacl" };        // documented: grants full access to everyone
  const allowed = new Set([userSid, SID_SYSTEM, SID_ADMINS]);
  const problems = [], advisories = [];
  if (isDir && !d.flags.includes("P")) advisories.push("directory-inherits-from-parent");
  if (d.aces.length === 0) problems.push("empty-dacl");             // documented: grants no access at all
  for (const a of d.aces) {
    if (a.type !== "A") problems.push(`non-allow-ace:${a.type}:${a.sid}`);
    else if (!allowed.has(a.sid)) problems.push(`foreign-principal:${a.sid}${NAMED[a.sid] ? "(" + NAMED[a.sid] + ")" : ""}`);
  }
  const mine = d.aces.filter((a) => a.type === "A" && a.sid === userSid);
  if (mine.length === 0) problems.push("owner-not-granted");
  // An ACE marked inherit-only (IO) does NOT apply to the object carrying it, so it cannot supply the
  // access the product needs -- and a foreign IO ACE still propagates to children, which is why it is
  // never ignored above.
  else if (!mine.some((a) => !/IO/.test(a.flags) && rightsSufficient(a, isDir))) problems.push("insufficient-rights");
  return { ok: problems.length === 0, reason: problems.length ? problems.join(",") : "private", advisories,
           flags: d.flags, aceCount: d.aces.length, principals: d.aces.map((a) => `${a.type}:${a.flags}:${a.rights}:${a.sid}`) };
}
function inspect(p, userSid, isDir) {
  const s = sddlOf(p);
  if (s.unavailable) return { ok: false, reason: "acl-tooling-unavailable" };
  if (s.failed) return { ok: false, reason: "acl-inspection-failed", detail: { status: s.status, timedOut: s.timedOut } };
  if (s.malformed) return { ok: false, reason: "acl-inspection-malformed", detail: { lines: s.lines } };
  return Object.assign(decide(s.sddl, userSid, isDir), { sddl: s.sddl });
}
function protect(dir, userSid) {
  const r = run(ICACLS, [dir, "/inheritance:r", "/grant:r", `*${userSid}:(OI)(CI)F`, `*${SID_SYSTEM}:(OI)(CI)F`, `*${SID_ADMINS}:(OI)(CI)F`, "/q"]);
  if (r.unavailable) return { ok: false, reason: "acl-tooling-unavailable" };
  if (r.status !== 0 || r.timedOut) return { ok: false, reason: "acl-enforcement-failed", status: r.status, timedOut: r.timedOut };
  // A partially successful icacls run reports failures on stdout while still exiting 0 in some forms;
  // treat any non-zero "Failed processing" count as an enforcement failure.
  const failed = /Failed processing (\d+) files/.exec(r.stdout || "");
  if (failed && failed[1] !== "0") return { ok: false, reason: "acl-enforcement-partial", failed: failed[1] };
  return { ok: true };
}
const briefly = (i) => ({ ok: i.ok, reason: i.reason, advisories: i.advisories, flags: i.flags, principals: i.principals, detail: i.detail });

// ---------------------------------------------------------------------------- modes
function facts() {
  log("platform", `${process.platform}/${process.arch} ${os.release()}`);
  log("node", process.version);
  log("user-sid", currentSid() || "unknown");
  const g = run(WHOAMI, ["/groups", "/fo", "csv", "/nh"]);
  log("integrity", /S-1-16-12288/.test(g.stdout) ? "high (elevated)" : /S-1-16-8192/.test(g.stdout) ? "medium (ordinary)" : "unknown");
  log("member-of-administrators", /S-1-5-32-544/.test(g.stdout) ? "YES" : "no");
  const pr = run(WHOAMI, ["/priv", "/fo", "csv", "/nh"]);
  log("SeCreateSymbolicLinkPrivilege", /SeCreateSymbolicLinkPrivilege/.test(pr.stdout) ? "present" : "absent");
  log("SeRestorePrivilege", /SeRestorePrivilege/.test(pr.stdout) ? "present" : "absent");
  log("SeTakeOwnershipPrivilege", /SeTakeOwnershipPrivilege/.test(pr.stdout) ? "present" : "absent");
  const iv = run(ICACLS, ["/?"]); log("icacls", fs.existsSync(ICACLS) ? `present (help exit ${iv.status})` : "ABSENT");
  const drive = (opt("--root", TMP)).slice(0, 2);
  const v = run(path.join(SYS32, "fsutil.exe"), ["fsinfo", "volumeinfo", drive]);
  const fsm = /File System Name\s*:\s*(\S+)/.exec(v.stdout || "");
  log("filesystem", fsm ? fsm[1] : `unreadable (fsutil status ${v.status}; needs elevation on some hosts)`);
  const ps = run(POWERSHELL, ["-NoProfile", "-NonInteractive", "-Command", "$PSVersionTable.PSVersion.ToString()"], 45000);
  log("windows-powershell", ps.unavailable ? "absent" : `status ${ps.status}: ${(ps.stdout || "").trim().slice(0, 20)}`);
  const p7 = run(PWSH, ["-NoProfile", "-NonInteractive", "-Command", "$PSVersionTable.PSVersion.ToString()"], 45000);
  log("pwsh7 (not depended on)", p7.unavailable ? "absent" : `status ${p7.status}: ${(p7.stdout || "").trim().slice(0, 20)}`);
  const cs = run(POWERSHELL, ["-NoProfile", "-NonInteractive", "-Command", "(Get-Culture).Name + ' / ' + (Get-UICulture).Name"], 45000);
  log("culture/ui-culture", (cs.stdout || "").trim() || `status ${cs.status}`);
}

function parser() {
  const me = "S-1-5-21-1-1-1-1003", other = "S-1-5-21-1-1-1-1004";
  const cases = [
    ["private protected dir",        `D:PAI(A;OICI;FA;;;${me})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`, true],
    ["private inherited dir",        `D:AI(A;OICIID;FA;;;${me})(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)`, true],
    ["private record",               `D:AI(A;ID;FA;;;${me})(A;ID;FA;;;SY)(A;ID;FA;;;BA)`, false],
    ["NULL dacl (explicit)",         `D:NO_ACCESS_CONTROL`, true],
    ["NULL dacl (no D: component)",  `O:BAG:BA`, true],
    ["empty dacl",                   `D:P`, true],
    ["empty dacl inherited-flagged", `D:AI`, true],
    ["owner read-only (RX)",         `D:PAI(A;OICI;0x1200a9;;;${me})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`, true],
    ["owner read+write not all",     `D:PAI(A;OICI;0x1301bf;;;${me})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`, true],
    ["owner FILE_ALL_ACCESS hex",    `D:PAI(A;OICI;0x1f01ff;;;${me})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`, true],
    ["owner grant is inherit-only",  `D:PAI(A;OICIIO;FA;;;${me})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`, true],
    ["foreign inherit-only ACE",     `D:PAI(A;OICIIO;FA;;;WD)(A;OICI;FA;;;${me})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`, true],
    ["foreign Users",                `D:PAI(A;OICI;FA;;;${me})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)`, true],
    ["foreign second user",          `D:AI(A;ID;FA;;;${me})(A;ID;0x1200a9;;;${other})(A;ID;FA;;;SY)(A;ID;FA;;;BA)`, false],
    ["deny ACE",                     `D:PAI(D;OICI;FA;;;WD)(A;OICI;FA;;;${me})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`, true],
    ["audit-style ACE type",         `D:PAI(AU;OICI;FA;;;WD)(A;OICI;FA;;;${me})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`, true],
    ["object ACE type",              `D:PAI(OA;OICI;FA;;;;${me})(A;OICI;FA;;;SY)`, true],
    ["unknown alias",                `D:PAI(A;OICI;FA;;;ZZ)(A;OICI;FA;;;${me})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`, true],
    ["truncated ACE",                `D:PAI(A;OICI;FA;;;${me}`, true],
    ["garbage",                      `not a descriptor`, true],
    ["empty string",                 ``, true],
  ];
  for (const [label, sddl, isDir] of cases) {
    const r = decide(sddl, me, isDir);
    console.log(`  ${label.padEnd(30)} ${r.ok ? "ACCEPT" : "REFUSE"}  ${r.reason}${r.advisories && r.advisories.length ? "  [" + r.advisories.join(",") + "]" : ""}`);
  }
  log("parser.accepts", cases.filter(([l, s, d]) => decide(s, me, d).ok).map(([l]) => l));
}

function saveShape() {
  const p = opt("--path"); const raw = saveRaw(p);
  if (raw.unavailable) { log("save-shape", "icacls unavailable"); return; }
  const buf = raw.buf;
  const text = buf ? buf.toString("utf16le") : "";
  const lines = text.replace(/^\uFEFF/, "").split(/\r?\n/).filter((l) => l.length);
  log("save-shape", {
    status: raw.status, bytes: buf ? buf.length : null,
    bom: buf && buf.length >= 2 ? `0x${buf[0].toString(16)}${buf[1].toString(16)}` : null,
    encodingReadsAsUtf16le: /^[\x20-\x7e]/.test(text.replace(/^\uFEFF/, "")),
    lineCount: lines.length,
    line0_is_object_name: lines[0] ? lines[0].slice(0, 40) : null,
    line1_starts_with: lines[1] ? lines[1].slice(0, 8) : null,
    containsOwnerComponent: /(^|[^A-Z])O:/.test(lines[1] || ""),
    containsGroupComponent: /(^|[^A-Z])G:/.test(lines[1] || ""),
    containsSaclComponent: /(^|[^A-Z])S:/.test(lines[1] || ""),
    containsAccountName: /[A-Za-z]{3,}\\[A-Za-z]/.test(lines[1] || ""),
  });
  log("save-shape.sddl", lines[1] || null);
}

function ownerOf() {
  const p = opt("--path"); const esc = p.replace(/'/g, "''");
  const out = { path: "<lab path>", processUserSid: currentSid() };
  const psOwner = (exe, label, cmdText) => {
    const r = run(exe, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", cmdText], 60000);
    if (r.unavailable) { out[label] = "exe-absent"; return; }
    const m = /(S-1-[0-9-]+)/.exec(r.stdout || "");
    out[label] = m ? m[1] : `status ${r.status}: ${(r.stderr || "").trim().split(/\r?\n/)[0] || "no sid"}`.slice(0, 120);
  };
  psOwner(POWERSHELL, "m1.Get-Acl", `(Get-Acl -LiteralPath '${esc}').GetOwner([System.Security.Principal.SecurityIdentifier]).Value`);
  psOwner(POWERSHELL, "m2.Import-Module+Get-Acl", `Import-Module Microsoft.PowerShell.Security -ErrorAction Stop; (Get-Acl -LiteralPath '${esc}').GetOwner([System.Security.Principal.SecurityIdentifier]).Value`);
  psOwner(POWERSHELL, "m3.dotnet-FileSecurity", `$i=Get-Item -LiteralPath '${esc}' -Force; if($i.PSIsContainer){$s=New-Object System.Security.AccessControl.DirectorySecurity('${esc}',[System.Security.AccessControl.AccessControlSections]::Owner)}else{$s=New-Object System.Security.AccessControl.FileSecurity('${esc}',[System.Security.AccessControl.AccessControlSections]::Owner)}; $s.GetOwner([System.Security.Principal.SecurityIdentifier]).Value`);
  psOwner(PWSH, "m4.pwsh7-Get-Acl (not depended on)", `(Get-Acl -LiteralPath '${esc}').GetOwner([System.Security.Principal.SecurityIdentifier]).Value`);
  // cmd `dir /q` prints an owner NAME, localized headers, no SID
  const d = run(CMD, ["/d", "/c", "dir", "/q", "/a", p]);
  const nameLine = (d.stdout || "").split(/\r?\n/).find((l) => /\\/.test(l) && !/Volume|Directory of/i.test(l));
  out["m5.cmd-dir-/q (name only, localized)"] = d.status === 0 ? (nameLine ? nameLine.trim().slice(0, 80) : "no owner line parsed") : `status ${d.status}`;
  // icacls itself: documented as DACL-only; confirm no owner appears
  const ic = run(ICACLS, [p]);
  out["m6.icacls-display"] = ic.status === 0 ? `no owner field (documented: /save stores DACLs; only /setowner changes owner)` : `status ${ic.status}`;
  log("owner-of", out);
  const resolved = [out["m1.Get-Acl"], out["m2.Import-Module+Get-Acl"], out["m3.dotnet-FileSecurity"]].filter((x) => /^S-1-/.test(String(x)));
  log("owner-of.verdict", resolved.length ? `owner SID readable without a native dependency: ${resolved[0]}` : "NO mechanism in the selected toolset returned an owner SID");
}

function createOpen() {
  const root = opt("--root"); const sid = currentSid();
  if (!root || !sid) throw new Error("--root and a resolvable SID are required");
  fs.rmSync(root, { recursive: true, force: true });
  fs.mkdirSync(root, { recursive: true });
  const i = inspect(root, sid, true);
  log("window.open.store", briefly(i));
  if (i.ok) throw new Error("setup failed: the store was already private before protection, so the window is not being measured");
  console.log("WINDOW-OPEN: " + root);
}

function plant() {
  // Runs AS THE ATTACKER, inside the open creation window.
  const store = opt("--store"); const sid = currentSid(); const res = { attackerSid: sid };
  const pend = path.join(store, "pending");
  const attempt = (n, f) => { try { const r = f(); res[n] = r === undefined ? "ok" : r; } catch (e) { res[n] = "error:" + code(e); } };
  attempt("plant.child-directory-pending", () => { fs.mkdirSync(pend, { recursive: true }); return fs.existsSync(pend) ? "created" : "absent"; });
  attempt("plant.junction-beside-pending", () => {
    const tgt = path.join(TMP, `redirect-${process.pid}`); fs.mkdirSync(tgt, { recursive: true });
    const j = path.join(store, "pending-redirect"); fs.symlinkSync(tgt, j, "junction");
    return fs.lstatSync(j).isSymbolicLink() ? "junction created (no privilege needed)" : "created, not a link";
  });
  const id = opt("--id"); const outDir = opt("--out"); const repo = opt("--repo");
  if (id) {
    // A record the product would look for. With --approved and a readable repo the attacker also supplies
    // the commitment it computes from the value it can read -- no privileged knowledge is involved.
    attempt("plant.record", () => {
      let rec = { version: 1, id, state: has("--approved") ? "approved" : "pending", fingerprint: opt("--fingerprint", ""),
                  path: opt("--root-canonical", repo || ""), file: opt("--file", "app.js"), line: 1,
                  ruleId: "github-token", provider: "github",
                  commitment: "0".repeat(64), createdAt: new Date().toISOString() };
      if (has("--approved")) { rec.approvedAt = new Date().toISOString(); rec.expiresAt = new Date(Date.now() + 900000).toISOString(); }
      if (outDir && repo) {
        const consent = require(path.join(outDir, "consent.js"));
        const v = fs.readFileSync(path.join(repo, "app.js"), "utf8").match(/"([^"]+)"/);
        if (v) rec.commitment = consent.commitmentOf(v[1]);   // computed from the readable repo, never printed
      }
      fs.mkdirSync(pend, { recursive: true });
      fs.writeFileSync(path.join(pend, id + ".json"), JSON.stringify(rec, null, 2) + "\n");
      return `${rec.state} record planted (commitment ${rec.commitment === "0".repeat(64) ? "placeholder" : "computed from the readable repo"})`;
    });
  }
  const anyPlanted = Object.entries(res).some(([k, v]) => k.startsWith("plant.") && !String(v).startsWith("error:"));
  log("window.plant", res);
  if (!anyPlanted) { console.log("PROBE-ERROR: no plant succeeded -- NON-MEASUREMENT, not a security pass"); process.exit(2); }
}

function hold() {
  // Runs AS THE ATTACKER. Opens handles BEFORE the owner protects, retains them across the protection,
  // then measures what the retained handles can still do. Bounded; never waits forever.
  const file = opt("--file"); const dir = opt("--dir");
  const ready = opt("--ready"); const go = opt("--go");
  const waitMs = Number(opt("--wait", "180")) * 1000;
  const res = { attackerSid: currentSid() };
  let fd = null, dh = null;
  try { fd = fs.openSync(file, "r+"); res["held.file-handle"] = "opened r+"; } catch (e) { res["held.file-handle"] = "error:" + code(e); }
  try { dh = fs.opendirSync(dir); res["held.directory-handle"] = "opened"; } catch (e) { res["held.directory-handle"] = "error:" + code(e); }
  if (fd === null && dh === null) { log("window.hold", res); console.log("PROBE-ERROR: no handle could be retained -- NON-MEASUREMENT"); process.exit(2); }
  fs.writeFileSync(ready, "ready\n");
  const deadline = Date.now() + waitMs;
  const nap = new Int32Array(new SharedArrayBuffer(4));
  while (!fs.existsSync(go) && Date.now() < deadline) { Atomics.wait(nap, 0, 0, 250); }
  res["window.closed-signal"] = fs.existsSync(go) ? "received" : "TIMED OUT (non-measurement)";
  // After the owner has applied the protected DACL: what can the RETAINED handles still do?
  const attempt = (n, f) => { try { const r = f(); res[n] = r === undefined ? "ok" : r; } catch (e) { res[n] = "error:" + code(e); } };
  if (fd !== null) {
    attempt("retained.read", () => { const b = Buffer.alloc(64); const n = fs.readSync(fd, b, 0, 64, 0); return `READ ${n} bytes`; });
    attempt("retained.write", () => {
      // Non-destructive on purpose: writing a different byte would corrupt the record and the LATER
      // question ("does the product trust it?") would measure this probe instead of the product.
      const b = Buffer.alloc(1); fs.readSync(fd, b, 0, 1, 0);
      const n = fs.writeSync(fd, b, 0, 1, 0);
      return `WROTE ${n} byte (same value written back; write access proven, record left intact)`;
    });
  }
  if (dh !== null) attempt("retained.directory-enumerate", () => { const e = dh.readSync(); return e ? `LISTED (${e.name.slice(0, 12)}…)` : "empty"; });
  // and a FRESH open by path, which the new DACL should govern
  attempt("fresh.open-by-path", () => { const f2 = fs.openSync(file, "r"); fs.closeSync(f2); return "OPENED"; });
  attempt("fresh.list-by-path", () => fs.readdirSync(dir).length);
  try { if (fd !== null) fs.closeSync(fd); } catch {}
  try { if (dh !== null) dh.closeSync(); } catch {}
  log("window.hold", res);
  if (res["window.closed-signal"] !== "received") process.exit(2);
}

function createClose() {
  const root = opt("--root"); const sid = currentSid();
  const before = inspect(root, sid, true); log("window.close.before", briefly(before));
  const pr = protect(root, sid); log("window.close.protect", pr);
  const after = inspect(root, sid, true); log("window.close.store-after", briefly(after));
  const pend = path.join(root, "pending");
  if (fs.existsSync(pend)) {
    const st = fs.lstatSync(pend);
    log("window.close.pending-after", Object.assign({ isLink: st.isSymbolicLink() }, briefly(inspect(pend, sid, true))));
    for (const f of fs.readdirSync(pend)) {
      const p = path.join(pend, f);
      log(`window.close.child-after[${f}]`, briefly(inspect(p, sid, false)));
    }
  }
  for (const extra of fs.readdirSync(root).filter((f) => f !== "pending")) {
    const p = path.join(root, extra); const st = fs.lstatSync(p);
    log(`window.close.extra[${extra}]`, Object.assign({ isLink: st.isSymbolicLink(), isDir: st.isDirectory() }, briefly(inspect(p, sid, st.isDirectory()))));
  }
}

function makeRepo() {
  const dir = opt("--repo"); fs.mkdirSync(dir, { recursive: true });
  const a = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let v = "ghp_"; for (let i = 0; i < 36; i++) v += a[(i * 29 + 5) % a.length];   // synthetic, never a real credential
  fs.writeFileSync(path.join(dir, "app.js"), `const t = "${v}";\n`);
  console.log("REPO: " + fs.realpathSync(dir));
}
function inspectMode() {
  const p = opt("--path"); const sid = currentSid(); const st = fs.lstatSync(p);
  const i = inspect(p, sid, st.isDirectory());
  log("inspect", Object.assign({ asUserSid: sid, isDir: st.isDirectory(), isReparsePoint: st.isSymbolicLink() }, briefly(i)));
  log("inspect.sddl", i.sddl || null);
}
function recordIdMode() {
  // Computes the id the product will look for, and the finding it belongs to, WITHOUT creating or
  // reading any consent record. This is knowledge an adversary that can read the repository also has.
  const OUT = opt("--out"); const repoDir = opt("--repo");
  const consent = require(path.join(OUT, "consent.js"));
  const mcp = require(path.join(OUT, "mcp-core.js"));
  const repo = fs.realpathSync(repoDir);
  mcp.setAllowedRoots([repo]); mcp.resetSessions();
  const scan = mcp.toolScan({ path: repo }); if (!scan.ok) throw new Error("scan failed: " + scan.error);
  const f = scan.payload.findings.find((x) => x.ruleId === "github-token"); if (!f) throw new Error("no github finding");
  console.log("RECORD-ID: " + consent.recordId(f.fingerprint, repo));
  console.log("FINGERPRINT: " + f.fingerprint);
  console.log("ROOT: " + repo);
  console.log("FILE: " + f.file);
}
async function trust() {
  // Does the MERGED PRODUCT trust what was planted in the window? Outbound boundary intercepted.
  const OUT = opt("--out"); const root = opt("--root"); const repoDir = opt("--repo");
  const consent = require(path.join(OUT, "consent.js"));
  const mcp = require(path.join(OUT, "mcp-core.js"));
  const repo = fs.realpathSync(repoDir);
  consent.setConsentRootForTests(root); mcp.setAllowedRoots([repo]); mcp.resetSessions();
  let outbound = 0;
  mcp.setVerifyFetchForTests(async () => { outbound++; return new Response("{}", { status: 401 }); });
  const scan = mcp.toolScan({ path: repo }); if (!scan.ok) throw new Error("scan failed: " + scan.error);
  const f = scan.payload.findings.find((x) => x.ruleId === "github-token"); if (!f) throw new Error("no github finding");
  const id = consent.recordId(f.fingerprint, repo);
  const rp = path.join(root, "pending", id + ".json");
  let fixture = { exists: fs.existsSync(rp) };
  if (fixture.exists) {
    fixture.bytes = fs.statSync(rp).size;
    try {
      const raw = JSON.parse(fs.readFileSync(rp, "utf8"));
      const required = ["id", "fingerprint", "path", "file", "ruleId", "provider", "commitment", "createdAt"];
      const badStrings = required.filter((k) => typeof raw[k] !== "string" || raw[k].length === 0);
      fixture.parses = true;
      fixture.fieldProblems = [
        ...badStrings.map((k) => `not-a-string:${k}`),
        raw.version === 1 ? null : "version",
        raw.state === "pending" || raw.state === "approved" ? null : "state",
        typeof raw.line === "number" ? null : "line",
        /^[0-9a-f]{64}$/.test(String(raw.commitment)) ? null : "commitment-not-sha256",
        raw.state === "approved" && typeof raw.expiresAt !== "string" ? "expiresAt" : null,
        raw.path === repo ? null : "path-mismatch",
      ].filter(Boolean);
      fixture.state = raw.state;
    } catch (e) { fixture.parses = false; fixture.jsonError = code(e); }
  }
  log("window.trust.fixture", fixture);   // a malformed fixture is a NON-MEASUREMENT, never a product pass
  let listed = "n/a", seen = "n/a";
  try { listed = consent.listRecords().length; } catch (e) { listed = "store-refused:" + (e.problem || code(e)); }
  try { const r = consent.readRecord(id); seen = r ? r.state : "absent"; } catch (e) { seen = "store-refused:" + (e.problem || code(e)); }
  const v = await mcp.toolVerify({ path: repo, fingerprint: f.fingerprint });
  const out = { recordId: id.slice(0, 8) + "…", recordsListed: listed, plantedRecordStateSeen: seen,
                verifyState: v.ok ? v.payload.state : "fail:" + String(v.error).slice(0, 90),
                outboundAttempted: outbound, externalTransmission: v.ok && v.payload.network ? v.payload.network.externalTransmission : null };
  log("window.trust", out);
  console.log("PLANTED-ID-MATCHES-PRODUCT: " + id);
  if (has("--expect-transmit") && outbound === 0) console.log("NOTE: the pre-planted approval did NOT reach the network on this path");
}

function ownClean() {
  // Runs AS THE ATTACKER: create a file the ATTACKER owns, whose DACL names only the principals the
  // proposed policy allows (the victim user, SYSTEM, Administrators). The attacker is NOT in the DACL.
  const dir = opt("--dir"); const victim = opt("--owner-sid"); const me = currentSid();
  const p = path.join(dir, "owned-by-attacker.json");
  fs.writeFileSync(p, JSON.stringify({ version: 1, state: "pending", note: "synthetic" }) + "\n");
  const r = run(ICACLS, [p, "/inheritance:r", "/grant:r", `*${victim}:F`, `*${SID_SYSTEM}:F`, `*${SID_ADMINS}:F`, "/q"]);
  log("ownership.construct", { attackerSid: me, victimSid: victim, icaclsStatus: r.status, stderr: (r.stderr || "").trim().slice(0, 80) });
  if (r.status !== 0) { console.log("PROBE-ERROR: could not construct the attacker-owned object -- NON-MEASUREMENT"); process.exit(2); }
  log("ownership.dacl-as-constructed", briefly(inspect(p, victim, false)));
  console.log("ATTACKER-OWNED-PATH: " + p);
}

function ownRegain() {
  // Runs AS THE ATTACKER, which OWNS the object but is absent from its DACL.
  const p = opt("--path"); const me = currentSid(); const res = { attackerSid: me };
  const attempt = (n, f) => { try { const r = f(); res[n] = r === undefined ? "ok" : r; } catch (e) { res[n] = "error:" + code(e); } };
  attempt("before.read", () => `READ ${fs.readFileSync(p).length} bytes`);
  attempt("before.write", () => { fs.appendFileSync(p, ""); return "ok"; });
  const g = run(ICACLS, [p, "/grant", `*${me}:F`, "/q"]);
  res["regrant.icacls-status"] = g.status;
  res["regrant.note"] = "an object's OWNER holds READ_CONTROL and WRITE_DAC implicitly, with no DACL entry";
  attempt("after.read", () => `READ ${fs.readFileSync(p).length} bytes`);
  attempt("after.write", () => { fs.appendFileSync(p, "\n"); return "WROTE"; });
  attempt("after.flip-to-approved", () => {
    const j = JSON.parse(fs.readFileSync(p, "utf8"));
    j.state = "approved"; j.approvedAt = new Date().toISOString(); j.expiresAt = new Date(Date.now() + 900000).toISOString();
    fs.writeFileSync(p, JSON.stringify(j, null, 2) + "\n"); return "WRITTEN";
  });
  log("ownership.regain", res);
}

function rights() {
  const root = opt("--root"); const sid = currentSid();
  fs.rmSync(root, { recursive: true, force: true }); fs.mkdirSync(root, { recursive: true });
  // (a) allowed principals, INSUFFICIENT rights for the current user
  const a = path.join(root, "readonly-for-owner"); fs.mkdirSync(a);
  const ra = run(ICACLS, [a, "/inheritance:r", "/grant:r", `*${sid}:(OI)(CI)RX`, `*${SID_SYSTEM}:(OI)(CI)F`, `*${SID_ADMINS}:(OI)(CI)F`, "/q"]);
  const ia = inspect(a, sid, true);
  let write; try { fs.writeFileSync(path.join(a, "r.json"), "{}\n"); write = "WROTE (rights were sufficient after all)"; } catch (e) { write = "error:" + code(e); }
  log("rights.owner-read-only", { icaclsStatus: ra.status, decision: briefly(ia), productWriteAttempt: write });
  // (b) inherit-only foreign ACE: does not apply to the directory, but propagates to children
  const b = path.join(root, "inherit-only"); fs.mkdirSync(b);
  run(ICACLS, [b, "/inheritance:r", "/grant:r", `*${sid}:(OI)(CI)F`, `*${SID_SYSTEM}:(OI)(CI)F`, `*${SID_ADMINS}:(OI)(CI)F`, "/q"]);
  const rb = run(ICACLS, [b, "/grant", `*S-1-1-0:(OI)(CI)(IO)F`, "/q"]);
  const ib = inspect(b, sid, true);
  const child = path.join(b, "child.json"); fs.writeFileSync(child, "{}\n");
  log("rights.inherit-only-foreign", { icaclsStatus: rb.status, directoryDecision: briefly(ib), childDecision: briefly(inspect(child, sid, false)) });
  // (c) empty DACL on a record, and what access remains
  const c = path.join(root, "empty-dacl.json"); fs.writeFileSync(c, "{}\n");
  const rc = run(ICACLS, [c, "/inheritance:r", "/q"]);   // removes inherited ACEs, leaving no ACE at all
  const ic = inspect(c, sid, false);
  let readC; try { readC = `READ ${fs.readFileSync(c).length} bytes`; } catch (e) { readC = "error:" + code(e); }
  const rec = run(ICACLS, [c, "/grant", `*${sid}:F`, "/q"]);
  let readC2; try { readC2 = `READ ${fs.readFileSync(c).length} bytes`; } catch (e) { readC2 = "error:" + code(e); }
  log("rights.empty-dacl", { icaclsStatus: rc.status, decision: briefly(ic), ownerReadAfterEmpty: readC, ownerRegrantStatus: rec.status, ownerReadAfterRegrant: readC2 });
  // (d) tooling errors and partial success
  const missing = run(ICACLS, [path.join(root, "does-not-exist"), "/save", path.join(TMP, "x.txt"), "/q"]);
  log("rights.icacls-missing-path", { status: missing.status, stderrHead: (missing.stderr || "").trim().split(/\r?\n/)[0] });
  const badSid = run(ICACLS, [root, "/grant", "*S-1-5-21-0-0-0-424242:F", "/q"]);
  log("rights.icacls-bad-sid", { status: badSid.status, stderrHead: (badSid.stderr || "").trim().split(/\r?\n/)[0] });
  const mixed = run(ICACLS, [root, "/grant", `*${sid}:F`, "/t"]);
  const okm = /Successfully processed (\d+) files/.exec(mixed.stdout || ""); const fm = /Failed processing (\d+) files/.exec(mixed.stdout || "");
  log("rights.icacls-tree-counts", { status: mixed.status, succeeded: okm ? okm[1] : null, failed: fm ? fm[1] : null });
  fs.rmSync(root, { recursive: true, force: true });
}

(async () => {
  try {
    if (mode === "facts") facts();
    else if (mode === "parser") parser();
    else if (mode === "save-shape") saveShape();
    else if (mode === "owner-of") ownerOf();
    else if (mode === "create-open") createOpen();
    else if (mode === "plant") plant();
    else if (mode === "hold") hold();
    else if (mode === "create-close") createClose();
    else if (mode === "make-repo") makeRepo();
    else if (mode === "inspect") inspectMode();
    else if (mode === "record-id") recordIdMode();
    else if (mode === "trust") await trust();
    else if (mode === "own-clean") ownClean();
    else if (mode === "own-regain") ownRegain();
    else if (mode === "rights") rights();
    else throw new Error("unknown mode " + mode);
  } catch (e) { console.log("PROBE-ERROR: " + ((e && e.stack) || e)); process.exit(2); }
})();
