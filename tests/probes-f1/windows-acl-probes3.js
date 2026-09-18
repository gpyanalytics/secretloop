#!/usr/bin/env node
/*
 * EVIDENCE-ONLY VALIDATION of the REVISED Windows consent-store ACL sequence. Not product code.
 * Implements the sequence fixed in advance (see the validation record's SEQUENCE section) and exercises it
 * adversarially. Synthetic records only, in an explicit lab. Never touches a real profile store.
 *
 * Inspection uses the in-box Windows PowerShell with a CONSTANT script delivered by -EncodedCommand and paths
 * supplied on stdin as JSON: no path, SID or other input is ever interpolated into PowerShell source, no file is
 * written, and no execution-policy change is requested. Enforcement uses icacls at its fixed System32 path.
 * Only SecurityIdentifier values are compared -- never an account name -- so results do not depend on UI language.
 *
 *   helper-source                            print the CONSTANT PowerShell script verbatim (runs anywhere)
 *   table                                    offline decision table (runs anywhere)
 *   facts                                    OS, filesystem, arch, Node, PowerShell/.NET, privileges
 *   chain        --path P                    the ancestor-chain rule over a real path, component by component
 *   inspect      --path P [--as-store]       one object under the ancestor rule or the store rule
 *   create       --root R                    the full creation sequence (C1-C7)
 *   operate      --root R [--record ID]      the full per-operation sequence (D1-D6), no product calls
 *   legit        --out O --root R --repo D   create, then the REAL product: call 1, approve, replace, claim, call 2
 *   attack-open  --store S                   attacker: can a handle be opened here at all?
 *   attack-swap  --path P                    attacker: rename/replace an inspected component
 *   plant        --store S --id I --json F   attacker: plant a record produced by the product
 *   make-record  --out O --repo D --scratch S --json-out F   a product-generated approved record (no guessing)
 *   toolfail     --root R                    tooling absent / failing must refuse, never fall through to creation
 *   common: --tmp DIR   --ps PATH (to simulate an absent helper)   --icacls PATH (to simulate absent enforcement)
 */
"use strict";
const fs = require("fs"), path = require("path"), cp = require("child_process"), os = require("os");
const args = process.argv.slice(2), mode = args[0];
const opt = (n, d) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : d; };
const has = (n) => args.includes(n);
const log = (k, v) => console.log(`${k}: ${typeof v === "string" ? v : JSON.stringify(v)}`);
const code = (e) => (e && e.code) || String((e && e.message) || e);
const WIN = process.platform === "win32";
if (!WIN && mode !== "table" && mode !== "helper-source") { console.log("PROBE-ERROR: win32 only (except table, helper-source)"); process.exit(3); }

const SYSTEM_ROOT = process.env.SystemRoot || "C:\\Windows";
const SYS32 = path.join(SYSTEM_ROOT, "System32");
const PS = opt("--ps") || path.join(SYS32, "WindowsPowerShell", "v1.0", "powershell.exe");
const ICACLS = opt("--icacls") || path.join(SYS32, "icacls.exe");
const WHOAMI = path.join(SYS32, "whoami.exe");
const PS_TIMEOUT_MS = 60000, PS_MAX_OUTPUT = 1 << 20;   // bounded time and output
const SID_SYSTEM = "S-1-5-18", SID_ADMINS = "S-1-5-32-544";
const NAMED = { "S-1-1-0": "Everyone", "S-1-5-11": "Authenticated Users", "S-1-5-32-545": "Users", "S-1-3-0": "CREATOR OWNER", "S-1-5-18": "SYSTEM", "S-1-5-32-544": "Administrators" };
const SDDL_ALIAS = { BA:"S-1-5-32-544", BU:"S-1-5-32-545", BG:"S-1-5-32-546", PU:"S-1-5-32-547", AO:"S-1-5-32-548", SO:"S-1-5-32-549", PO:"S-1-5-32-550", BO:"S-1-5-32-551", RE:"S-1-5-32-552", RU:"S-1-5-32-554", RD:"S-1-5-32-555", NO:"S-1-5-32-556", MU:"S-1-5-32-558", LU:"S-1-5-32-559", CY:"S-1-5-32-569", ES:"S-1-5-32-573", SY:"S-1-5-18", LS:"S-1-5-19", NS:"S-1-5-20", WD:"S-1-1-0", AU:"S-1-5-11", IU:"S-1-5-4", NU:"S-1-5-2", AN:"S-1-5-7", RC:"S-1-5-12", IS:"S-1-5-17", CO:"S-1-3-0", CG:"S-1-3-1", OW:"S-1-3-4", AC:"S-1-15-2-1", LW:"S-1-16-4096", ME:"S-1-16-8192", HI:"S-1-16-12288", SI:"S-1-16-16384" };
const canonSid = (x) => (x && /^S-1-/.test(x) ? x : (SDDL_ALIAS[x] || `unknown-alias:${x}`));

// SDDL access-rights tokens -> bits. For a file object the generic two-letter codes name bit positions.
const RIGHT_BITS = { CC:0x00000001, DC:0x00000002, LC:0x00000004, SW:0x00000008, RP:0x00000010, WP:0x00000020,
                     DT:0x00000040, LO:0x00000080, CR:0x00000100, SD:0x00010000, RC:0x00020000, WDAC:0x00040000,
                     WO:0x00080000, GA:0x10000000, GX:0x20000000, GW:0x40000000, GR:0x80000000,
                     FA:0x001F01FF, FR:0x00120089, FW:0x00120116, FX:0x001200A0 };
const FILE_ALL_ACCESS = 0x1F01FF;
// DELETE | FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER  -- the rights that let a principal replace or re-permission
const NAMESPACE_BITS = 0x00010000 | 0x00000040 | 0x00040000 | 0x00080000;
// FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY -- the rights that let a principal create the store name itself
const CREATE_CHILD_BITS = 0x00000002 | 0x00000004;
const GENERIC_WRITEISH = 0x10000000 | 0x40000000;      // GENERIC_ALL, GENERIC_WRITE

function rightsMask(text) {
  const t = String(text || "").trim();
  if (!t) return { mask: 0, unknown: [] };
  if (/^0x[0-9a-f]+$/i.test(t)) { const v = parseInt(t, 16); return Number.isFinite(v) ? { mask: v, unknown: [] } : { mask: 0, unknown: [t] };}
  let mask = 0; const unknown = []; let rest = t.toUpperCase();
  // WDAC is four characters and must be tried before the two-character tokens
  rest = rest.replace(/WDAC/g, (m) => { mask |= RIGHT_BITS.WDAC; return ""; });
  while (rest.length) {
    const tok = rest.slice(0, 2); rest = rest.slice(2);
    if (tok === "WD") { mask |= RIGHT_BITS.WDAC; continue; }       // SDDL WD == WRITE_DAC
    if (RIGHT_BITS[tok] !== undefined) mask |= RIGHT_BITS[tok]; else unknown.push(tok);
  }
  return { mask, unknown };
}
function parseDacl(sddl) {
  if (typeof sddl !== "string") return null;
  const t = sddl.trim();
  if (/^D:NO_ACCESS_CONTROL$/i.test(t)) return { nullDacl: true };
  if (!/^D:/.test(t)) return /^[OGS]:/.test(t) ? { nullDacl: true, noComponent: true } : null;
  const m = /^D:([A-Z]*)((?:\([^)]*\))*)$/.exec(t);
  if (!m) return null;
  const aces = [...m[2].matchAll(/\(([^)]*)\)/g)].map((x) => {
    const f = x[1].split(";"); const r = rightsMask(f[2]);
    return { type: f[0], flags: f[1] || "", rightsText: f[2] || "", mask: r.mask, unknownRights: r.unknown,
             sid: canonSid(f[5]), inheritOnly: /IO/.test(f[1] || "") };
  });
  return { flags: m[1], aces };
}
/** STORE RULE: principal-clean + the current user holds FILE_ALL_ACCESS through a non-inherit-only ACE. */
function decideStore(sddl, userSid) {
  const d = parseDacl(sddl);
  if (!d) return { ok: false, reason: "acl-inspection-malformed" };
  if (d.nullDacl) return { ok: false, reason: "null-dacl" };
  const allowed = new Set([userSid, SID_SYSTEM, SID_ADMINS]);
  const problems = [];
  if (d.aces.length === 0) problems.push("empty-dacl");
  for (const a of d.aces) {
    if (a.type !== "A") problems.push(`deny-ace:${a.type}:${a.sid}`);
    else if (!allowed.has(a.sid)) problems.push(`foreign-principal:${a.sid}${NAMED[a.sid] ? "(" + NAMED[a.sid] + ")" : ""}`);
    else if (a.unknownRights.length) problems.push(`acl-inspection-malformed:rights:${a.unknownRights.join("")}`);
  }
  const mine = d.aces.filter((a) => a.type === "A" && a.sid === userSid && !a.inheritOnly);
  if (!d.aces.some((a) => a.type === "A" && a.sid === userSid)) problems.push("owner-not-granted");
  else if (!mine.some((a) => (a.mask & FILE_ALL_ACCESS) === FILE_ALL_ACCESS || (a.mask & RIGHT_BITS.GA))) problems.push("insufficient-rights");
  return { ok: problems.length === 0, reason: problems.length ? problems.join(",") : "private",
           protectedDacl: d.flags.includes("P"), principals: d.aces.map((a) => `${a.type}:${a.flags}:${a.rightsText}:${a.sid}`) };
}
/** ANCESTOR RULE: no non-allowed principal may hold namespace-modifying rights (or, on the immediate parent,
 *  create-child rights). A read grant to Users on a volume root is tolerated on purpose. */
function decideAncestor(sddl, userSid, immediateParent) {
  const d = parseDacl(sddl);
  if (!d) return { ok: false, reason: "acl-inspection-malformed" };
  if (d.nullDacl) return { ok: false, reason: "null-dacl" };
  const problems = [], tolerated = [];
  for (const a of d.aces) {
    if (ancestorPrincipalAllowed(a.sid, userSid)) continue;
    if (a.type !== "A") { tolerated.push(`deny:${a.sid}`); continue; }   // a deny ACE only removes access
    if (a.unknownRights.length) { problems.push(`acl-inspection-malformed:rights:${a.unknownRights.join("")}`); continue; }
    const effective = a.inheritOnly ? 0 : a.mask;                        // an IO ACE does not apply to this object
    const bad = (effective & (NAMESPACE_BITS | GENERIC_WRITEISH)) ||
                (immediateParent ? (effective & (CREATE_CHILD_BITS | GENERIC_WRITEISH)) : 0);
    if (bad) problems.push(`unsafe-parent:${a.sid}${NAMED[a.sid] ? "(" + NAMED[a.sid] + ")" : ""}:0x${(bad >>> 0).toString(16)}`);
    else tolerated.push(`${a.sid}:${a.rightsText}${a.inheritOnly ? "(inherit-only)" : ""}`);
  }
  return { ok: problems.length === 0, reason: problems.length ? problems.join(",") : "no-foreign-write", tolerated };
}

// ---- the PowerShell inspection helper: CONSTANT source, paths on stdin as JSON ---------------------------
const PS_SOURCE = [
  "$ErrorActionPreference='Stop'",
  "$ProgressPreference='SilentlyContinue'",
  "$raw=[Console]::In.ReadToEnd()",
  // One path per line. ConvertFrom-Json on an array can yield a single nested value in PowerShell 5.1, which
  // made $p an array rather than a string; splitting lines has one unambiguous shape. Paths remain DATA on
  // stdin and are never interpolated into this source.
  "$paths=@($raw -split \"`r?`n\" | Where-Object { $_.Length -gt 0 })",
  "$out=New-Object System.Collections.ArrayList",
  "foreach($p in $paths){",
  "  $o=[ordered]@{path=[string]$p;ok=$false;exists=$false}",
  "  try{",
  "    $item=Get-Item -LiteralPath $p -Force",
  "    $o.exists=$true",
  "    $o.isDirectory=[bool]$item.PSIsContainer",
  "    $o.isReparsePoint=[bool](($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)",
  "    if($item.PSIsContainer){$sec=New-Object System.Security.AccessControl.DirectorySecurity($p,'Access,Owner')}",
  "    else{$sec=New-Object System.Security.AccessControl.FileSecurity($p,'Access,Owner')}",
  "    $o.ownerSid=$sec.GetOwner([System.Security.Principal.SecurityIdentifier]).Value",
  "    $o.sddl=$sec.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access)",
  "    $o.protected=[bool]$sec.AreAccessRulesProtected",
  "    $o.ok=$true",
  "  }catch{ $o.errorType=$_.Exception.GetType().FullName }",   // type name only: never a message, path or OS text
  "  [void]$out.Add((New-Object psobject -Property $o))",
  "}",
  // One compact JSON object per line. PowerShell 5.1 unwraps a single-element array, so emitting one array
  // would change shape with the number of paths; JSON Lines is the same shape for one path and for many.
  "foreach($r in $out){ ConvertTo-Json -InputObject $r -Depth 4 -Compress }",
].join("\n");
const PS_B64 = Buffer.from(PS_SOURCE, "utf16le").toString("base64");

let psCalls = 0;
// Probe-only diagnostic. A product would print none of this; it exists so a harness fault cannot be mistaken
// for a security result. Truncated, and the helper is only ever given paths -- never record content.
const probeRaw = (t) => String(t || "").slice(0, 400).replace(/\r?\n/g, " | ");
function psInspect(paths) {
  psCalls++;
  if (!fs.existsSync(PS)) return { fail: "acl-tooling-unavailable" };
  // A path carrying a line break could not be delivered unambiguously; refuse rather than guess.
  if (paths.some((p) => /[\r\n]/.test(p))) return { fail: "acl-inspection-failed", detail: "unsupported-path" };
  const r = cp.spawnSync(PS, ["-NoProfile", "-NonInteractive", "-EncodedCommand", PS_B64],
    { input: paths.join("\r\n") + "\r\n", encoding: "utf8", timeout: PS_TIMEOUT_MS, maxBuffer: PS_MAX_OUTPUT, windowsHide: true });
  if (r.error && (r.error.code === "ETIMEDOUT" || r.error.killed)) return { fail: "acl-inspection-failed", detail: "timeout" };
  if (r.error && r.error.code === "ENOBUFS") return { fail: "acl-inspection-failed", detail: "output-too-large" };
  if (r.error) return { fail: "acl-tooling-unavailable", detail: r.error.code };
  if (r.status !== 0) return { fail: "acl-inspection-failed", detail: `exit ${r.status}` };
  if (!r.stdout || r.stdout.length > PS_MAX_OUTPUT) return { fail: "acl-inspection-failed", detail: "empty-or-oversized" };
  const lines = r.stdout.split(/\r?\n/).filter((l) => l.trim().length);
  const byPath = new Map();
  for (const ln of lines) {
    let e; try { e = JSON.parse(ln); } catch { return { fail: "acl-inspection-malformed", raw: probeRaw(r.stdout) }; }
    if (e && typeof e.path === "string") byPath.set(path.resolve(e.path).toLowerCase(), e);
  }
  for (const p of paths) if (!byPath.has(path.resolve(p).toLowerCase())) {
    return { fail: "acl-inspection-malformed", detail: "missing-result", raw: probeRaw(r.stdout) };
  }
  return { byPath };
}
/** STORE objects: only these three principals may appear or own. */
const ownerAllowed = (sid, userSid) => sid === userSid || sid === SID_SYSTEM || sid === SID_ADMINS;
/**
 * ANCESTORS: a wider set, because measurement showed the store rule is unusable above the store.
 * Stock volume roots are owned by, and grant full control to, platform principals: C:\ is owned by
 * NT SERVICE\TrustedInstaller (S-1-5-80-*) and the runner's D:\ by NETWORK SERVICE (S-1-5-20).
 * The adversary class is "another ordinary local account that is not SYSTEM and not an Administrator".
 * A service identity or the platform installer is not in that class and cannot be assumed by an ordinary
 * user, so those principals are trusted ABOVE the store. This buys nothing against a compromised Windows
 * service or the platform itself, which was already out of scope; it is stated, not assumed away.
 */
function ancestorPrincipalAllowed(sid, userSid) {
  if (sid === userSid || sid === SID_SYSTEM || sid === SID_ADMINS) return true;
  if (sid === "S-1-5-19" || sid === "S-1-5-20") return true;          // LOCAL SERVICE, NETWORK SERVICE
  if (/^S-1-5-80-/.test(sid)) return true;                             // NT SERVICE\* (incl. TrustedInstaller)
  if (/^S-1-5-21-[\d-]+-500$/.test(sid)) return true;                  // the built-in Administrator account
  return false;                                                        // every ordinary account, Users, Everyone, ...
}

/** C.2 / D.2 -- the ancestor chain, top down. Returns the first failing component. */
function checkChain(storePath, userSid, info) {
  const parts = []; let cur = path.resolve(storePath);
  const parent = path.dirname(cur);
  for (let p = parent; ; p = path.dirname(p)) { parts.unshift(p); if (path.dirname(p) === p) break; }
  const results = [];
  for (const p of parts) {
    const e = info.byPath.get(p.toLowerCase());
    const immediate = p.toLowerCase() === parent.toLowerCase();
    if (!e || !e.ok) { results.push({ component: p, ok: false, reason: e && e.exists === false ? "unsafe-parent:absent" : "owner-unreadable", errorType: e && e.errorType }); break; }
    if (e.isReparsePoint) { results.push({ component: p, ok: false, reason: "unsafe-parent:reparse-point" }); break; }
    if (!e.isDirectory) { results.push({ component: p, ok: false, reason: "unsafe-parent:not-a-directory" }); break; }
    if (!ancestorPrincipalAllowed(e.ownerSid, userSid)) { results.push({ component: p, ok: false, reason: `unsafe-parent:foreign-owner:${e.ownerSid}`, immediate }); break; }
    const d = decideAncestor(e.sddl, userSid, immediate);
    results.push({ component: p, ok: d.ok, reason: d.reason, immediate, tolerated: d.tolerated });
    if (!d.ok) break;
  }
  const bad = results.find((r) => !r.ok);
  return { ok: !bad, failedAt: bad ? bad.component : null, reason: bad ? bad.reason : "chain-trusted", components: results };
}
/** The store rule on one object: reparse, owner, DACL, rights. */
function checkStoreObject(p, userSid, info, isDir) {
  const e = info.byPath.get(path.resolve(p).toLowerCase());
  if (!e) return { ok: false, reason: "acl-inspection-malformed" };
  if (!e.exists) return { ok: false, reason: "absent", absent: true };
  if (!e.ok) return { ok: false, reason: "owner-unreadable", errorType: e.errorType };
  if (e.isReparsePoint) return { ok: false, reason: "symlink" };
  if (isDir !== undefined && e.isDirectory !== isDir) return { ok: false, reason: "not-a-directory" };
  if (!ownerAllowed(e.ownerSid, userSid)) return { ok: false, reason: "foreign-owner", ownerSid: e.ownerSid };
  const d = decideStore(e.sddl, userSid);
  return { ok: d.ok, reason: d.reason, ownerSid: e.ownerSid, protectedDacl: d.protectedDacl, principals: d.principals };
}
function currentSid() {
  const r = cp.spawnSync(WHOAMI, ["/user", "/fo", "csv", "/nh"], { encoding: "utf8", timeout: 20000, windowsHide: true });
  if (r.status !== 0) return null;
  const m = /"(S-1-[0-9-]+)"/.exec(r.stdout || ""); return m ? m[1] : null;
}
function enforce(dir, userSid) {
  if (!fs.existsSync(ICACLS)) return { ok: false, reason: "acl-tooling-unavailable" };
  const r = cp.spawnSync(ICACLS, [dir, "/inheritance:r", "/grant:r", `*${userSid}:(OI)(CI)F`, `*${SID_SYSTEM}:(OI)(CI)F`, `*${SID_ADMINS}:(OI)(CI)F`, "/q"],
    { encoding: "utf8", timeout: 30000, windowsHide: true });
  if (r.error) return { ok: false, reason: "acl-enforcement-failed", detail: code(r.error) };
  if (r.status !== 0) return { ok: false, reason: "acl-enforcement-failed", status: r.status };
  const failed = /Failed processing (\d+) files/.exec(r.stdout || "");
  if (failed && failed[1] !== "0") return { ok: false, reason: "acl-enforcement-partial" };
  return { ok: true };
}

/** THE FULL CREATION SEQUENCE (C1-C7). Returns a refusal WITHOUT creating anything when the chain fails. */
function createSequence(store, userSid) {
  const steps = [];
  const parent = path.dirname(path.resolve(store));
  const chainPaths = []; for (let p = parent; ; p = path.dirname(p)) { chainPaths.unshift(p); if (path.dirname(p) === p) break; }
  const info = psInspect(chainPaths);
  if (info.fail) return { ok: false, reason: info.fail, detail: info.detail, created: false, steps };
  const chain = checkChain(store, userSid, info);
  steps.push({ step: "C2 ancestor chain", ok: chain.ok, reason: chain.reason, failedAt: chain.failedAt });
  if (!chain.ok) return { ok: false, reason: "unsafe-parent", created: false, createdAnything: fs.existsSync(store), chain, steps };
  fs.mkdirSync(store);                                            // C3 -- fails EEXIST if anything is already there
  steps.push({ step: "C3 mkdir", ok: true });
  const en = enforce(store, userSid);
  steps.push({ step: "C4 protect", ok: en.ok, reason: en.reason });
  if (!en.ok) return { ok: false, reason: en.reason, created: true, steps };
  const pend = path.join(store, "pending");
  fs.mkdirSync(pend);                                             // C6
  const after = psInspect([store, pend]);
  if (after.fail) return { ok: false, reason: after.fail, created: true, steps };
  const s5 = checkStoreObject(store, userSid, after, true), s6 = checkStoreObject(pend, userSid, after, true);
  steps.push({ step: "C5 verify store", ok: s5.ok, reason: s5.reason, owner: s5.ownerSid, protectedDacl: s5.protectedDacl });
  steps.push({ step: "C6 verify pending", ok: s6.ok, reason: s6.reason, owner: s6.ownerSid });
  return { ok: s5.ok && s6.ok, reason: s5.ok && s6.ok ? "created-private" : (s5.ok ? s6.reason : s5.reason), created: true, steps };
}
/** THE FULL PER-OPERATION SEQUENCE (D1-D6) over the store, pending and every record present. */
function operateSequence(store, userSid) {
  const parent = path.dirname(path.resolve(store));
  const chainPaths = []; for (let p = parent; ; p = path.dirname(p)) { chainPaths.unshift(p); if (path.dirname(p) === p) break; }
  const pend = path.join(store, "pending");
  let records = [];
  try { records = fs.readdirSync(pend).filter((f) => f.endsWith(".json")).map((f) => path.join(pend, f)); } catch { /* checked below */ }
  const info = psInspect([...chainPaths, store, pend, ...records]);
  if (info.fail) return { ok: false, reason: info.fail, detail: info.detail, trustedRecords: [] };
  const chain = checkChain(store, userSid, info);
  if (!chain.ok) return { ok: false, reason: "unsafe-parent", failedAt: chain.failedAt, chainReason: chain.reason, trustedRecords: [] };
  const s = checkStoreObject(store, userSid, info, true);
  if (s.absent) return { ok: true, reason: "store-absent (no records; creation would run the C sequence)", trustedRecords: [] };
  if (!s.ok) return { ok: false, reason: s.reason, ownerSid: s.ownerSid, trustedRecords: [] };
  const p = checkStoreObject(pend, userSid, info, true);
  if (p.absent) return { ok: true, reason: "pending-absent (no records)", trustedRecords: [] };
  if (!p.ok) return { ok: false, reason: p.reason, ownerSid: p.ownerSid, trustedRecords: [] };
  const perRecord = records.map((r) => { const c = checkStoreObject(r, userSid, info, false); return { record: path.basename(r), ok: c.ok, reason: c.reason, ownerSid: c.ownerSid }; });
  return { ok: true, reason: "store-trusted", store: { reason: s.reason, owner: s.ownerSid, protectedDacl: s.protectedDacl },
           pending: { reason: p.reason, owner: p.ownerSid }, perRecord,
           trustedRecords: perRecord.filter((x) => x.ok).map((x) => x.record),
           refusedRecords: perRecord.filter((x) => !x.ok).map((x) => `${x.record}:${x.reason}`) };
}

// ------------------------------------------------------------------ modes
function table() {
  const me = "S-1-5-21-1-1-1-1003", other = "S-1-5-21-1-1-1-1004";
  console.log("-- STORE rule");
  for (const [label, sddl] of [
    ["protected private", `D:PAI(A;OICI;FA;;;${me})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`],
    ["inherited private", `D:AI(A;OICIID;FA;;;${me})(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)`],
    ["NULL dacl", `D:NO_ACCESS_CONTROL`],
    ["absent D: component", `O:BAG:BA`],
    ["empty dacl", `D:P`],
    ["owner read-only", `D:PAI(A;OICI;0x1200a9;;;${me})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`],
    ["owner inherit-only", `D:PAI(A;OICIIO;FA;;;${me})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`],
    ["owner hex FILE_ALL", `D:PAI(A;OICI;0x1f01ff;;;${me})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`],
    ["foreign Users", `D:PAI(A;OICI;FA;;;${me})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)`],
    ["foreign read-only", `D:AI(A;ID;FA;;;${me})(A;ID;0x1200a9;;;${other})(A;ID;FA;;;SY)(A;ID;FA;;;BA)`],
    ["foreign inherit-only", `D:PAI(A;OICIIO;FA;;;WD)(A;OICI;FA;;;${me})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`],
    ["deny ACE", `D:PAI(D;OICI;FA;;;WD)(A;OICI;FA;;;${me})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`],
    ["audit-type ACE", `D:PAI(AU;OICI;FA;;;WD)(A;OICI;FA;;;${me})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`],
    ["unknown alias", `D:PAI(A;OICI;FA;;;ZZ)(A;OICI;FA;;;${me})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`],
    ["unknown rights token", `D:PAI(A;OICI;QQ;;;${me})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`],
    ["truncated", `D:PAI(A;OICI;FA;;;${me}`],
    ["garbage", `nonsense`],
    ["empty string", ``],
  ]) { const r = decideStore(sddl, me); console.log(`  ${label.padEnd(24)} ${r.ok ? "ACCEPT" : "REFUSE"}  ${r.reason}`); }
  console.log("-- ANCESTOR rule (immediate parent in brackets)");
  for (const [label, sddl] of [
    ["stock volume root shape", `D:PAI(A;OICIIO;GA;;;CO)(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;BA)(A;OICIIO;GA;;;BA)(A;;0x1200a9;;;BU)(A;OICIIO;GXGR;;;BU)(A;CI;LC;;;BU)(A;CI;DC;;;BU)`],
    ["profile-like private", `D:PAI(A;OICI;FA;;;${me})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`],
    ["users read+execute", `D:AI(A;OICIID;FA;;;${me})(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;0x1200a9;;;BU)`],
    ["users FULL", `D:AI(A;OICIID;FA;;;${me})(A;OICIID;FA;;;BA)(A;OICIID;FA;;;BU)`],
    ["other user delete", `D:AI(A;OICIID;FA;;;${me})(A;OICIID;SD;;;${other})(A;OICIID;FA;;;BA)`],
    ["other user WRITE_DAC", `D:AI(A;OICIID;FA;;;${me})(A;OICIID;WD;;;${other})(A;OICIID;FA;;;BA)`],
    ["other user delete-child", `D:AI(A;OICIID;FA;;;${me})(A;OICIID;DT;;;${other})(A;OICIID;FA;;;BA)`],
    ["other user deny", `D:AI(D;OICIID;FA;;;${other})(A;OICIID;FA;;;${me})(A;OICIID;FA;;;BA)`],
    ["TrustedInstaller full", `D:PAI(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)`],
    ["NETWORK SERVICE full", `D:PAI(A;OICI;FA;;;S-1-5-20)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`],
    ["built-in Administrator", `D:PAI(A;OICI;FA;;;S-1-5-21-1-1-1-500)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`],
  ]) {
    const a = decideAncestor(sddl, me, false), b = decideAncestor(sddl, me, true);
    console.log(`  ${label.padEnd(24)} ${a.ok ? "ACCEPT" : "REFUSE"} ${(a.reason).padEnd(42)} [${b.ok ? "ACCEPT" : "REFUSE"} ${b.reason}]`);
  }
}
function facts() {
  log("platform", `${process.platform}/${process.arch} ${os.release()}`);
  log("node", process.version);
  const sid = currentSid(); log("process-user-sid", sid || "unreadable");
  const g = cp.spawnSync(WHOAMI, ["/groups", "/fo", "csv", "/nh"], { encoding: "utf8", timeout: 20000 });
  log("integrity", /S-1-16-12288/.test(g.stdout || "") ? "high (ELEVATED)" : /S-1-16-8192/.test(g.stdout || "") ? "medium (ordinary)" : "unknown");
  log("member-of-administrators", /S-1-5-32-544/.test(g.stdout || "") ? "YES" : "no");
  const pr = cp.spawnSync(WHOAMI, ["/priv", "/fo", "csv", "/nh"], { encoding: "utf8", timeout: 20000 });
  for (const p of ["SeCreateSymbolicLinkPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege", "SeBackupPrivilege"])
    log(`privilege.${p}`, new RegExp(p).test(pr.stdout || "") ? "present" : "absent");
  log("powershell.path", fs.existsSync(PS) ? "present at the fixed System32 path" : "ABSENT");
  const v = cp.spawnSync(PS, ["-NoProfile", "-NonInteractive", "-EncodedCommand",
    Buffer.from("$PSVersionTable.PSVersion.ToString()+' / CLR '+[System.Environment]::Version.ToString()+' / '+(Get-UICulture).Name", "utf16le").toString("base64")],
    { encoding: "utf8", timeout: PS_TIMEOUT_MS });
  log("powershell.version/clr/uiculture", (v.stdout || "").trim() || `exit ${v.status}`);
  log("icacls.path", fs.existsSync(ICACLS) ? "present at the fixed System32 path" : "ABSENT");
  const drive = path.parse(opt("--root", process.cwd())).root.slice(0, 2);
  const fsu = cp.spawnSync(path.join(SYS32, "fsutil.exe"), ["fsinfo", "volumeinfo", drive], { encoding: "utf8", timeout: 20000 });
  const fsm = /File System Name\s*:\s*(\S+)/.exec(fsu.stdout || "");
  log("filesystem", fsm ? fsm[1] : `unreadable (fsutil exit ${fsu.status})`);
  // the helper round-trip itself
  const t0 = Date.now(); const probe = psInspect([process.cwd()]); const ms = Date.now() - t0;
  log("helper.round-trip", { ok: !probe.fail, ms, encodedCommandBytes: PS_B64.length, scriptIsConstant: true,
                             fail: probe.fail, detail: probe.detail, raw: probe.raw });
  if (probe.fail) { console.log("PROBE-ERROR: the inspection helper failed its own round trip -- NON-MEASUREMENT"); process.exit(2); }
  const e = probe.byPath.get(path.resolve(process.cwd()).toLowerCase());
  log("helper.sample", { ownerSidRead: !!e.ownerSid, sddlRead: !!e.sddl, protectedFlagRead: typeof e.protected === "boolean",
                         reparseFlagRead: typeof e.isReparsePoint === "boolean" });
}
function chainMode() {
  const p = opt("--path"); const sid = currentSid();
  const parts = []; for (let q = path.dirname(path.resolve(p)); ; q = path.dirname(q)) { parts.unshift(q); if (path.dirname(q) === q) break; }
  const info = psInspect(parts);
  if (info.fail) { log("chain", { fail: info.fail, detail: info.detail, raw: info.raw }); process.exit(2); }
  const c = checkChain(p, sid, info);
  log("chain.verdict", { ok: c.ok, reason: c.reason, failedAt: c.failedAt });
  for (const comp of c.components) {
    const e = info.byPath.get(comp.component.toLowerCase());
    log(`chain.component`, { component: comp.component, ok: comp.ok, reason: comp.reason, immediateParent: !!comp.immediate,
                             owner: e && e.ownerSid, reparse: e && e.isReparsePoint, tolerated: comp.tolerated });
  }
}
function inspectMode() {
  const p = path.resolve(opt("--path")); const sid = currentSid();
  const info = psInspect([p]);
  if (info.fail) { log("inspect", { fail: info.fail, detail: info.detail, raw: info.raw }); process.exit(2); }
  const e = info.byPath.get(p.toLowerCase());
  const st = has("--as-store") ? checkStoreObject(p, sid, info) : null;
  log("inspect", { exists: e.exists, isDirectory: e.isDirectory, reparse: e.isReparsePoint, owner: e.ownerSid,
                   protectedDacl: e.protected, errorType: e.errorType, storeRule: st && { ok: st.ok, reason: st.reason } });
  log("inspect.sddl", e.sddl || null);
}
function createMode() {
  const root = opt("--root"); const sid = currentSid();
  const existedBefore = fs.existsSync(root);
  const r = createSequence(root, sid);
  const existsAfter = fs.existsSync(root);
  log("create.result", r);
  log("create.filesystem-effect", { existedBefore, existsAfter, createdAnythingDespiteRefusal: !r.ok && !existedBefore && existsAfter });
  if (!r.ok && !existedBefore && existsAfter) { console.log("PROBE-ERROR: a refusal created something -- the sequence is unsafe"); process.exit(2); }
  if (r.ok) console.log("CREATED: " + root);
}
function operateMode() {
  const root = opt("--root"); const sid = currentSid();
  log("operate.result", operateSequence(root, sid));
}
function attackOpen() {
  const store = opt("--store"); const res = { attackerSid: currentSid() };
  const attempt = (n, f) => { try { const r = f(); res[n] = r === undefined ? "ok" : r; } catch (e) { res[n] = "error:" + code(e); } };
  attempt("list.parent", () => fs.readdirSync(path.dirname(store)).length);
  attempt("create.store-name-first", () => { fs.mkdirSync(store); return "CREATED THE STORE NAME"; });
  attempt("open.store-handle", () => { const d = fs.opendirSync(store); d.closeSync(); return "OPENED"; });
  attempt("plant.in-pending", () => { const p = path.join(store, "pending", "x.json"); fs.writeFileSync(p, "{}\n"); fs.unlinkSync(p); return "PLANTED"; });
  log("attack.open", res);
}
function attackSwap() {
  const p = opt("--path"); const res = { attackerSid: currentSid() };
  const attempt = (n, f) => { try { const r = f(); res[n] = r === undefined ? "ok" : r; } catch (e) { res[n] = "error:" + code(e); } };
  attempt("rename.component", () => { fs.renameSync(p, p + ".moved"); fs.renameSync(p + ".moved", p); return "RENAMED AND RESTORED"; });
  attempt("delete.component", () => { fs.rmdirSync(p); return "DELETED"; });
  attempt("junction.beside", () => { const j = p + "-sub"; fs.symlinkSync(os.tmpdir(), j, "junction"); fs.rmSync(j, { recursive: true, force: true }); return "JUNCTION CREATED"; });
  log("attack.swap", res);
}
function plant() {
  const store = opt("--store"), id = opt("--id"), json = opt("--json");
  const pend = path.join(store, "pending"); const res = { attackerSid: currentSid() };
  const attempt = (n, f) => { try { const r = f(); res[n] = r === undefined ? "ok" : r; } catch (e) { res[n] = "error:" + code(e); } };
  attempt("mkdir.pending", () => { fs.mkdirSync(pend, { recursive: true }); return "ok"; });
  attempt("copy.record", () => { fs.copyFileSync(json, path.join(pend, id + ".json")); return JSON.parse(fs.readFileSync(path.join(pend, id + ".json"), "utf8")).state + " record planted"; });
  log("attack.plant", res);
  if (String(res["copy.record"]).startsWith("error:")) { console.log("PROBE-ERROR: the plant did not happen -- NON-MEASUREMENT"); process.exit(2); }
}
async function makeRecord() {
  const OUT = opt("--out"), repoDir = opt("--repo"), scratch = opt("--scratch"), jsonOut = opt("--json-out");
  const consent = require(path.join(OUT, "consent.js")), mcp = require(path.join(OUT, "mcp-core.js"));
  fs.mkdirSync(repoDir, { recursive: true });
  if (!fs.existsSync(path.join(repoDir, "app.js"))) {
    const a = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let v = "ghp_"; for (let i = 0; i < 36; i++) v += a[(i * 31 + 3) % a.length];
    fs.writeFileSync(path.join(repoDir, "app.js"), `const t = "${v}";\n`);
  }
  const repo = fs.realpathSync(repoDir);
  fs.rmSync(scratch, { recursive: true, force: true });
  consent.setConsentRootForTests(scratch); mcp.setAllowedRoots([repo]); mcp.resetSessions();
  let outbound = 0; mcp.setVerifyFetchForTests(async () => { outbound++; return new Response("{}", { status: 401 }); });
  const scan = mcp.toolScan({ path: repo }); if (!scan.ok) throw new Error("scan failed");
  const f = scan.payload.findings.find((x) => x.ruleId === "github-token"); if (!f) throw new Error("no github finding");
  const c1 = await mcp.toolVerify({ path: repo, fingerprint: f.fingerprint });
  if (!c1.ok || c1.payload.state !== "CONSENT_REQUIRED") throw new Error("call 1 did not request consent");
  const id = consent.recordId(f.fingerprint, repo);
  const written = JSON.parse(fs.readFileSync(path.join(scratch, "pending", id + ".json"), "utf8"));
  fs.writeFileSync(jsonOut, JSON.stringify(Object.assign({}, written, { state: "approved", approvedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 900000).toISOString() }), null, 2) + "\n");
  fs.rmSync(scratch, { recursive: true, force: true });
  log("make-record", { call1: c1.payload.state, outbound, fieldsFromProduct: Object.keys(written).sort().join(","), flipped: "state,approvedAt,expiresAt" });
  console.log("RECORD-ID: " + id); console.log("FINGERPRINT: " + f.fingerprint); console.log("ROOT: " + repo);
}
/** P9: the accepted policy must not block anything legitimate -- create, write, replace, approve, claim, verify. */
async function legit() {
  const OUT = opt("--out"), root = opt("--root"), repoDir = opt("--repo"), sid = currentSid();
  const consent = require(path.join(OUT, "consent.js")), mcp = require(path.join(OUT, "mcp-core.js"));
  fs.mkdirSync(repoDir, { recursive: true });
  if (!fs.existsSync(path.join(repoDir, "app.js"))) {
    const a = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let v = "ghp_"; for (let i = 0; i < 36; i++) v += a[(i * 31 + 3) % a.length];
    fs.writeFileSync(path.join(repoDir, "app.js"), `const t = "${v}";\n`);
  }
  const repo = fs.realpathSync(repoDir);
  const created = createSequence(root, sid);
  log("legit.create", { ok: created.ok, reason: created.reason });
  if (!created.ok) { console.log("PROBE-ERROR: the legitimate creation was refused -- NON-MEASUREMENT"); process.exit(2); }
  consent.setConsentRootForTests(root); mcp.setAllowedRoots([repo]); mcp.resetSessions();
  let outbound = 0; mcp.setVerifyFetchForTests(async () => { outbound++; return new Response("{}", { status: 401 }); });
  const scan = mcp.toolScan({ path: repo }); if (!scan.ok) throw new Error("scan failed");
  const f = scan.payload.findings.find((x) => x.ruleId === "github-token");
  const c1 = await mcp.toolVerify({ path: repo, fingerprint: f.fingerprint });
  const id = consent.recordId(f.fingerprint, repo);
  log("legit.call1", { state: c1.ok ? c1.payload.state : "fail", outbound, recordWritten: fs.existsSync(path.join(root, "pending", id + ".json")) });
  log("legit.sequence-after-call1", (() => { const r = operateSequence(root, sid); return { ok: r.ok, reason: r.reason, trusted: r.trustedRecords.length, refused: r.refusedRecords }; })());
  // replacement: the product rewrites the record through temp + rename
  const rec = consent.readRecord(id);
  consent.writeRecord(Object.assign({}, rec, { line: rec.line }));
  log("legit.replace", { stillParses: !!consent.readRecord(id), sequenceOk: operateSequence(root, sid).ok });
  // approval through the product's own approveRecord over the CURRENT value, then call 2
  const disk = fs.readFileSync(path.join(repo, "app.js"), "utf8").match(/"([^"]+)"/)[1];
  consent.approveRecord(consent.readRecord(id), consent.commitmentOf(disk));
  const afterApprove = operateSequence(root, sid);
  log("legit.after-approve", { sequenceOk: afterApprove.ok, trusted: afterApprove.trustedRecords.length, refused: afterApprove.refusedRecords });
  mcp.resetSessions(); mcp.toolScan({ path: repo });
  const c2 = await mcp.toolVerify({ path: repo, fingerprint: f.fingerprint });
  log("legit.call2", { state: c2.ok ? c2.payload.state : "fail:" + String(c2.error).slice(0, 80), outboundAttempted: outbound,
                       externalTransmission: c2.ok && c2.payload.network ? c2.payload.network.externalTransmission : null,
                       recordClaimed: !fs.existsSync(path.join(root, "pending", id + ".json")) });
  const replay = await mcp.toolVerify({ path: repo, fingerprint: f.fingerprint });
  log("legit.replay-after-claim", { state: replay.ok ? replay.payload.state : "fail", outboundTotal: outbound });
}
/** P10: tooling failures refuse, and a refusal never becomes "no record" followed by a creation or write. */
function toolfail() {
  const root = opt("--root"); const sid = currentSid();
  fs.rmSync(root, { recursive: true, force: true });
  const r = createSequence(root, sid);
  log("toolfail.create", { ok: r.ok, reason: r.reason, detail: r.detail, created: r.created });
  log("toolfail.filesystem-effect", { storeExists: fs.existsSync(root) });
  const op = operateSequence(root, sid);
  log("toolfail.operate", { ok: op.ok, reason: op.reason, detail: op.detail, trustedRecords: op.trustedRecords });
  if (op.ok && /trusted/.test(String(op.reason))) { console.log("PROBE-ERROR: a tooling failure was treated as a trusted store"); process.exit(2); }
  if (fs.existsSync(root)) { console.log("PROBE-ERROR: a refused creation left a directory behind"); process.exit(2); }
}
(async () => {
  try {
    if (mode === "helper-source") { console.log(PS_SOURCE); console.log("--- delivered as -EncodedCommand, " + PS_B64.length + " base64 chars; paths arrive on stdin, one per line"); }
    else if (mode === "table") table();
    else if (mode === "facts") facts();
    else if (mode === "chain") chainMode();
    else if (mode === "inspect") inspectMode();
    else if (mode === "create") createMode();
    else if (mode === "operate") operateMode();
    else if (mode === "attack-open") attackOpen();
    else if (mode === "attack-swap") attackSwap();
    else if (mode === "plant") plant();
    else if (mode === "make-record") await makeRecord();
    else if (mode === "legit") await legit();
    else if (mode === "toolfail") toolfail();
    else throw new Error("unknown mode " + mode);
    if (WIN) log("helper.spawns", psCalls);
  } catch (e) { console.log("PROBE-ERROR: " + ((e && e.stack) || e)); process.exit(2); }
})();
