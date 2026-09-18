#!/usr/bin/env node
/*
 * EVIDENCE-ONLY PROBE HARNESS for the consent-file assessment. Not a test, not
 * product code. Drives the REAL consent module and the REAL MCP verify path from
 * a built `out/` directory, against synthetic records in a disposable directory.
 *
 *   node consent-probes.js --out <dir> facts
 *   node consent-probes.js --out <dir> lifecycle [--consent-root <dir>] [--umask 000|022|077]
 *   node consent-probes.js --out <dir> tamper --consent-root <dir>
 *   node consent-probes.js --out <dir> plant [--consent-root <dir>]
 *   node consent-probes.js other-user --target <record-file>
 *
 * Never prints a credential value or a commitment. Every probe reports
 * "fired"/"ok"/"error:<code>" rather than skipping; the parent decides.
 * The outbound boundary in `tamper` is REPLACED by an interceptor that records
 * the attempt and returns a synthetic response; no provider is contacted.
 */
"use strict";
const fs = require("fs");
const os = require("os");
const path = require("path");
const cp = require("child_process");
const crypto = require("crypto");

const args = process.argv.slice(2);
const opt = (name, def) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : def; };
const mode = args.find((a) => !a.startsWith("--") && args[args.indexOf(a) - 1] !== "--out" && args[args.indexOf(a) - 1] !== "--consent-root" && args[args.indexOf(a) - 1] !== "--umask" && args[args.indexOf(a) - 1] !== "--target") || "facts";
const OUT = opt("--out", null);
const win = process.platform === "win32";
const log = (k, v) => console.log(`${k}: ${typeof v === "string" ? v : JSON.stringify(v)}`);
const code = (e) => (e && e.code) || String(e);
const octal = (p) => { try { return (fs.lstatSync(p).mode & 0o777).toString(8).padStart(4, "0"); } catch (e) { return "error:" + code(e); } };
const owner = (p) => { try { const s = fs.statSync(p); return `${s.uid}:${s.gid}`; } catch (e) { return "error:" + code(e); } };
function icacls(p) {
  if (!win) return null;
  const r = cp.spawnSync("icacls", [p], { encoding: "utf8", timeout: 15000 });
  return (r.stdout || "").split(/\r?\n/).filter((l) => l.trim() && !/Successfully processed/.test(l)).map((l) => l.replace(p, "<path>").trim());
}
function getAclOwner(p) {
  if (!win) return null;
  const r = cp.spawnSync("powershell", ["-NoProfile", "-Command", `(Get-Acl -LiteralPath '${p.replace(/'/g, "''")}').Owner`], { encoding: "utf8", timeout: 20000 });
  return (r.stdout || "").trim() || "error:" + (r.stderr || "").trim().slice(0, 80);
}
function facts() {
  log("platform", `${process.platform}/${process.arch} ${os.release()}`);
  log("node", process.version);
  log("user", `${os.userInfo().username} uid=${os.userInfo().uid} gid=${os.userInfo().gid}`);
  log("homedir", "<homedir>");
  log("tmpdir-fs", win ? (cp.spawnSync("fsutil", ["fsinfo", "fstype", os.tmpdir().slice(0, 2)], { encoding: "utf8" }).stdout || "").trim() : (cp.spawnSync("df", ["-T", os.tmpdir()], { encoding: "utf8" }).stdout || cp.spawnSync("df", [os.tmpdir()], { encoding: "utf8" }).stdout || "").split("\n")[1]);
  if (!win) log("umask", process.umask().toString(8));
  if (win) {
    const r = cp.spawnSync("whoami", ["/groups"], { encoding: "utf8", timeout: 15000 });
    log("elevated", /S-1-16-12288/.test(r.stdout || "") ? "yes (high integrity)" : /S-1-16-8192/.test(r.stdout || "") ? "no (medium integrity)" : "unknown");
  } else {
    log("root", String(process.getuid && process.getuid() === 0));
  }
}
function load() {
  if (!OUT) throw new Error("--out <built out dir> is required");
  const consent = require(path.join(OUT, "consent.js"));
  return { consent };
}
function describe(p) {
  const d = { exists: fs.existsSync(p), mode: octal(p), owner: owner(p) };
  if (win) { d.icacls = icacls(p); d.aclOwner = getAclOwner(p); }
  return d;
}
function synthRecord(consent, id, extra) {
  return Object.assign({
    version: consent.CONSENT_VERSION, id, state: "pending", fingerprint: "src/app.js:github-token:" + "0".repeat(16),
    path: "/synthetic/root", file: "src/app.js", line: 1, ruleId: "github-token", provider: "github",
    commitment: crypto.createHash("sha256").update("synthetic-not-a-credential", "utf8").digest("hex"),
    createdAt: new Date().toISOString(),
  }, extra || {});
}
function lifecycle() {
  const { consent } = load();
  const root = opt("--consent-root", null);
  const um = opt("--umask", null);
  if (!win && um !== null) { const old = process.umask(parseInt(um, 8)); log("umask-set", `${um} (was ${old.toString(8)})`); }
  if (root) consent.setConsentRootForTests(root);
  const dir = consent.consentDir(); const pend = consent.pendingDir();
  log("consentRoot", root ? "<explicit disposable dir>" : "<homedir>/.secretloop (real path logic)");
  // 1. fresh creation
  fs.rmSync(dir, { recursive: true, force: true });
  const r1 = synthRecord(consent, consent.recordId("fp-1", "/synthetic/root"));
  consent.writeRecord(r1);
  log("create.dir", describe(dir)); log("create.pending", describe(pend)); log("create.record", describe(path.join(pend, r1.id + ".json")));
  log("create.readback", consent.readRecord(r1.id) ? "parsed" : "null");
  // 2. pre-existing permissive directory and file
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(pend, { recursive: true, mode: 0o777 });
  try { fs.chmodSync(dir, 0o777); fs.chmodSync(pend, 0o777); } catch (e) { log("preexisting.chmod", "error:" + code(e)); }
  if (win) { for (const p of [dir, pend]) { const r = cp.spawnSync("icacls", [p, "/grant", "Everyone:(OI)(CI)F"], { encoding: "utf8", timeout: 15000 }); log("preexisting.grantEveryone", r.status); } }
  const rp = path.join(pend, r1.id + ".json");
  fs.writeFileSync(rp, JSON.stringify(synthRecord(consent, r1.id, { provider: "planted" })) + "\n", { mode: 0o666 });
  try { fs.chmodSync(rp, 0o666); } catch {}
  if (win) { const r = cp.spawnSync("icacls", [rp, "/grant", "Everyone:F"], { encoding: "utf8", timeout: 15000 }); log("preexisting.file.grantEveryone", r.status); }
  log("preexisting.before.dir", describe(dir)); log("preexisting.before.pending", describe(pend)); log("preexisting.before.record", describe(rp));
  const inoBefore = (() => { try { return String(fs.statSync(rp).ino); } catch { return "?"; } })();
  consent.writeRecord(r1);
  const inoAfter = (() => { try { return String(fs.statSync(rp).ino); } catch { return "?"; } })();
  log("preexisting.after.dir", describe(dir)); log("preexisting.after.pending", describe(pend)); log("preexisting.after.record", describe(rp));
  log("preexisting.record.replaced-inode", inoBefore !== inoAfter);
  log("preexisting.readback.provider-is-ours", consent.readRecord(r1.id) && consent.readRecord(r1.id).provider === "github");
  // 3. unwritable/unchmodable parent (owned by someone else is simulated by a read-only dir where allowed)
  // 4. symlink / junction redirection of the pending directory
  fs.rmSync(dir, { recursive: true, force: true });
  const elsewhere = fs.mkdtempSync(path.join(os.tmpdir(), "consent-elsewhere-"));
  fs.mkdirSync(dir, { recursive: true });
  let linkKind = "none";
  try { fs.symlinkSync(elsewhere, pend, win ? "junction" : "dir"); linkKind = win ? "junction" : "symlink"; } catch (e) { log("redirect.link", "error:" + code(e)); }
  if (linkKind !== "none") {
    const r2 = synthRecord(consent, consent.recordId("fp-2", "/synthetic/root"));
    let wrote = "ok"; try { consent.writeRecord(r2); } catch (e) { wrote = "error:" + code(e); }
    const landed = fs.existsSync(path.join(elsewhere, r2.id + ".json"));
    log("redirect.pendingDir", { linkKind, write: wrote, recordLandedInRedirectTarget: landed, pendingStillLink: (() => { try { return fs.lstatSync(pend).isSymbolicLink(); } catch { return "gone"; } })(), pendingMode: octal(pend), targetMode: octal(elsewhere) });
    log("redirect.readback", consent.readRecord(r2.id) ? "parsed (followed the link)" : "null");
    log("redirect.list", consent.listRecords().length);
  }
  fs.rmSync(dir, { recursive: true, force: true }); fs.rmSync(elsewhere, { recursive: true, force: true });
  // 5. record path is itself a symlink to a file elsewhere
  fs.mkdirSync(pend, { recursive: true, mode: 0o700 });
  const else2 = fs.mkdtempSync(path.join(os.tmpdir(), "consent-else2-"));
  const r3 = synthRecord(consent, consent.recordId("fp-3", "/synthetic/root"));
  const tgt = path.join(else2, "target.json"); fs.writeFileSync(tgt, JSON.stringify(synthRecord(consent, r3.id, { provider: "planted" })) + "\n");
  let fl = "none"; try { fs.symlinkSync(tgt, path.join(pend, r3.id + ".json"), win ? "file" : undefined); fl = "symlink"; } catch (e) { log("recordlink.link", "error:" + code(e)); }
  if (fl !== "none") {
    log("recordlink.read-through-link.provider", (consent.readRecord(r3.id) || {}).provider || "null");
    consent.writeRecord(r3);
    log("recordlink.after-write", { pathIsLink: fs.lstatSync(path.join(pend, r3.id + ".json")).isSymbolicLink(), targetUntouched: JSON.parse(fs.readFileSync(tgt, "utf8")).provider === "planted", readback: (consent.readRecord(r3.id) || {}).provider || "null" });
  }
  fs.rmSync(dir, { recursive: true, force: true }); fs.rmSync(else2, { recursive: true, force: true });
  // 6. malformed / mismatched records
  fs.mkdirSync(pend, { recursive: true, mode: 0o700 });
  const r4 = synthRecord(consent, consent.recordId("fp-4", "/synthetic/root"));
  fs.writeFileSync(path.join(pend, r4.id + ".json"), "{not json");
  log("malformed.readRecord", consent.readRecord(r4.id) === null ? "null (ignored)" : "PARSED");
  fs.writeFileSync(path.join(pend, r4.id + ".json"), JSON.stringify(synthRecord(consent, "someotherid")) + "\n");
  log("idmismatch.readRecord", consent.readRecord(r4.id) === null ? "null (ignored)" : "PARSED");
  log("idmismatch.listRecords", consent.listRecords().length);
  fs.writeFileSync(path.join(pend, r4.id + ".json"), JSON.stringify(synthRecord(consent, r4.id, { state: "approved" })) + "\n");
  log("approved-without-expiry.readRecord", consent.readRecord(r4.id) === null ? "null (ignored)" : "PARSED");
  fs.writeFileSync(path.join(pend, r4.id + ".json"), JSON.stringify(synthRecord(consent, r4.id, { state: "approved", expiresAt: new Date(Date.now() - 1000).toISOString() })) + "\n");
  const exp = consent.readRecord(r4.id); log("approved-expired", exp ? (consent.isExpired(exp) ? "parsed, isExpired=true" : "parsed, NOT expired") : "null");
  // 7. approve replaces the file; consume claims once
  const r5 = synthRecord(consent, consent.recordId("fp-5", "/synthetic/root"));
  consent.writeRecord(r5);
  const p5 = path.join(pend, r5.id + ".json"); const ino5 = String(fs.statSync(p5).ino);
  consent.approveRecord(r5, "a".repeat(64));
  log("approve.replaced-inode", String(fs.statSync(p5).ino) !== ino5); log("approve.record", describe(p5));
  log("consume.first", consent.consumeRecord(r5.id)); log("consume.second", consent.consumeRecord(r5.id)); log("consume.fileGone", !fs.existsSync(p5));
  log("pending.leftovers", fs.readdirSync(pend));
  fs.rmSync(dir, { recursive: true, force: true });
  log("lifecycle", "done");
}
async function tamper() {
  const { consent } = load();
  const root = opt("--consent-root", null); if (!root) throw new Error("--consent-root required");
  consent.setConsentRootForTests(root); fs.rmSync(root, { recursive: true, force: true });
  const mcp = require(path.join(OUT, "mcp-core.js"));
  const cli = require(path.join(OUT, "cli.js"));
  const walk = require(path.join(OUT, "walk.js"));
  // synthetic repo with one github-token-shaped value, built at runtime
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), "consent-repo-"));
  const a = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"; let v = "ghp_"; for (let i = 0; i < 36; i++) v += a[(i * 19 + 11) % a.length];
  fs.writeFileSync(path.join(repo, "app.js"), `const t = "${v}";\n`);
  const realRepo = fs.realpathSync(repo);
  mcp.setAllowedRoots([realRepo]); mcp.resetSessions();
  let outbound = 0; const seen = [];
  mcp.setVerifyFetchForTests(async (url, init) => { outbound++; seen.push(String(url).replace(/[?].*/, "")); return new Response(JSON.stringify({}), { status: 401, headers: { "content-type": "application/json" } }); });
  const scan = mcp.toolScan({ path: realRepo }); if (!scan.ok) throw new Error("scan failed: " + scan.error);
  const f = scan.payload.findings.find((x) => x.ruleId === "github-token" || /github/.test(x.ruleId)); if (!f) throw new Error("no github finding: " + scan.payload.findings.map((x) => x.ruleId));
  const fp = f.fingerprint;
  const c1 = await mcp.toolVerify({ path: realRepo, fingerprint: fp });
  log("call1.state", c1.ok ? c1.payload.state : "fail:" + c1.error); log("call1.outbound", outbound);
  const id = consent.recordId(fp, realRepo); const rp = path.join(consent.pendingDir(), id + ".json");
  log("call1.record", { exists: fs.existsSync(rp), state: (consent.readRecord(id) || {}).state, mode: octal(rp), icacls: icacls(rp) });
  // A: forge approval with the CORRECT commitment (attacker who can write the record AND knows the value)
  const rec = consent.readRecord(id);
  const forgedA = Object.assign({}, rec, { state: "approved", commitment: consent.commitmentOf(v), approvedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 300000).toISOString() });
  fs.writeFileSync(rp, JSON.stringify(forgedA, null, 2) + "\n");
  const before = outbound; const c2 = await mcp.toolVerify({ path: realRepo, fingerprint: fp });
  log("forgeA.correct-commitment", { parsed: !!consent.readRecord(id) || "consumed", call2State: c2.ok ? c2.payload.state : "fail", outboundAttempted: outbound - before, network: c2.ok ? c2.payload.network : null, destinationHost: seen.slice(-1).map((u) => new URL(u).host) });
  // B: forge approval with a WRONG commitment (attacker who can write the record but does not know the value)
  mcp.resetSessions(); mcp.toolScan({ path: realRepo }); await mcp.toolVerify({ path: realRepo, fingerprint: fp });
  const rec2 = consent.readRecord(id);
  fs.writeFileSync(rp, JSON.stringify(Object.assign({}, rec2, { state: "approved", commitment: "b".repeat(64), approvedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 300000).toISOString() }), null, 2) + "\n");
  const b0 = outbound; const c3 = await mcp.toolVerify({ path: realRepo, fingerprint: fp });
  log("forgeB.wrong-commitment", { call2State: c3.ok ? c3.payload.state : "fail", reason: c3.ok ? c3.payload.reason : c3.error, outboundAttempted: outbound - b0, recordDeleted: !fs.existsSync(rp) });
  // C: forge with a stale expiry
  mcp.resetSessions(); mcp.toolScan({ path: realRepo }); await mcp.toolVerify({ path: realRepo, fingerprint: fp });
  const rec3 = consent.readRecord(id);
  fs.writeFileSync(rp, JSON.stringify(Object.assign({}, rec3, { state: "approved", commitment: consent.commitmentOf(v), approvedAt: new Date().toISOString(), expiresAt: new Date(Date.now() - 1000).toISOString() }), null, 2) + "\n");
  const c0 = outbound; const c4 = await mcp.toolVerify({ path: realRepo, fingerprint: fp });
  log("forgeC.expired", { call2State: c4.ok ? c4.payload.state : "fail", reason: c4.ok ? c4.payload.reason : c4.error, outboundAttempted: outbound - c0 });
  // D: planted record under a wrong filename (id mismatch) is ignored
  fs.writeFileSync(path.join(consent.pendingDir(), "zz" + id.slice(2) + ".json"), JSON.stringify(forgedA, null, 2) + "\n");
  log("forgeD.filename-mismatch.listed", consent.listRecords().filter((r) => r.fingerprint === fp).length);
  // E: control — the legitimate path: approve through runApprove with a fake TTY, then call 2
  mcp.resetSessions(); mcp.toolScan({ path: realRepo }); await mcp.toolVerify({ path: realRepo, fingerprint: fp });
  const io = { isTTY: true, out: () => {}, err: (m) => { io.lastErr = m; }, ask: async () => "y" };
  const rc = await cli.runApprove(fp, io);
  const e0 = outbound; const c5 = await mcp.toolVerify({ path: realRepo, fingerprint: fp });
  log("control.legitimate-approve", { approveExit: rc, call2State: c5.ok ? c5.payload.state : "fail", outboundAttempted: outbound - e0, network: c5.ok ? c5.payload.network : null });
  // F: the actor who can modify the REPOSITORY but not the consent dir: change the value after a legitimate approval
  mcp.resetSessions(); mcp.toolScan({ path: realRepo }); await mcp.toolVerify({ path: realRepo, fingerprint: fp });
  await cli.runApprove(fp, io);
  fs.writeFileSync(path.join(repo, "app.js"), `const t = "${v.slice(0, -1)}Z";\n`);
  const f0 = outbound; const c6 = await mcp.toolVerify({ path: realRepo, fingerprint: fp });
  log("repoActor.value-changed-after-approval", { call2State: c6.ok ? c6.payload.state : "fail", reason: c6.ok ? c6.payload.reason : c6.error, outboundAttempted: outbound - f0 });
  log("total.outbound-intercepted", outbound); log("value-or-commitment-printed", "never");
  fs.rmSync(repo, { recursive: true, force: true }); fs.rmSync(root, { recursive: true, force: true });
  log("tamper", "done");
}
function plant() {
  // Writes ONE synthetic pending record through the real writer and leaves it in place, printing its
  // path, so a different user (or the same user later) can attempt access to it. --consent-root
  // optional: without it the REAL path logic (<homedir>/.secretloop/pending) is used.
  const { consent } = load();
  const root = opt("--consent-root", null); if (root) consent.setConsentRootForTests(root);
  const r = synthRecord(consent, consent.recordId("fp-plant", "/synthetic/root"));
  consent.writeRecord(r);
  const p = path.join(consent.pendingDir(), r.id + ".json");
  log("planted.dir", describe(consent.consentDir())); log("planted.pending", describe(consent.pendingDir())); log("planted.record", describe(p));
  console.log("PLANTED-PATH: " + p);
}
function otherUser() {
  const target = opt("--target", null); if (!target) throw new Error("--target required");
  const res = { user: os.userInfo().username, uid: os.userInfo().uid };
  const parent = path.dirname(target), grand = path.dirname(parent);
  const attempt = (name, fn) => { try { const r = fn(); res[name] = r === undefined ? "ok" : r; } catch (e) { res[name] = "error:" + code(e); } };
  attempt("stat.grandparent", () => fs.statSync(grand) && "ok");
  attempt("list.grandparent", () => fs.readdirSync(grand).length);
  attempt("list.parent", () => fs.readdirSync(parent).length);
  attempt("read.record", () => { const s = fs.readFileSync(target, "utf8"); return "READ " + s.length + " bytes (" + (JSON.parse(s).state || "?") + ")"; });
  attempt("append.record", () => fs.appendFileSync(target, "\n"));
  attempt("write.record", () => fs.writeFileSync(target, "{}"));
  attempt("create.sibling", () => { const p = path.join(parent, "otheruser-planted.json"); fs.writeFileSync(p, "{}"); fs.rmSync(p, { force: true }); });
  attempt("rename.record", () => { fs.renameSync(target, target + ".moved"); fs.renameSync(target + ".moved", target); });
  attempt("delete.record", () => fs.rmSync(target + ".nonexistent", { force: true }) && "n/a");
  console.log("OTHER-USER: " + JSON.stringify(res));
}
(async () => {
  try {
    if (mode === "facts") facts();
    else if (mode === "lifecycle") lifecycle();
    else if (mode === "tamper") await tamper();
    else if (mode === "other-user") otherUser();
    else if (mode === "plant") plant();
    else throw new Error("unknown mode " + mode);
  } catch (e) { console.log("PROBE-ERROR: " + (e && e.stack || e)); process.exit(2); }
})();
