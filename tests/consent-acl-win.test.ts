import { test, suite, finish, assert, skip } from "./harness";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync, existsSync, readdirSync, realpathSync } from "fs";
import { spawnSync } from "child_process";
import { tmpdir } from "os";
import * as path from "path";
import {
  setAllowedRoots,
  getAllowedRoots,
  resetSessions,
  toolScan,
  toolVerify,
  setVerifyFetchForTests,
  resetOutboundCountForTests,
} from "../src/mcp-core";
import * as consent from "../src/consent";
import * as acl from "../src/consent-acl-win";

/**
 * THE WINDOWS CONSENT-STORE POLICY.
 *
 * Two halves. The first is the decision itself -- descriptor parsing, the store rule, the
 * ancestor rule and the helper's failure modes -- and runs on every platform, because it is
 * pure and because a rule that is only ever exercised on one operating system is a rule nobody
 * reads. The second drives the REAL consent flow against disposable stores on Windows, with the
 * outbound boundary replaced by a counting stub, so a verification that reaches the provider
 * step is counted rather than performed. The owner's real store is never touched.
 *
 * Cases needing a SECOND ordinary account live in consent-acl-win-twouser.test.ts, which states
 * its own reason for skipping when no such account has been provisioned.
 */

const WINDOWS = process.platform === "win32";
const ME = "S-1-5-21-1-1-1-1003";
const OTHER = "S-1-5-21-1-1-1-1004";
const SYSTEM = "S-1-5-18";
const ADMINS = "S-1-5-32-544";

const storeVerdict = (sddl: string): string => {
  const d = acl.decideStoreDacl(sddl, ME);
  return d.ok ? "accept" : d.problem;
};
const ancestorVerdict = (sddl: string, immediate = false): string => {
  const d = acl.decideAncestorDacl(sddl, ME, immediate);
  return d.ok ? "accept" : d.problem;
};

// ---------------------------------------------------------------------------
suite("windows consent ACL — the store rule");

test("a store object is accepted only when it names exactly this account, SYSTEM and Administrators", () => {
  assert.strictEqual(storeVerdict(`D:PAI(A;OICI;FA;;;${ME})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`), "accept");
  assert.strictEqual(storeVerdict(`D:AI(A;OICIID;FA;;;${ME})(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)`), "accept");
  // full access written as a hexadecimal mask is the same grant
  assert.strictEqual(storeVerdict(`D:PAI(A;OICI;0x1f01ff;;;${ME})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`), "accept");
});

test("a NULL access list is refused as such, and never confused with an empty one or with junk", () => {
  // Documented: a NULL DACL grants full access to any caller; an empty DACL grants none.
  assert.strictEqual(storeVerdict("D:NO_ACCESS_CONTROL"), "null-dacl");
  assert.strictEqual(storeVerdict("O:BAG:BA"), "null-dacl", "a descriptor with no D: component has a NULL DACL");
  assert.strictEqual(storeVerdict("D:P"), "empty-dacl");
  assert.strictEqual(storeVerdict("D:AI"), "empty-dacl");
  assert.strictEqual(storeVerdict("not a descriptor"), "acl-inspection-malformed");
  assert.strictEqual(storeVerdict(""), "acl-inspection-malformed");
  assert.strictEqual(storeVerdict(`D:PAI(A;OICI;FA;;;${ME}`), "acl-inspection-malformed", "truncated");
});

test("any other principal refuses, even one granted read only, and even inherit-only", () => {
  assert.strictEqual(storeVerdict(`D:PAI(A;OICI;FA;;;${ME})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)`), "foreign-principal");
  assert.strictEqual(storeVerdict(`D:AI(A;ID;FA;;;${ME})(A;ID;0x1200a9;;;${OTHER})(A;ID;FA;;;SY)(A;ID;FA;;;BA)`), "foreign-principal");
  assert.strictEqual(storeVerdict(`D:PAI(A;OICIIO;FA;;;WD)(A;OICI;FA;;;${ME})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`), "foreign-principal");
});

test("an entry that is not a plain allow refuses, whatever it would have granted", () => {
  assert.strictEqual(storeVerdict(`D:PAI(D;OICI;FA;;;WD)(A;OICI;FA;;;${ME})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`), "deny-ace");
  assert.strictEqual(storeVerdict(`D:PAI(AU;OICI;FA;;;WD)(A;OICI;FA;;;${ME})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`), "deny-ace");
});

test("this account must actually hold full access, not merely appear", () => {
  assert.strictEqual(storeVerdict(`D:PAI(A;OICI;0x1200a9;;;${ME})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`), "insufficient-rights", "read and execute only");
  assert.strictEqual(storeVerdict(`D:PAI(A;OICI;0x1301bf;;;${ME})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`), "insufficient-rights", "modify, short of full");
  assert.strictEqual(storeVerdict(`D:PAI(A;OICIIO;FA;;;${ME})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`), "insufficient-rights", "inherit-only grants nothing here");
  assert.strictEqual(storeVerdict(`D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`), "owner-not-granted");
});

test("an unrecognised principal alias or rights token refuses rather than being guessed at", () => {
  assert.strictEqual(storeVerdict(`D:PAI(A;OICI;FA;;;ZZ)(A;OICI;FA;;;${ME})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`), "foreign-principal");
  assert.strictEqual(acl.canonicalSid("ZZ"), "unknown-alias:ZZ");
  assert.strictEqual(acl.canonicalSid("BA"), ADMINS);
  assert.strictEqual(storeVerdict(`D:PAI(A;OICI;QQ;;;${ME})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`), "acl-inspection-malformed");
});

test("rights tokens map to the bits they name, with WRITE_DAC read correctly", () => {
  assert.strictEqual(acl.rightsMask("FA").mask, 0x1f01ff);
  assert.strictEqual(acl.rightsMask("0x1200a9").mask, 0x1200a9);
  assert.strictEqual(acl.rightsMask("WD").mask, 0x40000, "in SDDL, WD is WRITE_DAC — not write-data");
  assert.strictEqual(acl.rightsMask("WDAC").mask, 0x40000);
  assert.strictEqual(acl.rightsMask("LC").mask, 0x4, "add subdirectory");
  assert.strictEqual(acl.rightsMask("DC").mask, 0x2, "add file");
  assert.deepStrictEqual(acl.rightsMask("QQ").unknown, ["QQ"]);
});

// ---------------------------------------------------------------------------
suite("windows consent ACL — the ancestor rule");

/**
 * A stock volume root grants Users create-file and create-folder and is owned by
 * TrustedInstaller. The store rule would refuse it, so ancestors get a rights rule instead.
 * This shape was copied from a real `C:\` (windows-consent-acl-revised-validation).
 */
const STOCK_ROOT =
  `D:PAI(A;OICIIO;GA;;;CO)(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;BA)` +
  `(A;OICIIO;GA;;;BA)(A;;0x1200a9;;;BU)(A;OICIIO;GXGR;;;BU)(A;CI;LC;;;BU)(A;CI;DC;;;BU)`;

test("a stock volume root passes as an ancestor but not as the directory holding the store", () => {
  assert.strictEqual(ancestorVerdict(STOCK_ROOT, false), "accept", "refusing this would refuse every stock machine");
  assert.strictEqual(ancestorVerdict(STOCK_ROOT, true), "unsafe-parent", "another account could create the store name");
});

test("read access for other accounts is tolerated above the store; the power to replace is not", () => {
  assert.strictEqual(ancestorVerdict(`D:AI(A;OICIID;FA;;;${ME})(A;OICIID;FA;;;BA)(A;OICIID;0x1200a9;;;BU)`), "accept");
  assert.strictEqual(ancestorVerdict(`D:AI(A;OICIID;FA;;;${ME})(A;OICIID;SD;;;${OTHER})(A;OICIID;FA;;;BA)`), "unsafe-parent", "DELETE");
  assert.strictEqual(ancestorVerdict(`D:AI(A;OICIID;FA;;;${ME})(A;OICIID;DT;;;${OTHER})(A;OICIID;FA;;;BA)`), "unsafe-parent", "delete child");
  assert.strictEqual(ancestorVerdict(`D:AI(A;OICIID;FA;;;${ME})(A;OICIID;WD;;;${OTHER})(A;OICIID;FA;;;BA)`), "unsafe-parent", "WRITE_DAC");
  assert.strictEqual(ancestorVerdict(`D:AI(A;OICIID;FA;;;${ME})(A;OICIID;WO;;;${OTHER})(A;OICIID;FA;;;BA)`), "unsafe-parent", "WRITE_OWNER");
  assert.strictEqual(ancestorVerdict(`D:AI(A;OICIID;FA;;;${ME})(A;OICIID;FA;;;BU)`), "unsafe-parent", "Users full control");
});

test("a deny entry against another account is not a reason to refuse an ancestor", () => {
  assert.strictEqual(ancestorVerdict(`D:AI(D;OICIID;FA;;;${OTHER})(A;OICIID;FA;;;${ME})(A;OICIID;FA;;;BA)`), "accept");
});

test("platform identities are trusted above the store, and ordinary accounts are not", () => {
  // The adversary is another ordinary local account; a service identity cannot be assumed by one.
  assert.ok(acl.ancestorPrincipalAllowed("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", ME), "TrustedInstaller");
  assert.ok(acl.ancestorPrincipalAllowed("S-1-5-20", ME), "NETWORK SERVICE");
  assert.ok(acl.ancestorPrincipalAllowed("S-1-5-19", ME), "LOCAL SERVICE");
  assert.ok(acl.ancestorPrincipalAllowed("S-1-5-21-1-1-1-500", ME), "the built-in Administrator");
  assert.ok(!acl.ancestorPrincipalAllowed(OTHER, ME), "another ordinary account");
  assert.ok(!acl.ancestorPrincipalAllowed("S-1-5-32-545", ME), "Users");
  assert.ok(!acl.ancestorPrincipalAllowed("S-1-1-0", ME), "Everyone");
  assert.ok(!acl.ancestorPrincipalAllowed("S-1-5-11", ME), "Authenticated Users");
});

test("a network or UNC location is refused rather than walked", () => {
  assert.strictEqual(acl.ancestorChainOf("\\\\server\\share\\profile\\.secretloop"), null);
  const drive = acl.ancestorChainOf("C:\\Users\\someone\\.secretloop");
  assert.ok(drive && drive[0] === "C:\\" && drive[drive.length - 1].endsWith(".secretloop"));
});

// ---------------------------------------------------------------------------
suite("windows consent ACL — the helper's failure modes");

test("every way the helper can fail refuses, and none of them is permissive", () => {
  const paths = ["C:\\x"];
  const problem = (r: Parameters<typeof acl.classifyHelperResult>[0]): string => {
    const out = acl.classifyHelperResult(r, paths);
    return out.ok ? "accept" : out.problem;
  };
  assert.strictEqual(problem({ error: { code: "ETIMEDOUT" } }), "acl-inspection-failed", "timeout");
  assert.strictEqual(problem({ signal: "SIGTERM", error: { code: undefined } }), "acl-inspection-failed", "killed");
  assert.strictEqual(problem({ error: { code: "ENOBUFS" } }), "acl-inspection-failed", "output past the cap");
  assert.strictEqual(problem({ error: { code: "ENOENT" } }), "acl-tooling-unavailable", "could not be started");
  assert.strictEqual(problem({ status: 1, stdout: "" }), "acl-inspection-failed", "non-zero exit");
  assert.strictEqual(problem({ status: 0, stdout: "" }), "acl-inspection-failed", "silence");
  assert.strictEqual(problem({ status: 0, stdout: "x".repeat((1 << 20) + 1) }), "acl-inspection-failed", "oversized");
  assert.strictEqual(problem({ status: 0, stdout: "{not json}" }), "acl-inspection-malformed");
});

test("an incomplete or mistyped response refuses; every requested path must come back", () => {
  const rule = { sid: ME, allow: true, rights: 0x1f01ff, inheritOnly: false };
  const entry = (p: string, extra: Record<string, unknown> = {}) =>
    JSON.stringify({ path: p, ok: true, exists: true, isDirectory: true, isReparsePoint: false, ownerSid: ME, sddl: "D:P", rules: [rule], ...extra });
  const two = ["C:\\a", "C:\\b"];
  assert.ok(acl.parseHelperOutput(entry("C:\\a") + "\n" + entry("C:\\b"), two).ok);
  const missing = acl.parseHelperOutput(entry("C:\\a"), two);
  assert.ok(!missing.ok && missing.problem === "acl-inspection-malformed", "a missing per-path result refuses");
  const badOwner = acl.parseHelperOutput(entry("C:\\a", { ownerSid: "runner\\alice" }), ["C:\\a"]);
  assert.ok(!badOwner.ok, "an owner that is not a SID refuses — names are never matched");
  const badTypes = acl.parseHelperOutput(JSON.stringify({ path: "C:\\a", ok: true, exists: true, sddl: "D:P" }), ["C:\\a"]);
  assert.ok(!badTypes.ok, "missing fields refuse");
  const noRules = acl.parseHelperOutput(
    JSON.stringify({ path: "C:\\a", ok: true, exists: true, isDirectory: true, isReparsePoint: false, ownerSid: ME, sddl: "D:P" }),
    ["C:\\a"]
  );
  assert.ok(!noRules.ok, "a response without structured rules refuses; the decision is never made from the text alone");
  const ruleNotSid = acl.parseHelperOutput(entry("C:\\a", { rules: [{ sid: "BUILTIN\\Users", allow: true, rights: 1, inheritOnly: false }] }), ["C:\\a"]);
  assert.ok(!ruleNotSid.ok, "an access rule identified by name rather than by SID refuses");
});

test("the structured rules the product actually decides on behave the same way", () => {
  const r = (sid: string, rights: number, allow = true, inheritOnly = false) => ({ sid, allow, rights, inheritOnly });
  const FULL = 0x1f01ff;
  const priv = [r(ME, FULL), r(SYSTEM, FULL), r(ADMINS, FULL)];
  assert.ok(acl.decideStoreRules(priv, ME).ok);
  const withStranger = [...priv, r(OTHER, 0x1200a9)];
  const strangerVerdict = acl.decideStoreRules(withStranger, ME);
  assert.ok(!strangerVerdict.ok && strangerVerdict.problem === "foreign-principal");
  const denied = acl.decideStoreRules([...priv, r("S-1-1-0", FULL, false)], ME);
  assert.ok(!denied.ok && denied.problem === "deny-ace");
  const readOnly = acl.decideStoreRules([r(ME, 0x1200a9), r(SYSTEM, FULL), r(ADMINS, FULL)], ME);
  assert.ok(!readOnly.ok && readOnly.problem === "insufficient-rights");
  const inheritOnly = acl.decideStoreRules([r(ME, FULL, true, true), r(SYSTEM, FULL), r(ADMINS, FULL)], ME);
  assert.ok(!inheritOnly.ok && inheritOnly.problem === "insufficient-rights");
  assert.ok(!acl.decideStoreRules([], ME).ok, "no rules at all is an empty access list");
  // the built-in Administrator, which a stock profile is granted through, is trusted above the store
  assert.ok(acl.decideAncestorRules([r("S-1-5-21-9-9-9-500", FULL)], ME, true).ok);
  assert.ok(acl.decideAncestorRules([r("S-1-5-32-545", 0x1200a9)], ME, false).ok, "read access above the store is tolerated");
  assert.ok(!acl.decideAncestorRules([r("S-1-5-32-545", 0x1200a9 | 0x10000)], ME, false).ok, "DELETE is not");
  assert.ok(!acl.decideAncestorRules([r("S-1-5-32-545", 0x4)], ME, true).ok, "nor is creating a child in the store's own parent");
});

test("a stock Windows profile is not mistaken for an untrusted principal", () => {
  // Regression. A stock profile grants the built-in Administrator through the SDDL alias LA, which
  // has no fixed identifier because it is domain-relative. With that alias unmapped, a real profile
  // read as an unknown principal and every store beneath it was refused.
  assert.strictEqual(acl.canonicalSid("LA"), "domain-relative:500");
  assert.ok(acl.ancestorPrincipalAllowed(acl.canonicalSid("LA"), ME), "the built-in Administrator is trusted above the store");
  const profile = `D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;LA)(A;;0x100020;;;S-1-15-3-65536-1)`;
  assert.strictEqual(ancestorVerdict(profile, true), "accept", "a real profile must be usable as the store's parent");
});

test("the inspection script is a constant that interpolates nothing", () => {
  const source = acl.HELPER_SCRIPT_FOR_TESTS;
  assert.match(source, /\[Console\]::In\.ReadToEnd\(\)/, "paths arrive on standard input");
  assert.doesNotMatch(source, /\$\{/, "no template interpolation into PowerShell source");
  assert.match(source, /GetSecurityDescriptorSddlForm/, "the text form, for the NULL-versus-empty distinction");
  assert.match(source, /GetAccessRules\(\$true,\$true,\[System\.Security\.Principal\.SecurityIdentifier\]\)/, "structured rules, identified by SID");
  assert.match(source, /GetOwner\(\[System\.Security\.Principal\.SecurityIdentifier\]\)/, "owner as a SID, not a name");
  assert.match(source, /\$_\.Exception\.GetType\(\)\.FullName/, "exception type names only");
  assert.doesNotMatch(source, /\$_\.Exception\.Message/, "no operating-system text is ever returned");
  assert.doesNotMatch(source, /ExecutionPolicy/i, "no execution-policy change is requested");
  assert.doesNotMatch(source, /Out-File|Set-Content|New-Item/i, "nothing is written to disk");
});

test("every refusal sentence is fixed words, with no path, descriptor, record or OS text in it", () => {
  const problems: consent.ConsentStoreProblem[] = [
    "not-a-directory", "symlink", "foreign-owner", "permissive", "inaccessible",
    "identity-unreadable", "unsupported-location", "unsafe-parent", "foreign-principal",
    "deny-ace", "null-dacl", "empty-dacl", "owner-not-granted", "insufficient-rights",
    "owner-unreadable", "acl-tooling-unavailable", "acl-inspection-failed",
    "acl-inspection-malformed", "acl-enforcement-failed",
  ];
  for (const p of problems) {
    const sentence = new consent.ConsentStoreError(p).message;
    assert.ok(sentence.length > 20, `${p} has no sentence`);
    assert.match(sentence, /cannot be trusted/, `${p} does not say what follows`);
    assert.doesNotMatch(sentence, /[A-Za-z]:\\|\/tmp|D:\(|S-1-5-|0x[0-9a-f]{4}/, `${p} echoed a path, descriptor or SID`);
    assert.doesNotMatch(sentence, /ENOENT|EACCES|EPERM|errno|Exception/, `${p} echoed an OS error`);
  }
  assert.doesNotMatch(consent.CONSENT_STORE_GUIDANCE_WINDOWS, /\bdelete\b|sudo|takeown/i, "guidance must not push deletion or elevation");
  assert.match(consent.CONSENT_STORE_GUIDANCE_WINDOWS, /icacls/, "Windows guidance should name the tool that shows permissions");
});

// ---------------------------------------------------------------------------
suite("windows consent ACL — the real consent flow on Windows");

const REASON = "NOT RUN off win32: these drive real Windows security descriptors";
interface Ctx { base: string; root: string; store: string; cred: string; fingerprint: string }
let wire = { count: 0 };

function token(salt: number): string {
  const alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let out = "";
  for (let i = 0; i < 36; i++) out += alpha[(i * 13 + salt * 11 + 3) % alpha.length];
  return "ghp_" + out;
}
/** A disposable workspace and a store path under a parent this account alone controls. */
async function withWindowsStore(fn: (ctx: Ctx) => Promise<void>, opts: { protectParent?: boolean } = {}): Promise<void> {
  const base = mkdtempSync(path.join(tmpdir(), "secretloop-winacl-"));
  const savedRoots = getAllowedRoots();
  try {
    const parent = path.join(base, "home");
    mkdirSync(parent, { recursive: true });
    if (opts.protectParent !== false) {
      const sid = acl.currentUserSid();
      assert.ok(sid, "could not read this process's own account");
      const protection = acl.protectDirectory(parent, sid as string);
      assert.ok(protection.ok, "could not make the fixture parent private");
    }
    mkdirSync(path.join(base, "repo"), { recursive: true });
    const root = realpathSync(path.join(base, "repo"));
    const cred = token(4);
    writeFileSync(path.join(root, "app.js"), `const t = "${cred}";\n`, "utf8");
    const store = path.join(parent, ".secretloop");
    consent.setConsentRootForTests(store);
    setAllowedRoots([root]);
    resetSessions();
    wire = { count: 0 };
    resetOutboundCountForTests();
    setVerifyFetchForTests((async () => {
      wire.count++;
      return new Response("{}", { status: 401 });
    }) as unknown as typeof fetch);
    const scan = toolScan({ path: root }) as { ok: true; payload: { findings: { ruleId: string; fingerprint: string }[] } };
    const finding = scan.payload.findings.find((f) => f.ruleId === "github-token");
    assert.ok(finding, "fixture produced no verifiable finding");
    await fn({ base, root, store, cred, fingerprint: (finding as { fingerprint: string }).fingerprint });
  } finally {
    setAllowedRoots(savedRoots);
    consent.setConsentRootForTests(undefined);
    acl.setWindowsAclToolsForTests(undefined);
    rmSync(base, { recursive: true, force: true });
  }
}
const icacls = (args: string[]): number | null =>
  spawnSync(path.join(process.env.SystemRoot || "C:\\Windows", "System32", "icacls.exe"), args, { encoding: "utf8", timeout: 30_000 }).status;

test("a healthy store is created, used, replaced, approved, claimed once, and the replay refused", async () => {
  if (!WINDOWS) return skip(REASON);
  await withWindowsStore(async (ctx) => {
    assert.ok(!existsSync(ctx.store), "the fixture must start with no store");
    const first = (await toolVerify({ path: ctx.root, fingerprint: ctx.fingerprint })) as { ok: true; payload: { state: string } };
    assert.strictEqual(first.payload.state, "CONSENT_REQUIRED");
    assert.strictEqual(wire.count, 0, "the first call must transmit nothing");
    const id = consent.recordId(ctx.fingerprint, ctx.root);
    assert.ok(existsSync(path.join(ctx.store, "pending", `${id}.json`)), "no record was written");
    const record = consent.readRecord(id);
    assert.ok(record && record.state === "pending", "the record this account wrote must be readable");
    // replacement through the product's own writer
    consent.writeRecord(record as consent.ConsentRecord);
    assert.ok(consent.readRecord(id), "a replaced record must still be readable");
    // approval over the value currently on disk, then the second call
    consent.approveRecord(consent.readRecord(id) as consent.ConsentRecord, consent.commitmentOf(ctx.cred));
    resetSessions();
    toolScan({ path: ctx.root });
    const second = (await toolVerify({ path: ctx.root, fingerprint: ctx.fingerprint })) as { ok: true; payload: { state: string } };
    assert.strictEqual(wire.count, 1, "exactly one outbound attempt, and it was intercepted");
    assert.ok(["DEAD", "UNKNOWN", "LIVE"].includes(second.payload.state), "the approved call reached the provider step");
    assert.ok(!existsSync(path.join(ctx.store, "pending", `${id}.json`)), "the claim must consume the record");
    resetSessions();
    toolScan({ path: ctx.root });
    const replay = (await toolVerify({ path: ctx.root, fingerprint: ctx.fingerprint })) as { ok: true; payload: { state: string } };
    assert.strictEqual(replay.payload.state, "CONSENT_REQUIRED", "a replay must ask for consent again");
    assert.strictEqual(wire.count, 1, "a replay must not transmit");
  });
});

test("a store is refused before creation when another account could write its parent", async () => {
  if (!WINDOWS) return skip(REASON);
  await withWindowsStore(async (ctx) => {
    // Users can create and delete inside the parent: exactly the shape the rule exists to refuse.
    assert.strictEqual(icacls([path.dirname(ctx.store), "/grant", "*S-1-5-32-545:(OI)(CI)F", "/q"]), 0, "fixture setup failed");
    const result = (await toolVerify({ path: ctx.root, fingerprint: ctx.fingerprint })) as { ok: false; error: string };
    assert.strictEqual(result.ok, false, "an unsafe parent must refuse");
    assert.match(result.error, /cannot be trusted/);
    assert.ok(!existsSync(ctx.store), "a refusal must not create the store");
    assert.strictEqual(wire.count, 0);
  }, { protectParent: true });
});

test("a record owned by nobody this account trusts is refused even when its access list looks private", async () => {
  if (!WINDOWS) return skip(REASON);
  await withWindowsStore(async (ctx) => {
    await toolVerify({ path: ctx.root, fingerprint: ctx.fingerprint });
    const id = consent.recordId(ctx.fingerprint, ctx.root);
    const file = path.join(ctx.store, "pending", `${id}.json`);
    // LOCAL SERVICE stands in for "an account that is not this one": it is a principal this
    // machine always has, and setting it needs no second user to be provisioned. The record's
    // access list is untouched and still names only the trusted three.
    const set = icacls([file, "/setowner", "*S-1-5-19", "/q"]);
    if (set !== 0) return skip("NOT RUN: this account may not set another owner (SeRestorePrivilege absent)");
    let refused = false;
    try {
      consent.readRecord(id);
    } catch (err) {
      refused = err instanceof consent.ConsentStoreError && err.problem === "foreign-owner";
    }
    assert.ok(refused, "a record owned by another account must be refused, not read");
    resetSessions();
    toolScan({ path: ctx.root });
    const verify = (await toolVerify({ path: ctx.root, fingerprint: ctx.fingerprint })) as { ok: false; error: string };
    assert.strictEqual(verify.ok, false);
    assert.strictEqual(wire.count, 0, "nothing may be transmitted on the strength of that record");
  });
});

test("a record granted to another principal is refused while the store around it stays usable", async () => {
  if (!WINDOWS) return skip(REASON);
  await withWindowsStore(async (ctx) => {
    await toolVerify({ path: ctx.root, fingerprint: ctx.fingerprint });
    const id = consent.recordId(ctx.fingerprint, ctx.root);
    assert.strictEqual(icacls([path.join(ctx.store, "pending", `${id}.json`), "/grant", "*S-1-5-32-545:F", "/q"]), 0, "fixture setup failed");
    let problem: string | undefined;
    try {
      consent.readRecord(id);
    } catch (err) {
      problem = (err as consent.ConsentStoreError).problem;
    }
    assert.strictEqual(problem, "foreign-principal");
    assert.strictEqual(wire.count, 0);
  });
});

test("the store, its pending directory and a record are each refused when they are reparse points", async () => {
  if (!WINDOWS) return skip(REASON);
  await withWindowsStore(async (ctx) => {
    await toolVerify({ path: ctx.root, fingerprint: ctx.fingerprint });
    const id = consent.recordId(ctx.fingerprint, ctx.root);
    const pending = path.join(ctx.store, "pending");
    const elsewhere = path.join(ctx.base, "elsewhere");
    mkdirSync(elsewhere, { recursive: true });
    const link = path.join(pending, `${id}-link.json`);
    const made = spawnSync("cmd.exe", ["/d", "/c", "mklink", "/J", link.replace(/\.json$/, "-dir"), elsewhere], { encoding: "utf8", timeout: 20_000 });
    if (made.status !== 0) return skip("NOT RUN: this account may not create a junction here");
    // a junction inside pending is not a record and is never read; the store still works
    assert.ok(consent.readRecord(id), "an unrelated junction must not disturb a healthy record");
    // now make the pending directory itself a reparse point
    rmSync(pending, { recursive: true, force: true });
    assert.strictEqual(spawnSync("cmd.exe", ["/d", "/c", "mklink", "/J", pending, elsewhere], { encoding: "utf8", timeout: 20_000 }).status, 0);
    let problem: string | undefined;
    try {
      consent.readRecord(id);
    } catch (err) {
      problem = (err as consent.ConsentStoreError).problem;
    }
    assert.strictEqual(problem, "symlink", "a redirected pending directory is never followed");
  });
});

test("holding only read access in this account's own entry refuses", async () => {
  if (!WINDOWS) return skip(REASON);
  await withWindowsStore(async (ctx) => {
    await toolVerify({ path: ctx.root, fingerprint: ctx.fingerprint });
    const sid = acl.currentUserSid() as string;
    const pending = path.join(ctx.store, "pending");
    assert.strictEqual(
      icacls([pending, "/inheritance:r", "/grant:r", `*${sid}:(OI)(CI)RX`, "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "/q"]),
      0,
      "fixture setup failed"
    );
    let problem: string | undefined;
    try {
      consent.listRecords();
    } catch (err) {
      problem = (err as consent.ConsentStoreError).problem;
    }
    assert.strictEqual(problem, "insufficient-rights");
    // Whether a write then fails depends on who is running. This job is elevated, so the account
    // is also an Administrator and keeps full access through the Administrators entry: the rule is
    // CONSERVATIVE, refusing on this account's own entry rather than on its effective access. The
    // binding of the rule to a write that really fails is measured as an ORDINARY account, in
    // consent-acl-win-twouser.test.ts, where no Administrators membership can supply the access.
    let wrote = false;
    try {
      writeFileSync(path.join(pending, "probe.tmp"), "{}\n");
      wrote = true;
      rmSync(path.join(pending, "probe.tmp"), { force: true });
    } catch {
      wrote = false;
    }
    console.log(`      note: a real write ${wrote ? "still succeeded (this account is an Administrator)" : "failed, as the rule implies"}`);
    icacls([pending, "/grant", `*${sid}:(OI)(CI)F`, "/q"]);
  });
});

test("when the tools are missing nothing is created, nothing is trusted, and nothing falls through", async () => {
  if (!WINDOWS) return skip(REASON);
  await withWindowsStore(async (ctx) => {
    acl.setWindowsAclToolsForTests({ powershell: "C:\\nonexistent\\powershell.exe", icacls: "C:\\nonexistent\\icacls.exe" });
    const result = (await toolVerify({ path: ctx.root, fingerprint: ctx.fingerprint })) as { ok: false; error: string };
    assert.strictEqual(result.ok, false, "a missing inspection tool must refuse");
    assert.match(result.error, /cannot be trusted/);
    assert.ok(!existsSync(ctx.store), "a refusal must never fall through to creating a store");
    assert.strictEqual(wire.count, 0);
  });
});

test("when enforcement fails the store is not left behind half-made", async () => {
  if (!WINDOWS) return skip(REASON);
  await withWindowsStore(async (ctx) => {
    // inspection works; only the tool that applies permissions is gone
    acl.setWindowsAclToolsForTests({
      powershell: path.join(process.env.SystemRoot || "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
      icacls: "C:\\nonexistent\\icacls.exe",
    });
    const result = (await toolVerify({ path: ctx.root, fingerprint: ctx.fingerprint })) as { ok: false; error: string };
    assert.strictEqual(result.ok, false);
    assert.ok(!existsSync(ctx.store), "the directory this call created must be withdrawn when enforcement fails");
    assert.strictEqual(wire.count, 0);
  });
});

test("an existing private store keeps working when its pending directory has been removed", async () => {
  if (!WINDOWS) return skip(REASON);
  await withWindowsStore(async (ctx) => {
    await toolVerify({ path: ctx.root, fingerprint: ctx.fingerprint });
    rmSync(path.join(ctx.store, "pending"), { recursive: true, force: true });
    assert.strictEqual(consent.readRecord(consent.recordId(ctx.fingerprint, ctx.root)), null, "a missing pending directory is 'no record'");
    assert.deepStrictEqual(consent.listRecords(), []);
    resetSessions();
    toolScan({ path: ctx.root });
    const again = (await toolVerify({ path: ctx.root, fingerprint: ctx.fingerprint })) as { ok: true; payload: { state: string } };
    assert.strictEqual(again.payload.state, "CONSENT_REQUIRED");
    assert.ok(existsSync(path.join(ctx.store, "pending")), "the next request recreates it");
    assert.strictEqual(readdirSync(path.join(ctx.store, "pending")).filter((f) => f.endsWith(".json")).length, 1);
  });
});

finish();
