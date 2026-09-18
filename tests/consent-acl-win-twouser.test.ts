import { test, suite, finish, assert, skip } from "./harness";
import { existsSync, readdirSync, realpathSync, writeFileSync, rmSync } from "fs";
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
 * THE CASE A SECOND ACCOUNT IS NEEDED FOR.
 *
 * A record planted by another ordinary account, and later caught by a protected parent, has its
 * INHERITED access list rewritten to name only this account, SYSTEM and Administrators — it looks
 * private — while its owner stays the account that planted it, and an owner can re-grant itself
 * at will. That was measured before the policy was written, and a check that reads only the
 * access list accepts it. This is the regression for that: the product must refuse the record on
 * its OWNER and transmit nothing.
 *
 * Provisioning a second local account needs administrative rights, so the fixture is built by the
 * job described in the workflow and handed over through the environment. Where no such account
 * has been provisioned every case states that and skips: a skip here is an absence of evidence,
 * never a pass.
 */

const STORE = process.env.SECRETLOOP_WIN_TWOUSER_STORE;
const REPO = process.env.SECRETLOOP_WIN_TWOUSER_REPO;
const ATTACKER = process.env.SECRETLOOP_WIN_ATTACKER_SID;
const REASON =
  "NOT RUN: no second ordinary Windows account was provisioned for this run " +
  "(SECRETLOOP_WIN_TWOUSER_STORE, SECRETLOOP_WIN_TWOUSER_REPO, SECRETLOOP_WIN_ATTACKER_SID); " +
  "the test-windows-two-user CI job provides them";
const CONFIGURED = process.platform === "win32" && !!STORE && !!REPO && !!ATTACKER;

let wire = { count: 0 };
function armFetch(): void {
  wire = { count: 0 };
  resetOutboundCountForTests();
  setVerifyFetchForTests((async () => {
    wire.count++;
    return new Response("{}", { status: 401 });
  }) as unknown as typeof fetch);
}

suite("windows consent ACL — against a second ordinary account");

test("these cases run as the ordinary owner, not as the account that built the fixture", () => {
  if (!CONFIGURED) return skip(REASON);
  const expected = process.env.SECRETLOOP_WIN_EXPECTED_SID;
  if (!expected) return skip("NOT RUN: the job did not say which account these cases must run as");
  const me = acl.currentUserSid();
  // The fixture is built by an elevated account; the product must be exercised by an ordinary one.
  // Without this, an administrator's result could be presented as an ordinary user's.
  assert.strictEqual(me, expected, "the product is not running as the ordinary owner the job provisioned");
  assert.notStrictEqual(me, ATTACKER, "the owner and the attacker must be different accounts");
});

test("the planted record really is owned by the other account, or nothing below is evidence", () => {
  if (!CONFIGURED) return skip(REASON);
  const pending = path.join(STORE as string, "pending");
  const records = readdirSync(pending).filter((f) => f.endsWith(".json"));
  assert.strictEqual(records.length, 1, "the fixture must hold exactly one planted record");
  const inspected = acl.inspectPaths([path.join(pending, records[0])]);
  assert.ok(inspected.ok, "the fixture record could not be inspected");
  const info = (inspected as { ok: true; byPath: Map<string, { ownerSid: string; sddl: string }> }).byPath.get(
    path.resolve(path.join(pending, records[0])).toLowerCase()
  );
  assert.ok(info, "the fixture record was not reported");
  assert.strictEqual(info?.ownerSid, ATTACKER, "the fixture is not owned by the other account — this is a setup failure, not a defence");
  // and its access list must look private, or the case is not the one being tested
  const decision = acl.decideStoreDacl(info?.sddl as string, acl.currentUserSid() as string);
  assert.ok(decision.ok, "the planted record's access list must look private for this case to mean anything");
});

test("that record is refused on its owner, and nothing is transmitted on the strength of it", async () => {
  if (!CONFIGURED) return skip(REASON);
  const savedRoots = getAllowedRoots();
  try {
    const repo = realpathSync(REPO as string);
    consent.setConsentRootForTests(STORE as string);
    setAllowedRoots([repo]);
    resetSessions();
    armFetch();
    const scan = toolScan({ path: repo }) as { ok: true; payload: { findings: { ruleId: string; fingerprint: string }[] } };
    const finding = scan.payload.findings.find((f) => f.ruleId === "github-token");
    assert.ok(finding, "the fixture repository produced no verifiable finding");
    const fingerprint = (finding as { fingerprint: string }).fingerprint;

    let problem: string | undefined;
    try {
      consent.readRecord(consent.recordId(fingerprint, repo));
    } catch (err) {
      problem = (err as consent.ConsentStoreError).problem;
    }
    assert.strictEqual(problem, "foreign-owner", "a record owned by another account must be refused, not read");

    const verify = (await toolVerify({ path: repo, fingerprint })) as { ok: boolean; error?: string };
    assert.strictEqual(verify.ok, false, "the verification must refuse");
    assert.match(verify.error as string, /cannot be trusted/);
    assert.doesNotMatch(verify.error as string, /[A-Za-z]:\\|S-1-5-/, "the refusal echoed a path or a SID");
    assert.strictEqual(wire.count, 0, "an approval owned by another account must never reach the network");

    let listProblem: string | undefined;
    try {
      consent.listRecords();
    } catch (err) {
      listProblem = (err as consent.ConsentStoreError).problem;
    }
    assert.strictEqual(listProblem, "foreign-owner", "listing must refuse it too, so approve cannot show it");
  } finally {
    setAllowedRoots(savedRoots);
    consent.setConsentRootForTests(undefined);
  }
});

test("a parent the other account can write refuses before any store is created", async () => {
  if (!CONFIGURED) return skip(REASON);
  const permissive = process.env.SECRETLOOP_WIN_PERMISSIVE_PARENT;
  if (!permissive) return skip("NOT RUN: no permissive-parent fixture was provided for this run");
  const savedRoots = getAllowedRoots();
  const store = path.join(permissive, ".secretloop");
  try {
    const repo = realpathSync(REPO as string);
    consent.setConsentRootForTests(store);
    setAllowedRoots([repo]);
    resetSessions();
    armFetch();
    const scan = toolScan({ path: repo }) as { ok: true; payload: { findings: { ruleId: string; fingerprint: string }[] } };
    const finding = scan.payload.findings.find((f) => f.ruleId === "github-token");
    assert.ok(finding, "the fixture repository produced no verifiable finding");
    const verify = (await toolVerify({ path: repo, fingerprint: (finding as { fingerprint: string }).fingerprint })) as {
      ok: boolean;
      error?: string;
    };
    assert.strictEqual(verify.ok, false, "a parent another account can write must refuse");
    assert.ok(!existsSync(store), "a refusal must not create the store");
    assert.strictEqual(wire.count, 0);
  } finally {
    setAllowedRoots(savedRoots);
    consent.setConsentRootForTests(undefined);
  }
});

test("read-only rights refuse, and as an ordinary account the write really does fail", () => {
  if (!CONFIGURED) return skip(REASON);
  const rxStore = process.env.SECRETLOOP_WIN_RX_STORE;
  if (!rxStore) return skip("NOT RUN: no read-only-rights store fixture was provided for this run");
  const me = acl.currentUserSid();
  assert.ok(me, "could not read this account");
  // This account must NOT be an administrator, or the Administrators entry would supply the
  // access and the case would measure nothing.
  const pending = path.join(rxStore, "pending");
  try {
    consent.setConsentRootForTests(rxStore);
    let problem: string | undefined;
    try {
      consent.listRecords();
    } catch (err) {
      problem = (err as consent.ConsentStoreError).problem;
    }
    assert.strictEqual(problem, "insufficient-rights", "an account holding only read access must be refused");
    let wrote = false;
    try {
      writeFileSync(path.join(pending, "probe.tmp"), "{}\n");
      wrote = true;
      rmSync(path.join(pending, "probe.tmp"), { force: true });
    } catch {
      wrote = false;
    }
    assert.ok(!wrote, "the rule claimed insufficient rights, so the write it governs must really fail");
  } finally {
    consent.setConsentRootForTests(undefined);
  }
});

finish();
