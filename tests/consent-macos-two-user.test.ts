import { test, suite, finish, assert, skip } from "./harness";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync, chmodSync, readdirSync } from "fs";
import { execFileSync, spawnSync } from "child_process";
import { tmpdir } from "os";
import * as path from "path";
import * as consent from "../src/consent";
import {
  setAllowedRoots, getAllowedRoots, resetSessions, toolScan, toolVerify,
  setVerifyFetchForTests, resetOutboundCountForTests,
} from "../src/mcp-core";

/**
 * MACOS, TWO ORDINARY ACCOUNTS.
 *
 * Every macOS result so far has been single-account: what the owner's own process could observe
 * about modes and ACEs. That establishes the product's behaviour and says nothing about whether a
 * second account can actually reach a record. This suite closes that, and only runs where a real
 * second account exists — never on a developer machine, where none is created.
 *
 * The product always runs as the ordinary owner. Every attack runs as the second account through
 * passwordless `sudo -u`, and its real exit status is what is recorded; a printed ACL is never a
 * substitute for an operation. Administrative setup happened in a separate CI step, not here.
 */

const ATTACKER = process.env.SECRETLOOP_MAC_ATTACKER;
const MAC = process.platform === "darwin";

/**
 * Run one command as the second account.
 *
 * `sudo -n -u`, not `su`. On a GitHub-hosted macOS runner `su` answers "Sorry" even for an
 * account that exists, because it wants a password the job does not have; the runner user does
 * have passwordless sudo. That was an ENVIRONMENT failure, not a product one, and it is worth
 * recording that the identity assertion below is what caught it: without that assertion every
 * "denied" here would have been a command that never ran.
 *
 * The argv is passed as an array with no shell anywhere, so a path never has to be quoted and
 * nothing this file did not compose is ever interpreted.
 */
function asAttacker(argv: string[]): { ok: boolean; out: string } {
  const r = spawnSync("/usr/bin/sudo", ["-n", "-u", ATTACKER as string, "--", ...argv], {
    encoding: "utf8", timeout: 30_000,
  });
  return { ok: r.status === 0, out: (r.stdout || "") + (r.stderr || "") };
}
function refusal(fn: () => unknown): string {
  try {
    fn();
    return "NOT REFUSED";
  } catch (err) {
    return err instanceof consent.ConsentStoreError ? err.problem : `threw ${(err as Error).name}`;
  }
}
function record(id: string): consent.ConsentRecord {
  return {
    version: consent.CONSENT_VERSION, id, state: "pending",
    fingerprint: "app.js:github-token:" + "0".repeat(16), path: "/synthetic/root",
    file: "app.js", line: 1, ruleId: "github-token", provider: "GitHub",
    commitment: "a".repeat(64), createdAt: new Date().toISOString(),
  };
}
/** A world-readable base, so reaching the fixture is never what denies the attacker. */
function lab(): string {
  const d = mkdtempSync(path.join(tmpdir(), "sl-2u-"));
  chmodSync(d, 0o755);
  return d;
}

const ID = "a".repeat(32);

// ---------------------------------------------------------------------------
suite("macOS, two ordinary accounts");

test("these cases really do run as two different accounts", () => {
  if (!MAC) return skip("NOT RUN: macOS only");
  if (!ATTACKER) return skip("NOT RUN: no second account provisioned (SECRETLOOP_MAC_ATTACKER unset)");
  const me = execFileSync("/usr/bin/id", ["-u"], { encoding: "utf8" }).trim();
  const them = asAttacker(["/usr/bin/id", "-u"]);
  assert.ok(them.ok, "the second account must be able to run a command at all: " + them.out);
  const theirUid = them.out.trim().split("\n").pop() as string;
  assert.notStrictEqual(me, theirUid, `both ran as uid ${me}; nothing below would be evidence`);
  assert.notStrictEqual(theirUid, "0", "the attacker must be an ORDINARY account, not root");
});

test("CONTROL: a deliberately readable record IS readable by the second account", () => {
  if (!MAC || !ATTACKER) return skip("NOT RUN: macOS with a second account only");
  // Without this, every denial below could be a broken fixture rather than a protection.
  const base = lab();
  try {
    const open = path.join(base, "open");
    mkdirSync(open, { mode: 0o755 });
    const f = path.join(open, "readable.json");
    writeFileSync(f, "{}\n", { mode: 0o644 });
    const r = asAttacker(["/bin/cat", f]);
    assert.ok(r.ok, "the control must succeed, or nothing here is evidence: " + r.out);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("a private parent denies the second account create, rename and delete", () => {
  if (!MAC || !ATTACKER) return skip("NOT RUN: macOS with a second account only");
  const base = lab();
  try {
    const home = path.join(base, "home");
    mkdirSync(home, { mode: 0o700 });
    const store = path.join(home, ".secretloop");
    mkdirSync(path.join(store, "pending"), { recursive: true, mode: 0o700 });
    writeFileSync(path.join(store, "pending", `${ID}.json`),
      JSON.stringify(record(ID), null, 2) + "\n", { mode: 0o600 });
    for (const [what, argv] of [
      ["create in the store", ["/usr/bin/touch", path.join(store, "pending", "planted.json")]],
      ["rename the store", ["/bin/mv", store, path.join(home, "stolen")]],
      ["delete the store", ["/bin/rm", "-rf", store]],
      ["read the record", ["/bin/cat", path.join(store, "pending", `${ID}.json`)]],
    ] as Array<[string, string[]]>) {
      assert.ok(!asAttacker(argv).ok, `${what} must be denied by a 0700 parent`);
    }
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("PERMISSIVE CONTROL: a writable parent lets the second account replace the store", () => {
  if (!MAC || !ATTACKER) return skip("NOT RUN: macOS with a second account only");
  // The negative twin of the case above: with a writable parent the same operations SUCCEED, so
  // the denials above are the permissions and not the harness.
  const base = lab();
  try {
    const home = path.join(base, "home");
    mkdirSync(home, { mode: 0o755 });
    chmodSync(home, 0o777);
    const store = path.join(home, ".secretloop");
    mkdirSync(path.join(store, "pending"), { recursive: true, mode: 0o700 });
    assert.ok(asAttacker(["/bin/mv", store, path.join(home, "stolen")]).ok,
      "a world-writable parent must let the store be renamed away");
    assert.ok(asAttacker(["/bin/mkdir", "-p", path.join(store, "pending")]).ok,
      "and must let a replacement be created");
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("the ancestor rule refuses that writable parent, so no store is created under it", () => {
  if (!MAC || !ATTACKER) return skip("NOT RUN: macOS with a second account only");
  const base = lab();
  try {
    const home = path.join(base, "home");
    mkdirSync(home, { mode: 0o755 });
    chmodSync(home, 0o777);
    const store = path.join(home, ".secretloop");
    consent.setConsentRootForTests(store);
    assert.strictEqual(refusal(() => consent.writeRecord(record(ID))), "unsafe-parent-posix");
    assert.ok(!existsSync(store), "nothing may be created under a parent another account can write");
  } finally {
    consent.setConsentRootForTests(undefined);
    rmSync(base, { recursive: true, force: true });
  }
});

test("BASELINE EXPOSURE: an inherited ACE really does let the second account read a record", () => {
  if (!MAC || !ATTACKER) return skip("NOT RUN: macOS with a second account only");
  // This is the measurement that has never been made: that an inherited ACE is not merely present
  // but EFFECTIVE for another account. The record is written here deliberately, bypassing the
  // product, to establish what the product's refusal is protecting against.
  const base = lab();
  try {
    const home = path.join(base, "home");
    mkdirSync(home, { mode: 0o700 });
    execFileSync("/bin/chmod",
      ["+a", `${ATTACKER} allow read,write,execute,file_inherit,directory_inherit,search`, home],
      { timeout: 10_000 });
    const store = path.join(home, ".secretloop", "pending");
    mkdirSync(store, { recursive: true, mode: 0o700 });
    const f = path.join(store, `${ID}.json`);
    writeFileSync(f, JSON.stringify(record(ID), null, 2) + "\n", { mode: 0o600 });
    const r = asAttacker(["/bin/cat", f]);
    assert.ok(r.ok,
      "an inherited ACE must actually grant the read, or the macOS refusal protects nothing: " + r.out);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("with the protection on, that record is never written at all", () => {
  if (!MAC || !ATTACKER) return skip("NOT RUN: macOS with a second account only");
  const base = lab();
  try {
    const home = path.join(base, "home");
    mkdirSync(home, { mode: 0o700 });
    execFileSync("/bin/chmod",
      ["+a", `${ATTACKER} allow read,write,execute,file_inherit,directory_inherit,search`, home],
      { timeout: 10_000 });
    const store = path.join(home, ".secretloop");
    consent.setConsentRootForTests(store);
    const problem = refusal(() => consent.writeRecord(record(ID)));
    assert.ok(problem === "unsafe-parent-posix" || problem === "extended-acl",
      `expected a refusal naming the ACE or the parent; got ${problem}`);
    assert.ok(!existsSync(path.join(store, "pending", `${ID}.json`)),
      "no record content may reach the disk");
  } finally {
    consent.setConsentRootForTests(undefined);
    rmSync(base, { recursive: true, force: true });
  }
});

test("a legitimate chain still approves once, transmits once, and refuses the replay", async () => {
  if (!MAC || !ATTACKER) return skip("NOT RUN: macOS with a second account only");
  const base = lab();
  const savedRoots = getAllowedRoots();
  try {
    const repoDir = path.join(base, "repo");
    mkdirSync(repoDir, { recursive: true });
    const alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let value = "ghp_";
    for (let i = 0; i < 36; i++) value += alpha[(i * 13 + 7) % alpha.length];
    writeFileSync(path.join(repoDir, "app.js"), `const t = "${value}";\n`, "utf8");
    const root = require("fs").realpathSync(repoDir) as string;
    const home = path.join(base, "home");
    mkdirSync(home, { mode: 0o700 });
    consent.setConsentRootForTests(path.join(home, ".secretloop"));
    setAllowedRoots([root]);
    resetSessions();
    let wire = 0;
    resetOutboundCountForTests();
    setVerifyFetchForTests((async () => { wire++; return new Response("{}", { status: 401 }); }) as unknown as typeof fetch);

    const scan = toolScan({ path: root }) as { ok: true; payload: { findings: { ruleId: string; fingerprint: string }[] } };
    const finding = scan.payload.findings.find((x) => x.ruleId === "github-token");
    assert.ok(finding, "the fixture produced no verifiable finding");
    const fingerprint = (finding as { fingerprint: string }).fingerprint;

    const first = (await toolVerify({ path: root, fingerprint })) as { ok: true; payload: { state: string } };
    assert.strictEqual(first.payload.state, "CONSENT_REQUIRED");
    assert.strictEqual(wire, 0, "the request alone transmits nothing");

    const pending = consent.listRecords();
    assert.strictEqual(pending.length, 1, "exactly one pending record");
    consent.approveRecord(pending[0], pending[0].commitment);

    await toolVerify({ path: root, fingerprint });
    assert.strictEqual(wire, 1, "exactly one outbound attempt after approval");

    await toolVerify({ path: root, fingerprint });
    assert.strictEqual(wire, 1, "the replay must not transmit again");
  } finally {
    setVerifyFetchForTests(undefined as unknown as typeof fetch);
    setAllowedRoots(savedRoots);
    consent.setConsentRootForTests(undefined);
    resetSessions();
    rmSync(base, { recursive: true, force: true });
  }
});

test("sticky: accepted with a trusted owner, and the attacker still cannot take the store", () => {
  if (!MAC || !ATTACKER) return skip("NOT RUN: macOS with a second account only");
  const base = lab();
  try {
    const home = path.join(base, "home");
    mkdirSync(home, { mode: 0o755 });
    chmodSync(home, 0o1777); // sticky, world-writable, owned by the OWNER
    const store = path.join(home, ".secretloop");
    mkdirSync(path.join(store, "pending"), { recursive: true, mode: 0o700 });
    consent.setConsentRootForTests(store);
    assert.deepStrictEqual(consent.listRecords(), [], "sticky + trusted owner is accepted");
    // and sticky must actually stop the attacker taking it
    assert.ok(!asAttacker(["/bin/mv", store, path.join(home, "stolen")]).ok,
      "sticky must deny renaming an entry the attacker does not own");
    assert.ok(!asAttacker(["/bin/rm", "-rf", store]).ok,
      "and deny deleting it");
    // what sticky does NOT stop: creating a name that is not there yet
    assert.ok(asAttacker(["/bin/mkdir", path.join(home, ".secretloop-other")]).ok,
      "sticky does not restrict CREATE; the ownership rule is what answers a pre-planted store");
  } finally {
    consent.setConsentRootForTests(undefined);
    rmSync(base, { recursive: true, force: true });
  }
});

finish();
