import { test, suite, finish, assert, skip } from "./harness";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync, readdirSync, openSync, closeSync } from "fs";
import { execFileSync } from "child_process";
import { tmpdir } from "os";
import * as path from "path";
import * as consent from "../src/consent";
import * as macacl from "../src/consent-acl-macos";
import {
  setAllowedRoots, getAllowedRoots, resetSessions, toolScan, toolVerify,
  setVerifyFetchForTests, resetOutboundCountForTests,
} from "../src/mcp-core";

/**
 * MACOS EXTENDED ACLs ON THE CONSENT STORE.
 *
 * On Linux the ACL mask and the group bits of st_mode move together, so `(mode & 0o077) === 0`
 * already excludes every effective named entry — measured in both directions, with no escape
 * hatch found across six constructions and two filesystems. macOS is NFSv4-style and has no mask.
 * Measured with the product's own writer: under a parent carrying inheritance ACEs, `writeRecord`
 * produced a store, a pending directory and a RECORD all carrying `everyone inherited allow …`
 * while `st_mode` read 0700/0700/0600 and Node saw nothing. That is what these cases are about.
 *
 * What they do NOT establish, so nothing here is read as more: the inspection is path-based, so
 * it is not atomic with the product's later descriptor open; it says nothing about who could read
 * the store before the check; it cannot revoke a descriptor another process already holds; and
 * NO CASE HERE SHOWS A SECOND ACCOUNT ACTUALLY READING A RECORD — there is one ordinary account
 * on the development machine and this suite does not create another. The cross-user half is the
 * Linux measurement's job and remains NOT RUN on macOS.
 */

const MAC = process.platform === "darwin";
const ID_OK = "a".repeat(32);

interface Fixture { base: string; store: string; pending: string }
function fixture(): Fixture {
  const base = mkdtempSync(path.join(tmpdir(), "secretloop-macacl-"));
  const store = path.join(base, ".secretloop");
  const pending = path.join(store, "pending");
  mkdirSync(pending, { recursive: true, mode: 0o700 });
  consent.setConsentRootForTests(store);
  return { base, store, pending };
}
function done(f: Fixture): void {
  consent.setConsentRootForTests(undefined);
  macacl.setLsRunnerForTests(undefined);
  rmSync(f.base, { recursive: true, force: true });
}
function record(id: string): consent.ConsentRecord {
  return {
    version: consent.CONSENT_VERSION, id, state: "pending",
    fingerprint: "app.js:github-token:" + "0".repeat(16), path: "/synthetic/root",
    file: "app.js", line: 1, ruleId: "github-token", provider: "GitHub",
    commitment: "a".repeat(64), createdAt: new Date().toISOString(),
  };
}
function place(f: Fixture, id: string): string {
  const p = path.join(f.pending, `${id}.json`);
  writeFileSync(p, JSON.stringify(record(id), null, 2) + "\n", { mode: 0o600 });
  return p;
}
function addAce(target: string): void {
  execFileSync("/bin/chmod", ["+a", "everyone allow read", target], { timeout: 10_000 });
}
function refusal(fn: () => unknown): string {
  try {
    fn();
    return "NOT REFUSED";
  } catch (err) {
    return err instanceof consent.ConsentStoreError ? err.problem : `threw ${(err as Error).name}`;
  }
}

// ---------------------------------------------------------------------------
suite("macOS consent store — extended ACLs");

test("a store with no extended ACL still works exactly as before", () => {
  if (!MAC) return skip("NOT RUN: these are macOS rules; Linux is covered by the mode check");
  const f = fixture();
  try {
    place(f, ID_OK);
    assert.strictEqual(consent.readRecord(ID_OK)?.id, ID_OK, "a clean record is still read");
    assert.strictEqual(consent.listRecords().length, 1, "and still listed");
    consent.writeRecord(record("b".repeat(32)));
    assert.ok(existsSync(path.join(f.pending, "b".repeat(32) + ".json")), "and still written");
  } finally {
    done(f);
  }
});

test("an ACE on a RECORD is refused, and the record is not repaired", () => {
  if (!MAC) return skip("NOT RUN: these are macOS rules");
  const f = fixture();
  try {
    const p = place(f, ID_OK);
    addAce(p);
    assert.strictEqual(refusal(() => consent.readRecord(ID_OK)), "extended-acl");
    assert.strictEqual(refusal(() => consent.listRecords()), "extended-acl");
    // Refused, never repaired: the entry is left exactly as found.
    const after = execFileSync("/bin/ls", ["-lden", "--", path.basename(p)],
      { cwd: f.pending, encoding: "utf8" });
    assert.ok(after.split("\n").length > 2, "the ACE must still be there");
  } finally {
    done(f);
  }
});

test("an ACE on the store or the pending directory is refused", () => {
  if (!MAC) return skip("NOT RUN: these are macOS rules");
  for (const which of ["store", "pending"] as const) {
    const f = fixture();
    try {
      place(f, ID_OK);
      addAce(which === "store" ? f.store : f.pending);
      assert.strictEqual(refusal(() => consent.listRecords()), "extended-acl", which);
      assert.strictEqual(refusal(() => consent.writeRecord(record(ID_OK))), "extended-acl", which);
    } finally {
      done(f);
    }
  }
});

test("a store created under a parent with inheritance ACEs is refused BEFORE any record is written", () => {
  if (!MAC) return skip("NOT RUN: these are macOS rules");
  // The measured case, driven through the product's own writer. Before this change the store,
  // the pending directory AND the record were all created carrying `everyone inherited allow`,
  // at modes 0700/0700/0600, and nothing noticed.
  const base = mkdtempSync(path.join(tmpdir(), "secretloop-macinh-"));
  try {
    const home = path.join(base, "home");
    mkdirSync(home, { recursive: true, mode: 0o700 });
    execFileSync("/bin/chmod",
      ["+a", "everyone allow read,write,execute,file_inherit,directory_inherit", home],
      { timeout: 10_000 });
    const store = path.join(home, ".secretloop");
    consent.setConsentRootForTests(store);

    // Since the ancestor rule landed this is caught EARLIER and for a better reason: the parent
    // itself is an unsafe ancestor, so the refusal happens before the store is created rather
    // than after it has inherited. Before the ancestor rule this same case returned
    // `extended-acl`, detected on the store the product had already made. Both refuse and both
    // write nothing; the new code names the object actually at fault.
    assert.strictEqual(refusal(() => consent.writeRecord(record(ID_OK))), "unsafe-parent-posix");

    // The point of checking at creation rather than after the write: no record content ever
    // reached the disk, so there is nothing whose exposure a later check would have to undo.
    assert.ok(!existsSync(path.join(store, "pending", `${ID_OK}.json`)), "no record was written");
    // And the refusal undid only what it created, leaving no half-made store behind.
    assert.ok(!existsSync(store), "the store this call created was removed again");
  } finally {
    consent.setConsentRootForTests(undefined);
    rmSync(base, { recursive: true, force: true });
  }
});

test("a refusal transmits nothing and approves nothing", async () => {
  if (!MAC) return skip("NOT RUN: these are macOS rules");
  const base = mkdtempSync(path.join(tmpdir(), "secretloop-macflow-"));
  const savedRoots = getAllowedRoots();
  try {
    const repoDir = path.join(base, "repo");
    mkdirSync(repoDir, { recursive: true });
    const alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let value = "ghp_";
    for (let i = 0; i < 36; i++) value += alpha[(i * 13 + 7) % alpha.length];
    writeFileSync(path.join(repoDir, "app.js"), `const t = "${value}";\n`, "utf8");
    const root = require("fs").realpathSync(repoDir) as string;
    const store = path.join(base, ".secretloop");
    mkdirSync(path.join(store, "pending"), { recursive: true, mode: 0o700 });
    consent.setConsentRootForTests(store);
    addAce(store);
    setAllowedRoots([root]);
    resetSessions();
    let wire = 0;
    resetOutboundCountForTests();
    setVerifyFetchForTests((async () => { wire++; return new Response("{}", { status: 401 }); }) as unknown as typeof fetch);

    const scan = toolScan({ path: root }) as { ok: true; payload: { findings: { ruleId: string; fingerprint: string }[] } };
    const finding = scan.payload.findings.find((x) => x.ruleId === "github-token");
    assert.ok(finding, "the fixture produced no verifiable finding");
    const out = (await toolVerify({ path: root, fingerprint: (finding as { fingerprint: string }).fingerprint })) as
      { ok: false; error: string } | { ok: true; payload: { state: string } };

    assert.ok(!("payload" in out) || out.payload.state !== "VERIFIED", "nothing may be verified");
    assert.strictEqual(wire, 0, "no outbound call was made");
    assert.strictEqual(readdirSync(path.join(store, "pending")).length, 0, "no record was minted");
    if (!("payload" in out)) {
      assert.match(out.error, /extended access-control list/, out.error);
      assert.ok(!/\/(Users|tmp|private)\//.test(out.error), "no path may be echoed: " + out.error);
    }
  } finally {
    setVerifyFetchForTests(undefined as unknown as typeof fetch);
    setAllowedRoots(savedRoots);
    consent.setConsentRootForTests(undefined);
    resetSessions();
    rmSync(base, { recursive: true, force: true });
  }
});

// --- the parser boundary ---------------------------------------------------
suite("macOS ACL inspection — the parser boundary");

test("a hostile ANCESTOR name cannot corrupt the answer, with or without an ACE", () => {
  if (!MAC) return skip("NOT RUN: these are macOS rules");
  // The 32-hex record-name rule constrains a BASENAME only. The home path and every directory
  // above it are outside the product's control, so they are kept out of the output entirely by
  // passing the parent as the child's cwd and only the basename as the operand.
  const hostile = ["pa\nrent", "pa\rrent", "pa\trent", "parent", "pa rent", "pàrent中",
                   "-rf", " 0: group:everyone allow read", 'pa"rent'];
  const base = mkdtempSync(path.join(tmpdir(), "secretloop-macpath-"));
  try {
    for (const name of hostile) {
      for (const withAce of [false, true]) {
        const parent = path.join(base, (withAce ? "a" : "n") + Buffer.from(name).toString("hex"), name);
        mkdirSync(parent, { recursive: true });
        const store = path.join(parent, ".secretloop");
        mkdirSync(store, { mode: 0o700 });
        if (withAce) addAce(store);
        const verdict = macacl.inspectMacAcl({ parent, basename: ".secretloop" });
        if (withAce) {
          assert.deepStrictEqual(verdict, { ok: false, problem: "extended-acl" },
            `an ACE under ${JSON.stringify(name)} must still be seen`);
        } else {
          assert.deepStrictEqual(verdict, { ok: true },
            `a clean store under ${JSON.stringify(name)} must still pass`);
        }
      }
    }
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("a record name that could split the output is refused, not inspected", () => {
  if (!MAC) return skip("NOT RUN: these are macOS rules");
  // Names in `pending` come from readdir, which is what an adversary with write access there
  // controls. A name carrying a newline would split the header line and make an ACE line
  // indistinguishable from a filename continuation, so it is refused outright.
  assert.strictEqual(macacl.isInspectableBasename("re\ncord.json"), false);
  assert.strictEqual(macacl.isInspectableBasename("re\rcord.json"), false);
  assert.strictEqual(macacl.isInspectableBasename(`${"a".repeat(32)}.json`), true);
  const f = fixture();
  try {
    writeFileSync(path.join(f.pending, "re\ncord.json"), "{}\n", { mode: 0o600 });
    assert.strictEqual(refusal(() => consent.listRecords()), "acl-unreadable",
      "a record that cannot be inspected is not a record that can be trusted");
  } finally {
    done(f);
  }
});

test("the suffix character is never consulted", () => {
  if (!MAC) return skip("NOT RUN: these are macOS rules");
  // macOS shows '@' for extended attributes and '+' for an ACL, and '@' wins the slot. On this
  // OS an unremovable com.apple.provenance attribute means '+' may never appear at all, so a
  // suffix-only check would report "no ACL" for a file that has one. The parser counts ACE lines.
  const f = fixture();
  try {
    const p = place(f, ID_OK);
    const before = execFileSync("/bin/ls", ["-lden", "--", path.basename(p)], { cwd: f.pending, encoding: "utf8" });
    addAce(p);
    const after = execFileSync("/bin/ls", ["-lden", "--", path.basename(p)], { cwd: f.pending, encoding: "utf8" });
    assert.strictEqual(before.slice(0, 11), after.slice(0, 11),
      "the suffix did not change when the ACL appeared, which is exactly why it is not used");
    assert.deepStrictEqual(macacl.parseLsAclOutput(before, path.basename(p)), { ok: true, aceCount: 0 });
    assert.deepStrictEqual(macacl.parseLsAclOutput(after, path.basename(p)), { ok: true, aceCount: 1 });
  } finally {
    done(f);
  }
});

test("SIMULATED tool output: every ambiguity refuses and none reads as 'no ACL'", () => {
  // Platform-independent: this drives the parser directly with FABRICATED strings, not output
  // from /bin/ls, to reach bounds a filesystem fixture cannot construct. Labelled as simulation.
  const head = "drwx------  2 501 0 64 Jan 1 00:00 .secretloop";
  const bad: Array<[string, string]> = [
    ["empty output", ""],
    ["only a newline", "\n"],
    ["truncated mode line", "drwx---"],
    ["an ACE line before the header", " 0: 1234 allow read\n" + head],
    ["name is a prefix of the expected one", head + "EVIL"],
    ["trailing text after the name", head + " extra"],
    ["an unparseable line where an ACE should be", head + "\nnot-an-ace"],
    ["more ACE lines than the cap", head + "\n" +
      Array.from({ length: 129 }, (_, i) => ` ${i}: 1234 allow read`).join("\n")],
    ["output past the byte cap", head + "\n" + "x".repeat(64 * 1024 + 1)],
  ];
  for (const [label, out] of bad) {
    assert.deepStrictEqual(macacl.parseLsAclOutput(out, ".secretloop"), { ok: false },
      `${label} must refuse, never count as no ACL`);
  }
  assert.deepStrictEqual(macacl.parseLsAclOutput(head + "\n", ".secretloop"), { ok: true, aceCount: 0 });
  assert.deepStrictEqual(macacl.parseLsAclOutput(head + "\n 0: 1234 allow read\n", ".secretloop"),
    { ok: true, aceCount: 1 });
});

test("SIMULATED helper failures: unavailable, failed and timed out each refuse", () => {
  if (!MAC) return skip("NOT RUN: the runner is only consulted on macOS");
  const f = fixture();
  try {
    place(f, ID_OK);
    for (const problem of ["acl-tool-unavailable", "acl-unreadable"] as const) {
      macacl.setLsRunnerForTests(() => ({ ok: false, problem }));
      assert.strictEqual(refusal(() => consent.listRecords()), problem);
      assert.strictEqual(refusal(() => consent.readRecord(ID_OK)), problem);
      assert.strictEqual(refusal(() => consent.writeRecord(record(ID_OK))), problem);
    }
    // A runner that returns junk must not be believed either.
    macacl.setLsRunnerForTests(() => ({ ok: true, stdout: "who knows" }));
    assert.strictEqual(refusal(() => consent.listRecords()), "acl-unreadable");
  } finally {
    done(f);
  }
});

test("every new refusal sentence is fixed, and the guidance asks for no repair", () => {
  const codes: consent.ConsentStoreProblem[] = ["extended-acl", "acl-tool-unavailable", "acl-unreadable"];
  for (const code of codes) {
    const sentence = new consent.ConsentStoreError(code).message;
    assert.match(sentence, /cannot be trusted|are not trusted/, `${code} does not say what follows`);
    assert.doesNotMatch(sentence, /\/tmp|\/Users|[0-9a-f]{32}/, `${code} echoed a path or a record id`);
    assert.doesNotMatch(sentence, /ENOENT|EACCES|EPERM|ELOOP|errno|SIGKILL/, `${code} echoed an OS message`);
    const guidance = consent.consentStoreGuidance(code);
    assert.match(guidance, /no extended access-control entries/, guidance);
    assert.doesNotMatch(guidance, /chmod|-N\b|recursive/i, "no ACL stripping may be suggested");
  }
});

test("Linux and Windows behaviour is untouched by this change", () => {
  if (MAC) return skip("NOT RUN on darwin: this asserts the OTHER platforms are unaffected");
  const f = fixture();
  try {
    place(f, ID_OK);
    // No subprocess is spawned and no ACL code runs off macOS; the store behaves as before.
    macacl.setLsRunnerForTests(() => { throw new Error("the runner must never be called here"); });
    assert.strictEqual(consent.readRecord(ID_OK)?.id, ID_OK);
    assert.strictEqual(consent.listRecords().length, 1);
  } finally {
    done(f);
  }
});

test("descriptors are not leaked by the new refusals", () => {
  if (!MAC) return skip("NOT RUN: these are macOS rules");
  const f = fixture();
  try {
    const p = place(f, ID_OK);
    addAce(p);
    const probe = openSync(f.store, "r");
    closeSync(probe);
    for (let i = 0; i < 100; i++) refusal(() => consent.readRecord(ID_OK));
    const after = openSync(f.store, "r");
    closeSync(after);
    assert.ok(after - probe < 50, `descriptor numbers grew from ${probe} to ${after}`);
  } finally {
    done(f);
  }
});

finish();
