import { test, suite, finish, assert, skip } from "./harness";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync, chmodSync, symlinkSync, readdirSync, lstatSync } from "fs";
import { execFileSync } from "child_process";
import { tmpdir } from "os";
import * as path from "path";
import * as consent from "../src/consent";
import { checkParentChain, chainTargets, MAX_CHAIN_COMPONENTS } from "../src/consent-parent-chain";

/**
 * THE PATH ABOVE THE CONSENT STORE.
 *
 * Measured first, then written down. An account that can write the store's parent renamed the
 * whole store away and created its own; against that substituted store the product refused on
 * ownership and transmitted nothing, so in the cases measured the effect was denial of service
 * and not disclosure or an accepted approval — a statement about those cases, not a theorem. On
 * macOS the same position is worse, because an inheritance ACE on the parent is inherited by a
 * store and a record the owner's own process creates.
 *
 * WHAT THESE CASES DO NOT ESTABLISH. They run as ONE account and mutate fixtures as that account.
 * A same-user mutation is not a second-account bypass and is never described as one; the
 * two-account evidence is the Linux container job and, for macOS, is NOT RUN. A chain of `lstat`
 * calls is not an atomic snapshot: a component re-permissioned after the walk is not seen.
 */

const POSIX = process.platform !== "win32";
const MAC = process.platform === "darwin";
const EUID = typeof process.geteuid === "function" ? process.geteuid() : -1;

function lab(): string {
  return mkdtempSync(path.join(tmpdir(), "secretloop-pchain-"));
}
function storeUnder(base: string): string {
  const store = path.join(base, ".secretloop");
  mkdirSync(path.join(store, "pending"), { recursive: true, mode: 0o700 });
  return store;
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

// ---------------------------------------------------------------------------
suite("consent store — the ancestor chain");

test("a private chain is accepted, and the store still works", () => {
  if (!POSIX) return skip("NOT RUN on win32: Windows has its own ancestor rule from PR #91");
  const base = lab();
  try {
    const store = storeUnder(base);
    assert.deepStrictEqual(checkParentChain(store, EUID), { ok: true }, "the temp chain must pass");
    consent.setConsentRootForTests(store);
    consent.writeRecord(record("a".repeat(32)));
    assert.strictEqual(consent.readRecord("a".repeat(32))?.id, "a".repeat(32));
  } finally {
    consent.setConsentRootForTests(undefined);
    rmSync(base, { recursive: true, force: true });
  }
});

test("a group-writable ancestor is refused; the same chain without that bit is accepted", () => {
  if (!POSIX) return skip("NOT RUN on win32");
  const base = lab();
  try {
    const mid = path.join(base, "mid");
    mkdirSync(mid, { mode: 0o755 });
    const store = storeUnder(mid);
    // CONTROL first: the chain is accepted before the bit is set, so the refusal below is the
    // bit and not the fixture.
    assert.deepStrictEqual(checkParentChain(store, EUID), { ok: true }, "control: accepted at 0755");
    chmodSync(mid, 0o775);
    assert.deepStrictEqual(checkParentChain(store, EUID),
      { ok: false, problem: "unsafe-parent-posix" }, "0775 must refuse");
    chmodSync(mid, 0o755);
    assert.deepStrictEqual(checkParentChain(store, EUID), { ok: true }, "and accepted again");
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("a world-writable ancestor WITHOUT sticky is refused", () => {
  if (!POSIX) return skip("NOT RUN on win32");
  const base = lab();
  try {
    const mid = path.join(base, "mid");
    mkdirSync(mid, { mode: 0o755 });
    const store = storeUnder(mid);
    chmodSync(mid, 0o777);
    assert.deepStrictEqual(checkParentChain(store, EUID),
      { ok: false, problem: "unsafe-parent-posix" });
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("sticky is accepted only when a trusted principal owns the directory", () => {
  if (!POSIX) return skip("NOT RUN on win32");
  // The exception exists because /tmp is 1777 and a great deal of software lives under it.
  // Measured as a second ordinary account in a sticky root-owned world-writable directory:
  // deleting and renaming the owner's store are DENIED, which is what earns the exception; but
  // CREATING a name that does not exist yet is ALLOWED, so the store can be pre-planted. What
  // makes that tolerable is the separate ownership rule, which refuses a store it does not own.
  const base = lab();
  try {
    const mid = path.join(base, "mid");
    mkdirSync(mid, { mode: 0o755 });
    const store = storeUnder(mid);
    chmodSync(mid, 0o1777); // sticky, world-writable, owned by THIS account (trusted)
    assert.deepStrictEqual(checkParentChain(store, EUID), { ok: true },
      "sticky + owned by the effective uid is the accepted case");
    chmodSync(mid, 0o777); // same permissions, sticky removed
    assert.deepStrictEqual(checkParentChain(store, EUID),
      { ok: false, problem: "unsafe-parent-posix" },
      "the negative twin: identical bits without sticky must refuse");
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("an ancestor owned by another account is refused, and root is accepted", () => {
  if (!POSIX) return skip("NOT RUN on win32");
  // Owned by another ordinary account cannot be built without a second uid, so the rule is
  // exercised through the predicate: the real chain contains root-owned components (/, /usr or
  // /private) and they are accepted, while a fabricated euid makes the SAME chain refuse because
  // the user-owned components are then owned by "somebody else".
  const base = lab();
  try {
    const store = storeUnder(base);
    assert.deepStrictEqual(checkParentChain(store, EUID), { ok: true },
      "root-owned upper components are trusted");
    const notMe = EUID + 1000;
    assert.deepStrictEqual(checkParentChain(store, notMe),
      { ok: false, problem: "unsafe-parent-posix" },
      "the same chain seen by a different uid is foreign-owned and must refuse");
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("both the literal and the resolved chain are inspected", () => {
  if (!POSIX) return skip("NOT RUN on win32");
  const base = lab();
  try {
    const real = path.join(base, "real");
    mkdirSync(real, { mode: 0o755 });
    const link = path.join(base, "link");
    symlinkSync(real, link);
    const store = path.join(link, ".secretloop");
    mkdirSync(path.join(store, "pending"), { recursive: true, mode: 0o700 });
    const targets = chainTargets(store);
    assert.ok(targets.includes(link), "the link itself must be inspected");
    // realpathSync on the fixture: on macOS the resolved chain lives under /private, so comparing
    // against the unresolved path would never match however correct the product is.
    const realResolved = require("fs").realpathSync(real) as string;
    assert.ok(targets.some((t) => t === realResolved),
      `the resolved target ${realResolved} must be inspected; got ${targets.join(", ")}`);
    assert.deepStrictEqual(checkParentChain(store, EUID), { ok: true });
    // Loosening the LINK'S TARGET must refuse, because that is what the kernel traverses.
    chmodSync(real, 0o777);
    assert.deepStrictEqual(checkParentChain(store, EUID),
      { ok: false, problem: "unsafe-parent-posix" },
      "a permissive target is reached through the resolved chain");
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("a symbolic link on the path must itself be owned by a trusted principal", () => {
  if (!POSIX) return skip("NOT RUN on win32");
  // Whoever owns a symbolic link can delete it and repoint it whenever they like, so an
  // untrusted owner here is continuous control of the path and not a snapshot risk. The only
  // way an untrusted link reaches an otherwise-accepted path is through the sticky exception,
  // because sticky restricts rename and delete but NOT create. Measured in a container: a second
  // ordinary account planted a link in a sticky root-owned directory, the walk returned ok, and
  // the same account then removed and repointed it.
  //
  // A second uid cannot be created here, so the predicate is driven the way the other ownership
  // case is: the same chain seen by a different euid makes this account's link "somebody else's".
  // To isolate the LINK, every other component must stay trusted under the fabricated euid, or
  // the refusal could come from any of them and the case would prove nothing. So the link lives
  // in the sticky, root-owned /private/tmp (or /tmp) and points at a root-owned directory: under
  // a different euid the link is then the ONLY untrusted component on the whole chain.
  const sticky = existsSync("/private/tmp") ? "/private/tmp" : "/tmp";
  const target = existsSync("/usr/share") ? "/usr/share" : "/usr";
  const link = path.join(sticky, `sl-linkown-${process.pid}-${Date.now()}`);
  try {
    symlinkSync(target, link);
    const store = path.join(link, ".secretloop");
    const targets = chainTargets(store);
    assert.ok(targets.includes(link), "the link must be one of the components");

    const other = EUID + 1000;
    const untrusted = targets.filter((c) => {
      if (c === path.resolve(store)) return false;
      try {
        const st = lstatSync(c);
        return st.uid !== other && st.uid !== 0;
      } catch {
        return false;
      }
    });
    assert.deepStrictEqual(untrusted, [link],
      `only the link may be untrusted under the fabricated euid; got ${untrusted.join(", ")}`);

    assert.deepStrictEqual(checkParentChain(store, EUID), { ok: true },
      "control: a link this account owns, on an otherwise root-owned chain, is fine");
    assert.deepStrictEqual(checkParentChain(store, other),
      { ok: false, problem: "unsafe-parent-posix" },
      "a link owned by somebody else must refuse, not be skipped past");
  } finally {
    rmSync(link, { force: true });
  }
});

test("the store itself is judged by its own rules, not as an ancestor", () => {
  if (!POSIX) return skip("NOT RUN on win32");
  // Both spellings of the store must be out of the walk. Before that was fixed, the resolved
  // twin of the store stayed in the chain and an ACE on the STORE was reported as an unsafe
  // ANCESTOR — the wrong object and the wrong guidance.
  const base = lab();
  try {
    const store = storeUnder(base);
    const targets = chainTargets(store);
    assert.ok(!targets.includes(path.resolve(store)) ||
      checkParentChain(store, EUID).ok, "the store must not make its own chain fail");
    chmodSync(store, 0o777);
    assert.deepStrictEqual(checkParentChain(store, EUID), { ok: true },
      "a permissive STORE is the store rule's business, not the ancestor rule's");
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("the walk is bounded and does not follow an unbounded path", () => {
  if (!POSIX) return skip("NOT RUN on win32");
  const base = lab();
  try {
    let deep = base;
    for (let i = 0; i < 40; i++) {
      deep = path.join(deep, "d");
      mkdirSync(deep, { mode: 0o755 });
    }
    const store = path.join(deep, ".secretloop");
    mkdirSync(path.join(store, "pending"), { recursive: true, mode: 0o700 });
    const targets = chainTargets(store);
    // The cap counts COMPONENTS INSPECTED, not levels of nesting. With a symbolic link anywhere
    // on the path both the literal and the resolved chain are inspected, so the effective depth
    // is about half — measured at 64 levels with no link and 32 with one. The documentation used
    // to say "64 directories deep", which was only true of the no-link case; on macOS every temp
    // path goes through /var and so always has one.
    const resolvedDiffers = require("fs").realpathSync(deep) !== deep;
    assert.ok(targets.length >= 40, `the fixture should be deep; got ${targets.length}`);
    if (resolvedDiffers) {
      assert.ok(targets.length > 40,
        "with a link on the path both chains are counted, so components exceed the nesting depth");
    }
    const verdict = checkParentChain(store, EUID);
    if (targets.length > MAX_CHAIN_COMPONENTS) {
      assert.deepStrictEqual(verdict, { ok: false, problem: "parent-unreadable" },
        "past the cap the answer is a refusal, not an open-ended walk");
    } else {
      assert.ok(verdict.ok, "inside the cap it is simply checked");
    }
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("a refused chain is refused BEFORE the store is created, and leaves nothing behind", () => {
  if (!POSIX) return skip("NOT RUN on win32");
  const base = lab();
  try {
    const mid = path.join(base, "mid");
    mkdirSync(mid, { mode: 0o755 });
    // chmod, not mkdir's mode: the umask clips the creation mode, so a fixture built with
    // mkdir(0o777) is really 0o755 and would not have been permissive at all.
    chmodSync(mid, 0o777); // world-writable, not sticky
    const store = path.join(mid, ".secretloop");
    consent.setConsentRootForTests(store);
    assert.strictEqual(refusal(() => consent.writeRecord(record("a".repeat(32)))),
      "unsafe-parent-posix");
    assert.ok(!existsSync(store), "no store may be created under a refused chain");
    assert.deepStrictEqual(readdirSync(mid), [], "and nothing at all is left behind");
  } finally {
    consent.setConsentRootForTests(undefined);
    rmSync(base, { recursive: true, force: true });
  }
});

test("an unsafe ancestor refuses every consent operation, not only creation", () => {
  if (!POSIX) return skip("NOT RUN on win32");
  const base = lab();
  try {
    const mid = path.join(base, "mid");
    mkdirSync(mid, { mode: 0o755 });
    const store = storeUnder(mid);
    consent.setConsentRootForTests(store);
    consent.writeRecord(record("a".repeat(32)));
    assert.ok(consent.readRecord("a".repeat(32)), "control: it works before the bit is set");
    chmodSync(mid, 0o777);
    for (const [name, fn] of [
      ["readRecord", () => consent.readRecord("a".repeat(32))],
      ["listRecords", () => consent.listRecords()],
      ["writeRecord", () => consent.writeRecord(record("b".repeat(32)))],
      ["consumeRecord", () => consent.consumeRecord("a".repeat(32))],
    ] as Array<[string, () => unknown]>) {
      assert.strictEqual(refusal(fn), "unsafe-parent-posix", name);
    }
  } finally {
    consent.setConsentRootForTests(undefined);
    rmSync(base, { recursive: true, force: true });
  }
});

test("the refusal sentences are fixed and name no path", () => {
  for (const code of ["unsafe-parent-posix", "parent-unreadable"] as consent.ConsentStoreProblem[]) {
    const sentence = new consent.ConsentStoreError(code).message;
    assert.match(sentence, /cannot be trusted/, code);
    assert.doesNotMatch(sentence, /\/tmp|\/Users|\/private|[0-9a-f]{32}/, `${code} echoed a path`);
    assert.doesNotMatch(sentence, /ENOENT|EACCES|EPERM|errno/, `${code} echoed an OS message`);
    const guidance = consent.consentStoreGuidance(code);
    assert.match(guidance, /owned by you or by root/, guidance);
    assert.doesNotMatch(guidance, /chmod -R|recursive/i, "no recursive repair may be suggested");
  }
});

test("macOS: an ancestor carrying an extended ACE is refused as an unsafe parent", () => {
  if (!MAC) return skip("NOT RUN: macOS extended ACLs are the only ones the mode cannot show");
  const base = lab();
  try {
    const mid = path.join(base, "mid");
    mkdirSync(mid, { mode: 0o755 });
    const store = storeUnder(mid);
    consent.setConsentRootForTests(store);
    assert.ok(consent.listRecords().length === 0, "control: a clean chain is accepted");
    execFileSync("/bin/chmod", ["+a", "everyone allow read", mid], { timeout: 10_000 });
    assert.strictEqual(refusal(() => consent.listRecords()), "unsafe-parent-posix",
      "an ACE on an ANCESTOR is an unsafe parent, not the store's own extended-acl");
  } finally {
    consent.setConsentRootForTests(undefined);
    rmSync(base, { recursive: true, force: true });
  }
});

test("macOS: a stock home's default deny entry does NOT refuse the chain", () => {
  if (!MAC) return skip("NOT RUN: macOS extended ACLs only");
  // Every stock macOS home carries `0: group:everyone deny delete`, which Apple puts there. A
  // deny entry grants nobody anything. Requiring ancestors to carry NO entry refused every
  // unmodified Mac — a GitHub-hosted runner proved it by refusing its own /Users/runner during
  // the packaging smoke. Ancestors are therefore judged on `allow` entries only; the store keeps
  // the stricter rule because the product creates it.
  const macacl = require("../src/consent-acl-macos") as typeof import("../src/consent-acl-macos");
  const base = lab();
  try {
    const mid = path.join(base, "mid");
    mkdirSync(mid, { mode: 0o755 });
    execFileSync("/bin/chmod", ["+a", "everyone deny delete", mid], { timeout: 10_000 });
    const t = { parent: path.dirname(mid), basename: path.basename(mid) };
    assert.deepStrictEqual(macacl.inspectMacAcl(t, "any"),
      { ok: false, problem: "extended-acl" }, "the entry really is there");
    assert.deepStrictEqual(macacl.inspectMacAcl(t, "allow-only"),
      { ok: true }, "a deny-only entry must not refuse an ancestor");

    const store = storeUnder(mid);
    consent.setConsentRootForTests(store);
    assert.deepStrictEqual(consent.listRecords(), [],
      "a chain carrying only Apple's default entry must work");

    // The negative twin: an ALLOW entry on the same ancestor still refuses.
    execFileSync("/bin/chmod", ["+a", "everyone allow read", mid], { timeout: 10_000 });
    assert.strictEqual(refusal(() => consent.listRecords()), "unsafe-parent-posix",
      "an allow entry on an ancestor must still refuse");
  } finally {
    consent.setConsentRootForTests(undefined);
    // `everyone deny delete` does exactly what it says, including to this suite: without
    // stripping it first, removing the fixture fails with ENOTEMPTY. Only entries this case put
    // on its own disposable directory are removed.
    try {
      execFileSync("/bin/chmod", ["-N", path.join(base, "mid")], { timeout: 10_000 });
    } catch {
      /* already gone */
    }
    rmSync(base, { recursive: true, force: true });
  }
});

test("macOS: a broken inspector keeps its own reason instead of blaming the filesystem", () => {
  if (!MAC) return skip("NOT RUN: the inspector is only consulted on macOS");
  const macacl = require("../src/consent-acl-macos") as typeof import("../src/consent-acl-macos");
  const base = lab();
  try {
    const store = storeUnder(base);
    consent.setConsentRootForTests(store);
    macacl.setLsRunnerForTests(() => ({ ok: false, problem: "acl-tool-unavailable" }));
    assert.strictEqual(refusal(() => consent.listRecords()), "acl-tool-unavailable",
      "a tool that cannot run must not be reported as an unsafe ancestor");
  } finally {
    macacl.setLsRunnerForTests(undefined);
    consent.setConsentRootForTests(undefined);
    rmSync(base, { recursive: true, force: true });
  }
});

finish();
