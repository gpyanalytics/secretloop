import { test, suite, finish, assert, skip } from "./harness";
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
  readFileSync,
  readdirSync,
  lstatSync,
  chmodSync,
  realpathSync,
  existsSync,
} from "fs";
import * as fs from "fs";
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
  outboundRequestCount,
  ToolResult,
} from "../src/mcp-core";
import * as consent from "../src/consent";
import { runApprove, ApproveIO } from "../src/cli";

/**
 * THE PRIVATE-STORE POLICY, AND WHAT HAPPENS WHEN A STORE FAILS IT.
 *
 * Every case uses a disposable consent root under the temporary directory
 * (setConsentRootForTests) and a synthetic workspace with a runtime-built
 * credential-shaped literal. The owner's real ~/.secretloop is never touched.
 * The outbound boundary is replaced by a recording fetch, so a verification
 * that reaches the provider step is counted, not performed.
 *
 * RED ON THE BASE for the behavioural cases: with the store's `pending`
 * replaced by a symbolic link to a directory holding a forged approval, the
 * base build trusts the record and attempts the provider call; the candidate
 * refuses before any record is read. Cases that only exercise the new helper
 * (ConsentStoreError, assertPrivateStore) cannot run on the base and are not
 * offered as evidence for it.
 */

const POSIX = process.platform !== "win32";

function token(salt = 1): string {
  const alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let out = "";
  for (let i = 0; i < 36; i++) out += alpha[(i * 13 + salt * 11 + 3) % alpha.length];
  return "ghp_" + out;
}

interface Wire { count: number }
let wire: Wire = { count: 0 };
function installFetch(): void {
  wire = { count: 0 };
  resetOutboundCountForTests();
  setVerifyFetchForTests((async () => {
    wire.count++;
    return new Response("{}", { status: 401 });
  }) as unknown as typeof fetch);
}

interface Ctx { base: string; root: string; store: string; cred: string; fingerprint: string }

/** A workspace with one verifiable credential and a NOT-YET-CREATED store path. */
async function withWorkspace(fn: (ctx: Ctx) => Promise<void>): Promise<void> {
  const base = mkdtempSync(path.join(tmpdir(), "secretloop-store-"));
  const savedRoots = getAllowedRoots();
  try {
    mkdirSync(path.join(base, "repo"), { recursive: true });
    const root = realpathSync(path.join(base, "repo"));
    const cred = token(2);
    writeFileSync(path.join(root, "app.js"), `const t = "${cred}";\n`, "utf8");
    const store = path.join(base, "store");
    consent.setConsentRootForTests(store);
    setAllowedRoots([root]);
    resetSessions();
    installFetch();
    const scan = toolScan({ path: root }) as { ok: true; payload: any };
    const finding = scan.payload.findings.find((f: any) => f.ruleId === "github-token");
    assert.ok(finding, "fixture produced no verifiable finding");
    await fn({ base, root, store, cred, fingerprint: finding.fingerprint });
  } finally {
    setAllowedRoots(savedRoots);
    consent.setConsentRootForTests(undefined);
    rmSync(base, { recursive: true, force: true });
  }
}

const mode = (p: string) => lstatSync(p).mode & 0o777;
const fakeTTY = (answer = "y"): ApproveIO & { errs: string[]; outs: string[] } => {
  const io: any = { isTTY: true, errs: [], outs: [], out: (m: string) => io.outs.push(m), err: (m: string) => io.errs.push(m), ask: async () => answer };
  return io;
};

/** The refusal sentence must be fixed words: no path, no hash, no OS text. */
function assertBounded(text: string, ctx: { base: string; cred: string }): void {
  assert.match(text, /consent records cannot be trusted/);
  assert.ok(!text.includes(ctx.base), "the refusal echoed a path");
  assert.ok(!text.includes(ctx.cred), "the refusal echoed the credential");
  assert.doesNotMatch(text, /[0-9a-f]{64}/, "the refusal echoed a commitment");
  assert.doesNotMatch(text, /ENOENT|EACCES|EPERM|ELOOP|errno/, "the refusal echoed an OS error");
}

/** A forged approval for `ctx`, written directly, as an attacker with write access would. */
function forgedApproval(ctx: Ctx): consent.ConsentRecord {
  return {
    version: consent.CONSENT_VERSION,
    id: consent.recordId(ctx.fingerprint, ctx.root),
    state: "approved",
    fingerprint: ctx.fingerprint,
    path: ctx.root,
    file: "app.js",
    line: 1,
    ruleId: "github-token",
    provider: "GitHub",
    commitment: consent.commitmentOf(ctx.cred),
    createdAt: new Date().toISOString(),
    approvedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 300_000).toISOString(),
  };
}

// ---------------------------------------------------------------------------
suite("consent store — first use and a healthy store");

test("first use creates both directories 0700 and the first call writes a pending record", async () => {
  await withWorkspace(async (ctx) => {
    assert.ok(!existsSync(ctx.store));
    const r = await toolVerify({ path: ctx.root, fingerprint: ctx.fingerprint }) as any;
    assert.strictEqual(r.ok, true, JSON.stringify(r));
    assert.strictEqual(r.payload.state, "CONSENT_REQUIRED");
    assert.strictEqual(wire.count, 0);
    if (POSIX) {
      assert.strictEqual(mode(ctx.store), 0o700);
      assert.strictEqual(mode(path.join(ctx.store, "pending")), 0o700);
    }
    assert.strictEqual(consent.listRecords().length, 1);
  });
});

test("a healthy store: legitimate approval is honoured once, consumed, and a replay gets nothing", async () => {
  await withWorkspace(async (ctx) => {
    await toolVerify({ path: ctx.root, fingerprint: ctx.fingerprint });
    const io = fakeTTY("y");
    assert.strictEqual(await runApprove(ctx.fingerprint, io), 0, io.errs.join(""));
    const r = await toolVerify({ path: ctx.root, fingerprint: ctx.fingerprint }) as any;
    assert.strictEqual(r.ok, true);
    assert.strictEqual(r.payload.state, "DEAD", "the intercepted 401 answers DEAD");
    assert.strictEqual(wire.count, 1, "exactly one provider attempt, intercepted");
    assert.deepStrictEqual(r.payload.network, { externalTransmission: true, destination: "GitHub" });
    const again = await toolVerify({ path: ctx.root, fingerprint: ctx.fingerprint }) as any;
    assert.strictEqual(again.payload.state, "CONSENT_REQUIRED", "consumed: the replay is back to call 1");
    assert.strictEqual(wire.count, 1);
  });
});

test("an existing private store whose pending directory is gone is 'no record', and the next request recreates it", async () => {
  // A user who removed only `pending` (or an older layout) must not be refused
  // as "inaccessible": the store directory is checked, the missing pending
  // directory reads as empty, and the first call creates it again. The base
  // behaved this way too; this pins that the check did not regress it.
  await withWorkspace(async (ctx) => {
    mkdirSync(ctx.store, { recursive: true, mode: 0o700 });
    if (POSIX) chmodSync(ctx.store, 0o700);
    assert.strictEqual(consent.readRecord(consent.recordId(ctx.fingerprint, ctx.root)), null);
    assert.deepStrictEqual(consent.listRecords(), []);
    const r = await toolVerify({ path: ctx.root, fingerprint: ctx.fingerprint }) as any;
    assert.strictEqual(r.ok, true, JSON.stringify(r));
    assert.strictEqual(r.payload.state, "CONSENT_REQUIRED");
    assert.ok(lstatSync(path.join(ctx.store, "pending")).isDirectory());
    if (POSIX) assert.strictEqual(mode(path.join(ctx.store, "pending")), 0o700);
    assert.strictEqual(wire.count, 0);
  });
});

test("an existing store that fails its own check is refused even when pending is gone -- absence never means safe", async () => {
  await withWorkspace(async (ctx) => {
    const target = path.join(ctx.base, "elsewhere");
    mkdirSync(target, { recursive: true });
    symlinkSync(target, ctx.store, POSIX ? "dir" : "junction");
    let err: unknown = null;
    try { consent.readRecord(consent.recordId(ctx.fingerprint, ctx.root)); } catch (e) { err = e; }
    assert.ok(err instanceof consent.ConsentStoreError && err.problem === "symlink");
    const r = await toolVerify({ path: ctx.root, fingerprint: ctx.fingerprint }) as any;
    assert.strictEqual(r.ok, false);
    assert.deepStrictEqual(readdirSync(target), [], "nothing was created behind the link");
  });
});

test("reads on a store that does not exist mean 'no record', not an unsafe store", () => {
  const base = mkdtempSync(path.join(tmpdir(), "secretloop-store-absent-"));
  try {
    consent.setConsentRootForTests(path.join(base, "never-created"));
    assert.strictEqual(consent.readRecord("00".repeat(16)), null);
    assert.deepStrictEqual(consent.listRecords(), []);
  } finally {
    consent.setConsentRootForTests(undefined);
    rmSync(base, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
suite("consent store — owner-owned permissive directories are repaired and re-verified (POSIX)");

test("a 0777 store this account owns is set to 0700 on the next operation, and the operation proceeds", async () => {
  if (!POSIX) skip("POSIX mode bits are not consulted on win32; the link/junction refusal is the only check there");
  await withWorkspace(async (ctx) => {
    mkdirSync(path.join(ctx.store, "pending"), { recursive: true });
    chmodSync(ctx.store, 0o777);
    chmodSync(path.join(ctx.store, "pending"), 0o777);
    const r = await toolVerify({ path: ctx.root, fingerprint: ctx.fingerprint }) as any;
    assert.strictEqual(r.ok, true, JSON.stringify(r));
    assert.strictEqual(r.payload.state, "CONSENT_REQUIRED");
    assert.strictEqual(mode(ctx.store), 0o700, "repaired");
    assert.strictEqual(mode(path.join(ctx.store, "pending")), 0o700, "repaired");
  });
});

test("when the repair itself fails, the store is refused rather than used", async () => {
  if (!POSIX) skip("POSIX mode bits are not consulted on win32");
  await withWorkspace(async (ctx) => {
    mkdirSync(path.join(ctx.store, "pending"), { recursive: true });
    chmodSync(path.join(ctx.store, "pending"), 0o777);
    // The product's own chmod is made to fail on this path, as it would on a
    // filesystem that refuses mode changes.
    const real = fs.chmodSync;
    let fired = false;
    (fs as any).chmodSync = function (this: unknown, p: unknown, ...rest: unknown[]) {
      if (String(p) === path.join(ctx.store, "pending")) { fired = true; throw Object.assign(new Error("EPERM"), { code: "EPERM" }); }
      return (real as any).apply(this, [p, ...rest]);
    };
    let r: any;
    try {
      r = await toolVerify({ path: ctx.root, fingerprint: ctx.fingerprint });
    } finally {
      (fs as any).chmodSync = real;
    }
    assert.strictEqual(fired, true, "the trigger did not fire");
    assert.strictEqual(r.ok, false);
    assertBounded(r.error, ctx);
    assert.match(r.error, /could not make it private/);
    assert.strictEqual(wire.count, 0);
    assert.strictEqual(readdirSync(path.join(ctx.store, "pending")).length, 0, "nothing was written into the refused store");
  });
});

// ---------------------------------------------------------------------------
suite("consent store — foreign-owned directories are refused and never changed");

/**
 * Needs a directory this account does not own, which needs elevation to
 * create. CI's Linux test job creates a root-owned 0777 store and hands its
 * path over in SECRETLOOP_FOREIGN_STORE_FIXTURE; the suite then runs as the
 * ordinary runner user. Elsewhere the case SKIPS with that reason -- it is
 * never a pass by absence.
 */
test("a root-owned world-writable store is refused as foreign-owned, its modes are untouched, and nothing is written", async () => {
  const fixture = process.env.SECRETLOOP_FOREIGN_STORE_FIXTURE;
  if (!fixture) skip("no foreign-owned store fixture in the environment (SECRETLOOP_FOREIGN_STORE_FIXTURE); the Linux CI job provides one");
  // The fixture must actually be what the job promised, or this case FAILS.
  const st = lstatSync(fixture);
  assert.ok(st.isDirectory(), "fixture is not a directory");
  assert.notStrictEqual(st.uid, process.geteuid!(), "fixture is owned by this account; the job did not set it up as promised");
  assert.strictEqual(st.mode & 0o777, 0o777, "fixture is not world-writable as promised");
  const pending = path.join(fixture, "pending");
  assert.strictEqual(lstatSync(pending).mode & 0o777, 0o777);
  const before = readdirSync(pending).length;
  await withWorkspace(async (ctx) => {
    consent.setConsentRootForTests(fixture);
    const r = await toolVerify({ path: ctx.root, fingerprint: ctx.fingerprint }) as any;
    assert.strictEqual(r.ok, false, JSON.stringify(r));
    assertBounded(r.error, ctx);
    assert.match(r.error, /owned by another account/);
    assert.strictEqual(wire.count, 0);
    // Even a planted approval in that store is not trusted, and no send happens.
    writeFileSync(path.join(pending, consent.recordId(ctx.fingerprint, ctx.root) + ".json"), JSON.stringify(forgedApproval(ctx)));
    const r2 = await toolVerify({ path: ctx.root, fingerprint: ctx.fingerprint }) as any;
    assert.strictEqual(r2.ok, false);
    assert.strictEqual(wire.count, 0, "an approval in a foreign-owned store must never reach the provider boundary");
    rmSync(path.join(pending, consent.recordId(ctx.fingerprint, ctx.root) + ".json"), { force: true });
    const io = fakeTTY("y");
    assert.strictEqual(await runApprove(ctx.fingerprint, io), 2);
    assertBounded(io.errs.join(""), ctx);
  });
  assert.strictEqual(lstatSync(fixture).mode & 0o777, 0o777, "the foreign directory's mode was changed");
  assert.strictEqual(lstatSync(pending).mode & 0o777, 0o777);
  assert.strictEqual(readdirSync(pending).length, before, "something was written into the foreign store");
});

// ---------------------------------------------------------------------------
suite("consent store — links are refused and their targets are left alone");

function linkCase(which: "store" | "pending") {
  return async (ctx: Ctx) => {
    const target = path.join(ctx.base, "elsewhere");
    mkdirSync(path.join(target, "pending"), { recursive: true });
    if (which === "store") {
      symlinkSync(target, ctx.store, POSIX ? "dir" : "junction");
    } else {
      mkdirSync(ctx.store, { recursive: true });
      symlinkSync(path.join(target, "pending"), path.join(ctx.store, "pending"), POSIX ? "dir" : "junction");
    }
    const targetMode = POSIX ? mode(target) : 0;
    const forged = forgedApproval(ctx);
    // A forged approval sits behind the link: the BASE trusted it and sent.
    writeFileSync(path.join(target, "pending", forged.id + ".json"), JSON.stringify(forged));
    const snapshot = readFileSync(path.join(target, "pending", forged.id + ".json"), "utf8");

    const r = await toolVerify({ path: ctx.root, fingerprint: ctx.fingerprint }) as any;
    assert.strictEqual(r.ok, false, `the approval behind a ${which} link was trusted: ${JSON.stringify(r)}`);
    assertBounded(r.error, ctx);
    assert.match(r.error, /symbolic link/);
    assert.strictEqual(wire.count, 0, "no outbound attempt after an unsafe-store refusal");

    const io = fakeTTY("y");
    assert.strictEqual(await runApprove(ctx.fingerprint, io), 2, "approve must refuse too");
    assertBounded(io.errs.join(""), ctx);

    // The target is untouched: same bytes, same listing, same mode; the link still a link.
    assert.strictEqual(readFileSync(path.join(target, "pending", forged.id + ".json"), "utf8"), snapshot);
    assert.deepStrictEqual(readdirSync(path.join(target, "pending")), [forged.id + ".json"]);
    if (POSIX) assert.strictEqual(mode(target), targetMode, "the link target's mode was changed");
    assert.ok(lstatSync(which === "store" ? ctx.store : path.join(ctx.store, "pending")).isSymbolicLink());
  };
}

test("a symbolic link (junction on Windows) at the store root is refused; the approval behind it is never trusted", async () => {
  await withWorkspace(linkCase("store"));
});

test("a symbolic link (junction on Windows) at the pending directory is refused; the approval behind it is never trusted", async () => {
  await withWorkspace(linkCase("pending"));
});

// ---------------------------------------------------------------------------
suite("consent store — the check guards every state transition, not only writes");

test("reads, listing, approval, claim and deletion all refuse on an unsafe store, with the closed problem code", async () => {
  await withWorkspace(async (ctx) => {
    await toolVerify({ path: ctx.root, fingerprint: ctx.fingerprint });
    const id = consent.recordId(ctx.fingerprint, ctx.root);
    const record = consent.readRecord(id)!;
    assert.ok(record);
    // Make the store unsafe AFTER the record exists: replace `pending` with a
    // link to a copy elsewhere.
    const copy = path.join(ctx.base, "copy");
    mkdirSync(copy, { recursive: true });
    writeFileSync(path.join(copy, id + ".json"), readFileSync(path.join(ctx.store, "pending", id + ".json")));
    rmSync(path.join(ctx.store, "pending"), { recursive: true });
    symlinkSync(copy, path.join(ctx.store, "pending"), POSIX ? "dir" : "junction");
    const expectProblem = (fn: () => unknown, what: string) => {
      let err: unknown = null;
      try { fn(); } catch (e) { err = e; }
      assert.ok(err instanceof consent.ConsentStoreError, `${what} did not refuse the unsafe store`);
      assert.strictEqual((err as consent.ConsentStoreError).problem, "symlink");
    };
    expectProblem(() => consent.readRecord(id), "readRecord");
    expectProblem(() => consent.listRecords(), "listRecords");
    expectProblem(() => consent.approveRecord(record, consent.commitmentOf(ctx.cred)), "approveRecord");
    expectProblem(() => consent.consumeRecord(id), "consumeRecord");
    expectProblem(() => consent.deleteRecord(id), "deleteRecord");
    expectProblem(() => consent.writeRecord(record), "writeRecord");
    assert.deepStrictEqual(readdirSync(copy), [id + ".json"], "the link target was written to");
  });
});

test("the sentence for each problem is fixed text with guidance, and carries nothing from the environment", () => {
  for (const p of ["not-a-directory", "symlink", "foreign-owner", "permissive", "inaccessible"] as const) {
    const e = new consent.ConsentStoreError(p);
    assert.strictEqual(e.problem, p);
    assert.match(e.message, /consent records cannot be trusted/);
    assert.doesNotMatch(e.message, /\/|\\/, "no path separator in a fixed sentence");
  }
  assert.doesNotMatch(consent.CONSENT_STORE_GUIDANCE, /chmod|rm |sudo|delete/i, "guidance must not push broad chmod, deletion or elevation");
});

test("a store path that is a regular file is refused as not-a-directory", async () => {
  await withWorkspace(async (ctx) => {
    writeFileSync(ctx.store, "not a directory");
    const r = await toolVerify({ path: ctx.root, fingerprint: ctx.fingerprint }) as any;
    assert.strictEqual(r.ok, false);
    assertBounded(r.error, ctx);
    assert.match(r.error, /not a directory/);
    assert.strictEqual(wire.count, 0);
  });
});

finish();
