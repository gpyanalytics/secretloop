import { test, suite, finish, assert, skip } from "./harness";
import {
  mkdtempSync, mkdirSync, writeFileSync, symlinkSync, chmodSync, rmSync,
  readFileSync, lstatSync, statSync, existsSync, readdirSync, appendFileSync,
} from "fs";
import { execFileSync, spawnSync } from "child_process";
import { tmpdir } from "os";
import * as path from "path";
import {
  setAllowedRoots, getAllowedRoots, resetSessions, toolScan, toolVerify,
  setVerifyFetchForTests, resetOutboundCountForTests,
} from "../src/mcp-core";
import * as consent from "../src/consent";

/**
 * THE RECORD FILE ITSELF, ON POSIX.
 *
 * The store's two directories have been checked since PR #90, and on Windows PR #91 checks every
 * record. On macOS and Linux the record was never looked at: it was opened by name and read. So a
 * symbolic link at a record path was followed, a record owned by another account was read, one left
 * world-writable was read, and — measured before this change — a named pipe at a record path made
 * the reader hang until it was killed.
 *
 * Each case below drives the real product functions against a disposable store. The owner's real
 * `~/.secretloop` is never touched, every record is synthetic, and the one case that reaches the
 * network boundary replaces it with a counting stub.
 *
 * What these cases do NOT establish, so that nothing here is read as more: the checks bind the
 * classification and the read to one descriptor, which is not the same as making the lifecycle
 * atomic; `O_NOFOLLOW` refuses a link at the record name and says nothing about the directories
 * above it; and mode bits are not a statement about extended ACLs on either platform.
 */

const POSIX = process.platform !== "win32";
const ID_OK = "a".repeat(32);

interface Fixture { base: string; store: string; pending: string }
function fixture(): Fixture {
  const base = mkdtempSync(path.join(tmpdir(), "secretloop-recfile-"));
  const store = path.join(base, "store");
  const pending = path.join(store, "pending");
  mkdirSync(pending, { recursive: true, mode: 0o700 });
  consent.setConsentRootForTests(store);
  return { base, store, pending };
}
function done(f: Fixture): void {
  consent.setConsentRootForTests(undefined);
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
function place(f: Fixture, id: string, mode = 0o600): string {
  const p = path.join(f.pending, `${id}.json`);
  writeFileSync(p, JSON.stringify(record(id), null, 2) + "\n", { mode });
  return p;
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
suite("consent record file — what a record must be");

test("a record this account wrote privately is read, and listed", () => {
  if (!POSIX) return skip("NOT RUN on win32: the Windows record checks are PR #91's and are tested there");
  const f = fixture();
  try {
    place(f, ID_OK);
    const read = consent.readRecord(ID_OK);
    assert.ok(read && read.id === ID_OK, "a healthy record must still be readable");
    assert.strictEqual(consent.listRecords().length, 1);
  } finally {
    done(f);
  }
});

test("a symbolic link at a record path is refused, and its target is left alone", () => {
  if (!POSIX) return skip("NOT RUN on win32: junctions at a record path are refused by the Windows checks");
  const f = fixture();
  try {
    const target = path.join(f.base, "outside.json");
    writeFileSync(target, JSON.stringify(record(ID_OK), null, 2) + "\n");
    const before = readFileSync(target);
    const link = path.join(f.pending, `${ID_OK}.json`);
    symlinkSync(target, link);
    assert.strictEqual(refusal(() => consent.readRecord(ID_OK)), "symlink");
    assert.strictEqual(refusal(() => consent.listRecords()), "symlink", "listing must refuse it too");
    assert.ok(lstatSync(link).isSymbolicLink(), "the link is not removed");
    assert.deepStrictEqual(readFileSync(target), before, "the target is not read, written or removed");
  } finally {
    done(f);
  }
});

test("a record left readable by others is refused, and its mode is not quietly repaired", () => {
  if (!POSIX) return skip("NOT RUN on win32: POSIX mode bits carry no meaning there");
  const f = fixture();
  try {
    const p = place(f, ID_OK);
    chmodSync(p, 0o666);
    assert.strictEqual(refusal(() => consent.readRecord(ID_OK)), "record-permissive");
    assert.strictEqual(statSync(p).mode & 0o777, 0o666, "an unsafe record is refused, never repaired");
    // The reason must describe a RECORD. The directory sentence claims a repair to 0700 was
    // attempted, which is true of a directory and false of a file nothing repairs.
    const said = new consent.ConsentStoreError("record-permissive").message;
    assert.match(said, /a consent record in/);
    assert.doesNotMatch(said, /0700|could not make it private/, "a record is not repaired, and 0700 is a directory's mode");
  } finally {
    done(f);
  }
});

test("a directory standing in for a record is refused", () => {
  if (!POSIX) return skip("NOT RUN on win32: the Windows checks refuse an object of the wrong kind");
  const f = fixture();
  try {
    mkdirSync(path.join(f.pending, `${ID_OK}.json`));
    assert.strictEqual(refusal(() => consent.readRecord(ID_OK)), "not-a-regular-file");
  } finally {
    done(f);
  }
});

test("a file far larger than any record is refused before it is read", () => {
  if (!POSIX) return skip("NOT RUN on win32: covered by the Windows checks and the same bound");
  const f = fixture();
  try {
    writeFileSync(path.join(f.pending, `${ID_OK}.json`), Buffer.alloc(80 * 1024, 0x20), { mode: 0o600 });
    assert.strictEqual(refusal(() => consent.readRecord(ID_OK)), "oversized-record");
  } finally {
    done(f);
  }
});

test("a dangling link at a record path is refused, and both readers say the same thing", () => {
  if (!POSIX) return skip("NOT RUN on win32: exercised there by the reparse-point rules of PR #91");
  const f = fixture();
  try {
    // A link whose target does not exist. `existsSync` follows it and reports absent, so before
    // this the single-record reader answered "no record" while the enumerating reader refused the
    // very same object as a link. A reader that disagrees with its sibling about what is there is
    // the bug, whichever answer is nicer.
    const missingTarget = path.join(f.base, "no-such-target.json");
    const link = path.join(f.pending, `${ID_OK}.json`);
    symlinkSync(missingTarget, link);
    assert.strictEqual(existsSync(link), false, "the fixture must really be dangling");
    assert.strictEqual(refusal(() => consent.readRecord(ID_OK)), "symlink");
    assert.strictEqual(refusal(() => consent.listRecords()), "symlink", "and the two readers agree");
    assert.ok(lstatSync(link).isSymbolicLink(), "the link is not removed by being refused");
    assert.strictEqual(existsSync(missingTarget), false, "and nothing is created through it");
  } finally {
    done(f);
  }
});

test("a record exactly at the size limit is read, and one byte past it is refused", () => {
  if (!POSIX) return skip("NOT RUN on win32: the same bound applies and is covered by the Windows rules");
  const f = fixture();
  const LIMIT = 64 * 1024;
  try {
    const p = path.join(f.pending, `${ID_OK}.json`);
    // Grown to the limit through a real field, so this is a record the writer could produce.
    const padded = record(ID_OK) as consent.ConsentRecord & { fingerprint: string };
    const bare = Buffer.byteLength(JSON.stringify(padded, null, 2) + "\n");
    padded.fingerprint = padded.fingerprint + "x".repeat(LIMIT - bare);
    writeFileSync(p, JSON.stringify(padded, null, 2) + "\n", { mode: 0o600 });
    assert.strictEqual(statSync(p).size, LIMIT, "the fixture must sit exactly on the limit");
    assert.ok(consent.readRecord(ID_OK), "a record exactly at the limit is read, not refused");

    writeFileSync(p, Buffer.concat([readFileSync(p), Buffer.from("x")]), { mode: 0o600 });
    assert.strictEqual(statSync(p).size, LIMIT + 1);
    assert.strictEqual(refusal(() => consent.readRecord(ID_OK)), "oversized-record", "one byte past it is refused");
  } finally {
    done(f);
  }
});

test("a record that grows past the limit after it was written is refused on the next read", () => {
  if (!POSIX) return skip("NOT RUN on win32: the same bound applies and is covered by the Windows rules");
  const f = fixture();
  try {
    const p = place(f, ID_OK);
    assert.ok(consent.readRecord(ID_OK), "it starts readable");
    appendFileSync(p, "x".repeat(64 * 1024));
    // The size is taken from the descriptor at read time, so growth since the write is seen.
    assert.strictEqual(refusal(() => consent.readRecord(ID_OK)), "oversized-record");
  } finally {
    done(f);
  }
});

test("the largest record the writer can produce is well inside the bound", () => {
  // A single typical record is evidence of typical size, not of the maximum. Bound every variable
  // field by what the platform allows instead: a path, a repo-relative file and a fingerprint that
  // embeds the file, each at PATH_MAX.
  const PATH_MAX = 4096;
  const worst = {
    version: consent.CONSENT_VERSION, id: "a".repeat(32), state: "approved" as const,
    fingerprint: "s".repeat(PATH_MAX) + ":generic-api-key-assignment:" + "0".repeat(16),
    path: "/" + "d".repeat(PATH_MAX - 1), file: "s".repeat(PATH_MAX), line: Number.MAX_SAFE_INTEGER,
    ruleId: "generic-api-key-assignment", provider: "DigitalOcean", commitment: "a".repeat(64),
    createdAt: new Date().toISOString(), approvedAt: new Date().toISOString(), expiresAt: new Date().toISOString(),
  };
  const bytes = Buffer.byteLength(JSON.stringify(worst, null, 2) + "\n");
  assert.ok(bytes < 64 * 1024, `a worst-case record is ${bytes} bytes, which the reader would refuse`);
});

test("a record that is not there is still simply absent", () => {
  const f = fixture();
  try {
    assert.strictEqual(consent.readRecord(ID_OK), null);
    assert.deepStrictEqual(consent.listRecords(), []);
  } finally {
    done(f);
  }
});

test("a named pipe at a record path is refused instead of hanging the reader", () => {
  if (!POSIX) return skip("NOT RUN on win32: a FIFO cannot exist at an NTFS path");
  const f = fixture();
  try {
    try {
      execFileSync("mkfifo", [path.join(f.pending, `${ID_OK}.json`)], { timeout: 10_000 });
    } catch {
      return skip("NOT RUN: mkfifo is unavailable in this environment");
    }
    // The risky call runs in a child the parent can kill, because before this change it never
    // returned. The parent owns the fixture and removes it below whatever the child does.
    const child =
      `const c=require(${JSON.stringify(path.join(process.cwd(), "out", "consent.js"))});` +
      `c.setConsentRootForTests(${JSON.stringify(f.store)});` +
      `try{const r=c.readRecord(${JSON.stringify(ID_OK)});process.stdout.write("returned:"+(r?"record":"null"));}` +
      `catch(e){process.stdout.write("refused:"+e.problem);}`;
    const result = spawnSync(process.execPath, ["-e", child], { encoding: "utf8", timeout: 15_000 });
    const killed = !!result.signal || (result.error as NodeJS.ErrnoException | undefined)?.code === "ETIMEDOUT";
    assert.ok(!killed, "the reader blocked on the pipe and had to be killed");
    assert.strictEqual((result.stdout || "").trim(), "refused:not-a-regular-file");
  } finally {
    done(f);
  }
});

test("a record owned by another account is refused", () => {
  if (!POSIX) return skip("NOT RUN on win32: ownership is checked by the Windows rules instead");
  const planted = process.env.SECRETLOOP_FOREIGN_RECORD_FIXTURE;
  if (!planted) {
    return skip(
      "NOT RUN: no root-owned record fixture in the environment (SECRETLOOP_FOREIGN_RECORD_FIXTURE); " +
        "the Linux CI job provides one, and creating it needs elevation this suite does not take"
    );
  }
  const pending = path.join(planted, "pending");
  const entries = readdirSync(pending).filter((e) => e.endsWith(".json"));
  assert.strictEqual(entries.length, 1, "the fixture must hold exactly one planted record");
  const id = entries[0].replace(/\.json$/, "");
  const before = statSync(path.join(pending, entries[0]));
  // Without this the case would prove nothing: the record must really belong to another account.
  assert.notStrictEqual(before.uid, process.geteuid?.(), "the fixture is not owned by another account");
  const saved = consent.setConsentRootForTests(planted);
  void saved;
  try {
    assert.strictEqual(refusal(() => consent.readRecord(id)), "foreign-owner");
    assert.strictEqual(refusal(() => consent.listRecords()), "foreign-owner");
    const after = statSync(path.join(pending, entries[0]));
    assert.strictEqual(after.uid, before.uid, "the fixture's owner is untouched");
    assert.strictEqual(after.mode & 0o777, before.mode & 0o777, "the fixture's mode is untouched");
  } finally {
    consent.setConsentRootForTests(undefined);
  }
});

test("a record this account owns but cannot open is refused as unreadable, not as another account's", () => {
  if (!POSIX) return skip("NOT RUN on win32: POSIX permission bits carry no meaning there");
  if (process.geteuid?.() === 0) return skip("NOT RUN as root: root can open a mode-000 file, so the case cannot arise");
  const f = fixture();
  try {
    const p = place(f, ID_OK);
    chmodSync(p, 0o000);
    // The open is denied, so the descriptor can say nothing about the object. The reason must
    // still be the true one: this account owns it, so it is unreadable rather than foreign.
    assert.strictEqual(refusal(() => consent.readRecord(ID_OK)), "inaccessible");
    chmodSync(p, 0o600);
  } finally {
    done(f);
  }
});

test("refusals do not leak descriptors", () => {
  if (!POSIX) return skip("NOT RUN on win32: the descriptor table is inspected through POSIX paths");
  const fdDir = process.platform === "linux" ? "/proc/self/fd" : "/dev/fd";
  if (!existsSync(fdDir)) return skip(`NOT RUN: ${fdDir} is not available to count descriptors`);
  const f = fixture();
  try {
    mkdirSync(path.join(f.pending, `${ID_OK}.json`)); // refused on every call, after the open
    const open = () => readdirSync(fdDir).length;
    for (let i = 0; i < 20; i++) refusal(() => consent.readRecord(ID_OK));
    const settled = open();
    for (let i = 0; i < 200; i++) refusal(() => consent.readRecord(ID_OK));
    assert.ok(open() <= settled + 2, `descriptors grew across 200 refusals: ${settled} then ${open()}`);
  } finally {
    done(f);
  }
});

// ---------------------------------------------------------------------------
suite("consent record file — the authorization path is unchanged");

test("the healthy flow still approves once, dispatches once and refuses the replay", async () => {
  if (!POSIX) return skip("NOT RUN on win32: the same flow is covered by the Windows suites");
  const base = mkdtempSync(path.join(tmpdir(), "secretloop-recflow-"));
  const savedRoots = getAllowedRoots();
  try {
    const repoDir = path.join(base, "repo");
    mkdirSync(repoDir, { recursive: true });
    const alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let value = "ghp_";
    for (let i = 0; i < 36; i++) value += alpha[(i * 13 + 7) % alpha.length];
    writeFileSync(path.join(repoDir, "app.js"), `const t = "${value}";\n`, "utf8");
    const root = require("fs").realpathSync(repoDir) as string;
    consent.setConsentRootForTests(path.join(base, "store"));
    setAllowedRoots([root]);
    resetSessions();
    let wire = 0;
    resetOutboundCountForTests();
    setVerifyFetchForTests((async () => {
      wire++;
      return new Response("{}", { status: 401 });
    }) as unknown as typeof fetch);

    const scan = toolScan({ path: root }) as { ok: true; payload: { findings: { ruleId: string; fingerprint: string }[] } };
    const finding = scan.payload.findings.find((x) => x.ruleId === "github-token");
    assert.ok(finding, "the fixture produced no verifiable finding");
    const fingerprint = (finding as { fingerprint: string }).fingerprint;

    const first = (await toolVerify({ path: root, fingerprint })) as { ok: true; payload: { state: string } };
    assert.strictEqual(first.payload.state, "CONSENT_REQUIRED");
    assert.strictEqual(wire, 0, "the first call transmits nothing");

    const id = consent.recordId(fingerprint, root);
    const pending = consent.readRecord(id);
    assert.ok(pending && pending.state === "pending", "the record this call wrote must be readable");
    consent.approveRecord(pending as consent.ConsentRecord, consent.commitmentOf(value));

    resetSessions();
    toolScan({ path: root });
    const second = (await toolVerify({ path: root, fingerprint })) as { ok: true; payload: { state: string } };
    assert.ok(["LIVE", "DEAD", "UNKNOWN"].includes(second.payload.state), "the approved call reaches the provider step");
    assert.strictEqual(wire, 1, "exactly one intercepted dispatch");
    assert.strictEqual(consent.readRecord(id), null, "the claim consumes the record");

    resetSessions();
    toolScan({ path: root });
    const replay = (await toolVerify({ path: root, fingerprint })) as { ok: true; payload: { state: string } };
    assert.strictEqual(replay.payload.state, "CONSENT_REQUIRED", "a replay asks for consent again");
    assert.strictEqual(wire, 1, "a replay transmits nothing");
  } finally {
    setAllowedRoots(savedRoots);
    consent.setConsentRootForTests(undefined);
    rmSync(base, { recursive: true, force: true });
  }
});

test("a store whose pending directory is gone is still 'no record', and the next write recreates it", () => {
  const f = fixture();
  try {
    place(f, ID_OK);
    rmSync(f.pending, { recursive: true, force: true });
    assert.strictEqual(consent.readRecord(ID_OK), null, "PR #90's behaviour is unchanged");
    assert.deepStrictEqual(consent.listRecords(), []);
    consent.writeRecord(record(ID_OK));
    assert.ok(existsSync(f.pending), "the next write recreates it");
    assert.ok(consent.readRecord(ID_OK), "and the record is readable again");
  } finally {
    done(f);
  }
});

test("every refusal sentence stays fixed, with no path, mode, record or OS text", () => {
  const codes: consent.ConsentStoreProblem[] = ["not-a-regular-file", "oversized-record", "record-permissive", "symlink", "foreign-owner", "permissive"];
  for (const code of codes) {
    const sentence = new consent.ConsentStoreError(code).message;
    assert.match(sentence, /cannot be trusted/, `${code} does not say what follows`);
    // A fixed mode constant in the guidance ("private (0700)") is prose, not an echo of the
    // object's own state, so it is allowed; a path, a record id or an OS error is not.
    assert.doesNotMatch(sentence, /\/tmp|\/Users|[0-9a-f]{32}/, `${code} echoed a path or a record id`);
    assert.doesNotMatch(sentence, /ENOENT|EACCES|EPERM|ELOOP|errno/, `${code} echoed an OS error`);
  }
});

finish();
