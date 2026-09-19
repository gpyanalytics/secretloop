import { test, suite, finish, assert, skip } from "./harness";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync, readdirSync, chmodSync } from "fs";
import { spawnSync } from "child_process";
import { tmpdir } from "os";
import * as path from "path";
import * as consent from "../src/consent";
import * as budget from "../src/consent-budget";
import * as macacl from "../src/consent-acl-macos";
import {
  setAllowedRoots, getAllowedRoots, resetSessions, toolScan, toolVerify,
  setVerifyFetchForTests, resetOutboundCountForTests,
} from "../src/mcp-core";

/**
 * THE AGGREGATE WORK BUDGET.
 *
 * Every individual check was bounded and the SUM was not. Measured on macOS, one `/bin/ls` per
 * inspected object: `writeRecord` made 43 helper calls about 10 distinct objects because the
 * chain is re-walked, `approveRecord` made 60, and `listRecords` grew with the record count with
 * no ceiling. A per-subprocess timeout does not bound that.
 *
 * WHAT THESE CASES ESTABLISH, AND WHAT THEY DO NOT. The work limits are hard and the boundary
 * cases below are exact. The DEADLINE cases use a controlled clock and are SIMULATED: they show
 * the budget refuses when the clock says the time is gone, not that any real operation takes that
 * long. Native latency is measured separately and recorded. Nothing here claims a wall-clock
 * guarantee for a synchronous filesystem call on an unresponsive mount, because there is none.
 */

const MAC = process.platform === "darwin";
const POSIX = process.platform !== "win32";
const L = budget.LIMITS;
const ID = "a".repeat(32);

interface Fx { base: string; store: string; pending: string }
function fixture(): Fx {
  // /private/tmp, not os.tmpdir(): a shallow chain keeps the ancestor cost close to a real home.
  const base = POSIX ? mkdtempSync("/private/tmp/sl-bud-".replace("/private", existsSync("/private/tmp") ? "/private" : ""))
                     : mkdtempSync(path.join(tmpdir(), "sl-bud-"));
  const store = path.join(base, ".secretloop");
  const pending = path.join(store, "pending");
  mkdirSync(pending, { recursive: true, mode: 0o700 });
  consent.setConsentRootForTests(store);
  return { base, store, pending };
}
function done(f: Fx): void {
  consent.setConsentRootForTests(undefined);
  macacl.setLsRunnerForTests(undefined);
  budget.setClockForTests(undefined);
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
function problem(fn: () => unknown): string {
  try {
    fn();
    return "NOT REFUSED";
  } catch (err) {
    return err instanceof consent.ConsentStoreError ? err.problem : `threw ${(err as Error).name}`;
  }
}
/** Fill `pending` with n plain files, bypassing the product so the budget is not spent here. */
function fill(f: Fx, n: number): void {
  for (let i = readdirSync(f.pending).length; i < n; i++) {
    writeFileSync(path.join(f.pending, `${i.toString(16).padStart(32, "0")}.json`),
      JSON.stringify(record(i.toString(16).padStart(32, "0")), null, 2) + "\n", { mode: 0o600 });
  }
}

// ---------------------------------------------------------------------------
suite("consent operations — the aggregate work budget");

test("a legitimate store is unaffected: approve once, transmit once, refuse the replay", async () => {
  if (!POSIX) return skip("NOT RUN on win32: the budget covers the POSIX inspection work");
  const f = fixture();
  const savedRoots = getAllowedRoots();
  try {
    const repoDir = path.join(f.base, "repo");
    mkdirSync(repoDir, { recursive: true });
    const alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let value = "ghp_";
    for (let i = 0; i < 36; i++) value += alpha[(i * 13 + 7) % alpha.length];
    writeFileSync(path.join(repoDir, "app.js"), `const t = "${value}";\n`, "utf8");
    const root = require("fs").realpathSync(repoDir) as string;
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
    assert.strictEqual(wire, 0);
    const pending = consent.listRecords();
    assert.strictEqual(pending.length, 1);
    consent.approveRecord(pending[0], pending[0].commitment);
    await toolVerify({ path: root, fingerprint });
    assert.strictEqual(wire, 1, "exactly one outbound attempt");
    await toolVerify({ path: root, fingerprint });
    assert.strictEqual(wire, 1, "the replay must not transmit again");
  } finally {
    setVerifyFetchForTests(undefined as unknown as typeof fetch);
    setAllowedRoots(savedRoots);
    resetSessions();
    done(f);
  }
});

test("the directory-entry limit is exact, and one past it refuses", () => {
  if (!POSIX) return skip("NOT RUN on win32");
  const f = fixture();
  try {
    fill(f, L.dirEntries);
    assert.strictEqual(consent.listRecords().length, L.dirEntries,
      `exactly ${L.dirEntries} entries must still be listed`);
    fill(f, L.dirEntries + 1);
    assert.strictEqual(problem(() => consent.listRecords()), "operation-too-large",
      "one entry past the limit must refuse");
  } finally {
    done(f);
  }
});

test("enumeration itself is bounded, not filtered after loading the directory", () => {
  if (!POSIX) return skip("NOT RUN on win32");
  // A cap applied to an already-loaded listing would not bound the read. This asserts the read
  // STOPS: the budget records exactly the limit consumed, not the directory's real size.
  const f = fixture();
  try {
    fill(f, L.dirEntries * 4);
    let spentAtRefusal: number | undefined;
    try {
      budget.withBudget(() => {
        try {
          consent.listRecords();
        } finally {
          spentAtRefusal = budget.currentSpend()?.dirEntries;
        }
      });
    } catch {
      /* the refusal is asserted below */
    }
    assert.strictEqual(spentAtRefusal, L.dirEntries,
      `enumeration must stop at ${L.dirEntries}, not read all ${L.dirEntries * 4} entries`);
  } finally {
    done(f);
  }
});

test("an over-budget listing refuses and never returns a partial subset", () => {
  if (!POSIX) return skip("NOT RUN on win32");
  const f = fixture();
  try {
    fill(f, L.dirEntries + 50);
    let returned: unknown = "did not return";
    try {
      returned = consent.listRecords();
    } catch (err) {
      returned = err instanceof consent.ConsentStoreError ? err.problem : "other";
    }
    assert.strictEqual(returned, "operation-too-large",
      "a short array would be a complete-looking answer from a directory never fully read");
  } finally {
    done(f);
  }
});

test("a nested call joins the budget instead of restarting it", () => {
  if (!POSIX) return skip("NOT RUN on win32");
  const f = fixture();
  try {
    assert.strictEqual(budget.currentSpend(), undefined, "no budget outside an operation");
    let sawInner = 0;
    budget.withBudget(() => {
      consent.writeRecord(record(ID));
      const afterWrite = budget.currentSpend();
      assert.ok(afterWrite, "a budget must be active inside");
      consent.readRecord(ID);
      const afterRead = budget.currentSpend();
      assert.ok(afterRead, "still active");
      sawInner = afterRead.dirEntries + afterRead.helperCalls;
      assert.ok(afterRead.helperCalls >= afterWrite.helperCalls,
        "the count must carry across nested calls, not reset");
    });
    assert.strictEqual(budget.currentSpend(), undefined, "and it is released afterwards");
    assert.ok(sawInner >= 0);
  } finally {
    done(f);
  }
});

test("SIMULATED clock: the deadline refuses, and refuses across nested calls", () => {
  if (!POSIX) return skip("NOT RUN on win32");
  // Controlled clock, labelled as simulation: this shows the budget refuses when the clock says
  // the time is gone. It does NOT show that any real operation takes that long.
  const f = fixture();
  try {
    consent.writeRecord(record(ID));
    let t = 1_000_000;
    budget.setClockForTests(() => t);
    assert.strictEqual(problem(() => {
      budget.withBudget(() => {
        consent.readRecord(ID);       // inside the deadline
        t += L.deadlineMs + 1;        // the clock jumps past it
        consent.readRecord(ID);       // the nested call must now refuse
      });
    }), "operation-too-large");
  } finally {
    done(f);
  }
});

test("SIMULATED clock: a child is offered only the remaining time, never a fresh timeout", () => {
  let t = 5_000_000;
  budget.setClockForTests(() => t);
  try {
    assert.strictEqual(budget.remainingMs(5_000), 5_000, "outside an operation the cap applies");
    budget.withBudget(() => {
      assert.strictEqual(budget.remainingMs(60_000), L.deadlineMs,
        "a cap larger than the deadline is clamped to the deadline");
      t += L.deadlineMs - 100;
      assert.strictEqual(budget.remainingMs(5_000), 100,
        "late in the operation a child gets only what is left");
      t += 200;
      assert.throws(() => budget.remainingMs(5_000), /budget exhausted/,
        "and past the deadline no child is started at all");
    });
  } finally {
    budget.setClockForTests(undefined);
  }
});

test("SIMULATED helper: an oversized response is charged and the aggregate refuses", () => {
  if (!MAC) return skip("NOT RUN: the helper is only consulted on macOS");
  const f = fixture();
  try {
    consent.writeRecord(record(ID));
    // Each response is inside the per-response cap but the total is not.
    const big = "drwx------  2 501 20 64 Jan 1 00:00 ".padEnd(60_000, "x");
    macacl.setLsRunnerForTests(() => ({ ok: true, stdout: big }));
    assert.ok(["operation-too-large", "acl-unreadable"].includes(problem(() => consent.listRecords())),
      "an aggregate of oversized responses must refuse");
  } finally {
    done(f);
  }
});

test("SIMULATED helper: the inspection count is capped, and the cap stops work", () => {
  if (!MAC) return skip("NOT RUN: the helper is only consulted on macOS");
  const f = fixture();
  try {
    let calls = 0;
    macacl.setLsRunnerForTests((t) => {
      calls++;
      return { ok: true, stdout: "drwx------  2 501 20 64 Jan 1 00:00 " + t.basename + "\n" };
    });
    fill(f, 200);
    problem(() => consent.listRecords());
    assert.ok(calls <= L.helperCalls,
      `the helper must not be called more than ${L.helperCalls} times; it was called ${calls}`);
  } finally {
    done(f);
  }
});

test("a budget refusal before authorization transmits nothing and mints nothing", async () => {
  if (!POSIX) return skip("NOT RUN on win32");
  const f = fixture();
  const savedRoots = getAllowedRoots();
  try {
    const repoDir = path.join(f.base, "repo");
    mkdirSync(repoDir, { recursive: true });
    const alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let value = "ghp_";
    for (let i = 0; i < 36; i++) value += alpha[(i * 13 + 7) % alpha.length];
    writeFileSync(path.join(repoDir, "app.js"), `const t = "${value}";\n`, "utf8");
    const root = require("fs").realpathSync(repoDir) as string;
    // NOT the entry cap: `toolVerify` names one record and never enumerates `pending`, so a large
    // directory does no unbounded work there and is correctly not refused. The budget has to be
    // exhausted by something the verify path actually spends, so the clock is used.
    const before = readdirSync(f.pending).length;
    setAllowedRoots([root]);
    resetSessions();
    let wire = 0;
    resetOutboundCountForTests();
    setVerifyFetchForTests((async () => { wire++; return new Response("{}", { status: 401 }); }) as unknown as typeof fetch);

    const scan = toolScan({ path: root }) as { ok: true; payload: { findings: { ruleId: string; fingerprint: string }[] } };
    const finding = scan.payload.findings.find((x) => x.ruleId === "github-token");
    assert.ok(finding, "the fixture produced no verifiable finding");
    let t = 4_000_000;
    budget.setClockForTests(() => { const v = t; t += L.deadlineMs + 1; return v; });
    const out = (await toolVerify({ path: root, fingerprint: (finding as { fingerprint: string }).fingerprint })) as
      { ok: false; error: string } | { ok: true; payload: { state: string } };
    budget.setClockForTests(undefined);

    assert.strictEqual(wire, 0, "nothing may be transmitted");
    assert.strictEqual(readdirSync(f.pending).length, before, "and no record may be minted");
    if (!("payload" in out)) {
      assert.match(out.error, /more work than SecretLoop allows/, out.error);
      assert.ok(!/\/(Users|tmp|private)\//.test(out.error), "no path may be echoed");
    }
  } finally {
    setVerifyFetchForTests(undefined as unknown as typeof fetch);
    setAllowedRoots(savedRoots);
    resetSessions();
    done(f);
  }
});

test("exhaustion during creation leaves no store behind", () => {
  if (!POSIX) return skip("NOT RUN on win32");
  // Every unit of budgeted work in writeRecord happens BEFORE the temp file is written, and the
  // creation undo is the same bounded, non-recursive one. A refusal must therefore leave nothing.
  const f = fixture();
  try {
    const fresh = path.join(f.base, "fresh", ".secretloop");
    mkdirSync(path.dirname(fresh), { recursive: true, mode: 0o755 });
    consent.setConsentRootForTests(fresh);
    let t = 2_000_000;
    budget.setClockForTests(() => { const v = t; t += L.deadlineMs + 1; return v; });
    assert.strictEqual(problem(() => consent.writeRecord(record(ID))), "operation-too-large");
    budget.setClockForTests(undefined);
    assert.ok(!existsSync(path.join(fresh, "pending", `${ID}.json`)), "no record may be written");
    assert.ok(!existsSync(fresh), "and the store this call created must be removed again");
  } finally {
    done(f);
  }
});

test("a claim is never half-made, and never restored to make a timeout retryable", () => {
  if (!POSIX) return skip("NOT RUN on win32");
  const f = fixture();
  try {
    consent.writeRecord(record(ID));
    assert.ok(existsSync(path.join(f.pending, `${ID}.json`)), "the record is there to claim");
    // A genuine claim removes it, and a second claim fails: replay prevention is untouched.
    assert.strictEqual(consent.consumeRecord(ID), true, "the first claim succeeds");
    assert.ok(!existsSync(path.join(f.pending, `${ID}.json`)), "and the record is gone");
    assert.strictEqual(consent.consumeRecord(ID), false, "the replay is refused");
    // A budget refusal happens before the rename, so it can never leave a partly-claimed record.
    consent.writeRecord(record("b".repeat(32)));
    let t = 3_000_000;
    budget.setClockForTests(() => { const v = t; t += L.deadlineMs + 1; return v; });
    assert.strictEqual(problem(() => consent.consumeRecord("b".repeat(32))), "operation-too-large");
    budget.setClockForTests(undefined);
    assert.ok(existsSync(path.join(f.pending, "b".repeat(32) + ".json")),
      "the record is untouched: the refusal came before the claim, and nothing was restored");
    assert.strictEqual(readdirSync(f.pending).filter((e) => e.includes(".consumed.")).length, 0,
      "no half-claimed leftover");
  } finally {
    done(f);
  }
});

test("a budget error raised inside the helper is never relabelled as an ACL problem", () => {
  if (!MAC) return skip("NOT RUN: the helper is only consulted on macOS");
  // The allowance is read twice around one helper call: when charging the invocation, and again
  // by remainingMs INSIDE the try, as an argument. Expiring at that second read used to be caught
  // by the catch-all and returned as `acl-unreadable`, which handed the user ACL guidance for a
  // TIME problem. A stepped clock lands the expiry on each read in turn.
  const macacl2 = require("../src/consent-acl-macos") as typeof import("../src/consent-acl-macos");
  const f = fixture();
  try {
    const target = { parent: f.store, basename: "pending" };
    for (const expireAt of [2, 3]) {
      let n = 0;
      const t = 1_000_000;
      budget.setClockForTests(() => { n++; return n >= expireAt ? t + L.deadlineMs + 1 : t; });
      let threw: string | null = null;
      let verdict: unknown;
      try {
        budget.withBudget(() => { verdict = macacl2.inspectMacAcl(target); });
      } catch (err) {
        threw = (err as Error).name;
      }
      budget.setClockForTests(undefined);
      assert.strictEqual(threw, "BudgetExceededError",
        `expiring at clock read ${expireAt} must refuse on the budget, not return ${JSON.stringify(verdict)}`);
    }
  } finally {
    done(f);
  }
});

test("a child's output buffer is the smaller of its own cap and the remaining allowance", () => {
  if (!MAC) return skip("NOT RUN: the helper is only consulted on macOS");
  // A fixed per-call cap would let a child accept far more than the operation as a whole still
  // permits, and only refuse once the data had already been read.
  assert.strictEqual(budget.remainingBytes(64 * 1024), 64 * 1024,
    "outside an operation the call's own cap applies");
  budget.withBudget(() => {
    assert.strictEqual(budget.remainingBytes(L.helperBytes * 2), L.helperBytes,
      "a cap larger than the whole allowance is clamped to the allowance");
    budget.spendHelperBytes(L.helperBytes - 100);
    assert.strictEqual(budget.remainingBytes(64 * 1024), 100,
      "late in the operation a child may buffer only what is left");
    budget.spendHelperBytes(100);
    assert.throws(() => budget.remainingBytes(64 * 1024), /budget exhausted/,
      "and with none left no child is given a buffer at all");
  });

  // The behaviour above is the helper's; this asserts the CALL SITE actually uses it. It is a
  // source-level check and is labelled as one, because `setLsRunnerForTests` replaces the spawn
  // entirely and there is no seam through which a real child's maxBuffer can be observed.
  const macSrc = require("fs").readFileSync(
    path.join(__dirname, "..", "src", "consent-acl-macos.ts"), "utf8") as string;
  const maxBuffer = /maxBuffer:\s*(.+)$/m.exec(macSrc);
  assert.ok(maxBuffer, "the helper must set a maxBuffer at all");
  assert.match((maxBuffer as RegExpExecArray)[1], /remainingBytes/,
    `the child's buffer must be sized from the remaining allowance; it was ${(maxBuffer as RegExpExecArray)[1].trim()}`);
});

test("the enumeration boundary, stated exactly: 256 charged, 257 read", () => {
  if (!POSIX) return skip("NOT RUN on win32");
  // The overflow entry must be RETURNED before its charge can be refused, so the product reads
  // one more than it charges. Saying "only 256 entries were observed" would be wrong.
  const f = fixture();
  try {
    fill(f, 1024);
    const fsmod = require("fs") as typeof import("fs");
    const realOpendir = fsmod.opendirSync;
    let reads = 0, opened = 0, closed = 0;
    (fsmod as { opendirSync: unknown }).opendirSync = function (this: unknown, ...args: unknown[]) {
      const dir = (realOpendir as (...a: unknown[]) => import("fs").Dir).apply(this, args);
      opened++;
      const rs = dir.readSync.bind(dir), cs = dir.closeSync.bind(dir);
      dir.readSync = () => { reads++; return rs(); };
      dir.closeSync = () => { closed++; return cs(); };
      return dir;
    };
    let charged: number | undefined;
    try {
      budget.withBudget(() => {
        try { consent.listRecords(); } finally { charged = budget.currentSpend()?.dirEntries; }
      });
    } catch {
      /* the refusal is the point */
    }
    (fsmod as { opendirSync: unknown }).opendirSync = realOpendir;
    assert.strictEqual(charged, L.dirEntries, "exactly the limit is charged");
    assert.strictEqual(reads, L.dirEntries + 1,
      "and exactly one more entry is READ, because the overflow must be seen to be refused");
    assert.strictEqual(closed, opened, "the directory handle closes on the refusal path");
  } finally {
    done(f);
  }
});

test("every directory entry counts, not only names that look like records", () => {
  if (!POSIX) return skip("NOT RUN on win32");
  const f = fixture();
  try {
    fill(f, 10);
    writeFileSync(path.join(f.pending, "README.txt"), "x", { mode: 0o600 });
    writeFileSync(path.join(f.pending, "a".repeat(32) + ".json.tmp.999.abc"), "x", { mode: 0o600 });
    mkdirSync(path.join(f.pending, "a-subdirectory"), { mode: 0o700 });
    let charged: number | undefined;
    budget.withBudget(() => {
      consent.listRecords();
      charged = budget.currentSpend()?.dirEntries;
    });
    assert.strictEqual(charged, 13,
      "all 13 entries are charged: the cost being bounded is the enumeration, not the parsing");
  } finally {
    done(f);
  }
});

test("the refusal names size and time, and asks for no permission change", () => {
  const sentence = new consent.ConsentStoreError("operation-too-large").message;
  assert.match(sentence, /more work than SecretLoop allows/, sentence);
  assert.doesNotMatch(sentence, /\/tmp|\/Users|[0-9a-f]{32}/, "no path or record id");
  assert.doesNotMatch(sentence, /ENOENT|EACCES|errno/, "no OS message");
  const guidance = consent.consentStoreGuidance("operation-too-large");
  assert.match(guidance, /about size, not permissions/, guidance);
  assert.doesNotMatch(guidance, /chmod|0700|access-control|ACL/i,
    "an ACL repair must not be suggested for a size problem");
});

test("the PREVIOUS implementation does unbounded enumeration on the same directory", () => {
  if (!POSIX) return skip("NOT RUN on win32");
  // Shows the case is a real change and not a no-op, WITHOUT hanging this suite: a child process
  // with a hard timeout reads the same directory the old way and reports how many entries it
  // loaded before anything could object.
  const f = fixture();
  try {
    fill(f, L.dirEntries * 4);
    const child = `const fs=require("fs");` +
      `const n=fs.readdirSync(${JSON.stringify(f.pending)}).length;` +
      `process.stdout.write(String(n));`;
    const r = spawnSync(process.execPath, ["-e", child], { encoding: "utf8", timeout: 15_000 });
    assert.ok(!r.signal, "the probe must not have to be killed");
    const loaded = Number(r.stdout);
    assert.strictEqual(loaded, L.dirEntries * 4,
      "readdirSync loads every entry before any cap could apply -- that is what was unbounded");
    assert.ok(loaded > L.dirEntries,
      "and it is more than the budget now admits, so the new limit really binds");
  } finally {
    done(f);
  }
});

finish();
