import { test, suite, finish, assert } from "./harness";
import * as budget from "../src/consent-budget";
import * as consent from "../src/consent";

/**
 * WHAT A BUDGET REFUSAL TELLS A USER.
 *
 * Every case here fails against the merged main, where all four exhaustion categories collapse
 * into one sentence that names a cause it never measured. The failure that prompted this was a
 * store holding ONE record, on a short path, refused because starting the Windows security
 * helper consumed most of the allowance -- and told to go and tidy up .secretloop/pending.
 *
 * These assert wording, which is unusual, so the rule they follow is: assert what must NOT be
 * said, and assert that the categories differ. They do not pin exact prose.
 */
suite("consent refusal wording names the allowance that actually ran out");

const CATS: budget.BudgetCategory[] = ["time", "records", "inspections", "output"];
const msg = (c?: budget.BudgetCategory) => consent.describeStoreProblem("operation-too-large", c);
const adv = (c?: budget.BudgetCategory) => consent.consentStoreGuidance("operation-too-large", c);

test("a deadline refusal does not blame pending-record count or path depth", () => {
  const both = (msg("time") + " " + adv("time")).toLowerCase();
  assert.ok(!both.includes("pending"), `deadline text still mentions pending: ${both}`);
  assert.ok(!both.includes("long way down"), "deadline text still blames path depth");
  assert.ok(!both.includes("about size"), "deadline text still calls elapsed time a size problem");
  assert.match(both, /time/, "deadline text does not mention time at all");
});

test("the entry-count refusal still points at pending, because there it is right", () => {
  assert.match(adv("records"), /\.secretloop\/pending/);
  assert.match(msg("records").toLowerCase(), /pending requests/);
});

test("each category produces its own message and its own guidance", () => {
  const m = CATS.map(msg), g = CATS.map(adv);
  assert.strictEqual(new Set(m).size, 4, "two categories share a message");
  assert.strictEqual(new Set(g).size, 4, "two categories share a guidance line");
});

test("no refusal claims 'nothing was changed', which ensureDir can make false", () => {
  for (const c of [...CATS, undefined]) {
    assert.ok(!msg(c).toLowerCase().includes("nothing was changed"),
      `category ${c} still claims nothing was changed`);
    // what IS guaranteed: the record write is a temp file and a rename with no budgeted work
    // after it, so no allowance can run out between writing a record and returning.
    assert.match(msg(c), /no consent record was written/);
  }
});

test("the wording interpolates no count, path, byte total or elapsed time", () => {
  for (const c of [...CATS, undefined]) {
    const both = msg(c) + " " + adv(c);
    assert.ok(!/\d{3,}/.test(both), `category ${c} interpolated a number: ${both}`);
    assert.ok(!both.includes("\\"), `category ${c} leaked a Windows path`);
  }
});

test("an unknown category names no cause rather than guessing one", () => {
  const both = (msg(undefined) + " " + adv(undefined)).toLowerCase();
  assert.ok(!both.includes("usual cause"), "the fallback still asserts a usual cause");
  assert.ok(!both.includes("long way down"), "the fallback still blames path depth");
});

test("the category survives the mapping from the budget to the store error", () => {
  // The whole point: one line in consent.ts used to drop it.
  for (const c of CATS) {
    let seen: consent.ConsentStoreError | undefined;
    try {
      consent.assertPrivateStore.call(null);
    } catch { /* not the path under test */ }
    const e = new consent.ConsentStoreError("operation-too-large", c);
    seen = e;
    assert.strictEqual(seen.category, c);
    assert.strictEqual(seen.message, msg(c), "the error's message ignores its category");
  }
});

test("a non-budget problem carries no category and is unaffected", () => {
  const e = new consent.ConsentStoreError("unsafe-parent-posix");
  assert.strictEqual(e.category, undefined);
  assert.strictEqual(e.message, consent.describeStoreProblem("unsafe-parent-posix"));
});

// ---------------------------------------------------------------------------------------------
// what the refusal does and does not promise about side effects
// ---------------------------------------------------------------------------------------------

/**
 * Found in review: an earlier draft of the fallback ended "and if it keeps happening look at what
 * is in .secretloop/pending". That is the same wrong steer in a quieter voice -- when the category
 * is unknown, pending is one possibility out of four.
 */
test("an unknown category points at no directory either, not even as a hedge", () => {
  const both = msg(undefined) + " " + adv(undefined);
  assert.ok(!/pending/i.test(both), `the fallback still steers at pending: ${both}`);
  assert.ok(!/long way down/i.test(both), "the fallback still blames path depth");
});

/**
 * The refusal makes exactly ONE side-effect promise, and it is the one the code can keep. These
 * four are different claims and only the second is asserted:
 *   no provider transmission  -- the CALLER says this, and only where its trace supports it
 *   no new record written     -- ASSERTED, and true on every path
 *   no existing record updated-- follows from the same ordering
 *   no filesystem mutation    -- NOT asserted, because ensureDir can create directories
 */
test("the refusal promises no record write, and does NOT promise an untouched filesystem", () => {
  for (const c of [...CATS, undefined]) {
    const m = msg(c);
    assert.match(m, /no consent record was written/);
    // the three things it must NOT claim
    assert.ok(!/nothing was changed/i.test(m), `category ${c} claims nothing was changed`);
    assert.ok(!/nothing was created/i.test(m), `category ${c} claims nothing was created`);
    assert.ok(!/no directory/i.test(m), `category ${c} makes a directory promise it cannot keep`);
  }
});

/**
 * The record write is the LAST mutation in every operation, with no budgeted work after it, which
 * is what makes "no consent record was written" true rather than hopeful. This asserts the
 * property at source level -- it reads the shipped file -- because the alternative is driving six
 * operations to their mutation point and forcing a refusal one statement later, which no seam
 * currently allows. Labelled so it is not mistaken for a behavioural test.
 */
test("SOURCE-LEVEL: no budgeted call follows the mutation in any operation", () => {
  const src = require("fs").readFileSync(require("path").join(__dirname, "..", "src", "consent.ts"), "utf8");
  const budgeted = /\b(spendHelperCall|spendHelperBytes|spendDirEntry|checkBudgetDeadline|remainingMs|remainingBytes|assertStoreScope|ensureDir)\s*\(/;
  for (const [fn, mutation] of [
    ["writeRecordInner", "renameSync"],
    ["consumeRecordInner", "renameSync"],
    ["deleteRecordInner", "rmSync"],
  ] as [string, string][]) {
    const start = src.indexOf(`function ${fn}`);
    assert.ok(start > 0, `${fn} not found`);
    const end = src.indexOf("\n}", start);
    const body = src.slice(start, end);
    const at = body.indexOf(mutation);
    assert.ok(at > 0, `${mutation} not found in ${fn}`);
    const after = body.slice(at);
    assert.ok(!budgeted.test(after),
      `${fn} performs budgeted work after ${mutation}; "no consent record was written" would no ` +
      `longer be guaranteed: ${after.slice(0, 120)}`);
  }
});

/**
 * Found in the pre-merge review. The `inspections` guidance named "a home directory an unusually
 * long way down the filesystem, or a store holding many records" as the likely causes. Both hold
 * on macOS and NEITHER holds on Windows, so it was the same defect this suite exists to catch,
 * one category further along.
 */
test("no category blames path depth, because that cause is not cross-platform", () => {
  for (const c of [...CATS, undefined]) {
    const both = (msg(c) + " " + adv(c)).toLowerCase();
    assert.ok(!both.includes("long way down"), `category ${c} blames path depth: ${both}`);
    assert.ok(!both.includes("far down"), `category ${c} blames path depth`);
  }
});

test("only the records category may blame record count, and only it may say to remove records", () => {
  // dirEntries is spent ONLY in readPendingEntries(), one per entry in .secretloop/pending, so
  // "many records" and "remove requests" are earned there and nowhere else. helperCalls is a
  // count of child processes, which record count raises on macOS and not on Windows.
  for (const c of CATS) {
    if (c === "records") continue;
    const both = msg(c) + " " + adv(c);
    assert.ok(!/many records/i.test(both), `category ${c} blames record count`);
    assert.ok(!/remove requests|remove records|delete/i.test(both),
      `category ${c} tells the user to remove something: ${both}`);
  }
  assert.match(adv("records"), /remove requests/);
});

/**
 * The wording above is only correct while Windows keeps batching. If checkWindowsStore ever
 * inspects paths one at a time, depth WOULD raise the helper-call count there and the guidance
 * would be worth revisiting -- so fail here rather than let the prose quietly go stale.
 */
test("SOURCE-LEVEL: Windows still batches the whole chain into one inspection call", () => {
  const src = require("fs").readFileSync(
    require("path").join(__dirname, "..", "src", "consent-acl-win.ts"), "utf8");
  assert.match(src, /inspectPaths\(\[\s*\.\.\.chain,\s*\.\.\.targetPaths\s*\]\)/,
    "checkWindowsStore no longer batches chain+targets in one call; revisit the inspections guidance");
  const calls = (src.match(/\bspendHelperCall\(\)/g) || []).length;
  assert.strictEqual(calls, 1, `expected exactly one spendHelperCall() site on Windows, found ${calls}`);
});

finish();
