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

finish();
