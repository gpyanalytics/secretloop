/*
 * DISPOSABLE diagnostic. Drives each exhaustion category against the module inside the PACKED
 * TARBALL, so the classification is established for the artifact the smoke actually runs, not
 * for the working tree. Always exits 0 and asserts nothing.
 *
 * Every exhaustion here is INJECTED and reproduces nothing.
 *
 * Usage: node packaged-budget-controls.js <path to package/out/consent-budget.js>
 */
"use strict";
const target = process.argv[2];
const budget = require(target);
const say = (s) => process.stderr.write("PCONTROL " + s + "\n");

function run(label, fn) {
  let outcome = "completed with no refusal";
  try {
    budget.withBudget(() => {
      fn();
      const s = budget.currentSpend();
      outcome = `no refusal; calls=${s.helperCalls} bytes=${s.helperBytes} entries=${s.dirEntries}`;
    });
  } catch (e) {
    outcome = `REFUSED ${e && e.name} what=${(e && e.what) || "-"}`;
  }
  say(`${label.padEnd(26)} -> ${outcome}`);
}

const L = budget.LIMITS;
say(`module under test: ${target}`);
say(`LIMITS helperCalls=${L.helperCalls} helperBytes=${L.helperBytes} dirEntries=${L.dirEntries} deadlineMs=${L.deadlineMs}`);

run("injected: deadline", () => {
  // withBudget already captured startedAt from the real Date.now, so the fake clock has to be
  // anchored to real time. A small absolute number makes the elapsed time negative instead.
  const past = Date.now() + L.deadlineMs + 1;
  budget.setClockForTests(() => past);
  try { budget.checkBudgetDeadline(); } finally { budget.setClockForTests(undefined); }
});
run("injected: entry count", () => { for (let i = 0; i <= L.dirEntries + 1; i++) budget.spendDirEntry(); });
run("injected: inspections", () => { for (let i = 0; i <= L.helperCalls + 1; i++) budget.spendHelperCall(); });
run("injected: output bytes", () => { budget.spendHelperBytes(L.helperBytes + 1); });
run("injected: none (healthy)", () => { budget.spendDirEntry(); budget.spendHelperCall(); budget.spendHelperBytes(16); });

// What a user is told, from the PACKAGED consent module, for every one of the four.
try {
  const consent = require(require("path").join(require("path").dirname(target), "consent.js"));
  say("");
  say("WHAT THE PACKAGED BUILD TELLS A USER, FOR ALL FOUR CATEGORIES:");
  say(`  one problem code for all four: operation-too-large   platform=${process.platform}`);
  say(`  message : ${consent.describeStoreProblem("operation-too-large")}`);
  say(`  guidance: ${consent.consentStoreGuidance("operation-too-large")}`);
} catch (e) {
  say(`could not read the packaged guidance: ${e && e.message}`);
}
