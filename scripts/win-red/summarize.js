#!/usr/bin/env node
"use strict";
// Per-case VERDICT from five inputs, printing FIXED LABELS only (rev4).
//
//   node summarize.js <label> <expect> <raw-output-file> <test-exit-code> <measurement.json> <measure-exit-code> <cleanup.json> <predictions.json>
//     expect: BASELINE | W1 | W2 | W3
//     measurement.json: output of measure-markers.js (or {"measured":false,...} written by the orchestrator)
//     measure-exit-code (rev4): the measurement PROCESS's exit code; anything but 0 fails the case even if the JSON
//       says measured:true (a process that prints valid JSON and then exits nonzero is not a measurement)
//     cleanup.json (from Job Object accounting):
//       {"method":"job-accounting","verified":true|false,"labsDelta":N,"lingered":N,"survivors":N,"treeTerminated":bool,
//        "sampledMax":N,"sampleFailures":N,"reason":"..."}
//       lingered  = processes still inside the job(s) after the root process exited on its own (0 = tree ended with the root)
//       survivors = processes still inside the job(s) after every termination attempt (0 = proven empty by accounting)
//       sampledMax/sampleFailures are DIAGNOSTIC (CIM sampling) and never influence the verdict
//
// A case is GOOD only if ALL hold:
//   BASELINE: outcome "ok", test exit 0, measurement matches predictions.BASELINE, measure exit 0, cleanup proven clean.
//   W1-W3:    outcome "FAIL", test exit != 0, the first assertion message after FAIL is the INTENDED one,
//             measurement matches predictions.<W>, measure exit 0, cleanup proven clean.
//   cleanup proven clean = method "job-accounting" AND verified AND labsDelta 0 AND lingered 0 AND survivors 0 AND not treeTerminated.
// Anything else -- no outcome line, skip, exit 0 with a FAIL line, unknown/injected message, measurement failure, mismatch or
// nonzero measurement exit, cleanup by any other method (e.g. sampling), unverified cleanup, unknown counts, leftovers -- is
// NOT RED evidence and fails (exit 1). Output never contains raw test text: only outcome word, fixed labels, numbers, a known message.
const fs = require("fs");
const [label, expect, rawPath, exitCodeArg, measPath, measExitArg, cleanPath, predPath] = process.argv.slice(2);
if (!label || !expect || !rawPath || exitCodeArg === undefined || !measPath || measExitArg === undefined || !cleanPath || !predPath) { console.log("SUMMARIZE-ERROR: usage"); process.exit(2); }
const exitCode = Number(exitCodeArg), measExit = Number(measExitArg);
const TITLE = "the shipped script and the same script without markers produce byte-identical stdout; markers are four and monotonic";
const KNOWN = [
  "stripped script exit status", "shipped script exit status",
  "stdout is byte-identical with and without markers",
  "the product's parse of both outputs is identical", "the inspection succeeded on the lab paths",
  /^four markers \(\d+ malformed, \d+ other\)$/,
  "markers are monotonic", "markers lie within the parent's spawn window (50 ms clock slack)",
  /^marker stderr is small: \d+ B$/,
];
const INTENDED = { W1: /^stdout is byte-identical with and without markers$/, W2: /^four markers \(\d+ malformed, \d+ other\)$/, W3: /^four markers \(\d+ malformed, \d+ other\)$/ };
const readJson = (p) => { try { return JSON.parse(fs.readFileSync(p, "utf8")); } catch { return null; } };
const raw = (() => { try { return fs.readFileSync(rawPath, "utf8"); } catch { return null; } })();
const meas = readJson(measPath), clean = readJson(cleanPath), preds = readJson(predPath);
const problems = [];
// --- outcome of the isolated test
let outcome = "none", message = null;
if (raw === null) problems.push("NO-RAW-OUTPUT");
else {
  const lines = raw.split(/\r?\n/);
  const oi = lines.findIndex((l) => /^\s*(ok|FAIL|skip) - /.test(l) && l.includes(TITLE));
  if (oi < 0) problems.push("NO-TEST-OUTCOME");
  else {
    outcome = lines[oi].trim().split(" - ")[0].trim();
    if (outcome === "FAIL") {
      const next = (lines[oi + 1] || "").trim();
      const known = KNOWN.find((k) => (k instanceof RegExp ? k.test(next) : k === next));
      message = known ? next : "UNEXPECTED-ASSERTION";
    }
  }
}
if (!Number.isInteger(exitCode)) problems.push("EXIT-CODE-UNKNOWN");
if (expect === "BASELINE") {
  if (outcome !== "ok") problems.push("BASELINE-OUTCOME-" + outcome.toUpperCase());
  if (exitCode !== 0) problems.push("BASELINE-EXIT-" + exitCode);
} else if (/^W[123]$/.test(expect)) {
  if (outcome !== "FAIL") problems.push("OUTCOME-" + outcome.toUpperCase() + "-NOT-FAIL");
  if (outcome === "FAIL" && exitCode === 0) problems.push("FAIL-LINE-BUT-EXIT-0");
  if (exitCode === 0 && outcome !== "FAIL") problems.push("EXIT-0");
  if (outcome === "FAIL" && !(message && INTENDED[expect].test(message))) problems.push("NOT-AT-INTENDED-ASSERTION(" + (message || "no-message") + ")");
} else problems.push("UNKNOWN-EXPECT");
// --- independent measurement: process exit 0 AND measured:true AND exact prediction
const pred = preds && preds[expect];
if (!Number.isInteger(measExit)) problems.push("MEASUREMENT-EXIT-UNKNOWN");
else if (measExit !== 0) problems.push("MEASUREMENT-EXIT-" + measExit);
if (!pred) problems.push("NO-PREDICTION");
else if (!meas || meas.measured !== true) problems.push("MEASUREMENT-FAILED(" + String((meas && meas.reason) || "no-measurement").replace(/[^A-Za-z0-9-]/g, "") + ")");
else {
  for (const [k, v] of Object.entries(pred)) {
    const got = meas[k];
    if (JSON.stringify(got) !== JSON.stringify(v)) problems.push("MEASUREMENT-MISMATCH(" + k + ": expected " + JSON.stringify(v) + ", got " + JSON.stringify(got === undefined ? null : got) + ")");
  }
}
// --- cleanup: only Job Object accounting counts as proof; anything unknown or unclean FAILS
const isCount = (x) => Number.isInteger(x) && x >= 0;
let cleanText = "none";
if (!clean) problems.push("CLEANUP-UNVERIFIED(no-cleanup-json)");
else if (clean.method !== "job-accounting") { problems.push("CLEANUP-UNVERIFIED(method-" + String(clean.method || "missing").replace(/[^A-Za-z0-9-]/g, "") + "-is-not-proof)"); cleanText = "UNVERIFIED (not job accounting)"; }
else if (clean.verified !== true) { problems.push("CLEANUP-UNVERIFIED(" + String(clean.reason || "unspecified").replace(/[^A-Za-z0-9-]/g, "") + ")"); cleanText = "UNVERIFIED"; }
else {
  if (!isCount(clean.labsDelta)) problems.push("LABS-UNKNOWN"); else if (clean.labsDelta !== 0) problems.push("LABS-LEFT(" + clean.labsDelta + ")");
  if (!isCount(clean.lingered)) problems.push("LINGERED-UNKNOWN"); else if (clean.lingered !== 0) problems.push("LINGERING-DESCENDANTS(" + clean.lingered + ")");
  if (!isCount(clean.survivors)) problems.push("SURVIVORS-UNKNOWN"); else if (clean.survivors !== 0) problems.push("OWNED-SURVIVORS(" + clean.survivors + ")");
  if (clean.treeTerminated !== false) problems.push("TREE-TERMINATED");
  cleanText = `job-accounting labs ${isCount(clean.labsDelta) ? clean.labsDelta : "?"} lingered ${isCount(clean.lingered) ? clean.lingered : "?"} survivors ${isCount(clean.survivors) ? clean.survivors : "?"} terminated ${clean.treeTerminated === true}` +
    (isCount(clean.sampledMax) ? ` (diag sampledMax ${clean.sampledMax}, sampleFailures ${isCount(clean.sampleFailures) ? clean.sampleFailures : "?"})` : "");
}
const good = problems.length === 0;
const verdict = good ? (expect === "BASELINE" ? "BASELINE-GOOD" : expect + "-RED-AT-INTENDED-ASSERTION") : (expect === "BASELINE" ? "BASELINE-NOT-GOOD" : expect + "-NOT-RED");
const measSummary = meas && meas.measured ? `markers stderr ${meas.stderrMarkerLines}/${meas.stderrMalformed}/${meas.stderrDuplicates}/${meas.stderrOtherLines} dup=[${(meas.duplicatedStages || []).join(",")}] stdoutMarkers ${meas.stdoutMarkerLines} stdoutIdentical ${meas.stdoutIdentical} parsedIdentical ${meas.parsedIdentical} parsedOk ${meas.parsedOk}` : "measurement unavailable";
console.log(`${label}: ${verdict} | outcome ${outcome} | exit ${exitCodeArg} | measure exit ${measExitArg}${message ? " | assertion: " + message : ""} | ${measSummary} | cleanup ${cleanText}${problems.length ? " | problems: " + problems.join("; ") : ""}`);
process.exit(good ? 0 : 1);
