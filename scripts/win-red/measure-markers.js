#!/usr/bin/env node
"use strict";
// INDEPENDENT MARKER MEASUREMENT (B2). Runs the product's helper script -- shipped, and stripped of
// its marker lines -- once each on a fresh lab of three paths, exactly the paths the committed runtime
// test uses, and reports NUMBERS, BOOLEANS and FIXED STAGE NAMES only. It reuses the real artefacts:
// HELPER_SCRIPT_FOR_TESTS, HELPER_MARKER_PREFIX, HELPER_MARKER_STAGES and classifyHelperResult from
// src/consent-acl-win.ts, and parseHelperMarkers from tests/helper-markers.ts (loaded through
// ts-node/register/transpile-only, so a MUTATED src is what gets measured).
//
// DUPLICATED LOGIC, stated: the stripped-script construction (drop lines containing the prefix and
// the "$marked=$false" line) and the spawn invocation (-NoProfile -NonInteractive -EncodedCommand,
// paths on stdin CRLF-joined, 60 s timeout, 1 MiB buffer) mirror the committed test; they cannot be
// imported because the test keeps them inline. Per-stage duplicate attribution is computed here from
// the same regex shape the test-side parser uses.
//
// Output: one JSON line on stdout. On any failure: {"measured":false,"reason":"<fixed label>"} and
// exit 2. Nothing from the helper's stdout/stderr is ever included.
//
// usage: node -r ts-node/register/transpile-only measure-markers.js <copy-root>
const fs = require("fs"), os = require("os"), path = require("path"), { spawnSync } = require("child_process");
const root = process.argv[2];
function fail(reason) { process.stdout.write(JSON.stringify({ measured: false, reason }) + "\n"); process.exit(2); }
if (!root) fail("usage");
if (process.platform !== "win32") fail("not-win32");
let acl, parseHelperMarkers;
try {
  acl = require(path.join(root, "src", "consent-acl-win.ts"));
  ({ parseHelperMarkers } = require(path.join(root, "tests", "helper-markers.ts")));
} catch { fail("module-load-failed"); }
const shipped = acl.HELPER_SCRIPT_FOR_TESTS;
const stripped = shipped.split("\n").filter((l) => !l.includes(acl.HELPER_MARKER_PREFIX) && l !== "$marked=$false").join("\n");
if (shipped === stripped) fail("stripped-equals-shipped");
const exe = path.join(process.env.SystemRoot || "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
const lab = fs.mkdtempSync(path.join(os.tmpdir(), "secretloop-markers-measure-"));
let out;
try {
  fs.writeFileSync(path.join(lab, "f.txt"), "x", "utf8");
  const paths = [lab, path.join(lab, "f.txt"), path.join(lab, "absent")];
  const run = (src) => spawnSync(exe, ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(src, "utf16le").toString("base64")], {
    input: paths.join("\r\n") + "\r\n", encoding: "utf8", timeout: 60_000, maxBuffer: 1 << 20, windowsHide: true,
  });
  const a = run(stripped), b = run(shipped);
  if (a.error || b.error) fail("spawn-error");
  const markerLine = new RegExp("^" + acl.HELPER_MARKER_PREFIX + " (" + acl.HELPER_MARKER_STAGES.join("|") + ") (\\d{13})$");
  const stageCounts = (text) => {
    const counts = {};
    for (const raw of String(text || "").split(/\r?\n/)) { const m = markerLine.exec(raw.replace(/\r$/, "")); if (m) counts[m[1]] = (counts[m[1]] || 0) + 1; }
    return counts;
  };
  const m = parseHelperMarkers(b.stderr);
  const dup = Object.entries(stageCounts(b.stderr)).filter(([, n]) => n > 1).map(([s]) => s).sort();
  const stdoutMarkers = Object.values(stageCounts(b.stdout)).reduce((x, y) => x + y, 0);
  let parsedIdentical = null, parsedOk = null;
  try {
    const pa = acl.classifyHelperResult({ error: null, signal: a.signal, status: a.status, stdout: a.stdout }, paths);
    const pb = acl.classifyHelperResult({ error: null, signal: b.signal, status: b.status, stdout: b.stdout }, paths);
    parsedIdentical = JSON.stringify(pa) === JSON.stringify(pb);
    parsedOk = pa.ok === true;
  } catch { parsedIdentical = false; parsedOk = false; }
  out = {
    measured: true,
    statusStripped: a.status, statusShipped: b.status,
    stdoutIdentical: a.stdout === b.stdout,
    parsedIdentical, parsedOk,
    stderrMarkerLines: m.markerLines, stderrMalformed: m.malformed, stderrDuplicates: m.duplicates, stderrOtherLines: m.otherLines,
    duplicatedStages: dup,
    stdoutMarkerLines: stdoutMarkers,
    helperRuns: 2,
  };
} finally {
  try { fs.rmSync(lab, { recursive: true, force: true }); } catch { /* reported by the orchestrator's lab delta */ }
}
process.stdout.write(JSON.stringify(out) + "\n");
