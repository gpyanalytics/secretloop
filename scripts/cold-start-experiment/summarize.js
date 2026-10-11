#!/usr/bin/env node
"use strict";
// summarize.js (rev4) -- turns one experiment job's local files into a SANITIZED summary (JSON + text).
// Only fixed labels, allowlisted process categories and bounded numbers are written. Nothing from the raw suite output is
// copied except numbers parsed from the test's own fixed-format first-call line and test titles that pass a strict
// character allowlist.
//
// usage: node summarize.js --label L --setup <outcome> --samples F --stamps F --exit F --check F --env F --sampler-pid F
//                          --out-json F --out-text F
//
// Counter formulas (Microsoft, "Calculating counter values"; type codes from the CounterType qualifier table):
//   PERF_100NSEC_TIMER     542180608  100*(N1-N0)/(D1-D0)     -> process CPU seconds over an interval = (N1-N0)/1e7
//   PERF_100NSEC_TIMER_INV 558957824  100*(1-(N1-N0)/(D1-D0)) -> per-processor busy %
//   PERF_ELAPSED_TIME      807666944  (D0-N0)/F               -> N0 is the process's start time in the object time base
//                                                                (D0 = Timestamp_Object, F = Frequency_Object)
//   PERF_COUNTER_RAWCOUNT 65536 / PERF_COUNTER_LARGE_RAWCOUNT 65792 -> instantaneous value
// A counter whose recorded CounterType differs is not used; where the creation identity is unavailable the instance and
// helper logic fall back to heuristics and helper attribution is reported unavailable.
const fs = require("fs");

const SLOW_START_MS = 10_000; // experiment threshold for a slow first Windows PowerShell start; NOT the product's limit
const MIN_COVERAGE_FOR_OBSERVATIONS = 0.8;
// Creation-evidence tolerance: an EXPERIMENT HEURISTIC, NOT A GUARANTEED ERROR BOUND -- two median sampler-query durations
// plus a fixed 50 ms margin. Rationale, not proof: a creation estimate is "sample time minus process age" and each sample's
// counters are expected to be read somewhere inside its [t0, t1] query, so estimates of one start time are expected to differ
// by roughly a query duration; the 50 ms margin allows for millisecond clock reads, JSON number rounding and the median's
// own spread. Nothing here guarantees that the object time base and the wall clock behave this way on the runner. Query timing must be valid (finite, at least two samples,
// median <= MAX_VALID_QUERY_MS); otherwise creation evidence is treated as unusable, never as zero uncertainty.
const CREATION_MARGIN_MS = 50;
const MAX_VALID_QUERY_MS = 5000;
const T = { TIMER: 542180608, TIMER_INV: 558957824, ELAPSED: 807666944, RAW: 65536, LARGE_RAW: 65792 };
const K = {
  PROC_CPU: "Win32_PerfRawData_PerfProc_Process.PercentProcessorTime", PROC_ELAPSED: "Win32_PerfRawData_PerfProc_Process.ElapsedTime",
  CORE: "Win32_PerfRawData_PerfOS_Processor.PercentProcessorTime", QUEUE: "Win32_PerfRawData_PerfOS_System.ProcessorQueueLength",
  DISK: "Win32_PerfRawData_PerfDisk_PhysicalDisk.CurrentDiskQueueLength",
};
const CATEGORY = new Map(Object.entries({
  node: "node", msmpeng: "MsMpEng", mpdefendercoreservice: "MpDefenderCoreService", nissrv: "NisSrv",
  mscorsvw: "mscorsvw", ngen: "ngen", ngentask: "ngentask", tiworker: "TiWorker", trustedinstaller: "TrustedInstaller",
  svchost: "svchost", wmiprvse: "WmiPrvSE (includes the sampler's own queries)", system: "System", registry: "Registry",
  conhost: "conhost", cmd: "cmd", git: "git", whoami: "whoami", icacls: "icacls", searchindexer: "SearchIndexer",
  compattelrunner: "CompatTelRunner", mousocoreworker: "MoUsoCoreWorker", usoclient: "UsoClient", wuauclt: "wuauclt",
  "runner.worker": "Runner.Worker", "runner.listener": "Runner.Listener", provisioner: "provisioner",
}));
const SAFE_TITLE = /^[A-Za-z0-9 ,.;:'()\-+=<>!?&%#\[\]{}|_*"]{1,160}$/;
const UNSAFE_IN_TITLE = /([A-Za-z]:\\|\\\\|\/(Users|home|tmp|private|var)\/|S-1-5-21|runnervm|@)/i;

const finite = (x) => typeof x === "number" && Number.isFinite(x);
const round = (x, d = 1) => (finite(x) ? Math.round(x * 10 ** d) / 10 ** d : null);
const norm = (n) => String(n || "").replace(/#\d+$/, "").toLowerCase();
const readText = (p) => { try { return p ? fs.readFileSync(p, "utf8") : null; } catch { return null; } };
const overlap = (f, t, w0, w1) => Math.max(0, Math.min(t, w1) - Math.max(f, w0));
function args() {
  const a = {}; const v = process.argv.slice(2);
  for (let i = 0; i < v.length; i += 2) { if (!/^--[a-z-]+$/.test(v[i]) || v[i + 1] === undefined) { a.bad = true; break; } a[v[i].slice(2)] = v[i + 1]; }
  return a;
}

// ------------------------------------------------------------------ suite output
function parseStamps(text) {
  if (text === null) return null;
  const out = { lines: [], malformed: 0 };
  for (const raw of text.split(/\r?\n/)) {
    if (raw === "") continue;
    const m = /^(\d{13})\t(.*)$/.exec(raw);
    if (!m) { out.malformed++; continue; }
    out.lines.push({ t: Number(m[1]), s: m[2] });
  }
  return out;
}
function parseFirstCall(st) {
  const tl = st.lines.filter((l) => l.s.includes("first call, helper timeline (sanitized):"));
  if (tl.length !== 1) return { ok: false, reason: tl.length === 0 ? "first-call-line-absent" : "first-call-line-repeated" };
  const head = /(\d+) spawn\(s\), (\d+)ms wall/.exec(tl[0].s);
  if (!head) return { ok: false, reason: "first-call-line-unparseable" };
  const spawns = []; const re = /#(\d+) ([a-z0-9._-]+) @(\d+)ms (\d+)ms (exit -?\d+|error [A-Z_]+|signal [A-Z0-9]+)/g; let m;
  while ((m = re.exec(tl[0].s))) spawns.push({ i: +m[1], exe: m[2], startMs: +m[3], durMs: +m[4], outcome: m[5].startsWith("exit") ? "exit" : m[5] });
  const mk = /markers\[hostStart\(parent↔child\) (\d+)ms input (\d+)ms import\+firstCmdlet (\d+)ms body (\d+)ms/.exec(tl[0].s);
  return { ok: true, arrivalMs: tl[0].t, wallMs: +head[2], spawnCount: +head[1], spawns, helper: spawns.find((s) => s.exe === "powershell.exe") || null,
    markers: mk ? { hostStartMs: +mk[1], inputMs: +mk[2], importFirstCmdletMs: +mk[3], bodyMs: +mk[4] } : null };
}
function parseOutcomes(st) {
  const i = st.lines.findIndex((l) => /^\s*(ok|FAIL|skip) - the first call returns CONSENT_REQUIRED and makes zero provider requests/.test(l.s));
  let firstCall = "not-reached";
  if (i >= 0) {
    const word = st.lines[i].s.trim().split(" ")[0];
    if (word === "ok" || word === "skip") firstCall = word;
    else firstCall = /^expected ok, got refusal: .*ran out of the time/.test((st.lines[i + 1] && st.lines[i + 1].s.trim()) || "") ? "fail-time-refusal-at-liveness" : "fail-other";
  }
  const others = []; let failLines = 0;
  for (const l of st.lines) {
    const m = /^\s*FAIL - (.*)$/.exec(l.s); if (!m) continue; failLines++;
    if (/the first call returns CONSENT_REQUIRED/.test(m[1])) continue;
    const t = m[1].trim(); others.push(SAFE_TITLE.test(t) && !UNSAFE_IN_TITLE.test(t) ? t : "<title withheld: not in the safe character set>");
  }
  return { firstCall, otherFailures: others.slice(0, 20), otherFailureCount: others.length, failLines };
}

// ------------------------------------------------------------------ sampler output
function parseSamples(text) {
  if (text === null) return { ok: false, reason: "samples-file-absent" };
  const r = { meta: null, samples: [], end: null, malformed: 0, nonMonotonic: 0 }; let last = -Infinity;
  for (const raw of text.split(/\r?\n/)) {
    if (raw.trim() === "") continue;
    let o; try { o = JSON.parse(raw); } catch { r.malformed++; continue; }
    if (!o || typeof o !== "object") { r.malformed++; continue; }
    if (o.kind === "meta" && !r.meta) r.meta = o;
    else if (o.kind === "end") r.end = o;
    else if (o.kind === "sample") {
      if (!finite(o.t0) || !finite(o.t1) || o.t1 < o.t0) { r.malformed++; continue; }
      if (o.t0 <= last) { r.nonMonotonic++; continue; }
      last = o.t0; o.mid = (o.t0 + o.t1) / 2; o.procsValid = Array.isArray(o.procs); r.samples.push(o);
    } else r.malformed++;
  }
  if (!r.meta) return { ok: false, reason: "sampler-meta-absent" };
  if (r.samples.length < 2) return { ok: false, reason: "fewer-than-two-samples" };
  return { ok: true, ...r };
}
const typeIs = (meta, key, allowed) => !!meta && !!meta.counterTypes && allowed.includes(meta.counterTypes[key]);

// Process instances. With the creation identity (PERF_ELAPSED_TIME verified) an instance is PID + raw start time, so a
// reused PID is a different instance whenever both were sampled. Without it, a run is split on an observed absence (in a
// sample whose process list is valid), a name change or a CPU counter going backwards; a same-name reuse between two
// consecutive samples with a higher counter cannot be detected and is reported as a residual uncertainty.
function buildInstances(S, creationOk, tol) {
  const inst = new Map(); const runKey = new Map(); const runSeq = new Map();
  S.samples.forEach((s, k) => {
    s.unusablePids = new Set();
    if (!s.procsValid) return;
    const present = new Set();
    for (const p of s.procs) {
      if (!p || !finite(p.pid) || p.pid === 0) continue;
      let key, created = null;
      if (creationOk && finite(p.et) && finite(p.to) && finite(p.fo) && p.fo > 0 && p.to >= p.et) {
        key = p.pid + ":" + p.et; created = s.mid - ((p.to - p.et) / p.fo) * 1000;
      } else if (creationOk) { s.unusablePids.add(p.pid); continue; } // unusable creation data: kept as "present but unmeasured", never as absence
      else {
        const prev = runKey.get(p.pid);
        const prevInst = prev && inst.get(prev);
        const contiguous = prevInst && prevInst.lastK === lastValidBefore(S, k) && norm(prevInst.name) === norm(p.n) && finite(p.cpu) && p.cpu >= prevInst.rows[prevInst.rows.length - 1].cpu;
        if (contiguous) key = prev; else { const n = (runSeq.get(p.pid) || 0) + 1; runSeq.set(p.pid, n); key = p.pid + "#run" + n; runKey.set(p.pid, key); }
      }
      present.add(key);
      let I = inst.get(key);
      if (!I) { I = { key, pid: p.pid, ppid: p.ppid, name: norm(p.n), created, firstK: k, lastK: k, rows: [] }; inst.set(key, I); }
      if (norm(p.n) !== I.name) { I.nameChanged = true; continue; }
      if (created !== null) I.createdEst = (I.createdEst || []).concat(created);
      I.lastK = k; I.rows.push({ k, cpu: p.cpu, ts: p.ts, mid: s.mid, t1: s.t1 });
    }
  });
  for (const I of inst.values()) {
    if (I.createdEst && I.createdEst.length) {
      const e = I.createdEst.slice().sort((a, b) => a - b); I.created = e[Math.floor(e.length / 2)];
      I.createdSpreadMs = e[e.length - 1] - e[0];
    }
    const prevK = lastUsableBefore(S, I.firstK, I.pid); const nextK = firstUsableAfter(S, I.lastK, I.pid);
    I.firstSeen = S.samples[I.firstK].mid; I.lastSeen = S.samples[I.lastK].mid;
    I.prevSampleT1 = prevK === null ? null : S.samples[prevK].t1; I.prevSampleMid = prevK === null ? null : S.samples[prevK].mid;
    I.nextAbsent = nextK === null ? null : S.samples[nextK].mid;
    // consistency (creation identity only): estimates agree within tol, and no usable process list taken clearly after the
    // claimed creation (its query started more than tol after it) and before the last sighting lacked the instance
    if (creationOk && finite(I.created)) {
      const seen = new Set(I.rows.map((r) => r.k));
      I.contradicted = S.samples.some((x, j) => j < I.lastK && x.procsValid && !x.unusablePids.has(I.pid) && !seen.has(j) && x.t0 > I.created + tol);
      I.consistent = finite(tol) && I.createdSpreadMs <= tol && !I.contradicted;
    } else I.consistent = false;
  }
  return inst;
}
// neighbours that can establish absence for a PID: a valid process list in which that PID had no unusable row
function lastUsableBefore(S, k, pid) { for (let j = k - 1; j >= 0; j--) if (S.samples[j].procsValid && !S.samples[j].unusablePids.has(pid)) return j; return null; }
function firstUsableAfter(S, k, pid) { for (let j = k + 1; j < S.samples.length; j++) if (S.samples[j].procsValid && !S.samples[j].unusablePids.has(pid)) return j; return null; }
function lastValidBefore(S, k) { for (let j = k - 1; j >= 0; j--) if (S.samples[j].procsValid) return j; return null; }
function firstValidAfter(S, k) { for (let j = k + 1; j < S.samples.length; j++) if (S.samples[j].procsValid) return j; return null; }

function category(I, helperKey, samplerPid) {
  if (I.name === "powershell") return I.key === helperKey ? "Windows PowerShell helper (identified)" : "Windows PowerShell (not the identified helper)";
  if (I.name === "pwsh") return I.pid === samplerPid ? "pwsh sampler" : "pwsh (PowerShell 7, not the sampler)";
  return CATEGORY.get(I.name) || "other";
}

// ------------------------------------------------------------------ main
function main() {
  const a = args();
  if (a.bad || !a["out-json"] || !a["out-text"]) { console.log("SUMMARIZE-ERROR: usage"); process.exit(2); }
  const R = { label: /^[A-Za-z0-9_.-]{1,40}$/.test(a.label || "") ? a.label : "unlabelled", version: 2,
    slowStartThresholdMs: SLOW_START_MS, thresholdNote: "experiment classification of the first Windows PowerShell spawn; not the product's 20 s allowance",
    status: null, unavailable: [] };
  const exitText = readText(a.exit);
  R.npmNativeExit = exitText !== null && /^-?\d+$/.test(exitText.trim()) ? Number(exitText.trim()) : null;
  if (R.npmNativeExit === null) R.unavailable.push("npm-native-exit-code");
  const check = readText(a.check); const cm = check && /^fail-lines=(\d+) inconsistent=(yes|no)$/.exec(check.trim());
  R.wrapperCheck = cm ? { failLinesSeenByWrapper: Number(cm[1]), zeroExitWithFailLines: cm[2] === "yes" } : null;
  if (!R.wrapperCheck) R.unavailable.push("wrapper-fail-line-check");
  const env = (() => { try { return JSON.parse(readText(a.env)); } catch { return null; } })();
  R.psModulePath = env && typeof env === "object" ? { present: env.present === true, entries: finite(env.entries) ? env.entries : null,
    ps7PathBeforeWinPsSystemPath: typeof env.ps7First === "boolean" ? env.ps7First : null, winPsSystemPathPresent: typeof env.winPsSystem === "boolean" ? env.winPsSystem : null,
    note: "facts about the step's environment (inherited by npm, node and the helper); not the helper's own observed environment and not an explanation of startup time" } : null;
  if (!R.psModulePath) R.unavailable.push("psmodulepath-facts");
  if (a.setup !== "success") { R.status = "SETUP-FAILED"; return finish(R, a); }

  const st = parseStamps(readText(a.stamps));
  let fc = { ok: false, reason: "suite-output-unavailable" };
  if (st) {
    R.stampMalformedLines = st.malformed;
    const oc = parseOutcomes(st); R.firstCallTest = oc.firstCall; R.otherFailures = oc.otherFailures; R.otherFailureCount = oc.otherFailureCount; R.failLinesInOutput = oc.failLines;
    R.zeroExitWithFailLines = R.npmNativeExit === 0 && oc.failLines > 0;
    fc = parseFirstCall(st);
  } else R.unavailable.push("suite-output");
  if (fc.ok) {
    R.firstCallTimeline = { wallMs: fc.wallMs, spawnCount: fc.spawnCount, helperDurationMsByTest: fc.helper ? fc.helper.durMs : null, helperMarkers: fc.markers,
      spawns: fc.spawns.map((s) => ({ i: s.i, exe: /^(powershell|icacls|whoami|git)(\.exe)?$/.test(s.exe) ? s.exe : "other", startMs: s.startMs, durMs: s.durMs, outcome: s.outcome })) };
  } else R.unavailable.push("first-call-timeline (" + fc.reason + ")");

  const S = parseSamples(readText(a.samples));
  if (!S.ok) { R.status = "SAMPLER-UNAVAILABLE"; R.samplerReason = S.reason; classifyStart(R, fc, null); return finish(R, a); }
  const samplerPid = (() => { const t = readText(a["sampler-pid"]); const m = t && /^(\d+)(\s+\d+)?$/.exec(t.trim()); return m ? Number(m[1]) : null; })();
  const interval = finite(S.meta.intervalMs) ? S.meta.intervalMs : 1000;
  const procOk = typeIs(S.meta, K.PROC_CPU, [T.TIMER]); const creationOk = typeIs(S.meta, K.PROC_ELAPSED, [T.ELAPSED]);
  R.sampler = { samples: S.samples.length, samplesWithProcessList: S.samples.filter((s) => s.procsValid).length, malformedLines: S.malformed, nonMonotonicSamples: S.nonMonotonic,
    endReason: S.end && ["stop-file", "deadline"].includes(S.end.reason) ? S.end.reason : "absent",
    medianQueryMs: (() => { const d = S.samples.map((s) => s.t1 - s.t0).filter((x) => finite(x) && x >= 0).sort((x, y) => x - y); return d.length >= 2 ? d[Math.floor(d.length / 2)] : null; })(),
    processCpuCounterVerified: procOk, creationIdentityVerified: creationOk };
  if (!procOk) { R.status = "SAMPLER-UNAVAILABLE"; R.samplerReason = "process-cpu-counter-type-unverified"; classifyStart(R, fc, null); return finish(R, a); }
  if (!creationOk) R.unavailable.push("creation-identity (ElapsedTime not PERF_ELAPSED_TIME): instances split by heuristics; helper attribution unavailable");
  const queryOk = finite(R.sampler.medianQueryMs) && R.sampler.medianQueryMs <= MAX_VALID_QUERY_MS;
  const tol = queryOk ? 2 * R.sampler.medianQueryMs + CREATION_MARGIN_MS : null;
  R.creationTolerance = { ms: tol, rule: "experiment heuristic, not a guaranteed error bound: 2 x median sampler query duration + " + CREATION_MARGIN_MS + " ms", queryTimingValid: queryOk };

  // ---- helper candidates, from samples only: a powershell instance whose creator is a node instance verified as the parent
  const inst = buildInstances(S, creationOk, tol);
  const byPid = new Map(); for (const I of inst.values()) { if (!byPid.has(I.pid)) byPid.set(I.pid, []); byPid.get(I.pid).push(I); }
  const parentOf = (I) => {
    const ps = (byPid.get(I.ppid) || []).filter((P) => P.name === "node");
    if (!creationOk) return { verified: false, found: ps.length > 0 };
    const t = I.created;
    const alive = ps.filter((P) => P.consistent && finite(P.created) && P.created <= t && P.lastSeen + interval >= t);
    return { verified: alive.length === 1, found: ps.length > 0, multiple: alive.length > 1 };
  };
  const suiteStart = S.samples[0].mid;
  const ps = [...inst.values()].filter((I) => I.name === "powershell" && (!creationOk || (finite(I.created) && I.created >= suiteStart - interval)));
  const verified = ps.filter((I) => parentOf(I).verified);
  const unverified = ps.filter((I) => !parentOf(I).verified && parentOf(I).found);
  R.helperCandidates = { powershellInstances: ps.length, withVerifiedNodeParent: verified.length, withUnverifiedNodeParent: unverified.length };
  let helper = null;
  R.helperSelection = "earliest-created among sampled candidates (a process that lived entirely between two samples is never a candidate)";
  if (!creationOk) R.helperIdentity = "unavailable-without-creation-identity";
  else if (!queryOk) { R.helperIdentity = "creation evidence inconsistent"; R.creationInconsistency = "query-timing-invalid"; }
  else if (!verified.length) R.helperIdentity = unverified.length ? "ambiguous (node parent unverified)" : "not-observed-by-sampler";
  else {
    const good = verified.filter((I) => I.consistent).sort((x, y) => x.created - y.created);
    const bad = verified.filter((I) => !I.consistent);
    const earliest = good[0];
    // an inconsistent candidate whose earliest estimate could precede the earliest consistent one makes the order unknowable
    const badEarlier = bad.some((B) => !earliest || (finite(B.created) && B.created - (finite(B.createdSpreadMs) ? B.createdSpreadMs : 0) <= earliest.created + tol));
    if (badEarlier) { R.helperIdentity = "creation evidence inconsistent"; R.creationInconsistency = bad.some((B) => B.contradicted) ? "valid-absence-contradicts-lifetime" : "estimates-disagree"; }
    else {
      const unverifiedEarlier = unverified.some((U) => finite(U.created) && U.created <= earliest.created + tol);
      const tie = good.length > 1 && Math.abs(good[1].created - earliest.created) <= tol;
      if (unverifiedEarlier || tie) R.helperIdentity = "ambiguous";
      else { R.helperIdentity = "identified"; helper = earliest; }
    }
  }
  if (!helper) { R.status = "MEASURED-HELPER-UNAVAILABLE"; R.unavailable.push("helper attribution (" + R.helperIdentity + ")"); classifyStart(R, fc, null); return finish(R, a); }

  // ---- helper lifetime bounds, from samples
  const lastRow = helper.rows[helper.rows.length - 1];
  const life = {
    createdUtcMs: Math.round(helper.created), creationSource: "PERF_ELAPSED_TIME raw start (uncertainty about half a sampler query)",
    firstSampledAfterCreationMs: Math.round(helper.firstSeen - helper.created), lastSampledAfterCreationMs: Math.round(helper.lastSeen - helper.created),
    exitAfterCreationAtMostMs: helper.nextAbsent === null ? null : Math.round(helper.nextAbsent - helper.created),
    endUnobservedMs: helper.nextAbsent === null ? null : Math.round(helper.nextAbsent - helper.lastSeen),
    samples: helper.rows.length,
  };
  R.helperLifetime = life;
  if (fc.ok && fc.helper) {
    const stampStart = fc.arrivalMs - fc.wallMs + fc.helper.startMs;
    R.stampCrossCheck = { stampDerivedStartMinusSampledCreationMs: Math.round(stampStart - helper.created),
      note: "approximate only: suite-line arrival includes unmeasured npm, pipe and reader latency (positive = stamps later than the sampled creation)" };
    const lo = life.lastSampledAfterCreationMs, hi = life.exitAfterCreationAtMostMs, d = fc.helper.durMs;
    const lowerOk = d + 500 >= lo, upperOk = hi === null ? null : d <= hi + 500;
    R.timelineConsistency = !lowerOk || upperOk === false ? "inconsistent" : upperOk === null ? "lower-bound-consistent; upper bound unavailable" : "consistent";
  } else R.timelineConsistency = "duration-unavailable (no first-call timeline; sampled bounds only)";
  if (R.timelineConsistency === "inconsistent") {
    R.helperIdentity = "inconsistent-with-test-duration";
    R.status = "MEASURED-HELPER-UNAVAILABLE"; R.unavailable.push("helper attribution (the test's measured helper duration contradicts the sampled lifetime)");
    // the rejected duration must not classify the start, and the candidate's sampled lifetime is not trusted to either
    R.startClass = "UNDETERMINED"; R.startClassBasis = "test duration inconsistent with sampled lifetime"; return finish(R, a);
  }
  R.helperCpu = { cpuSecondsFromCreationToLastSample: round(lastRow.cpu / 1e7, 2),
    averageCoresFromCreationToLastSample: round((lastRow.cpu / 1e7) / Math.max(0.001, (helper.lastSeen - helper.created) / 1000), 2),
    note: "raw Process counter at the helper's last sample = CPU since creation; CPU after the last sample (up to endUnobservedMs) is not observed" };
  classifyStart(R, fc, life);

  // ---- window = [creation, last sample] of the helper; attribution with explicit coverage
  const w0 = helper.created, w1 = helper.lastSeen, winMs = Math.max(1, w1 - w0);
  R.window = { startUtcMs: Math.round(w0), endUtcMs: Math.round(w1), durationMs: Math.round(winMs), basis: "the identified helper's sampled lifetime (creation to last sample); independent of suite-output stamps" };
  let procCovered = 0; const byCat = new Map(); const counts = { creationSupportedFirstSight: 0, firstSightOmitted: 0, firstSightOmittedCpuSeconds: 0, exitedInWindow: 0, invalidIntervals: 0 };
  for (let k = 1; k < S.samples.length; k++) {
    const A = S.samples[k - 1], B = S.samples[k];
    if (!A.procsValid || !B.procsValid || A.unusablePids.size || B.unusablePids.size) continue; // unusable rows: not valid coverage
    const ov = overlap(A.mid, B.mid, w0, w1); if (ov <= 0) continue;
    procCovered += ov;
  }
  for (const I of inst.values()) {
    if (I.lastSeen < w0 - interval || I.firstSeen > w1 + interval) continue;
    if (I.nextAbsent !== null && I.lastSeen >= w0 && I.lastSeen < w1) counts.exitedInWindow++;
    for (let r = 1; r < I.rows.length; r++) {
      const x = I.rows[r - 1], y = I.rows[r];
      if (lastValidBefore(S, y.k) !== x.k) continue; // a failed sample between them: the interval is not attributed
      if (!finite(x.cpu) || !finite(y.cpu) || y.cpu < x.cpu || !finite(x.ts) || !finite(y.ts) || y.ts <= x.ts) { counts.invalidIntervals++; continue; }
      const cpuS = (y.cpu - x.cpu) / 1e7;
      const lp = finite(S.meta.logicalProcessors) ? S.meta.logicalProcessors : null;
      if (lp && cpuS > ((y.ts - x.ts) / 1e7) * lp * 1.05) { counts.invalidIntervals++; continue; }
      const ov = overlap(x.mid, y.mid, w0, w1); if (ov <= 0) continue;
      add(byCat, category(I, helper.key, samplerPid), cpuS * ov / (y.mid - x.mid));
    }
    // first sight: attribute the raw (since-creation) CPU only when creation evidence places it after the previous sample
    const first = I.rows[0];
    if (I.key === helper.key) { add(byCat, category(I, helper.key, samplerPid), (first.cpu / 1e7) * overlap(I.created, first.mid, w0, w1) / Math.max(1, first.mid - I.created)); continue; }
    if (I.firstSeen < w0 - interval || I.firstSeen > w1 + interval) continue;
    if (creationOk && finite(I.created) && I.prevSampleT1 !== null && I.created > I.prevSampleT1) {
      counts.creationSupportedFirstSight++;
      add(byCat, category(I, helper.key, samplerPid), (first.cpu / 1e7) * overlap(I.created, first.mid, w0, w1) / Math.max(1, first.mid - I.created));
    } else { counts.firstSightOmitted++; counts.firstSightOmittedCpuSeconds += finite(first.cpu) ? first.cpu / 1e7 : 0; }
  }
  const winS = winMs / 1000;
  R.processCoverage = { temporal: round(procCovered / winMs, 2), samplesInWindowWithUnusableRows: S.samples.filter((x) => x.mid >= w0 && x.mid <= w1 && x.unusablePids.size).length,
    note: "fraction of the window covered by consecutive samples that both returned a complete, usable process list; uncovered time is unavailable, not zero",
    completeness: { creationSupportedFirstSightInstances: counts.creationSupportedFirstSight, firstSightOmittedInstances: counts.firstSightOmitted,
      firstSightOmittedLifetimeCpuSeconds: round(counts.firstSightOmittedCpuSeconds, 2), instancesExitedInWindow: counts.exitedInWindow, invalidIntervals: counts.invalidIntervals,
      note: "per-category CPU is a lower bound: omitted first-sight lifetime CPU and CPU after an instance's last sample are not included" } };
  R.windowCpuByCategory = [...byCat.entries()].sort((x, y) => y[1] - x[1]).slice(0, 8).map(([c, v]) => ({ category: c, cpuSeconds: round(v, 2), averageCores: round(v / winS, 2) }));

  // per-core and queues, each with its own coverage
  if (!typeIs(S.meta, K.CORE, [T.TIMER_INV])) R.unavailable.push("per-core busy (counter type unverified)");
  else {
    let covered = 0, maxBusy = null, invalid = 0;
    for (let k = 1; k < S.samples.length; k++) {
      const A = S.samples[k - 1], B = S.samples[k]; const ov = overlap(A.mid, B.mid, w0, w1); if (ov <= 0) continue;
      if (!Array.isArray(A.cores) || !Array.isArray(B.cores)) continue;
      const prev = new Map(A.cores.map((c) => [c && c.n, c])); let any = false;
      for (const c of B.cores) {
        if (!c || c.n === "_Total") continue; const q = prev.get(c.n);
        if (!q || !finite(c.idle) || !finite(q.idle) || !finite(c.ts) || !finite(q.ts) || c.ts <= q.ts || c.idle < q.idle) { invalid++; continue; }
        const busy = 100 * (1 - (c.idle - q.idle) / (c.ts - q.ts)); if (!(busy >= -1 && busy <= 101)) { invalid++; continue; }
        any = true; maxBusy = Math.max(maxBusy === null ? 0 : maxBusy, Math.min(100, Math.max(0, busy)));
      }
      if (any) covered += ov;
    }
    R.perCore = { temporalCoverage: round(covered / winMs, 2), maxSingleCoreBusyPct: round(maxBusy, 1), invalidIntervals: invalid };
  }
  for (const [key, field, out] of [[K.QUEUE, "queue", "processorQueueLength"], [K.DISK, "diskQueue", "diskQueueLength"]]) {
    if (!typeIs(S.meta, key, [T.RAW, T.LARGE_RAW])) { R.unavailable.push(out + " (counter type unverified)"); continue; }
    const inW = S.samples.filter((s) => s.mid >= w0 && s.mid <= w1);
    const v = inW.filter((s) => finite(s[field]) && s[field] >= 0).map((s) => s[field]);
    const expected = Math.max(1, Math.floor(winMs / interval));
    R[out] = v.length ? { mean: round(v.reduce((x, y) => x + y, 0) / v.length, 2), max: Math.max(...v), validSamples: v.length, expectedSamples: expected } : null;
    if (!v.length) R.unavailable.push(out + " (no valid sample in window)");
  }

  // observations consistent with H1-H4 (descriptive thresholds), only with adequate process coverage
  const notes = []; const hc = R.helperCpu.averageCoresFromCreationToLastSample;
  const top = R.windowCpuByCategory.find((c) => !/helper \(identified\)|^other$/.test(c.category));
  if (R.processCoverage.temporal < MIN_COVERAGE_FOR_OBSERVATIONS) notes.push(`process coverage ${R.processCoverage.temporal} is below ${MIN_COVERAGE_FOR_OBSERVATIONS}: no H1-H4 observation is stated`);
  else {
    if (hc >= 0.7) notes.push("helper averaged >= 0.7 of one processor from creation to its last sample: consistent with H1 (CPU work inside the helper)");
    if (hc < 0.3 && top && top.averageCores >= 0.7) notes.push(`a non-helper category (${top.category}) averaged >= 0.7 of one processor (lower bound) while the helper averaged < 0.3: consistent with H2 (contention); concurrency alone does not show it delayed the helper`);
    if (hc < 0.3 && R.diskQueueLength && R.diskQueueLength.mean >= 2) notes.push("disk queue averaged >= 2 while the helper averaged < 0.3: consistent with H3 (I/O)");
    if (hc < 0.3 && !(top && top.averageCores >= 0.7) && !(R.diskQueueLength && R.diskQueueLength.mean >= 1) && R.perCore && R.perCore.maxSingleCoreBusyPct !== null && R.perCore.maxSingleCoreBusyPct < 70) notes.push("helper, other observed processes, cores and disk queue all low: consistent with H4 (waiting on something unobserved)");
    if (!notes.length) notes.push("no H1-H4 pattern matched the descriptive thresholds");
  }
  R.observations = notes;
  R.status = "MEASURED-HELPER-IDENTIFIED";
  return finish(R, a);
}
function add(m, k, v) { if (finite(v) && v > 0) m.set(k, (m.get(k) || 0) + v); }
function classifyStart(R, fc, life) {
  // the test's own measured helper duration when available; otherwise sampled lifetime bounds; otherwise undetermined
  if (fc && fc.ok && fc.helper) { R.startClass = fc.helper.durMs >= SLOW_START_MS ? "SLOW-START" : "NOT-SLOW"; R.startClassBasis = "test's own helper duration"; return; }
  if (life) {
    if (life.lastSampledAfterCreationMs >= SLOW_START_MS) { R.startClass = "SLOW-START"; R.startClassBasis = "sampled lifetime lower bound"; return; }
    if (life.exitAfterCreationAtMostMs !== null && life.exitAfterCreationAtMostMs < SLOW_START_MS) { R.startClass = "NOT-SLOW"; R.startClassBasis = "sampled lifetime upper bound"; return; }
  }
  R.startClass = "UNDETERMINED"; R.startClassBasis = "no test duration and no conclusive sampled bound";
}
function finish(R, a) {
  const words = { "SETUP-FAILED": "setup failed before the suite; no measurement", "SAMPLER-UNAVAILABLE": "sampler produced no usable samples (this is not 'no recurrence')",
    "MEASURED-HELPER-UNAVAILABLE": "samples available; helper attribution unavailable (this is not 'no recurrence')", "MEASURED-HELPER-IDENTIFIED": "measured" };
  const L = [];
  L.push(`job ${R.label}: ${R.status} — ${words[R.status] || "?"}`);
  L.push(`npm native exit ${R.npmNativeExit === null ? "unavailable" : R.npmNativeExit}; first-call test outcome ${R.firstCallTest || "unavailable"}${R.zeroExitWithFailLines ? "; ZERO EXIT WITH FAIL LINES (wrapper failed the step)" : ""}`);
  if (R.startClass) L.push(`first Windows PowerShell spawn: ${R.startClass} (${R.startClassBasis}; experiment threshold ${SLOW_START_MS} ms, not the product's allowance)`);
  if (R.otherFailureCount) L.push(`other failing tests: ${R.otherFailureCount} (${R.otherFailures.join(" | ")})`);
  if (R.helperIdentity) L.push(`helper identity: ${R.helperIdentity}${R.creationInconsistency ? " (" + R.creationInconsistency + ")" : ""}; selection: earliest-created among sampled candidates (candidates: ${JSON.stringify(R.helperCandidates)})`);
  if (R.helperLifetime) L.push(`helper sampled lifetime: first sample +${R.helperLifetime.firstSampledAfterCreationMs} ms, last sample +${R.helperLifetime.lastSampledAfterCreationMs} ms, exit at most +${R.helperLifetime.exitAfterCreationAtMostMs} ms after creation (end unobserved ${R.helperLifetime.endUnobservedMs} ms)`);
  if (R.helperCpu) L.push(`helper CPU ${R.helperCpu.cpuSecondsFromCreationToLastSample} s from creation to last sample (~${R.helperCpu.averageCoresFromCreationToLastSample} of one processor)`);
  if (R.timelineConsistency) L.push(`test duration vs sampled lifetime: ${R.timelineConsistency}${R.stampCrossCheck ? "; stamp cross-check offset " + R.stampCrossCheck.stampDerivedStartMinusSampledCreationMs + " ms (approximate)" : ""}`);
  L.push(`creation tolerance: ${R.creationTolerance && finite(R.creationTolerance.ms) ? R.creationTolerance.ms + " ms" : "unavailable"} (experiment heuristic, not a guaranteed error bound); samples in window with unusable process rows: ${R.processCoverage && finite(R.processCoverage.samplesInWindowWithUnusableRows) ? R.processCoverage.samplesInWindowWithUnusableRows : "unavailable"}`);
  if (R.processCoverage) L.push(`process coverage of the window: ${R.processCoverage.temporal}; first-sight CPU omitted for ${R.processCoverage.completeness.firstSightOmittedInstances} instance(s)`);
  for (const c of R.windowCpuByCategory || []) L.push(`  window CPU (lower bound) ${c.category}: ${c.cpuSeconds} s (${c.averageCores} cores avg)`);
  if (R.perCore) L.push(`busiest single core in window: ${R.perCore.maxSingleCoreBusyPct}% (coverage ${R.perCore.temporalCoverage})`);
  if (R.processorQueueLength) L.push(`processor queue length: mean ${R.processorQueueLength.mean}, max ${R.processorQueueLength.max} (${R.processorQueueLength.validSamples}/${R.processorQueueLength.expectedSamples} samples)`);
  if (R.diskQueueLength) L.push(`disk queue length: mean ${R.diskQueueLength.mean}, max ${R.diskQueueLength.max} (${R.diskQueueLength.validSamples}/${R.diskQueueLength.expectedSamples} samples)`);
  for (const n of R.observations || []) L.push(`observation: ${n}`);
  if (R.unavailable.length) L.push(`unavailable: ${R.unavailable.join("; ")}`);
  if (R.psModulePath) L.push(`PSModulePath facts: entries ${R.psModulePath.entries}, PowerShell 7 path before the Windows PowerShell system path: ${R.psModulePath.ps7PathBeforeWinPsSystemPath}`);
  L.push("not a product pass, not a D5 result: a refusal recorded here is experiment data; the job's conclusion follows npm's exit code (and the wrapper's FAIL-line safeguard)");
  fs.writeFileSync(a["out-json"], JSON.stringify(R, null, 2) + "\n");
  fs.writeFileSync(a["out-text"], L.join("\n") + "\n");
  console.log(L[0]);
  process.exit(0);
}
module.exports = { parseStamps, parseFirstCall, parseSamples, buildInstances, SLOW_START_MS };
if (require.main === module) main();
