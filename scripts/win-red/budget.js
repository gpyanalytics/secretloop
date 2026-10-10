#!/usr/bin/env node
"use strict";
// Time budget for the win-red harness (rev3): ONE source of the arithmetic, used by the orchestrator at start
// (it runs this script and refuses to proceed unless ok=true) and by the mechanics tests.
//
// Model. Every launch is bounded by its own timeout plus a fixed settle allowance: GraceSec for the job's
// ActiveProcesses to reach 0 after the root exits, and TerminateSec for TerminateJobObject to drain if it did not.
//   launch(t)   = t + grace + terminate
//   setup       = launch(budget) + launch(nodeVersion) + launch(catfile) + launch(archive) + launch(untar)
//               + launch(npmCi) + launch(compile) + launch(util)            [util = extract]
//   perCase     = launch(run) + launch(measure) + launch(util)                [util = summarize]
//   mutationOps = 6 * launch(util)                                           [3 apply + 3 restore]
//   worst       = setup + 5 * perCase + mutationOps
//   total       = worst + workflowOverhead                                   [checkout, fetch, setup-node, Add-Type, upload, gate]
//   ok          = total + minHeadroom <= jobTimeoutMin * 60
// Per-phase worst cases are exported so the orchestrator can refuse to START a phase that cannot finish inside
// the modelled worst case (BUDGET-EXHAUSTED), never leaving a RESULT line behind.
//
// usage: node budget.js [key=value ...]      prints one JSON line; exit 0 if ok, 1 if not ok, 2 on bad input
const DEFAULTS = {
  jobTimeoutMin: 90,       // workflow timeout-minutes (the mechanics test checks the YAML equals this)
  workflowOverheadSec: 300, // checkout+fetch+setup-node+Add-Type compile+upload+gate, generous
  minHeadroomSec: 900,     // required slack between the modelled total and the job timeout
  graceSec: 10, terminateSec: 10,
  budgetSec: 30, nodeVersionSec: 30, catfileSec: 30, archiveSec: 60, untarSec: 60,
  npmCiSec: 480,           // observed x64 10-20 s, arm 143-178 s (run 38088814975); 480 leaves >= 5 min even for a cold cache
  compileSec: 120,         // observed 5-6 s
  utilSec: 30,             // extract / mutate / summarize node scripts
  runSec: 300,             // the isolated test: 4 helper spawns x 60 s spawnSync timeout = 240 s + ts-node start
  measureSec: 180,         // measure-markers.js: 2 helper spawns x 60 s = 120 s + ts-node start
};
function plan(overrides) {
  const p = Object.assign({}, DEFAULTS);
  for (const [k, v] of Object.entries(overrides || {})) {
    if (!(k in DEFAULTS)) throw new Error("unknown budget key: " + k);
    const n = Number(v);
    if (!Number.isInteger(n) || n < 0) throw new Error("budget value must be a non-negative integer: " + k);
    p[k] = n;
  }
  const settle = p.graceSec + p.terminateSec;
  const launch = (t) => t + settle;
  const setup = launch(p.budgetSec) + launch(p.nodeVersionSec) + launch(p.catfileSec) + launch(p.archiveSec) + launch(p.untarSec) + launch(p.npmCiSec) + launch(p.compileSec) + launch(p.utilSec);
  const perCase = launch(p.runSec) + launch(p.measureSec) + launch(p.utilSec);
  const mutationOps = 6 * launch(p.utilSec);
  const worstHarnessSec = setup + 5 * perCase + mutationOps;
  const totalSec = worstHarnessSec + p.workflowOverheadSec;
  const jobSec = p.jobTimeoutMin * 60;
  const headroomSec = jobSec - totalSec;
  return {
    ok: headroomSec >= p.minHeadroomSec,
    params: p, settleSec: settle,
    phases: { setupSec: setup, perCaseSec: perCase, mutationOpsSec: mutationOps, mutationOpSec: launch(p.utilSec), launchUtilSec: launch(p.utilSec) },
    worstHarnessSec, totalSec, jobSec, headroomSec, minHeadroomSec: p.minHeadroomSec,
    arithmetic: `setup ${setup} + 5*perCase ${perCase} + mutationOps ${mutationOps} = worst ${worstHarnessSec} s; + overhead ${p.workflowOverheadSec} = ${totalSec} s of job ${jobSec} s; headroom ${headroomSec} s (min ${p.minHeadroomSec})`,
  };
}
// remaining-time guard used by the orchestrator: may a phase needing needSec start when remainSec remain? (never negative)
function mayStart(needSec, remainSec) { return Number.isFinite(needSec) && Number.isFinite(remainSec) && needSec >= 0 && remainSec >= needSec; }
module.exports = { DEFAULTS, plan, mayStart };
if (require.main === module) {
  try {
    const overrides = {};
    for (const a of process.argv.slice(2)) { const m = /^([A-Za-z]+)=(\d+)$/.exec(a); if (!m) { console.log(JSON.stringify({ ok: false, error: "bad-argument" })); process.exit(2); } overrides[m[1]] = m[2]; }
    const out = plan(overrides);
    console.log(JSON.stringify(out));
    process.exit(out.ok ? 0 : 1);
  } catch (e) { console.log(JSON.stringify({ ok: false, error: String(e.message || e) })); process.exit(2); }
}
