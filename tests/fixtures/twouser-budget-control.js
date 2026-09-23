#!/usr/bin/env node
/*
 * DISPOSABLE diagnostic control for the paired two-account comparison. Not product code.
 *
 * Runs the shim's injected-deadline control in a process of its own, AFTER the measured
 * executions, so the control can never warm or reorder them. Loads only the budget module: no
 * helper, no store, no request.
 *
 *   node --require twouser-trace-shim.js twouser-budget-control.js --out <build>
 */
"use strict";
const path = require("path");
const i = process.argv.indexOf("--out");
if (i < 0 || !process.argv[i + 1]) { console.log("CONTROL-ERROR: --out is required"); process.exit(2); }
process.env.TTRACE_INJECTED_CONTROL = "1";
require(path.join(process.argv[i + 1], "consent-budget.js"));
console.log("CONTROL-DONE");
