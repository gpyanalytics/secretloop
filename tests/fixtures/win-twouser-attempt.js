#!/usr/bin/env node
/*
 * Fixture helper: what a SECOND ordinary account can do to a directory. Not a test, not product
 * code. Run as that second account by the two-account CI job, once against a parent only the
 * owner controls and once against a permissive parent. The second run is the control: if the
 * same operations cannot succeed anywhere, their failure under the private parent proves nothing.
 *
 * Prints one JSON object of outcomes and exits 0 when it ran; a probe that cannot run exits 2.
 *
 *   node win-twouser-attempt.js --dir <directory>
 */
"use strict";
const fs = require("fs");
const path = require("path");

const i = process.argv.indexOf("--dir");
const dir = i >= 0 ? process.argv[i + 1] : undefined;
if (!dir) {
  console.log("FIXTURE-ERROR: --dir is required");
  process.exit(2);
}

const out = {};
const attempt = (name, fn) => {
  try {
    fn();
    out[name] = "SUCCEEDED";
  } catch (err) {
    out[name] = "refused:" + ((err && err.code) || "unknown");
  }
};

const planted = path.join(dir, ".secretloop-planted");
attempt("create-store-name", () => {
  fs.mkdirSync(planted);
  fs.rmdirSync(planted);
});
attempt("rename-parent", () => {
  fs.renameSync(dir, dir + "-moved");
  fs.renameSync(dir + "-moved", dir);
});
attempt("delete-parent", () => fs.rmdirSync(dir));
attempt("list-parent", () => fs.readdirSync(dir).length);

console.log(JSON.stringify(out));
