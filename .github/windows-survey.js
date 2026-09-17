// TEMPORARY DIAGNOSTIC. Runs every test file the `test` script names, one child
// process each with a hard timeout, and reports every file's outcome instead of
// stopping at the first failing file the way `npm test`'s && chain does. Exists
// so that one native Windows run surfaces every Windows failure at once; it is
// removed once the failures are classified. It is NOT the check -- `npm test`
// is -- and its step never decides the job's conclusion.
const { spawnSync } = require("child_process");
const { readFileSync, symlinkSync, mkdtempSync, rmSync, writeFileSync } = require("fs");
const { tmpdir } = require("os");
const path = require("path");

const script = JSON.parse(readFileSync("package.json", "utf8")).scripts.test;
const files = [...script.matchAll(/tests\/[\w.-]+\.test\.ts/g)].map((m) => m[0]);
const tsNode = require.resolve("ts-node/dist/bin.js");

console.log(`SURVEY platform=${process.platform} arch=${process.arch} node=${process.version} files=${files.length}`);

// Which link mechanisms this runner permits, recorded rather than assumed.
const lab = mkdtempSync(path.join(tmpdir(), "secretloop-survey-"));
writeFileSync(path.join(lab, "t.txt"), "x");
for (const [label, fn] of [
  ["file symlink", () => symlinkSync(path.join(lab, "t.txt"), path.join(lab, "l1"))],
  ["dir symlink", () => symlinkSync(lab, path.join(lab, "l2"), "dir")],
  ["junction", () => symlinkSync(lab, path.join(lab, "l3"), "junction")],
]) {
  try { fn(); console.log(`PROBE ${label}: created`); }
  catch (e) { console.log(`PROBE ${label}: ${e.code || e.message}`); }
}
rmSync(lab, { recursive: true, force: true });
for (const tool of ["bash", "sh", "mkfifo", "pgrep", "tar", "unzip", "npx"]) {
  const r = spawnSync(tool, ["--version"], { encoding: "utf8", timeout: 20000, shell: false });
  console.log(`TOOL ${tool}: ${r.error ? r.error.code : `status=${r.status}`}`);
}

let failed = 0;
for (const f of files) {
  const r = spawnSync(process.execPath, [tsNode, "--transpile-only", f], {
    encoding: "utf8",
    timeout: 5 * 60 * 1000,
  });
  const out = `${r.stdout || ""}`;
  const summary = out.split(/\r?\n/).filter((l) => /passed, \d+ failed|^\s*(FAIL|skip) - |^\s{4}\S/.test(l));
  const verdict = r.error ? `ERROR ${r.error.code}` : `status=${r.status}`;
  if (r.status !== 0) failed++;
  console.log(`\n=== ${f} ${verdict} signal=${r.signal}`);
  console.log(summary.join("\n"));
  const err = (r.stderr || "").trim();
  if (err) console.log(err.split(/\r?\n/).slice(-15).join("\n"));
}
console.log(`\nSURVEY DONE: ${failed} of ${files.length} files exited non-zero`);
