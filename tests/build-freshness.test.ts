import { test, suite, finish, assert } from "./harness";
import { spawnSync } from "child_process";
import { mkdirSync, mkdtempSync, rmSync, utimesSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import * as path from "path";

/**
 * The pretest guard, tested against fixtures rather than against out/.
 *
 * It cannot be tested against the repository's own build: the suite is running
 * from that build while the assertions execute, and back-dating out/cli.js to
 * prove the guard fires would break the five test files that spawn it. The
 * script takes its two directories as arguments for exactly this reason.
 */

const SCRIPT = path.join(__dirname, "..", "scripts", "check-build-fresh.js");

/**
 * The artifacts this branch builds, from the same place the guard reads them.
 *
 * Hard-coded "cli.js" and "extension.js" here passed on release-0.1.1 and
 * failed the moment the suite ran on mcp-layer, whose bundle script has a third
 * entry point: the fixtures were missing an artifact the guard correctly
 * insisted on. A test that names the list independently is a test that only
 * agrees with the code on the branch it was written on.
 */
function artifactNames(): string[] {
  const bundle: string = require("../package.json").scripts.bundle;
  const names = [...bundle.matchAll(/src\/([A-Za-z0-9_.-]+)\.ts/g)].map((m) => `${m[1]}.js`);
  assert.ok(names.length >= 2, `expected several bundle entry points, found ${names.join(",")}`);
  return names;
}

interface Layout {
  /** Seconds past the base time for each source file. */
  sources: Record<string, number>;
  /**
   * One offset per built artifact, in bundle-entry order; the last value
   * repeats. null means out/ does not exist at all.
   */
  built: number[] | null;
  /** Files in out/ that are not artifacts of this branch. */
  extra?: Record<string, number>;
}

function run(layout: Layout): { status: number; stderr: string } {
  const base = mkdtempSync(path.join(tmpdir(), "secretloop-fresh-"));
  try {
    const src = path.join(base, "src");
    const out = path.join(base, "out");
    mkdirSync(src, { recursive: true });
    // A fixed base time, so the assertions are about the ordering the test set
    // up and not about how long the test took to run.
    const t0 = 1_700_000_000;
    const stamp = (file: string, offset: number) => utimesSync(file, t0 + offset, t0 + offset);
    for (const [name, offset] of Object.entries(layout.sources)) {
      const file = path.join(src, name);
      writeFileSync(file, "export const x = 1;\n", "utf8");
      stamp(file, offset);
    }
    if (layout.built) {
      mkdirSync(out, { recursive: true });
      const names = artifactNames();
      names.forEach((name, i) => {
        const offset = layout.built![Math.min(i, layout.built!.length - 1)];
        const file = path.join(out, name);
        writeFileSync(file, "// built\n", "utf8");
        stamp(file, offset);
      });
      for (const [name, offset] of Object.entries(layout.extra ?? {})) {
        const file = path.join(out, name);
        writeFileSync(file, "// stray\n", "utf8");
        stamp(file, offset);
      }
    }
    const res = spawnSync("node", [SCRIPT, src, out], { encoding: "utf8" });
    return { status: res.status ?? -1, stderr: res.stderr };
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
}

suite("build freshness — the pretest guard");

test("a build newer than every source passes", () => {
  const { status, stderr } = run({ sources: { "a.ts": 0, "b.ts": 10 }, built: [20] });
  assert.strictEqual(status, 0, `refused a fresh build: ${stderr}`);
  assert.strictEqual(stderr, "");
});

test("a build older than any source is refused, and says which files", () => {
  const { status, stderr } = run({ sources: { "a.ts": 0, "late.ts": 500 }, built: [100] });
  assert.strictEqual(status, 1, "ran the suite against a stale build");
  assert.match(stderr, /stale relative to src/);
  assert.match(stderr, /npm run compile/);
  // Naming both sides is the whole point: "something is stale" sends someone
  // back to the same guessing the guard exists to end.
  assert.match(stderr, /\.js was built before .*late\.ts was last changed/);
});

test("the oldest artifact decides, not the newest", () => {
  // One rebuilt file and one left behind is the branch-switch case, and the
  // stale one is the one a test would spawn.
  const { status } = run({ sources: { "a.ts": 300 }, built: [100, 900] });
  assert.strictEqual(status, 1, "a fresh later artifact covered for a stale first one");
});

test("a tie passes", () => {
  // Editing a file in the same second a build finished is not evidence of
  // staleness, and a guard that cries wolf gets removed rather than fixed.
  const { status } = run({ sources: { "a.ts": 100 }, built: [100] });
  assert.strictEqual(status, 0);
});

test("a missing build is refused with a different message", () => {
  const { status, stderr } = run({ sources: { "a.ts": 0 }, built: null });
  assert.strictEqual(status, 1);
  assert.match(stderr, /has no build/);
  assert.ok(!stderr.includes("stale relative"), "a missing build is not a stale one");
});

test("an artifact this branch does not build is ignored", () => {
  // out/ accumulates across branches. release-0.1.1 never rebuilds an
  // out/mcp.js left behind by mcp-layer, and refusing to run because of it
  // would be a false alarm on every branch switch — which is how a guard gets
  // deleted instead of fixed. Found by running the first version of the guard,
  // not by reading it.
  const { status, stderr } = run({
    sources: { "a.ts": 300 },
    built: [900],
    // Never an entry point on any branch, so this stays a stray everywhere.
    extra: { "leftover.js": 1 },
  });
  assert.strictEqual(status, 0, `a stray artifact blocked the suite: ${stderr}`);
});

test("the guard is wired to run before the suite", () => {
  // A script nothing invokes is a script that protects nothing.
  const manifest = require("../package.json");
  assert.strictEqual(
    manifest.scripts.pretest,
    "node scripts/check-build-fresh.js",
    "npm test no longer runs the freshness guard first"
  );
});

finish();
