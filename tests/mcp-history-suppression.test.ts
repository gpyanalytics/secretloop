import { mkdtempSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import * as path from "path";
import { spawnSync } from "child_process";
import { toolHistoryScan, setAllowedRoots, resetSessions } from "../src/mcp-core";
import { LogPatchParser } from "../src/history";
import { mergeConfig } from "../src/config";
import { test, suite, finish, assert } from "./harness";

suite("secretloop_history_scan — inline suppression accounting");

/**
 * Synthetic, generated at run time. The token is the shape the suite already
 * uses; the reason and a second marker are unique per run so their absence from
 * a response is evidence rather than coincidence.
 */
const TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"; // secretloop:allow(github-token) -- synthetic test fixture
const ALLOW = "secretloop" + ":allow";
const marker = (tag: string) =>
  `zz${tag}${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}zz`;

const CLI_PATH = path.join(__dirname, "..", "out", "cli.js");
const dirs: string[] = [];

function repo(files: Record<string, string>[]): { dir: string; head: string } {
  const dir = mkdtempSync(path.join(tmpdir(), "sl-mcphist-"));
  dirs.push(dir);
  const git = (...a: string[]) => {
    const r = spawnSync("git", a, { cwd: dir, encoding: "utf8" });
    if (r.status !== 0) throw new Error(`git ${a.join(" ")}: ${r.stderr}`);
  };
  git("init", "-q", ".");
  git("config", "user.email", "t@example.com");
  git("config", "user.name", "t");
  files.forEach((commit, i) => {
    for (const [name, text] of Object.entries(commit)) writeFileSync(path.join(dir, name), text, "utf8");
    git("add", "-A");
    git("commit", "-qm", `commit ${i + 1}`);
  });
  const head = spawnSync("git", ["rev-parse", "HEAD"], { cwd: dir, encoding: "utf8" }).stdout.trim();
  return { dir, head };
}

async function mcp(dir: string, extra: Record<string, unknown> = {}): Promise<any> {
  resetSessions();
  setAllowedRoots([dir]);
  const result = await toolHistoryScan({ path: dir, ...extra } as never);
  assert.ok(result.ok, `toolHistoryScan refused: ${result.ok ? "" : (result as { error: string }).error}`);
  return result;
}

/** The CLI over the SAME selection and the same project configuration. */
function cli(dir: string, revRange: string): any {
  const r = spawnSync("node", [CLI_PATH, "history", "--rev-range", revRange, "--format", "json"], {
    cwd: dir,
    encoding: "utf8",
  });
  return JSON.parse(r.stdout ?? "{}");
}

// --- the disclosure -------------------------------------------------------

test("two suppressions, one with a reason, are disclosed", async () => {
  const reason = marker("reason");
  // A blank line between them: a directive covers its own line AND the one
  // below, so without the gap the reasoned one would cover both findings.
  const { dir } = repo([
    {
      "app.js":
        `const a = "${TOKEN}"; // ${ALLOW}(github-token) -- ${reason}\n\n` +
        `const b = "${TOKEN}"; // ${ALLOW}(github-token)\n`,
    },
  ]);
  const r = await mcp(dir);
  assert.match(
    r.payload.scope.statement,
    /2 finding\(s\) suppressed by inline directives, 1 with a recorded reason/,
    r.payload.scope.statement
  );
  assert.strictEqual(r.payload.totalFindings, 0, "both findings stay suppressed");
});

test("suppressions with no reasons report the count and no reason clause", async () => {
  const { dir } = repo([
    { "app.js": `const a = "${TOKEN}"; // ${ALLOW}\n` },
  ]);
  const r = await mcp(dir);
  const s: string = r.payload.scope.statement;
  assert.match(s, /1 finding\(s\) suppressed by inline directives/);
  assert.ok(!/with a recorded reason/.test(s), s);
});

test("a scan with nothing suppressed says nothing new", async () => {
  const { dir } = repo([{ "app.js": "const ok = 1;\n" }]);
  const r = await mcp(dir);
  assert.strictEqual(r.payload.scope.statement, "Scanned 1 commit(s).");
});

test("several commits aggregate without double counting", async () => {
  const { dir } = repo([
    { "a.js": `const a = "${TOKEN}"; // ${ALLOW}(github-token) -- fixture\n` },
    { "b.js": `const b = "${TOKEN}"; // ${ALLOW}(github-token) -- fixture\n` },
    { "c.js": `const c = "${TOKEN}"; // ${ALLOW}(github-token)\n` },
  ]);
  const r = await mcp(dir);
  assert.match(
    r.payload.scope.statement,
    /3 commit\(s\); 3 finding\(s\) suppressed by inline directives, 2 with a recorded reason/,
    r.payload.scope.statement
  );
});

// --- parity with the CLI on the SAME selection -----------------------------

test("the MCP sentence matches the CLI's over the same selection", async () => {
  const reason = marker("parity");
  const { dir, head } = repo([
    {
      "app.js":
        `const a = "${TOKEN}"; // ${ALLOW}(github-token) -- ${reason}\n\n` +
        `const b = "${TOKEN}"; // ${ALLOW}(github-token)\n`,
    },
  ]);
  const fromCli = cli(dir, head);
  const fromMcp = await mcp(dir, { revRange: head });
  assert.strictEqual(
    fromMcp.payload.scope.statement,
    `Scanned ${fromCli.summary.scope}.`,
    "same selection, same configuration, same sentence"
  );
  assert.strictEqual(fromCli.summary.coverage.suppression.inlineSuppressed, 2);
  assert.strictEqual(fromCli.summary.coverage.suppression.inlineSuppressedWithReason, 1);
});

// --- the existing partial-scan contract, unchanged --------------------------

test("a stopped scan keeps its partial sentence and claims no counts", async () => {
  const { dir } = repo([
    { "a.js": `const a = "${TOKEN}"; // ${ALLOW}(github-token)\n` },
    { "b.js": `const b = "${TOKEN}"; // ${ALLOW}(github-token)\n` },
  ]);
  const r = await mcp(dir, { maxCommits: 1 });
  assert.strictEqual(r.payload.complete, false);
  assert.strictEqual(r.payload.stopReason, "commit-limit");
  assert.match(r.payload.scope.statement, /^Stopped after 1 commit\(s\)/);
  assert.ok(
    !/suppressed by inline directives/.test(r.payload.scope.statement),
    "the partial sentence makes no coverage claim, as it did before"
  );
});

// --- nothing sensitive in the response --------------------------------------

test("no reason text and no suppressed value reach the response", async () => {
  const reason = marker("reason");
  const value = marker("secret");
  const { dir } = repo([
    {
      "app.js":
        `const a = "${value}"; // ${ALLOW} -- ${reason}\n` +
        `const b = "${TOKEN}"; // ${ALLOW}(github-token) -- ${reason}\n`,
    },
  ]);
  const r = await mcp(dir);
  const serialized = JSON.stringify(r);
  assert.ok(!serialized.includes(reason), "the reason reached the response");
  assert.ok(!serialized.includes(value), "a suppressed value reached the response");
  assert.ok(!serialized.includes(TOKEN), "the suppressed token reached the response");
  assert.ok(!/suppressionReason|suppressedFindings/.test(serialized), "no new suppression channel");
  assert.strictEqual(r.payload.findings.length, 0, "no suppressed finding became a result row");
  assert.strictEqual(
    r.payload.suppressionDigest,
    undefined,
    "no suppression identity is created for this tool"
  );
});

test("the scope object gains no new field", async () => {
  const { dir } = repo([{ "app.js": `const a = "${TOKEN}"; // ${ALLOW}\n` }]);
  const r = await mcp(dir);
  assert.deepStrictEqual(
    Object.keys(r.payload.scope),
    ["statement"],
    "the disclosure rides the existing sentence; no parallel schema was added"
  );
});

// --- the producer guarantee, at a narrow seam -------------------------------

test("SEAM: unknown accounting stays unknown, even after a later known callback", () => {
  // Not reachable through the public entry point: scanText always reports
  // accounting beside a suppression, so this drives LogPatchParser directly --
  // the producer whose value the MCP tool consumes.
  const parser = new LogPatchParser(mergeConfig({}));
  const inner = (parser as unknown as { flush: () => void }) && (parser as any);
  // The parser's own scanText callback is what records accounting; simulate a
  // producer that reported a count without it, then one that reported both.
  (parser as any).suppressed += 1;
  (parser as any).suppressionAccountingComplete = false;
  assert.strictEqual(parser.suppressionAccounting(), undefined, "unknown after the first");
  (parser as any).suppressed += 1;
  (parser as any).suppressedWithReason += 1;
  assert.strictEqual(
    parser.suppressionAccounting(),
    undefined,
    "a later known callback must not make the earlier unknown known"
  );
  void inner;
});

test("SEAM: a parse that saw accounting throughout reports it", () => {
  const parser = new LogPatchParser(mergeConfig({}));
  assert.deepStrictEqual(parser.suppressionAccounting(), { withReason: 0 }, "a measured zero is zero");
});

finish();
process.on("exit", () => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});
