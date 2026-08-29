import { test, suite, finish, assert } from "./harness";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync, realpathSync } from "fs";
import { tmpdir } from "os";
import { spawnSync } from "child_process";
import * as path from "path";
import { listFilesWithExclusions, readTextFile } from "../src/walk";
import { mergeConfig } from "../src/config";
import { describeScope } from "../src/report";

/**
 * Working-tree scans stay inside the directory they were pointed at.
 *
 * git tracks symlinks (mode 120000), so a clone can contain a link to
 * ~/.aws/credentials. Before this, `git ls-files` listed the link and
 * readTextFile followed it: the target's content was scanned, reported with a
 * path inside the repository, and — with --verify — transmitted to a provider.
 *
 * The rule is containment, not symlink avoidance: a link resolving back inside
 * the scan root is an ordinary file and is still scanned.
 */

const CLI = path.join(__dirname, "..", "out", "cli.js");
const MARKER = "MARKER_OUTSIDE_ONLY_7c4b";

function token(salt = 1): string {
  const a = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let out = "";
  for (let i = 0; i < 36; i++) out += a[(i * 17 + salt * 7 + 5) % a.length];
  return "ghp_" + out;
}

interface Ctx { base: string; repo: string; outside: string; cred: string }

function withWorkspace(fn: (c: Ctx) => void, gitInit = false): void {
  const base = mkdtempSync(path.join(tmpdir(), "secretloop-contain-"));
  try {
    const repo = realpathSync(mkdirSyncP(path.join(base, "repo")));
    const outside = realpathSync(mkdirSyncP(path.join(base, "outside")));
    const cred = token(2);
    writeFileSync(path.join(outside, "creds.txt"), `token = "${cred}"\n${MARKER}\n`, "utf8");
    writeFileSync(path.join(repo, "app.js"), "const ok = 1;\n", "utf8");
    if (gitInit) {
      const git = (...a: string[]) => spawnSync("git", a, { cwd: repo, encoding: "utf8" });
      git("init", "-q", ".");
    }
    fn({ base, repo, outside, cred });
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
}
function mkdirSyncP(p: string): string { mkdirSync(p, { recursive: true }); return p; }

function cli(args: string[], dir: string) {
  const r = spawnSync("node", [CLI, ...args, "--path", dir], { encoding: "utf8" });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}
function commitAll(repo: string) {
  const git = (...a: string[]) => spawnSync("git", a, { cwd: repo, encoding: "utf8" });
  git("add", "-A");
  git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-qm", "x");
}

// ---------------------------------------------------------------------------
suite("containment — a file symlink pointing outside the scan root");

test("is dropped and disclosed, in the non-git walk", () => {
  withWorkspace((c) => {
    symlinkSync(path.join(c.outside, "creds.txt"), path.join(c.repo, "link.txt"));
    const out = cli(["scan"], c.repo);
    assert.match(out.stdout, /No secrets found/, `the outside file was scanned:\n${out.stdout}`);
    assert.match(
      out.stdout,
      /1 file\(s\) excluded \(symlinks resolving outside the scan root\)/,
      `the drop was silent:\n${out.stdout}`
    );
  });
});

test("is dropped and disclosed, in the git-tracked walk", () => {
  withWorkspace((c) => {
    symlinkSync(path.join(c.outside, "creds.txt"), path.join(c.repo, "link.txt"));
    commitAll(c.repo);
    const out = cli(["scan"], c.repo);
    assert.match(out.stdout, /No secrets found/, `git ls-files path leaked:\n${out.stdout}`);
    assert.match(out.stdout, /file\(s\) excluded \(symlinks resolving outside the scan root\)/);
  }, true);
});

test("a directory symlink exposes nothing beneath it", () => {
  withWorkspace((c) => {
    symlinkSync(c.outside, path.join(c.repo, "linkdir"));
    const out = cli(["scan", "--format", "json"], c.repo);
    const d = JSON.parse(out.stdout);
    const files: string[] = d.findings.map((f: any) => f.file);
    assert.ok(!files.some((f) => f.startsWith("linkdir")), `walked the outside tree: ${files}`);
    assert.strictEqual(d.summary.total, 0);
  });
});

test("a symlink resolving back INSIDE the root is scanned normally", () => {
  // Containment, not symlink-phobia. A filter written as "skip symlinks" passes
  // every other test here and quietly stops scanning legitimate files.
  withWorkspace((c) => {
    const cred = token(5);
    mkdirSync(path.join(c.repo, "real"), { recursive: true });
    writeFileSync(path.join(c.repo, "real", "conf.js"), `const t = "${cred}";\n`, "utf8");
    symlinkSync(path.join(c.repo, "real", "conf.js"), path.join(c.repo, "linked.js"));
    const d = JSON.parse(cli(["scan", "--format", "json"], c.repo).stdout);
    const files: string[] = d.findings.map((f: any) => f.file);
    assert.ok(files.includes("linked.js"), `an in-root symlink was dropped: ${files}`);
    assert.doesNotMatch(
      cli(["scan"], c.repo).stdout,
      /excluded \(symlinks resolving outside/,
      "an in-root symlink was counted as outside"
    );
  });
});

test("a broken symlink is dropped, not an error", () => {
  withWorkspace((c) => {
    symlinkSync(path.join(c.outside, "does-not-exist"), path.join(c.repo, "dangling.txt"));
    const out = cli(["scan"], c.repo);
    assert.strictEqual(out.status, 0, `a broken link failed the scan:\n${out.stderr}`);
    assert.match(out.stdout, /No secrets found/);
  });
});

// ---------------------------------------------------------------------------
suite("containment — nothing from outside reaches any output format");

test("the outside credential and a plain marker are absent from text, json and sarif", () => {
  withWorkspace((c) => {
    symlinkSync(path.join(c.outside, "creds.txt"), path.join(c.repo, "link.txt"));
    symlinkSync(c.outside, path.join(c.repo, "linkdir"));
    const all = ["", "--format json", "--format sarif"]
      .map((f) => cli(["scan", ...(f ? f.split(" ") : [])], c.repo))
      .map((r) => r.stdout + r.stderr)
      .join("\n");
    assert.ok(all.length > 200, "captured nothing; the search would pass vacuously");
    assert.ok(!all.includes(c.cred), "the outside credential crossed the boundary");
    assert.ok(!all.includes(MARKER), "ordinary content from the outside file crossed the boundary");
  });
});

test("the walker reports the count alongside the files", () => {
  withWorkspace((c) => {
    symlinkSync(path.join(c.outside, "creds.txt"), path.join(c.repo, "link.txt"));
    const listed = listFilesWithExclusions(c.repo, mergeConfig({}));
    assert.deepStrictEqual(listed.files, ["app.js"]);
    assert.strictEqual(listed.outsideExcluded, 1);
  });
});

test("readTextFile refuses a path that resolves outside, on its own", () => {
  // Defence at the read, not only at the walk: a caller with its own file list
  // (the staged path) never goes through listFiles.
  withWorkspace((c) => {
    symlinkSync(path.join(c.outside, "creds.txt"), path.join(c.repo, "link.txt"));
    assert.strictEqual(readTextFile(c.repo, "link.txt", mergeConfig({})), null);
    assert.ok(readTextFile(c.repo, "app.js", mergeConfig({})) !== null);
  });
});

test("the staged path is covered too", () => {
  withWorkspace((c) => {
    symlinkSync(path.join(c.outside, "creds.txt"), path.join(c.repo, "link.txt"));
    const git = (...a: string[]) => spawnSync("git", a, { cwd: c.repo, encoding: "utf8" });
    git("add", "-A");
    const out = cli(["staged"], c.repo);
    assert.doesNotMatch(out.stdout, /link\.txt/, `staged scan read through the link:\n${out.stdout}`);
    assert.ok(!out.stdout.includes(c.cred) && !out.stdout.includes(MARKER));
  }, true);
});

test("history is not a route to the target — git stores the link text", () => {
  // Re-confirming the pin here rather than inheriting it: git stores a symlink
  // as a mode 120000 blob whose content is the target PATH, so `git log -p`
  // shows "../outside/creds.txt" and never the file behind it.
  withWorkspace((c) => {
    symlinkSync(path.join(c.outside, "creds.txt"), path.join(c.repo, "link.txt"));
    commitAll(c.repo);
    const modes = spawnSync("git", ["ls-files", "-s"], { cwd: c.repo, encoding: "utf8" }).stdout;
    assert.match(modes, /^120000 /m, "git did not store a symlink; the fixture is wrong");
    const out = cli(["history", "--format", "json"], c.repo);
    const d = JSON.parse(out.stdout);
    assert.ok(!JSON.stringify(d).includes(c.cred), "history reached the symlink target");
    assert.ok(!JSON.stringify(d).includes(MARKER));
  }, true);
});

// ---------------------------------------------------------------------------
suite("containment — the scope clause");

test("describeScope carries the clause only when nonzero", () => {
  assert.strictEqual(describeScope(10, "file", {}), "10 file(s)");
  assert.strictEqual(
    describeScope(10, "file", { outsideExcluded: 2 }),
    "10 file(s); 2 file(s) excluded (symlinks resolving outside the scan root)"
  );
  // Clauses compose, in a fixed order, and none of them swallows another.
  const all = describeScope(10, "file", { generatedExcluded: 1, suppressed: 2, outsideExcluded: 3 });
  assert.match(all, /1 generated file\(s\) excluded by default/);
  assert.match(all, /2 finding\(s\) suppressed by inline directives/);
  assert.match(all, /3 file\(s\) excluded \(symlinks resolving outside the scan root\)/);
});

finish();
