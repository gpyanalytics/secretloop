import { test, suite, finish, assert, skip } from "./harness";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync, realpathSync } from "fs";
import { tmpdir } from "os";
import { spawnSync } from "child_process";
import * as path from "path";
import { listFilesWithExclusions, readTextFile, isInsideRoot, relativeEscapes } from "../src/walk";
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

suite("\ncontainment — a name that merely begins with '..' is inside the root");

/*
 * `..env` and `..cfg/` are ordinary names. Containment used to test `rel.startsWith("..")`, so a top-level entry
 * whose name begins with two dots was treated as a path out of the root: dropped from the scan, counted as "resolved
 * outside the scan root" and described as a symlink. Only a first segment that IS `..` leaves the root.
 */
const GENERIC = () => "pass" + 'word = "Qm7vR2xKp9Lw4Tz8Hc3N"\n'; // generic tier only; assembled so no literal sits here

function withDotNames(fn: (root: string, outside: string) => void): void {
  const base = mkdtempSync(path.join(tmpdir(), "secretloop-dotnames-"));
  try {
    const root = realpathSync(mkdirSyncP(path.join(base, "repo")));
    const outside = realpathSync(mkdirSyncP(path.join(base, "outside")));
    for (const rel of ["..env", "..cfg/app.js", "x.env", "sub/..env"]) {
      mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
      writeFileSync(path.join(root, rel), GENERIC(), "utf8");
    }
    writeFileSync(path.join(outside, "x.js"), GENERIC(), "utf8");
    fn(root, outside);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
}

test("isInsideRoot accepts '..'-prefixed names and still refuses a real '../' escape", () => {
  withDotNames((root) => {
    for (const rel of ["..env", "..cfg/app.js", "x.env", "sub/..env"]) {
      assert.strictEqual(isInsideRoot(root, rel), true, `${rel} was treated as outside`);
    }
    assert.strictEqual(isInsideRoot(root, path.join("..", "outside", "x.js")), false, "a real escape was accepted");
  });
});

test("the walk lists top-level '..' names and excludes nothing when nothing escapes", () => {
  withDotNames((root) => {
    const l = listFilesWithExclusions(root, mergeConfig({}));
    assert.deepStrictEqual([...l.files].sort(), ["..cfg/app.js", "..env", "sub/..env", "x.env"]);
    assert.strictEqual(l.outsideExcluded, 0, "a '..' name was counted as resolved outside the root");
  });
});

test("the reader opens a top-level '..' name", () => {
  withDotNames((root) => {
    assert.notStrictEqual(readTextFile(root, "..env", mergeConfig({})), null, "readTextFile refused ..env as outside");
  });
});

test("a CLI scan reports '..' names, stays complete, and says nothing about escapes", () => {
  withDotNames((root) => {
    const r = spawnSync("node", [CLI, "scan", ".", "--format", "json", "--fail-on", "never"], { cwd: root, encoding: "utf8" });
    assert.strictEqual(r.status, 0, r.stderr);
    const j = JSON.parse(r.stdout);
    const files = [...new Set(j.findings.map((f: { file: string }) => f.file))].sort();
    assert.deepStrictEqual(files, ["..cfg/app.js", "..env", "sub/..env", "x.env"]);
    assert.strictEqual(j.incomplete, false, `limitations: ${JSON.stringify(j.summary.coverage?.limitations)}`);
    assert.ok(!/outside the scan root/.test(j.summary.scope), `scope says: ${j.summary.scope}`);
  });
});

test("a staged top-level '..env' is scanned by the staged scan, as the pre-commit hook runs it", () => {
  withDotNames((root) => {
    const git = (...a: string[]) => spawnSync("git", a, { cwd: root, encoding: "utf8" });
    git("init", "-q");
    git("add", "..env", "x.env");
    const r = spawnSync("node", [CLI, "staged", "--format", "json", "--fail-on", "never"], { cwd: root, encoding: "utf8" });
    assert.strictEqual(r.status, 0, r.stderr);
    const j = JSON.parse(r.stdout);
    const files = [...new Set(j.findings.map((f: { file: string }) => f.file))].sort();
    assert.deepStrictEqual(files, ["..env", "x.env"], `a staged ..env was refused: ${JSON.stringify(files)}`);
    assert.strictEqual(j.incomplete, false, `limitations: ${JSON.stringify(j.summary.coverage?.limitations)}`);
  });
});

test("control: with a real outside link present, only the link is excluded and described", () => {
  withDotNames((root, outside) => {
    try {
      symlinkSync(path.join(outside, "x.js"), path.join(root, "link.js"));
    } catch (err: any) {
      if (err?.code === "EPERM" || err?.code === "EACCES") skip("this account may not create symlinks");
      throw err;
    }
    const l = listFilesWithExclusions(root, mergeConfig({}));
    assert.strictEqual(l.outsideExcluded, 1);
    assert.ok(l.files.includes("..env") && !l.files.includes("link.js"));
    const r = spawnSync("node", [CLI, "scan", ".", "--format", "json", "--fail-on", "never"], { cwd: root, encoding: "utf8" });
    const j = JSON.parse(r.stdout);
    assert.match(j.summary.scope, /1 file\(s\) excluded \(symlinks resolving outside the scan root\)/);
    assert.ok(j.findings.some((f: { file: string }) => f.file === "..env"));
  });
});

test("relativeEscapes reads the first segment with this platform's separator", () => {
  assert.strictEqual(relativeEscapes(".."), true);
  assert.strictEqual(relativeEscapes(path.join("..", "x")), true);
  assert.strictEqual(relativeEscapes(path.resolve("/x")), true, "an absolute result is an escape");
  for (const name of ["..env", path.join("..cfg", "app.js"), "...", path.join("sub", "..env"), "x"]) {
    assert.strictEqual(relativeEscapes(name), false, `${name} was read as an escape`);
  }
  // A backslash separates segments only on Windows; on POSIX it is part of a file name.
  assert.strictEqual(relativeEscapes("..\\x"), process.platform === "win32");
});

suite("\ncontainment — the fallback walk lists a directory link and never walks it");

/*
 * Outside git, the walk enumerates the tree itself, and it followed every directory link: one link to `.` scanned
 * each file once per level until the OS refused to resolve the path (33 times on macOS), two such links multiplied
 * that until the scan never finished, and a link to `..` enumerated the parent's whole tree only to refuse it file by
 * file. It now lists a directory reached through a link as one entry, as `git ls-files` does: inside the root it is
 * "not a regular file", outside it is excluded as resolving outside the scan root. Real directories are walked as
 * before, and file links are unchanged. The two-link case runs in a child process with a hard timeout, so the
 * unchanged code fails the test instead of hanging the suite.
 */
const LINK_GENERIC = () => "pass" + 'word = "Qm7vR2xKp9Lw4Tz8Hc3N"\n';

function dirLinkOrSkip(target: string, at: string): void {
  try {
    symlinkSync(target, at, "dir");
  } catch (err: any) {
    if (err?.code === "EPERM" || err?.code === "EACCES") skip("this account may not create directory symlinks");
    throw err;
  }
}

function boundedScan(dir: string): { status: number | null; report?: { findings: Array<{ file: string }>; summary: any; incomplete: boolean } } {
  const r = spawnSync("node", [CLI, "scan", ".", "--format", "json", "--fail-on", "never"], {
    cwd: dir,
    encoding: "utf8",
    timeout: 20000,
    killSignal: "SIGKILL",
    maxBuffer: 1 << 26,
  });
  return r.status === 0 ? { status: 0, report: JSON.parse(r.stdout) } : { status: r.status };
}

const scannedFiles = (r: { findings: Array<{ file: string }> }) => r.findings.map((f) => f.file).sort();

test("a link to '.' is listed once and scanned nothing twice", () => {
  withWorkspace((c) => {
    writeFileSync(path.join(c.repo, "a.js"), LINK_GENERIC(), "utf8");
    dirLinkOrSkip(".", path.join(c.repo, "self"));
    const l = listFilesWithExclusions(c.repo, mergeConfig({}));
    assert.deepStrictEqual([...l.files].sort(), ["a.js", "app.js", "self"], "the walk descended through the link");
    const r = boundedScan(c.repo);
    assert.strictEqual(r.status, 0, "the scan did not finish");
    assert.deepStrictEqual(scannedFiles(r.report!), ["a.js"], "a file was scanned more than once");
  });
});

test("two links to '.' do not hang the scan", () => {
  withWorkspace((c) => {
    writeFileSync(path.join(c.repo, "a.js"), LINK_GENERIC(), "utf8");
    dirLinkOrSkip(".", path.join(c.repo, "s1"));
    dirLinkOrSkip(".", path.join(c.repo, "s2"));
    const r = boundedScan(c.repo);
    assert.strictEqual(r.status, 0, "the scan did not finish within 20 s");
    assert.deepStrictEqual(scannedFiles(r.report!), ["a.js"]);
  });
});

test("a link to '..' is one exclusion, and nothing of the parent is enumerated", () => {
  withWorkspace((c) => {
    writeFileSync(path.join(c.repo, "a.js"), LINK_GENERIC(), "utf8");
    dirLinkOrSkip("..", path.join(c.repo, "up"));
    const l = listFilesWithExclusions(c.repo, mergeConfig({}));
    assert.deepStrictEqual([...l.files].sort(), ["a.js", "app.js"]);
    assert.strictEqual(l.outsideExcluded, 1, "the parent's files were enumerated and refused one by one");
    const r = boundedScan(c.repo);
    assert.match(r.report!.summary.scope, /1 file\(s\) excluded \(symlinks resolving outside the scan root\)/);
    assert.deepStrictEqual(scannedFiles(r.report!), ["a.js"]);
  });
});

test("a link to a real directory inside the root does not scan it a second time", () => {
  withWorkspace((c) => {
    mkdirSync(path.join(c.repo, "sub"), { recursive: true });
    writeFileSync(path.join(c.repo, "sub", "x.js"), LINK_GENERIC(), "utf8");
    dirLinkOrSkip("sub", path.join(c.repo, "lnk"));
    const r = boundedScan(c.repo);
    assert.strictEqual(r.status, 0);
    assert.deepStrictEqual(scannedFiles(r.report!), ["sub/x.js"], "the linked directory was scanned again");
    assert.strictEqual(r.report!.incomplete, true, "the unwalked link is disclosed, as git's listing of it is");
    assert.ok(JSON.stringify(r.report!.summary.coverage?.limitations).includes("not a regular file"));
  });
});

finish();
