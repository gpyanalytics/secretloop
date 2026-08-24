import { scanWorkspaceFiles, scanFiles, verifyScannedFiles } from "../src/workspace";
import { mergeConfig } from "../src/config";
import { test, suite, finish, assert } from "./harness";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { spawnSync } from "child_process";
import * as path from "path";

const GH_TOKEN = 'const t = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";\n';

/** A real repo, because the enumeration depends on real git state. */
function withRepo(fn: (dir: string, git: (...a: string[]) => void) => void): void {
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-ws-test-"));
  const git = (...args: string[]) => {
    const res = spawnSync("git", args, { cwd: dir, encoding: "utf8" });
    if (res.status !== 0) throw new Error(`git ${args.join(" ")}: ${res.stderr}`);
  };
  try {
    git("init", "-q");
    git("config", "user.email", "t@example.com");
    git("config", "user.name", "t");
    fn(dir, git);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const mockFetch = ((async () => ({
  status: 200,
  json: async () => ({}),
  text: async () => "",
  headers: { get: () => null },
})) as unknown) as typeof fetch;

suite("workspace.ts — one path for the editor and the CLI");

test("excludePaths from the project config is honoured", () => {
  // The editor used a hardcoded exclusion list and ignored the user's config
  // entirely, so a path excluded in .secretloop.json was still scanned there
  // and not in CI — the divergence the config comment promises cannot happen.
  withRepo((dir) => {
    mkdirSync(path.join(dir, "fixtures"));
    writeFileSync(path.join(dir, "fixtures", "sample.js"), GH_TOKEN);
    writeFileSync(path.join(dir, "app.js"), GH_TOKEN);
    const config = mergeConfig({ excludePaths: ["fixtures/**"] });
    const scanned = scanWorkspaceFiles(dir, config);
    assert.deepStrictEqual(scanned.map((s) => s.path), ["app.js"]);
  });
});

test("maxFileSizeBytes is honoured", () => {
  withRepo((dir) => {
    writeFileSync(path.join(dir, "big.js"), GH_TOKEN + "x".repeat(5000));
    writeFileSync(path.join(dir, "small.js"), GH_TOKEN);
    const scanned = scanWorkspaceFiles(dir, mergeConfig({ maxFileSizeBytes: 1000 }));
    assert.deepStrictEqual(scanned.map((s) => s.path), ["small.js"]);
  });
});

test("binary files are skipped", () => {
  withRepo((dir) => {
    writeFileSync(path.join(dir, "blob.bin"), Buffer.from([0x00, 0x01, 0x02, 0x00]));
    writeFileSync(path.join(dir, "app.js"), GH_TOKEN);
    const scanned = scanWorkspaceFiles(dir, mergeConfig({}));
    assert.deepStrictEqual(scanned.map((s) => s.path), ["app.js"]);
  });
});

test("gitignored files are not scanned", () => {
  withRepo((dir, git) => {
    writeFileSync(path.join(dir, ".gitignore"), "ignored.js\n");
    writeFileSync(path.join(dir, "ignored.js"), GH_TOKEN);
    writeFileSync(path.join(dir, "app.js"), GH_TOKEN);
    git("add", ".gitignore");
    git("commit", "-qm", "ignore");
    const scanned = scanWorkspaceFiles(dir, mergeConfig({}));
    assert.ok(!scanned.some((s) => s.path === "ignored.js"), "gitignored must stay out of scope");
    assert.ok(scanned.some((s) => s.path === "app.js"));
  });
});

test("findings carry the repo-relative path", () => {
  withRepo((dir) => {
    mkdirSync(path.join(dir, "src"));
    writeFileSync(path.join(dir, "src", "app.js"), GH_TOKEN);
    const scanned = scanWorkspaceFiles(dir, mergeConfig({}));
    const hit = scanned.flatMap((s) => s.findings).find((f) => f.ruleId === "github-token");
    assert.ok(hit);
    assert.strictEqual(hit!.file, "src/app.js");
  });
});

suite("\nworkspace.ts — unsaved editor buffers");

test("a secret only in an unsaved buffer is found", () => {
  // A miss only the editor can have: the file on disk is clean, the buffer the
  // user is looking at is not, and reading from disk would report nothing.
  withRepo((dir) => {
    writeFileSync(path.join(dir, "app.js"), "const t = 1;\n");
    const scanned = scanWorkspaceFiles(dir, mergeConfig({}), {
      textFor: (p) => (p === "app.js" ? GH_TOKEN : undefined),
    });
    const hit = scanned.flatMap((s) => s.findings).find((f) => f.ruleId === "github-token");
    assert.ok(hit, "the unsaved buffer must be scanned");
  });
});

test("the disk version does not shadow an unsaved buffer", () => {
  // The inverse: disk holds an old secret, the buffer has replaced it. Reporting
  // the disk finding would send someone to rotate something already gone.
  withRepo((dir) => {
    writeFileSync(path.join(dir, "app.js"), GH_TOKEN);
    const scanned = scanWorkspaceFiles(dir, mergeConfig({}), {
      textFor: (p) => (p === "app.js" ? "const t = process.env.TOKEN;\n" : undefined),
    });
    assert.strictEqual(
      scanned.flatMap((s) => s.findings).filter((f) => f.ruleId === "github-token").length,
      0,
      "the buffer replaced it, so there is nothing to report"
    );
    assert.strictEqual(scanned[0].text, "const t = process.env.TOKEN;\n");
  });
});

test("textFor returning undefined falls back to disk", () => {
  withRepo((dir) => {
    writeFileSync(path.join(dir, "app.js"), GH_TOKEN);
    const scanned = scanWorkspaceFiles(dir, mergeConfig({}), { textFor: () => undefined });
    assert.ok(scanned.flatMap((s) => s.findings).some((f) => f.ruleId === "github-token"));
  });
});

suite("\nworkspace.ts — an explicit file list");

test("scanFiles reads a caller-supplied list through the same guards", () => {
  // The staged scan gets its list from git, not from enumeration, but must
  // still honour the size and binary guards the CLI applies.
  withRepo((dir) => {
    writeFileSync(path.join(dir, "big.js"), GH_TOKEN + "x".repeat(5000));
    writeFileSync(path.join(dir, "app.js"), GH_TOKEN);
    const scanned = scanFiles(dir, ["big.js", "app.js"], mergeConfig({ maxFileSizeBytes: 1000 }));
    assert.deepStrictEqual(scanned.map((s) => s.path), ["app.js"]);
  });
});

suite("\nworkspace.ts — verification is one pass over the whole scan");

test("the outbound count is the workspace total, not a per-file count", () => {
  // scanWorkspace is the widest fan-out, so an inaccurate number matters most
  // here: it is the record of how many credentials left the machine.
  return (async () => {
    const scanned = ["a.js", "b.js", "c.js"].map((p, i) => ({
      path: p,
      text: "",
      findings: [
        {
          ruleId: "github-token",
          description: "GitHub",
          value: `ghp_${i}`,
          startIndex: 0,
          endIndex: 5,
          confidence: "format-match" as const,
          severity: "critical" as const,
          line: 1,
          file: p,
        },
      ],
    }));
    const sent = await verifyScannedFiles(scanned, mockFetch);
    assert.strictEqual(sent.length, 3, "one batch across every file, counted once");
    assert.deepStrictEqual(sent.map((f) => f.file).sort(), ["a.js", "b.js", "c.js"]);
  })();
});

test("each finding is verified with the text of its own file", () => {
  // The AWS verifier pairs an access key ID with the secret key beside it, so a
  // shared blob would pair a key in one file with a secret in another.
  return (async () => {
    const seen: string[] = [];
    const capturing = ((async (_u: unknown, _i: unknown) => ({
      status: 200,
      json: async () => ({}),
      text: async () => "",
      headers: { get: () => null },
    })) as unknown) as typeof fetch;
    const scanned = ["a.js", "b.js"].map((p) => ({
      path: p,
      text: `contents of ${p}`,
      findings: [
        {
          ruleId: "github-token",
          description: "GitHub",
          value: `ghp_${p}`,
          startIndex: 0,
          endIndex: 5,
          confidence: "format-match" as const,
          severity: "critical" as const,
          line: 1,
          file: p,
        },
      ],
    }));
    await verifyScannedFiles(scanned, capturing, { onContext: (f, ctx) => seen.push(ctx.fullText) });
    assert.deepStrictEqual(seen.sort(), ["contents of a.js", "contents of b.js"]);
  })();
});

finish();
