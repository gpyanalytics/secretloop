import { test, suite, finish, assert } from "./harness";
import { spawnSync } from "child_process";
import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import * as path from "path";
import { positiveSamples } from "./fixtures";
import { scanText } from "../src/scanner";
import { defaultConfig } from "../src/config";

/**
 * `secretloop mask` — a filter for pasting logs and config somewhere else.
 *
 * The design constraints are what the tests are about: masked text goes to
 * stdout and nothing else does, so `| pbcopy` cannot capture a summary line;
 * the whole input is read before scanning, so a PEM block split across reads is
 * impossible by construction rather than by luck; and it exits 0 on success
 * always, because a transform that fails the build is not a transform.
 */

const CLI = path.join(__dirname, "..", "out", "cli.js");

function mask(input: string | Buffer, args: string[] = [], cwd?: string) {
  // No encoding: spawnSync then returns Buffers, which is what a byte-count
  // assertion on stdout needs. ("buffer" is not a valid encoding string.)
  const r = spawnSync("node", [CLI, "mask", ...args], { input, cwd });
  return {
    status: r.status,
    stdout: r.stdout.toString("utf8"),
    stderr: r.stderr.toString("utf8"),
    stdoutBytes: r.stdout.length,
  };
}

// ---------------------------------------------------------------------------
suite("mask — the transform");

test("replaces every secret with [REDACTED:<ruleId>] and leaves the rest alone", () => {
  const gh = positiveSamples["github-token"];
  const stripe = positiveSamples["stripe-secret-key"];
  const input = `line one\nconst t = "${gh}";\nmiddle\nconst s = "${stripe}";\nlast\n`;
  const out = mask(input);
  assert.strictEqual(out.status, 0, out.stderr);
  assert.strictEqual(
    out.stdout,
    'line one\nconst t = "[REDACTED:github-token]";\nmiddle\nconst s = "[REDACTED:stripe-secret-key]";\nlast\n'
  );
});

test("a PEM block is masked whole, not line by line", () => {
  const pem = positiveSamples["private-key-block"] ?? positiveSamples["pem-key"];
  assert.ok(pem, "no PEM fixture");
  const out = mask(`before\n${pem}\nafter\n`);
  assert.strictEqual(out.status, 0, out.stderr);
  assert.ok(!out.stdout.includes("MIIE") && !/[A-Za-z0-9+/]{60,}/.test(out.stdout),
    `PEM body survived:\n${out.stdout}`);
  assert.match(out.stdout, /\[REDACTED:/);
});

test("empty input produces empty output and exits 0", () => {
  const out = mask("");
  assert.strictEqual(out.status, 0);
  assert.strictEqual(out.stdout, "");
});

test("input with no secrets passes through byte-identical", () => {
  const input = "const a = 1;\nconst b = 2;\n\ttabbed\r\ncrlf\n";
  const out = mask(input);
  assert.strictEqual(out.status, 0);
  assert.strictEqual(out.stdout, input);
});

// ---------------------------------------------------------------------------
suite("mask — stdout carries the transform and nothing else");

test("the summary goes to stderr, so a pipe never captures it", () => {
  const out = mask(`const t = "${positiveSamples["github-token"]}";\n`);
  assert.doesNotMatch(out.stdout, /masked/i, `summary leaked into stdout:\n${out.stdout}`);
  assert.match(out.stderr, /masked 1 finding\(s\)/);
  assert.match(out.stderr, /github-token/);
});

test("no secret from the fixture corpus survives to stdout", () => {
  // Ground truth is what the scanner captured, not arbitrary long substrings of
  // the fixture. The first version of this asserted on any 20+ character run and
  // failed on `aws_secret_access_key` -- the variable NAME, which masking leaves
  // in place on purpose: the point is to remove the credential while keeping
  // enough context to know one was there.
  const values = Object.values(positiveSamples);
  const input = values.map((v, i) => `line${i}: ${v}`).join("\n") + "\n";
  const out = mask(input, ["--entropy"]);
  assert.strictEqual(out.status, 0, out.stderr);

  const captured = scanText(input, {
    config: { ...defaultConfig, entropyPassEnabled: true },
  }).map((f) => f.value);
  assert.ok(captured.length > 30, `only ${captured.length} values captured; the check is thin`);

  const leaked = captured.filter((v) => out.stdout.includes(v));
  assert.deepStrictEqual(leaked, [], `${leaked.length} captured value(s) survived masking`);
});

// ---------------------------------------------------------------------------
suite("mask — refusals are loud and produce no output");

test("oversize input refuses with exit 2 and writes nothing to stdout", () => {
  const big = "a".repeat(1_000_001);
  const out = mask(big);
  assert.strictEqual(out.status, 2);
  assert.strictEqual(out.stdoutBytes, 0, "a refused input still emitted stdout");
  assert.match(out.stderr, /too large/i);
});

test("binary input refuses with exit 2 and writes nothing to stdout", () => {
  const bin = Buffer.concat([Buffer.from("prefix\n"), Buffer.from([0x00, 0x01, 0x02]), Buffer.from("tail")]);
  const out = mask(bin);
  assert.strictEqual(out.status, 2);
  assert.strictEqual(out.stdoutBytes, 0, "binary input was passed through");
  assert.match(out.stderr, /binary/i);
});

// ---------------------------------------------------------------------------
suite("mask — tiers and configuration");

test("the entropy tier is OFF by default and --entropy turns it on", () => {
  const blob = 'const x = "Zr7Kq2Vh9Lm4Xt6Bn8WdQp1Sx3Tj5YcAb9Cd";\n';
  const off = mask(blob);
  const on = mask(blob, ["--entropy"]);
  assert.strictEqual(off.stdout, blob, "the entropy tier masked by default");
  assert.match(on.stdout, /\[REDACTED:generic-high-entropy\]/);
});

test("help states the inversion rather than leaving it surprising", () => {
  const h = spawnSync("node", [CLI, "--help"], { encoding: "utf8" }).stdout;
  assert.match(h, /mask/);
  assert.match(h, /--entropy/);
});

test("a project config's allowValues and excludeRules are honoured", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-mask-"));
  try {
    const gh = positiveSamples["github-token"];
    writeFileSync(path.join(dir, ".secretloop.json"), JSON.stringify({ excludeRules: ["github-token"] }), "utf8");
    const out = mask(`const t = "${gh}";\n`, [], dir);
    assert.strictEqual(out.stdout, `const t = "${gh}";\n`, "excludeRules was ignored");
    writeFileSync(path.join(dir, ".secretloop.json"), JSON.stringify({ allowValues: [gh] }), "utf8");
    const out2 = mask(`const t = "${gh}";\n`, [], dir);
    assert.strictEqual(out2.stdout, `const t = "${gh}";\n`, "allowValues was ignored");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
suite("mask — the clipboard is read on demand and nowhere else");

test("clipboard.readText appears exactly once, inside the command handler", () => {
  // Structural, not a promise. A secret scanner that watched the clipboard
  // would be indistinguishable from the thing it warns about, so the guarantee
  // is "there is one call site and it is in a command handler" -- which is a
  // property of the source, checkable here.
  const { readFileSync } = require("fs") as typeof import("fs");
  const src = readFileSync(path.join(__dirname, "..", "src", "extension.ts"), "utf8");
  const reads = [...src.matchAll(/clipboard\.readText\s*\(/g)];
  assert.strictEqual(reads.length, 1, `clipboard.readText has ${reads.length} call sites; expected 1`);

  // ...and it is inside registerCommand("secretloop.maskClipboard", ...).
  const cmd = src.indexOf('registerCommand("secretloop.maskClipboard"');
  assert.ok(cmd !== -1, "the maskClipboard command is gone");
  const nextCmd = src.indexOf("registerCommand(", cmd + 20);
  assert.ok(
    reads[0].index! > cmd && (nextCmd === -1 || reads[0].index! < nextCmd),
    "the clipboard read is not inside the maskClipboard handler"
  );

  // No listener or timer could reach it either.
  for (const watcher of [/onDidChangeClipboard/, /setInterval\s*\(/, /setTimeout\s*\([^)]*clipboard/i]) {
    assert.doesNotMatch(src, watcher, `extension.ts matches ${watcher}`);
  }
});

test("the command is contributed, so it is reachable from the palette", () => {
  const { readFileSync } = require("fs") as typeof import("fs");
  const pkg = JSON.parse(readFileSync(path.join(__dirname, "..", "package.json"), "utf8"));
  const cmd = pkg.contributes.commands.find((c: any) => c.command === "secretloop.maskClipboard");
  assert.ok(cmd, "secretloop.maskClipboard is registered but not contributed");
  assert.match(cmd.title, /Mask Secrets in Clipboard/);
});

finish();
