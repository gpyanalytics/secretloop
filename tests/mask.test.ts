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

test("a project config cannot disable masking, whichever knob it reaches for", () => {
  // This test used to assert the opposite, and the behaviour it pinned was the
  // defect: config came from loadConfig(findRepoRoot(process.cwd())), so
  // whichever repository you were standing in decided what got scrubbed.
  // `{"allowValues":[".*"]}` in a cloned repo turned
  // `kubectl logs prod | secretloop mask | pbcopy` into a passthrough that
  // reported "masked 0 finding(s)".
  //
  // A stream piped through a scrubber is not that repository's findings. Rule
  // selection is a property of the transform now, and no file on disk widens it.
  const gh = positiveSamples["github-token"];
  const input = `const t = "${gh}";\n`;
  const hostile: Array<[string, unknown]> = [
    ["allowValues matching everything", { allowValues: [".*"] }],
    ["allowValues naming the value", { allowValues: [gh] }],
    ["excludeRules disabling the rule", { excludeRules: ["github-token"] }],
    ["entropyPassEnabled off", { entropyPassEnabled: false }],
  ];
  for (const [label, config] of hostile) {
    const dir = mkdtempSync(path.join(tmpdir(), "secretloop-mask-"));
    try {
      writeFileSync(path.join(dir, ".secretloop.json"), JSON.stringify(config), "utf8");
      const out = mask(input, [], dir);
      assert.strictEqual(out.status, 0, `${label}: ${out.stderr}`);
      assert.ok(
        !out.stdout.includes(gh),
        `${label} let the credential through to stdout:\n${out.stdout}`
      );
      assert.match(out.stdout, /\[REDACTED:github-token\]/, `${label} suppressed the mask`);
      assert.match(out.stderr, /masked 1 finding\(s\)/, `${label} also suppressed the count`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

test("a malformed project config still does not stop a mask", () => {
  // The fallback the old code needed is now the only path, so this cannot
  // regress into reading the file again -- but a config that cannot be parsed
  // must still not turn into a crash on someone's pipe.
  const gh = positiveSamples["github-token"];
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-mask-"));
  try {
    writeFileSync(path.join(dir, ".secretloop.json"), "{ not json", "utf8");
    const out = mask(`const t = "${gh}";\n`, [], dir);
    assert.strictEqual(out.status, 0, out.stderr);
    assert.match(out.stdout, /\[REDACTED:github-token\]/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
suite("mask — an inline directive does not silence the scrubber");

test("a trailing gitleaks:allow does not put the credential on stdout", () => {
  // scanText honours secretloop:allow / gitleaks:allow on the matching line and
  // the line below. A suppressed match never enters `findings`, so maskFindings
  // had nothing to redact and the summary said "masked 0 finding(s)" -- the
  // credential on stdout, described as an absence of them.
  //
  // The annotation exists BECAUSE the value beside it is real and someone
  // accepted it, which is what makes honouring it here the wrong reading. It is
  // a triage decision about a repository, and this is a stream.
  const gh = positiveSamples["github-token"];
  const out = mask(`token = "${gh}" # gitleaks:allow\n`);
  assert.strictEqual(out.status, 0, out.stderr);
  assert.ok(!out.stdout.includes(gh), `the credential reached stdout:\n${out.stdout}`);
  assert.match(out.stdout, /\[REDACTED:github-token\]/);
  assert.match(out.stderr, /masked 1 finding\(s\)/, "the mask happened but was not counted");
  // The directive itself is content and is left alone; only its effect is gone.
  assert.match(out.stdout, /# gitleaks:allow/);
});

test("the above-the-line form does not either", () => {
  const gh = positiveSamples["github-token"];
  const out = mask(`# secretloop:allow\ntoken = "${gh}"\n`);
  assert.strictEqual(out.status, 0, out.stderr);
  assert.ok(!out.stdout.includes(gh), `the credential reached stdout:\n${out.stdout}`);
  assert.match(out.stdout, /\[REDACTED:github-token\]/);
  assert.match(out.stderr, /masked 1 finding\(s\)/);
});

test("every directive spelling is neutralised, on both lines, for both tiers", () => {
  const gh = positiveSamples["github-token"];
  const blob = "Zr7Kq2Vh9Lm4Xt6Bn8WdQp1Sx3Tj5YcAb9Cd";
  for (const directive of ["secretloop:allow", "secretloop-ignore", "gitleaks:allow"]) {
    for (const [label, input] of [
      ["same line", `token = "${gh}" // ${directive}\n`],
      ["line above", `// ${directive}\ntoken = "${gh}"\n`],
    ] as const) {
      const out = mask(input);
      assert.ok(
        !out.stdout.includes(gh),
        `${directive} (${label}) leaked the credential:\n${out.stdout}`
      );
    }
    // The entropy tier reads the same set of ignored lines, so it has to be
    // covered too -- the guard is one site precisely so these cannot diverge.
    const entropyOut = mask(`blob = "${blob}" // ${directive}\n`, ["--entropy"]);
    assert.ok(
      !entropyOut.stdout.includes(blob),
      `${directive} leaked an entropy-tier value:\n${entropyOut.stdout}`
    );
  }
});

test("scanning still honours directives — only mask opts out", () => {
  // The guard is scoped to the transform. A repository scan that stopped
  // honouring annotations would re-report every finding a team dismissed.
  const gh = positiveSamples["github-token"];
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-mask-"));
  try {
    writeFileSync(path.join(dir, "app.js"), `const t = "${gh}"; // gitleaks:allow\n`, "utf8");
    const res = spawnSync("node", [CLI, "scan", "--format", "json", "--path", dir], {
      encoding: "utf8",
    });
    const d = JSON.parse(res.stdout);
    assert.strictEqual(d.summary.total, 0, "scan stopped honouring inline directives");
    assert.match(d.summary.scope, /1 finding\(s\) suppressed by inline directives/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
suite("mask — a malformed invocation is reported, not ignored");

test("an unknown option exits 2 and masks nothing", () => {
  // main() dispatched mask before validateArgs, and validateArgs is the only
  // reader of args.errors -- so every parse error was discarded for the one
  // command whose failure mode is an unmasked secret. `mask --entropoy` masked
  // with the generic tier off and exited 0.
  const gh = positiveSamples["github-token"];
  const out = mask(`token = "${gh}"\n`, ["--entropoy", "--no-such-flag"]);
  assert.strictEqual(out.status, 2, `expected exit 2, got ${out.status}`);
  assert.strictEqual(out.stdoutBytes, 0, "a refused invocation still wrote to stdout");
  assert.match(out.stderr, /unknown option --entropoy/);
});

test("a flag given no value is reported too", () => {
  const out = mask("x\n", ["--format"]);
  assert.strictEqual(out.status, 2);
  assert.strictEqual(out.stdoutBytes, 0);
  assert.match(out.stderr, /--format requires a value/);
});

test("the flags mask really takes still work", () => {
  const blob = 'const x = "Zr7Kq2Vh9Lm4Xt6Bn8WdQp1Sx3Tj5YcAb9Cd";\n';
  const on = mask(blob, ["--entropy"]);
  assert.strictEqual(on.status, 0, on.stderr);
  assert.match(on.stdout, /\[REDACTED:generic-high-entropy\]/);
  assert.strictEqual(mask("x\n", ["--help"]).status, 0, "--help must still be answerable");
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
