import { test, suite, finish, assert } from "./harness";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { spawnSync } from "child_process";
import * as path from "path";
import { scanText, Finding, ENTROPY_RULE_ID } from "../src/scanner";
import { defaultConfig, SecretLoopConfig } from "../src/config";

/**
 * 0.1.5 — N8, the key-context gate.
 *
 * When enabled, the generic entropy tier reports a QUOTED string literal only
 * if the identifier it is assigned to carries a secret-like word. It is the
 * third gate on this tier, after N7a (ordered runs) and N7b (identifier paths),
 * and unlike those two it ships OFF.
 *
 * WHY IT SHIPS OFF, recorded here because the reason is a measurement result
 * and not a preference: the number that would justify a default-on gate is the
 * fraction of TRUE POSITIVES it suppresses, and that number cannot be measured
 * with available data. The two real-world proxies bracket it from opposite
 * sides by selection bias -- identifiers taken from a keyword-anchored
 * detector's own hits word-match 100% by construction, and identifiers taken
 * from all high-entropy strings in real packages word-match ~10% because that
 * population is overwhelmingly hashes and resource IDs rather than secrets.
 * Any threshold placed between those two is chosen, not measured. So the gate
 * is opt-in, its false-positive reduction is reported as a figure rather than
 * defended against a bar, and the decision is left to whoever knows how their
 * own repository names things.
 *
 * THE HARD PROHIBITION, which no percentage can buy out: the identifier must
 * come from source text strictly OUTSIDE the candidate's span. The previous
 * attempt derived it from the candidate itself -- an FCM registration token
 * reads AAAA<id>:APA91b<rest>, the bare-assignment pattern split it at the
 * token's OWN colon, and a real credential was then gated on half of itself.
 * The first suite below is that prohibition, and it fails the slice on its own.
 */

// ---------------------------------------------------------------- generators

let seed = 20260902;
function rand(): number {
  // xorshift32, matching tests/fixtures.ts and tests/entropy-precision.test.ts.
  seed ^= seed << 13;
  seed ^= seed >>> 17;
  seed ^= seed << 5;
  return Math.abs(seed) / 2 ** 31;
}
const ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/** A uniform draw. Credential-shaped values are generated, never written. */
function gen(n: number, alphabet = ALNUM): string {
  let out = "";
  for (let i = 0; i < n; i++) out += alphabet[Math.floor(rand() * alphabet.length)];
  return out;
}

// Drawn once, in this order, so every constant below is stable across runs.

/** The ONE literal used for all three placements. */
const SECRET = gen(40);

/**
 * A Firebase Cloud Messaging server key, the shape that broke the last attempt.
 * Matches `firebase-cloud-messaging-key`, and carries a colon at a fixed offset
 * with a bare identifier-shaped run in front of it.
 */
const FCM = "AAAA" + gen(7) + ":APA91b" + gen(140);

/**
 * The same hazard inside a QUOTED candidate. A colon cannot appear in one --
 * it is outside the entropy tier's character class, so a colon-bearing quoted
 * string is never a candidate in the first place -- but `=` is inside that
 * class, so `"<word>=<random>"` is one single candidate whose own text carries
 * an identifier-shaped run in front of a separator. This is the quoted-literal
 * form of the FCM hazard, and the one the gate can actually reach.
 */
const EQ_TOKEN_NEUTRAL = "Zk" + gen(9) + "=" + gen(40);

/**
 * The sharpest form: the word-list word `secret` sits INSIDE the value, and the
 * identifier outside it does not. If resolution ever reads the candidate's own
 * text, this reports; it must be suppressed.
 */
const EQ_TOKEN_WORDED = "secret=" + gen(40);

// ------------------------------------------------------------------ helpers

const GATE_ON: SecretLoopConfig = {
  ...defaultConfig,
  keyContextRequired: true,
} as SecretLoopConfig;

const GATE_OFF: SecretLoopConfig = { ...defaultConfig } as SecretLoopConfig;

function scan(text: string, config: SecretLoopConfig): Finding[] {
  return scanText(text, { config });
}

function entropyFindings(text: string, config: SecretLoopConfig): Finding[] {
  return scan(text, config).filter((f) => f.ruleId === ENTROPY_RULE_ID);
}

function ruleIds(text: string, config: SecretLoopConfig): string[] {
  return scan(text, config).map((f) => f.ruleId);
}

/** Asserts the gate-off control first, so a suppression claim cannot be vacuous. */
function assertSuppressedOnlyWhenGated(text: string, label: string): void {
  assert.strictEqual(
    entropyFindings(text, GATE_OFF).length,
    1,
    `${label}: control failed — the gate-off scan must report exactly one entropy finding`
  );
  assert.strictEqual(
    entropyFindings(text, GATE_ON).length,
    0,
    `${label}: the gate should have suppressed this`
  );
}

function assertReportedBothWays(text: string, label: string): void {
  assert.strictEqual(
    entropyFindings(text, GATE_OFF).length,
    1,
    `${label}: control failed — the gate-off scan must report exactly one entropy finding`
  );
  assert.strictEqual(
    entropyFindings(text, GATE_ON).length,
    1,
    `${label}: the gate must NOT have suppressed this`
  );
}

// ------------------------------------- the hard prohibition: no self-derived id

suite("N8 — the identifier never comes from inside the candidate");

test("the FCM shape is still reported by its named rule with the gate on", () => {
  const text = `  ${FCM}\n`;
  assert.ok(
    ruleIds(text, GATE_ON).includes("firebase-cloud-messaging-key"),
    "a provider rule must be untouched by this gate"
  );
});

test("the FCM shape is not gated on the run in front of its own colon", () => {
  // Bare, which is how the token appears in a registration log or a curl line.
  // The old bare-assignment path read `AAAA<id>` as the identifier; `AAAA<id>`
  // carries no word-list word, so the gate would have closed on a real key.
  const text = `  ${FCM}\n`;
  const off = ruleIds(text, GATE_OFF).sort();
  const on = ruleIds(text, GATE_ON).sort();
  assert.deepStrictEqual(on, off, "the gate must not change what an FCM token reports");
});

test("a separator-bearing token with no outside identifier falls through", () => {
  const text = `[\n  "${EQ_TOKEN_NEUTRAL}"\n]\n`;
  assertReportedBothWays(text, "separator token, no identifier");
});

test("a word-list word INSIDE the value cannot open the gate", () => {
  // `author` outside, `secret` inside. Reading the inside would report this.
  const text = `const author = "${EQ_TOKEN_WORDED}";\n`;
  assertSuppressedOnlyWhenGated(text, "worded separator token under a non-secret identifier");
});

test("an outside secret identifier opens the gate regardless of the value's own text", () => {
  const text = `const sessionToken = "${EQ_TOKEN_NEUTRAL}";\n`;
  assertReportedBothWays(text, "neutral separator token under a secret identifier");
});

// ------------------------------------------------ one literal, three placements

suite("N8 — one literal, three placements");

test("a non-secret identifier suppresses it", () => {
  assertSuppressedOnlyWhenGated(`const author = "${SECRET}";\n`, "author");
});

test("a secret identifier reports it", () => {
  assertReportedBothWays(`const sessionToken = "${SECRET}";\n`, "sessionToken");
});

test("no identifier at all reports it", () => {
  assertReportedBothWays(`[\n  "${SECRET}"\n]\n`, "array element");
});

// --------------------------------------------- unquoted candidates are never gated

suite("N8 — unquoted candidates are never gated");

test("a bare assignment reports exactly as it does with the gate off", () => {
  const text = `  author = ${SECRET}\n`;
  assert.deepStrictEqual(
    ruleIds(text, GATE_ON).sort(),
    ruleIds(text, GATE_OFF).sort(),
    "a bare assignment is out of scope for this gate"
  );
  assert.strictEqual(entropyFindings(text, GATE_ON).length, 1, "and it still reports");
});

test("a .env-style line reports exactly as it does with the gate off", () => {
  const text = `AUTHOR=${SECRET}\n`;
  assert.deepStrictEqual(
    ruleIds(text, GATE_ON).sort(),
    ruleIds(text, GATE_OFF).sort(),
    "a .env line is out of scope for this gate"
  );
  assert.strictEqual(entropyFindings(text, GATE_ON).length, 1, "and it still reports");
});

test("a YAML-style unquoted value reports exactly as it does with the gate off", () => {
  const text = `author: ${SECRET}\n`;
  assert.deepStrictEqual(
    ruleIds(text, GATE_ON).sort(),
    ruleIds(text, GATE_OFF).sort(),
    "an unquoted YAML value is out of scope for this gate"
  );
});

// ------------------------------------------------------- word-boundary matching

suite("N8 — whole-word matching, never substrings");

for (const id of ["author", "design", "apiVersion", "bypass", "keyboard", "signal"]) {
  test(`\`${id}\` does not open the gate`, () => {
    assertSuppressedOnlyWhenGated(`const ${id} = "${SECRET}";\n`, id);
  });
}

for (const id of ["API_TOKEN", "db_pass", "sessionToken", "signing_material", "user-credentials"]) {
  test(`\`${id}\` opens the gate`, () => {
    assertReportedBothWays(`const ${id} = "${SECRET}";\n`, id);
  });
}

test("`apiKey` and `clientSecret` still report, through the named generic rule", () => {
  for (const id of ["apiKey", "clientSecret"]) {
    const text = `const ${id} = "${SECRET}";\n`;
    assert.ok(
      scan(text, GATE_ON).length >= 1,
      `${id}: a keyword-anchored assignment must still report with the gate on`
    );
  }
});

// ------------------------------------------------------------- default and flag

suite("N8 — off by default, opt-in by config and flag");

test("the gate is off in the default config", () => {
  assert.strictEqual(
    (defaultConfig as SecretLoopConfig).keyContextRequired,
    false,
    "keyContextRequired must default to false"
  );
});

test("the default config reports a non-secret identifier, as before", () => {
  assert.strictEqual(
    entropyFindings(`const author = "${SECRET}";\n`, defaultConfig).length,
    1,
    "default behaviour must be unchanged"
  );
});

test("N7a and N7b stay active with the gate on", () => {
  // An ordered alphabet run under a secret identifier: the gate opens and N7a
  // must still reject it. A gate that reports what a veto rejected is worse
  // than no gate.
  const ordered = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP";
  assert.strictEqual(
    entropyFindings(`const sessionToken = "${ordered}";\n`, GATE_ON).length,
    0,
    "N7a must still veto an ordered run"
  );
  const idPath = "Components/Widgets/PrimaryButton/DefaultStory";
  assert.strictEqual(
    entropyFindings(`const sessionToken = "${idPath}";\n`, GATE_ON).length,
    0,
    "N7b must still veto an identifier path"
  );
});

const CLI = path.join(__dirname, "..", "out", "cli.js");

function scanTreeWithCli(body: string, extraArgs: string[] = []): Finding[] {
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-n8-0.1.5-"));
  try {
    mkdirSync(path.join(dir, "src"), { recursive: true });
    writeFileSync(path.join(dir, "src", "config.js"), body, "utf8");
    const res = spawnSync(
      "node",
      [CLI, "scan", "--format", "json", "--fail-on", "never", ...extraArgs, "--path", dir],
      { encoding: "utf8" }
    );
    assert.strictEqual(res.status, 0, `CLI exited ${res.status}: ${res.stderr}`);
    return JSON.parse(res.stdout).findings as Finding[];
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("the CLI reports a non-secret identifier by default", () => {
  const found = scanTreeWithCli(`const author = "${SECRET}";\n`);
  assert.strictEqual(
    found.filter((f) => f.ruleId === ENTROPY_RULE_ID).length,
    1,
    "without the flag the gate must be off"
  );
});

test("--key-context turns the gate on", () => {
  const found = scanTreeWithCli(`const author = "${SECRET}";\n`, ["--key-context"]);
  assert.strictEqual(
    found.filter((f) => f.ruleId === ENTROPY_RULE_ID).length,
    0,
    "--key-context must enable the gate"
  );
});

test("--key-context leaves a secret identifier reporting", () => {
  const found = scanTreeWithCli(`const sessionToken = "${SECRET}";\n`, ["--key-context"]);
  assert.strictEqual(
    found.filter((f) => f.ruleId === ENTROPY_RULE_ID).length,
    1,
    "--key-context must not suppress a secret-named identifier"
  );
});

test("--key-context is documented in the help text", () => {
  const res = spawnSync("node", [CLI, "help"], { encoding: "utf8" });
  assert.ok(res.stdout.includes("--key-context"), "the flag must appear in help");
});

finish();
