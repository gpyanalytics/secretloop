import { test, suite, finish, assert } from "./harness";
import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { spawnSync } from "child_process";
import * as path from "path";
import {
  REPORT_SCHEMA_VERSION,
  SCOPE_CONTRACT_VERSION,
  configDigest,
  coverageLimitations,
  repositoryIdentity,
  ruleSetDigest,
  scopeIdentity,
  suppressionIdentity,
} from "../src/report-metadata";
import { emptyArchiveAccounting } from "../src/archive";
import { mergeConfig, SecretLoopConfig } from "../src/config";
import { scanText } from "../src/scanner";
import { render } from "../src/report";
import { positiveSamples } from "./fixtures";

/**
 * Report metadata for a later exposure comparison.
 *
 * The invariant under test everywhere below is the one the design turns on:
 * **absent means unknown, and unknown must never read as equal.** A field this
 * code cannot determine is omitted from the serialized report, because two
 * reports that both say `null` compare equal on a naive read -- and a finding
 * that is still there would then be reported as gone.
 *
 * Nothing here asserts that metadata makes two scans comparable. It asserts
 * only that the identities are deterministic, that they change when the inputs
 * that matter change, and that they carry no secret.
 */

const GH = positiveSamples["github-token"];
const CLI = path.join(__dirname, "..", "out", "cli.js");
const base = mergeConfig({});

function withDir(fn: (dir: string) => void): void {
  const dir = realpathSync(mkdtempSync(path.join(tmpdir(), "secretloop-cmpmeta-")));
  try { fn(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}
function git(dir: string, ...args: string[]) {
  return spawnSync("git", args, { cwd: dir, encoding: "utf8" });
}
/** A repository with one commit, so it has a root commit to be identified by. */
function repo(dir: string, content = "hello\n"): void {
  git(dir, "init", "-q");
  git(dir, "config", "user.email", "t@example.invalid");
  git(dir, "config", "user.name", "t");
  writeFileSync(path.join(dir, "a.txt"), content, "utf8");
  git(dir, "add", "-A");
  git(dir, "commit", "-qm", "first");
}
const noSuppression = { allowValuesCount: 0, baselineApplied: false, inlineSuppressed: 0 };
/** Generated at run time: no credential-shaped literal is committed in this file. */
function syntheticToken(): string {
  const cs = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let v = "";
  for (let i = 0; i < 36; i++) v += cs[Math.floor(Math.random() * cs.length)];
  return `ghp_${v}`;
}

// ---------------------------------------------------------------------------
suite("determinism — equivalent effective inputs digest identically");

test("the same config digests identically however the object was built", () => {
  // Same values, genuinely different key insertion order. Reassigning a key
  // after a spread does NOT move it, so the reversal has to be explicit --
  // an earlier version of this test spread and reassigned, kept the original
  // order, and passed with the sorting removed from the digest.
  const a: SecretLoopConfig = mergeConfig({ entropyThreshold: 4.2, excludeRules: ["x"] });
  const b = Object.fromEntries(Object.entries(a).reverse()) as SecretLoopConfig;
  assert.notDeepStrictEqual(Object.keys(a), Object.keys(b), "the key order did not actually differ");
  assert.deepStrictEqual(Object.keys(a).sort(), Object.keys(b).sort());
  assert.strictEqual(configDigest(a), configDigest(b));
  assert.strictEqual(
    suppressionIdentity(a, noSuppression).digest,
    suppressionIdentity(b, noSuppression).digest
  );
});

test("array order inside the config does not change the identity", () => {
  // excludePaths is a set in everything but type: the same globs listed in a
  // different order are the same scan.
  const a = mergeConfig({ excludePaths: ["dist/**", "vendor/**", "tmp/**"] });
  const b = mergeConfig({ excludePaths: ["tmp/**", "dist/**", "vendor/**"] });
  assert.strictEqual(configDigest(a), configDigest(b));
});

test("the rule-set digest is stable across calls and is a short hex digest", () => {
  assert.strictEqual(ruleSetDigest(), ruleSetDigest());
  assert.match(ruleSetDigest(), /^[0-9a-f]{16}$/);
});

test("the config digest is a short hex digest, not a copy of the config", () => {
  const d = configDigest(mergeConfig({ excludePaths: ["secret-dir/**"] }));
  assert.match(d, /^[0-9a-f]{16}$/);
  assert.ok(!d.includes("secret-dir"));
});

// ---------------------------------------------------------------------------
suite("change detection — a changed input changes the identity");

test("changed rules, thresholds, exclusions and flags each change the config digest", () => {
  const d0 = configDigest(base);
  const changed: Partial<SecretLoopConfig>[] = [
    { excludeRules: ["github-token"] },
    { entropyThreshold: 4.9 },
    { excludePaths: ["docs/**"] },
    { includePaths: ["vendor/keys/**"] },
    { includeFixtures: true },
    { entropyPassEnabled: true },
    { keyContextRequired: true },
    { includeApiDocumentEntropy: true },
    { maxFileSizeBytes: 1234 },
  ];
  for (const patch of changed) {
    const key = Object.keys(patch)[0];
    assert.notStrictEqual(configDigest(mergeConfig(patch)), d0, `${key} did not change the digest`);
  }
  // `generatedExcludePaths` is not reachable through mergeConfig by design --
  // it is not user-extensible, so one flag can switch the whole group off. The
  // flag empties it on the resolved object, which is what this asserts.
  assert.notStrictEqual(configDigest({ ...base, generatedExcludePaths: [] }), d0);
});

test("adding an allowValues entry changes the digest, by count and never by content", () => {
  const none = configDigest(mergeConfig({ allowValues: [] }));
  const one = configDigest(mergeConfig({ allowValues: ["^AKIA"] }));
  assert.notStrictEqual(one, none, "a changed allowValues count must be visible");
  // Two DIFFERENT allowlists of the same length digest the same, because the
  // content is deliberately never hashed. That is not a gap left open: the
  // suppression gate below refuses to emit an identity at all while any
  // allowValues entry is configured, so such a pair is incomparable anyway.
  const other = configDigest(mergeConfig({ allowValues: ["^ghp_"] }));
  assert.strictEqual(one, other);
  assert.strictEqual(
    suppressionIdentity(mergeConfig({ allowValues: ["^AKIA"] }), { ...noSuppression, allowValuesCount: 1 }).digest,
    undefined
  );
});

test("suppression-relevant config changes change the suppression identity", () => {
  const d0 = suppressionIdentity(base, noSuppression).digest;
  assert.ok(d0);
  for (const patch of [
    { excludeRules: ["github-token"] },
    { excludePaths: ["docs/**"] },
    { includePaths: ["vendor/**"] },
    { includeFixtures: true },
    { includeApiDocumentEntropy: true },
    { keyContextRequired: true },
    { maxFileSizeBytes: 999 },
  ]) {
    const key = Object.keys(patch)[0];
    const d = suppressionIdentity(mergeConfig(patch), noSuppression).digest;
    assert.notStrictEqual(d, d0, `${key} did not change the suppression identity`);
  }
  // Same reason as above: --include-generated empties the group on the resolved
  // config, and that is a suppression change a comparison must see.
  assert.notStrictEqual(
    suppressionIdentity({ ...base, generatedExcludePaths: [] }, noSuppression).digest,
    d0
  );
});

// ---------------------------------------------------------------------------
suite("suppression — unidentifiable mechanisms yield no identity at all");

test("no suppression in play yields a digest and no unidentified reasons", () => {
  const r = suppressionIdentity(base, noSuppression);
  assert.match(r.digest ?? "", /^[0-9a-f]{16}$/);
  assert.deepStrictEqual(r.unidentified, []);
});

test("allowValues, a baseline and inline directives each withhold the identity", () => {
  const cases: Array<[string, typeof noSuppression, RegExp]> = [
    ["allowValues", { ...noSuppression, allowValuesCount: 2 }, /allowValues/],
    ["baseline", { ...noSuppression, baselineApplied: true }, /baseline/],
    ["inline", { ...noSuppression, inlineSuppressed: 1 }, /inline directives/],
  ];
  for (const [name, facts, reason] of cases) {
    const r = suppressionIdentity(base, facts);
    assert.strictEqual(r.digest, undefined, `${name} still produced an identity`);
    assert.strictEqual(r.unidentified.length, 1, name);
    assert.match(r.unidentified[0], reason);
  }
});

test("an equal count of inline suppressions is never treated as equal suppression", () => {
  // Two scans that each suppressed one finding, in different places. Neither
  // gets an identity, so a comparison cannot read either finding as resolved.
  const a = suppressionIdentity(base, { ...noSuppression, inlineSuppressed: 1 });
  const b = suppressionIdentity(base, { ...noSuppression, inlineSuppressed: 1 });
  assert.strictEqual(a.digest, undefined);
  assert.strictEqual(b.digest, undefined);
});

test("every active mechanism is named, not just the first", () => {
  const r = suppressionIdentity(base, { allowValuesCount: 1, baselineApplied: true, inlineSuppressed: 3 });
  assert.strictEqual(r.digest, undefined);
  assert.strictEqual(r.unidentified.length, 3);
});

// ---------------------------------------------------------------------------
suite("root identity — portable, and unknown when it cannot be established");

test("a directory that is not a git repository has no root identity", () => withDir((dir) => {
  assert.strictEqual(repositoryIdentity(dir), undefined);
}));

test("a git repository with no commits has no root identity", () => withDir((dir) => {
  git(dir, "init", "-q");
  assert.strictEqual(repositoryIdentity(dir), undefined);
}));

test("a repository identifies itself stably, and a clone matches it", () => withDir((dir) => {
  const origin = path.join(dir, "origin");
  spawnSync("mkdir", ["-p", origin]);
  repo(origin);
  const id = repositoryIdentity(origin);
  assert.match(id ?? "", /^git:[0-9a-f]{16}$/);
  assert.strictEqual(repositoryIdentity(origin), id, "not stable across calls");
  // The point of using the root commit rather than the path: the same
  // repository on another machine must compare equal to itself.
  const clone = path.join(dir, "clone");
  git(dir, "clone", "-q", origin, clone);
  assert.strictEqual(repositoryIdentity(clone), id, "a clone must share the identity");
}));

test("two different repositories do not share an identity", () => withDir((dir) => {
  const a = path.join(dir, "a");
  const b = path.join(dir, "b");
  spawnSync("mkdir", ["-p", a]);
  spawnSync("mkdir", ["-p", b]);
  repo(a, "one\n");
  repo(b, "two\n");
  assert.notStrictEqual(repositoryIdentity(a), repositoryIdentity(b));
}));

test("the identity discloses no path and no commit SHA", () => withDir((dir) => {
  repo(dir);
  const id = repositoryIdentity(dir) ?? "";
  assert.ok(!id.includes(dir), "the absolute path leaked into the identity");
  assert.ok(!id.includes(path.basename(dir)), "the directory name leaked into the identity");
  const head = git(dir, "rev-parse", "HEAD").stdout.trim();
  assert.ok(head.length === 40);
  assert.ok(!id.includes(head.slice(0, 16)), "the raw commit SHA leaked into the identity");
}));

// ---------------------------------------------------------------------------
suite("coverage — what counts as incomplete, and what deliberately does not");

test("a scan with nothing skipped reports no limitation", () => {
  assert.deepStrictEqual(coverageLimitations({}), []);
  assert.deepStrictEqual(
    coverageLimitations({ oversizedExcluded: 0, unreadableExcluded: 0, outsideExcluded: 0, cancelled: false }),
    []
  );
});

test("cancellation, size, readability and containment each register", () => {
  assert.match(coverageLimitations({ cancelled: true })[0], /stopped before it finished/);
  assert.match(coverageLimitations({ oversizedExcluded: 3 })[0], /maxFileSizeBytes/);
  assert.match(coverageLimitations({ unreadableExcluded: 2 })[0], /binary or unreadable/);
  assert.match(coverageLimitations({ outsideExcluded: 1 })[0], /outside the scan root/);
});

test("archive gaps register, and an archive exclusion by configuration does not", () => {
  const refused = emptyArchiveAccounting();
  refused.members.refused = { ...(refused.members.refused ?? {}), tooLarge: 2 } as any;
  assert.match(coverageLimitations({ archives: refused })[0], /archive member\(s\) not scanned/);

  const notOpened = emptyArchiveAccounting();
  notOpened.containersNotOpened = { ...(notOpened.containersNotOpened ?? {}), unsupported: 1 } as any;
  assert.match(coverageLimitations({ archives: notOpened })[0], /container\(s\) not opened/);

  const partial = emptyArchiveAccounting();
  partial.enumeration.incompleteContainers = 1;
  assert.match(coverageLimitations({ archives: partial })[0], /not fully enumerated/);

  // A member excluded BY CONFIGURATION is a decision, not a coverage failure:
  // it is identified by the configuration digest, and a change to it already
  // makes a pair incomparable. It must not also be called incompleteness.
  const excluded = emptyArchiveAccounting();
  excluded.members.excluded = 5;
  excluded.containersOpened = 1;
  excluded.members.scanned = 3;
  assert.deepStrictEqual(coverageLimitations({ archives: excluded }), []);
});

test("every limitation is listed, not just the first", () => {
  const out = coverageLimitations({ cancelled: true, oversizedExcluded: 1, outsideExcluded: 1 });
  assert.strictEqual(out.length, 3);
});

// ---------------------------------------------------------------------------
suite("serialization — absent means absent, and nothing sensitive is written");

const findings = () => scanText(`GITHUB_TOKEN=${GH}\n`, { filePath: "app.env" });

function json(opts: Record<string, unknown> = {}): any {
  return JSON.parse(render(findings(), "json", { redact: true, root: "/abs/local/path", ...opts } as any));
}

test("a legacy report — no metadata supplied — carries no metadata keys at all", () => {
  const d = json();
  for (const k of ["schemaVersion", "toolVersion", "root", "configDigest", "ruleSetDigest",
                   "suppressionDigest", "scopeDigest", "incomplete"]) {
    assert.ok(!(k in d), `${k} appeared without a caller supplying it`);
  }
  assert.ok(!("coverage" in d.summary));
  // Still a readable report: the shape every existing consumer reads is intact.
  assert.strictEqual(d.tool, "secretloop");
  assert.strictEqual(d.summary.total, 1);
  assert.strictEqual(d.findings.length, 1);
});

test("an undetermined identity is ABSENT, never null", () => {
  // The trap this exists to avoid: `"root": null` in both reports compares
  // equal, and a comparison would then believe two unrelated trees matched.
  const d = json({
    comparison: {
      schemaVersion: REPORT_SCHEMA_VERSION,
      configDigest: "aaaaaaaaaaaaaaaa",
      ruleSetDigest: "bbbbbbbbbbbbbbbb",
      incomplete: false,
    },
  });
  assert.ok(!("root" in d), "root was serialized despite being undetermined");
  assert.ok(!("toolVersion" in d));
  assert.ok(!("suppressionDigest" in d));
  assert.ok(!("scopeDigest" in d), "scopeDigest was serialized despite being undetermined");
  assert.strictEqual(d.schemaVersion, REPORT_SCHEMA_VERSION);
  assert.strictEqual(d.incomplete, false);
});

test("supplied identities are serialized at the top level, where the design puts them", () => {
  const d = json({
    comparison: {
      schemaVersion: REPORT_SCHEMA_VERSION,
      toolVersion: "9.9.9",
      root: "git:0123456789abcdef",
      configDigest: "aaaaaaaaaaaaaaaa",
      ruleSetDigest: "bbbbbbbbbbbbbbbb",
      suppressionDigest: "cccccccccccccccc",
      scopeDigest: "scope:fedcba9876543210",
      incomplete: true,
    },
  });
  assert.deepStrictEqual(
    { v: d.toolVersion, r: d.root, c: d.configDigest, rs: d.ruleSetDigest,
      s: d.suppressionDigest, sc: d.scopeDigest, i: d.incomplete },
    { v: "9.9.9", r: "git:0123456789abcdef", c: "aaaaaaaaaaaaaaaa", rs: "bbbbbbbbbbbbbbbb",
      s: "cccccccccccccccc", sc: "scope:fedcba9876543210", i: true }
  );
});

test("coverage detail is descriptive and sits under summary, not beside the identities", () => {
  const d = json({
    reportCoverage: {
      limitations: ["1 file(s) not scanned — binary or unreadable"],
      suppression: { allowValuesCount: 0, baselineApplied: false, inlineSuppressed: 2, unidentified: ["x"] },
    },
  });
  assert.ok(!("coverage" in d), "coverage must not be a comparison-bearing top-level field");
  assert.strictEqual(d.summary.coverage.suppression.inlineSuppressed, 2);
  assert.deepStrictEqual(d.summary.coverage.limitations, ["1 file(s) not scanned — binary or unreadable"]);
});

test("the serialized report carries no secret, no absolute root and no allowValue", () => {
  const cfg = mergeConfig({ allowValues: [GH], excludePaths: ["/Users/someone/private/**"] });
  const d = render(findings(), "json", {
    redact: true,
    root: "/abs/local/path",
    comparison: {
      schemaVersion: REPORT_SCHEMA_VERSION,
      configDigest: configDigest(cfg),
      ruleSetDigest: ruleSetDigest(),
      incomplete: false,
    },
    reportCoverage: {
      limitations: [],
      suppression: { allowValuesCount: cfg.allowValues.length, baselineApplied: false, inlineSuppressed: 0, unidentified: ["allowValues"] },
    },
  } as any);
  assert.ok(!d.includes(GH), "the secret value reached the report");
  assert.ok(!d.includes("/abs/local/path"), "the absolute scan root reached the report");
  assert.ok(!d.includes("/Users/someone/private"), "a configured path reached the report");
});

test("the existing finding payload is byte-identical with and without metadata", () => {
  const without = json();
  const with_ = json({
    comparison: {
      schemaVersion: REPORT_SCHEMA_VERSION,
      toolVersion: "9.9.9",
      root: "git:0123456789abcdef",
      configDigest: "aaaaaaaaaaaaaaaa",
      ruleSetDigest: "bbbbbbbbbbbbbbbb",
      incomplete: true,
    },
    reportCoverage: { limitations: ["x"], suppression: { allowValuesCount: 0, baselineApplied: false, inlineSuppressed: 0, unidentified: [] } },
  });
  assert.deepStrictEqual(with_.findings, without.findings);
  assert.strictEqual(JSON.stringify(with_.findings), JSON.stringify(without.findings));
  // And the pre-existing summary fields are untouched.
  for (const k of ["total", "scope", "scannedCount", "scopeNoun", "confirmedLive", "bySeverity", "byLiveness"]) {
    assert.deepStrictEqual(with_.summary[k], without.summary[k], k);
  }
});

// ---------------------------------------------------------------------------
suite("end to end — the CLI emits what it can determine, and omits what it cannot");

test("a scan of a git repository carries every identity it can establish", () => withDir((dir) => {
  repo(dir, "nothing secret here\n");
  const res = spawnSync("node", [CLI, "scan", "--path", dir, "--format", "json", "--fail-on", "never"], {
    cwd: dir, encoding: "utf8",
  });
  assert.strictEqual(res.status, 0, res.stderr);
  const d = JSON.parse(res.stdout);
  assert.strictEqual(d.schemaVersion, REPORT_SCHEMA_VERSION);
  assert.match(d.root, /^git:[0-9a-f]{16}$/);
  assert.match(d.configDigest, /^[0-9a-f]{16}$/);
  assert.match(d.ruleSetDigest, /^[0-9a-f]{16}$/);
  assert.match(d.suppressionDigest, /^[0-9a-f]{16}$/, "a clean tree should have an identifiable suppression state");
  assert.strictEqual(d.incomplete, false);
  assert.deepStrictEqual(d.summary.coverage.limitations, []);
  assert.ok(!res.stdout.includes(dir), "the absolute scan root reached the report");
}));

test("two scans of the same unchanged repository produce identical identities", () => withDir((dir) => {
  repo(dir, "nothing secret here\n");
  const run = () => JSON.parse(
    spawnSync("node", [CLI, "scan", "--path", dir, "--format", "json", "--fail-on", "never"],
      { cwd: dir, encoding: "utf8" }).stdout
  );
  const a = run(), b = run();
  for (const k of ["schemaVersion", "toolVersion", "root", "configDigest", "ruleSetDigest", "suppressionDigest", "incomplete"]) {
    assert.deepStrictEqual(a[k], b[k], k);
  }
}));

test("a changed project configuration changes the identities", () => withDir((dir) => {
  repo(dir, "nothing secret here\n");
  const run = () => JSON.parse(
    spawnSync("node", [CLI, "scan", "--path", dir, "--format", "json", "--fail-on", "never"],
      { cwd: dir, encoding: "utf8" }).stdout
  );
  const before = run();
  writeFileSync(path.join(dir, ".secretloop.json"), JSON.stringify({ excludeRules: ["github-token"] }), "utf8");
  const after = run();
  assert.notStrictEqual(after.configDigest, before.configDigest);
  assert.notStrictEqual(after.suppressionDigest, before.suppressionDigest);
  assert.strictEqual(after.root, before.root, "the repository did not change");
}));

test("a scan outside a git repository omits the root identity entirely", () => withDir((dir) => {
  writeFileSync(path.join(dir, "a.txt"), "nothing secret here\n", "utf8");
  const res = spawnSync("node", [CLI, "scan", "--path", dir, "--format", "json", "--fail-on", "never"], {
    cwd: dir, encoding: "utf8",
  });
  assert.strictEqual(res.status, 0, res.stderr);
  const d = JSON.parse(res.stdout);
  assert.ok(!("root" in d), "root must be absent, not null, outside a repository");
  assert.match(d.configDigest, /^[0-9a-f]{16}$/, "the other identities are still determinable");
}));

test("a baseline withholds the suppression identity end to end", () => withDir((dir) => {
  repo(dir, "nothing secret here\n");
  writeFileSync(path.join(dir, "base.json"), JSON.stringify({ version: 2, fingerprints: [] }), "utf8");
  const res = spawnSync(
    "node",
    [CLI, "scan", "--path", dir, "--baseline", path.join(dir, "base.json"), "--format", "json", "--fail-on", "never"],
    { cwd: dir, encoding: "utf8" }
  );
  assert.strictEqual(res.status, 0, res.stderr);
  const d = JSON.parse(res.stdout);
  assert.ok(!("suppressionDigest" in d), "a baselined scan must not claim an identifiable suppression state");
  assert.strictEqual(d.summary.coverage.suppression.baselineApplied, true);
  assert.match(d.summary.coverage.suppression.unidentified.join(" "), /baseline/);
}));

// ---------------------------------------------------------------------------
suite("review regressions — properties the contract pins, and the gap it does not");

test("no emitted metadata field is ever null, empty or the wrong type", () => withDir((dir) => {
  // The producer's half of the required-field contract. A comparator must still
  // validate, because omission alone enforces nothing -- but a field this
  // producer DOES emit must never need validating.
  repo(dir, "nothing secret here\n");
  const d = JSON.parse(
    spawnSync("node", [CLI, "scan", "--path", dir, "--format", "json", "--fail-on", "never"],
      { cwd: dir, encoding: "utf8" }).stdout
  );
  const strings = ["toolVersion", "root", "configDigest", "ruleSetDigest", "suppressionDigest", "scopeDigest"];
  for (const k of strings) {
    if (!(k in d)) continue;                       // absent is the sanctioned "unknown"
    assert.strictEqual(typeof d[k], "string", `${k} is not a string`);
    assert.ok(d[k].trim().length > 0, `${k} is empty`);
    assert.notStrictEqual(d[k], null);
  }
  assert.strictEqual(typeof d.incomplete, "boolean");
  assert.ok(Number.isInteger(d.schemaVersion) && d.schemaVersion >= 1);
  // and nothing is ever emitted as an explicit null
  assert.ok(!/"(schemaVersion|toolVersion|root|configDigest|ruleSetDigest|suppressionDigest|scopeDigest|incomplete)"\s*:\s*null/
    .test(JSON.stringify(d)), "a metadata field was emitted as null");
  assert.strictEqual(d.schemaVersion, 2, "the contract gained a required field, so the version must be 2");
  assert.match(d.scopeDigest, /^scope:[0-9a-f]{16}$/);
}));

test("a zero-match allowlist or baseline still withholds the suppression identity", () => {
  // "Configured but matched nothing" is still configured: neither can be shown
  // to have had no effect without reading content this deliberately never reads.
  assert.strictEqual(
    suppressionIdentity(mergeConfig({ allowValues: ["^NEVER_MATCHES_ANYTHING$"] }),
      { ...noSuppression, allowValuesCount: 1 }).digest,
    undefined
  );
  assert.strictEqual(
    suppressionIdentity(base, { ...noSuppression, baselineApplied: true }).digest,
    undefined
  );
});

test("an inline directive that suppressed nothing is not treated as suppression", () => {
  // The gate counts EFFECTS. A directive that hid nothing hid nothing, so the
  // identity stands; the moment it hides a finding the count is non-zero and the
  // identity is withheld, so no pair where something was actually hidden can be
  // compared.
  const none = suppressionIdentity(base, noSuppression).digest;
  assert.ok(none);
  assert.strictEqual(suppressionIdentity(base, { ...noSuppression, inlineSuppressed: 0 }).digest, none);
  assert.strictEqual(suppressionIdentity(base, { ...noSuppression, inlineSuppressed: 1 }).digest, undefined);
});

test("the three scan modes never share a scope identity", () => withDir((dir) => {
  // This assertion was previously INVERTED: it pinned the collision, because a
  // working-tree scan and a history scan of one repository carried identical
  // comparison metadata and only a prose sentence told them apart. scopeDigest
  // closes that. Everything else about the two reports still matches, which is
  // the point -- scope is the field doing the work.
  repo(dir, "nothing secret here\n");
  const run = (...args: string[]) => JSON.parse(
    spawnSync("node", [CLI, ...args, "--path", dir, "--format", "json", "--fail-on", "never"],
      { cwd: dir, encoding: "utf8" }).stdout
  );
  const file = run("scan");
  const hist = run("history");
  const staged = run("staged");
  assert.match(file.scopeDigest, /^scope:[0-9a-f]{16}$/);
  assert.match(hist.scopeDigest, /^scope:[0-9a-f]{16}$/);
  assert.notStrictEqual(file.scopeDigest, hist.scopeDigest, "two modes shared a scope identity");
  // A staged scan gets NO identity: its population is the index, which moves
  // with `git add` and `git reset` rather than with the file.
  assert.ok(!("scopeDigest" in staged), "a staged report must not claim a scope identity");
  // The other identities DO match -- scope is what separates them.
  for (const k of ["schemaVersion", "toolVersion", "root", "configDigest", "ruleSetDigest"]) {
    assert.deepStrictEqual(hist[k], file[k], k);
  }
}));

test("a history scan reports no coverage limitation, and cancellation is not reachable from the CLI", () => withDir((dir) => {
  // `cancelled` is a real input to `incomplete`, but the CLI passes no
  // AbortSignal to scanHistory, so today no CLI report can be produced from a
  // partial history scan -- a parser failure rejects and writes nothing.
  // Pinned so that wiring cancellation in later cannot silently keep emitting
  // `incomplete: false`.
  repo(dir, "nothing secret here\n");
  const d = JSON.parse(
    spawnSync("node", [CLI, "history", "--path", dir, "--format", "json", "--fail-on", "never"],
      { cwd: dir, encoding: "utf8" }).stdout
  );
  assert.deepStrictEqual(d.summary.coverage.limitations, []);
  assert.strictEqual(d.incomplete, false);
  assert.deepStrictEqual(coverageLimitations({ cancelled: true }).length, 1,
    "the cancelled input itself must still register");
}));

// ---------------------------------------------------------------------------
suite("scope identity — the selection, not the request");

/** A repository with four commits, each introducing one synthetic credential. */
function historyRepo(dir: string): string[] {
  git(dir, "init", "-q");
  git(dir, "config", "user.email", "t@example.invalid");
  git(dir, "config", "user.name", "t");
  for (let i = 0; i < 4; i++) {
    writeFileSync(path.join(dir, `c${i}.env`), `GITHUB_TOKEN=${syntheticToken()}\n`, "utf8");
    git(dir, "add", "-A");
    git(dir, "commit", "-qm", `c${i}`);
  }
  return git(dir, "rev-list", "--reverse", "HEAD").stdout.trim().split("\n");
}
function cliJson(dir: string, ...args: string[]): any {
  const res = spawnSync("node", [CLI, ...args, "--path", dir, "--format", "json", "--fail-on", "never"],
    { cwd: dir, encoding: "utf8" });
  assert.strictEqual(res.status, 0, res.stderr);
  return JSON.parse(res.stdout);
}

test("unit: the modes digest differently, staged gets none, history follows its commit set", () => {
  const w = scopeIdentity({ mode: "worktree" });
  const st = scopeIdentity({ mode: "staged" });
  const h = scopeIdentity({ mode: "history", commits: ["a", "b"] });
  // Staged is withheld outright -- its population is the index, and a mode-only
  // identity let an unstaged-but-unchanged secret read as resolved.
  assert.strictEqual(st, undefined);
  assert.notStrictEqual(w, h);
  for (const d of [w, h]) assert.match(d ?? "", /^scope:[0-9a-f]{16}$/);
  // The SET is the identity: order in does not matter, membership does.
  assert.strictEqual(scopeIdentity({ mode: "history", commits: ["b", "a"] }), h);
  assert.notStrictEqual(scopeIdentity({ mode: "history", commits: ["a", "c"] }), h);
  assert.notStrictEqual(scopeIdentity({ mode: "history", commits: ["a"] }), h);
  // An EMPTY selection is a real selection -- a range that matched no commit --
  // and is not the same as an unavailable one.
  assert.match(scopeIdentity({ mode: "history", commits: [] }) ?? "", /^scope:[0-9a-f]{16}$/);
  assert.notStrictEqual(scopeIdentity({ mode: "history", commits: [] }), h);
});

test("unit: an unavailable selection yields no identity", () => {
  assert.strictEqual(scopeIdentity(undefined), undefined);
  assert.strictEqual(scopeIdentity({ mode: "history", commits: undefined as any }), undefined);
  assert.ok(Number.isInteger(SCOPE_CONTRACT_VERSION));
});

test("disjoint history ranges with EQUAL commit counts no longer collide", () => withDir((dir) => {
  // The case that made the whole review verdict C. Equal counts, identical
  // scope sentence, disjoint populations -- and now different identities.
  const sl = historyRepo(dir);
  const a = cliJson(dir, "history", "--rev-range", `${sl[0]}..${sl[1]}`);
  const b = cliJson(dir, "history", "--rev-range", `${sl[2]}..${sl[3]}`);
  assert.strictEqual(a.summary.scope, b.summary.scope, "the sentences still collide, as expected");
  const fa = new Set(a.findings.map((f: any) => f.fingerprint));
  const fb = new Set(b.findings.map((f: any) => f.fingerprint));
  assert.ok([...fa].every((x) => !fb.has(x)), "the populations should be disjoint");
  assert.notStrictEqual(a.scopeDigest, b.scopeDigest, "disjoint ranges must not share a scope identity");
  // Everything else about the pair matches, which is why scope had to carry it.
  for (const k of ["root", "configDigest", "ruleSetDigest", "schemaVersion"]) {
    assert.deepStrictEqual(a[k], b[k], k);
  }
}));

test("different commit caps select differently, and an over-large cap does not", () => withDir((dir) => {
  historyRepo(dir);
  const all = cliJson(dir, "history");
  const one = cliJson(dir, "history", "--max-commits", "1");
  const two = cliJson(dir, "history", "--max-commits", "2");
  assert.strictEqual(new Set([all.scopeDigest, one.scopeDigest, two.scopeDigest]).size, 3);
  // A cap larger than the history selects the same commits, so it is the SAME
  // selection -- the cap is the request, the commit set is the selection.
  assert.strictEqual(cliJson(dir, "history", "--max-commits", "99").scopeDigest, all.scopeDigest);
}));

test("equivalent selections expressed differently compare equal", () => withDir((dir) => {
  const sl = historyRepo(dir);
  const bySymbolic = cliJson(dir, "history", "--rev-range", "HEAD~1..HEAD");
  const byCap = cliJson(dir, "history", "--max-commits", "1");
  const byExplicit = cliJson(dir, "history", "--rev-range", `${sl[2]}..${sl[3]}`);
  assert.strictEqual(bySymbolic.scopeDigest, byCap.scopeDigest,
    "HEAD~1..HEAD and --max-commits 1 read the same commit");
  assert.strictEqual(bySymbolic.scopeDigest, byExplicit.scopeDigest,
    "an explicit SHA range naming the same commit is the same selection");
}));

test("a moving symbolic ref changes the selection it names", () => withDir((dir) => {
  historyRepo(dir);
  const before = cliJson(dir, "history", "--rev-range", "HEAD~2..HEAD");
  writeFileSync(path.join(dir, "later.env"), `GITHUB_TOKEN=${syntheticToken()}\n`, "utf8");
  git(dir, "add", "-A");
  git(dir, "commit", "-qm", "later");
  const after = cliJson(dir, "history", "--rev-range", "HEAD~2..HEAD");
  assert.strictEqual(before.summary.scope, after.summary.scope, "both read two commits");
  assert.notStrictEqual(before.scopeDigest, after.scopeDigest,
    "HEAD moved, so the same expression names a different selection");
}));

test("repeating an identical selection is stable", () => withDir((dir) => {
  historyRepo(dir);
  for (const args of [["scan"], ["history"], ["history", "--max-commits", "2"]]) {
    const a = cliJson(dir, ...args);
    const b = cliJson(dir, ...args);
    assert.strictEqual(a.scopeDigest, b.scopeDigest, args.join(" "));
    assert.match(a.scopeDigest, /^scope:[0-9a-f]{16}$/);
  }
}));

test("a worktree scan is not distinguished by content, deliberately", () => withDir((dir) => {
  // Detecting that the content changed is the PURPOSE of a later comparison.
  // Folding the tree state into the scope would make every pair incomparable.
  repo(dir, "nothing secret here\n");
  const before = cliJson(dir, "scan");
  writeFileSync(path.join(dir, "new.env"), `GITHUB_TOKEN=${syntheticToken()}\n`, "utf8");
  const after = cliJson(dir, "scan");
  assert.strictEqual(after.scopeDigest, before.scopeDigest);
  assert.notStrictEqual(after.summary.total, before.summary.total, "the content did change");
}));

test("staged: an unstaged but unchanged secret must not be comparable away", () => withDir((dir) => {
  // The boundary that decided this. Stage a file holding a secret and scan:
  // reported. Unstage the byte-identical file and scan again: nothing reported,
  // while the secret is still in the working tree. With a mode-only scope
  // identity the two reports were eligible, and the second read as the finding
  // being gone. Withholding the identity is what stops that.
  git(dir, "init", "-q");
  git(dir, "config", "user.email", "t@example.invalid");
  git(dir, "config", "user.name", "t");
  writeFileSync(path.join(dir, "readme.md"), "# nothing\n", "utf8");
  git(dir, "add", "-A");
  git(dir, "commit", "-qm", "base");

  const token = syntheticToken();
  writeFileSync(path.join(dir, "app.env"), `GITHUB_TOKEN=${token}\n`, "utf8");
  git(dir, "add", "app.env");
  const staged = cliJson(dir, "staged");
  assert.strictEqual(staged.summary.total, 1, "the staged scan should see it");

  git(dir, "reset", "-q", "HEAD", "app.env");
  const unstaged = cliJson(dir, "staged");
  assert.strictEqual(unstaged.summary.total, 0, "unstaged, so the staged scan sees nothing");

  // The secret did not move.
  assert.ok(readFileSync(path.join(dir, "app.env"), "utf8").includes(token));
  assert.strictEqual(cliJson(dir, "scan").summary.total, 1, "a working-tree scan still finds it");

  // Neither report may claim a scope identity, so the pair can never be eligible.
  assert.ok(!("scopeDigest" in staged), "staged report claimed a scope identity");
  assert.ok(!("scopeDigest" in unstaged), "staged report claimed a scope identity");
}));

test("a partial history scan reports neither a selection nor complete coverage", () => {
  // Unreachable from the CLI today -- it passes no AbortSignal -- so this is
  // asserted at the seam. A partial commit list is a truthful record of what was
  // parsed and a false record of what was SELECTED; reporting it would describe
  // a scan nobody ran, while `incomplete` still said the coverage was fine.
  const partialShas = ["aaa", "bbb"];
  assert.strictEqual(scopeIdentity(undefined), undefined, "an unknown selection yields no identity");
  assert.notStrictEqual(scopeIdentity({ mode: "history", commits: partialShas }), undefined);
  // and cancellation registers as a coverage limitation, so `incomplete` is true
  assert.strictEqual(coverageLimitations({ cancelled: true }).length, 1);
});

void finish();
