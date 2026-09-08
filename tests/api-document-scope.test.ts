import { test, suite, finish, assert } from "./harness";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync } from "fs";
import { tmpdir } from "os";
import { spawnSync } from "child_process";
import { createHash } from "crypto";
import * as path from "path";
import { isApiDocument, API_DOCUMENT_YAML_HEAD } from "../src/api-document";
import { scanText, Finding } from "../src/scanner";
import { mergeConfig, defaultConfig, loadConfig } from "../src/config";
import { scanFiles, scanWorkspaceScan } from "../src/workspace";
import { describeScope } from "../src/report";
import { toolScan, setAllowedRoots, ToolResult } from "../src/mcp-core";
import { buildZip } from "./archive-builders";

/**
 * Entropy-scope v1, Candidate B: the generic-high-entropy tier is not run over
 * recognized API description documents (OpenAPI / Swagger / AsyncAPI, by
 * intrinsic marker AND .json/.yaml/.yml extension), whole-document, disclosed
 * as a document count, restorable with --include-api-document-entropy /
 * includeApiDocumentEntropy. Named rules never consult the classifier. History
 * and mask keep the pre-scope behaviour. Contract:
 * entropy-scope-v1-preimplementation-freeze-v0.4.0.md, Phase A.1 amendment.
 */

const CLI = path.join(__dirname, "..", "out", "cli.js");
// Generic secret-shaped values: no provider prefix, no keyword, 4 character
// classes, well over the 4.3 bar. Built by concatenation so this file carries
// no literal that a scan of the repository itself would report.
const SEED = ["Qm7vX2pL9kR4", "tW8yZ1cB5nH3", "jF6gD0sA2eU4", "iO7pK9lM="].join("");
const SEED2 = ["Vb3nR8xT1qL6", "wK9zP4mD7yH2", "sG5cJ0fA8eN3", "uI6oX1rQ4t=="].join("");
function ghp(salt = 3): string {
  const a = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let out = "";
  for (let i = 0; i < 36; i++) out += a[(i * 13 + salt * 11 + 7) % a.length];
  return "ghp_" + out;
}
const API_KEY_IDENT = ["api", "key"].join("_");

function openapi(example: string, extra: Record<string, unknown> = {}): string {
  return JSON.stringify(
    {
      openapi: "3.0.0",
      info: { title: "Billing", version: "1.0.0" },
      paths: {
        "/invoices": {
          get: {
            operationId: "listInvoices",
            parameters: [{ name: "X-Seal", in: "header", schema: { type: "string" }, example }],
            responses: { "200": { description: "ok" } },
          },
        },
      },
      components: { schemas: {} },
      ...extra,
    },
    null,
    2
  );
}
function openapiYaml(example: string): string {
  return [
    "openapi: 3.0.0",
    "info:",
    "  title: Billing",
    "  version: 1.0.0",
    "paths:",
    "  /invoices:",
    "    get:",
    "      operationId: listInvoices",
    "      parameters:",
    "        - name: X-Seal",
    "          in: header",
    `          example: ${example}`,
    "",
  ].join("\n");
}
const entropyOn = mergeConfig({ entropyPassEnabled: true });
const restored = mergeConfig({ entropyPassEnabled: true, includeApiDocumentEntropy: true });
function generic(fs: Finding[]): Finding[] {
  return fs.filter((f) => f.ruleId === "generic-high-entropy");
}
function expectedFingerprint(file: string, value: string): string {
  return `${file}:generic-high-entropy:${createHash("sha256").update(value).digest("hex").slice(0, 16)}`;
}
function tmp(): string {
  return mkdtempSync(path.join(tmpdir(), "sl-apidoc-"));
}
function write(root: string, rel: string, text: string): void {
  mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
  writeFileSync(path.join(root, rel), text);
}
function cli(cwd: string, ...args: string[]) {
  return spawnSync("node", [CLI, ...args], { cwd, encoding: "utf8" });
}
function cliJson(cwd: string, ...args: string[]): { findings: Finding[]; summary: { scope: string } } {
  const res = cli(cwd, ...args, "--format", "json", "--fail-on", "never");
  assert.strictEqual(res.status, 0, res.stderr);
  return JSON.parse(res.stdout);
}
function payload(result: ToolResult): Record<string, any> {
  assert.ok(result.ok, JSON.stringify(result));
  return (result as { ok: true; payload: Record<string, any> }).payload;
}

// ---------------------------------------------------------------------------
suite("api-document classifier — JSON");

test("OpenAPI, Swagger and AsyncAPI objects qualify", () => {
  assert.ok(isApiDocument("api/openapi.json", '{"openapi":"3.0.0","paths":{}}'));
  assert.ok(isApiDocument("api/openapi.json", '{"openapi":"3.1.0","components":{}}'));
  assert.ok(isApiDocument("api/swagger.json", '{"swagger":"2.0","definitions":{}}'));
  assert.ok(isApiDocument("api/events.json", '{"asyncapi":"2.6.0","channels":{}}'));
  // No version-format check: any string marker qualifies.
  assert.ok(isApiDocument("a.json", '{"openapi":"x","paths":null}'));
});

test("shape and marker negatives", () => {
  const neg = [
    '{"info":{"openapi":"3.0.0","paths":{}}}', // nested only
    '{"description":"see the openapi spec","paths":{}}', // prose
    '[{"openapi":"3.0.0","paths":{}}]', // array
    '"openapi"', // scalar
    "null",
    '{"openapi":"3.0.0","paths":{}', // malformed
    "﻿" + '{"openapi":"3.0.0","paths":{}}', // BOM is not stripped
    '{"openapi":"3.0.0","info":{}}', // no paths/components/definitions
    '{"openapi":3,"paths":{}}', // marker not a string
    '{"asyncapi":"2.0.0","paths":{}}', // asyncapi needs channels
    '{"info":{"_postman_id":"x"},"item":[]}', // Postman
    "",
    "not json at all",
  ];
  for (const text of neg) assert.strictEqual(isApiDocument("api/openapi.json", text), false, text.slice(0, 40));
});

test("duplicate keys resolve exactly as JSON.parse does (last wins)", () => {
  assert.ok(isApiDocument("a.json", '{"openapi":3,"openapi":"3.0.0","paths":{}}'));
  assert.strictEqual(isApiDocument("a.json", '{"openapi":"3.0.0","openapi":3,"paths":{}}'), false);
});

test("extension is mandatory, lower-cased, and taken from the logical basename", () => {
  const doc = '{"openapi":"3.0.0","paths":{}}';
  assert.ok(isApiDocument("api/Billing.JSON", doc));
  assert.ok(isApiDocument("API/Spec.Json", doc));
  assert.strictEqual(isApiDocument("api/openapi", doc), false, "extensionless never qualifies");
  assert.strictEqual(isApiDocument("api/openapi.json5", doc), false);
  assert.strictEqual(isApiDocument("api/openapi.jsonc", doc), false);
  assert.strictEqual(isApiDocument("api/openapi.txt", doc), false);
  assert.strictEqual(isApiDocument(".json", doc), false, "a dotfile has no extension");
  assert.strictEqual(isApiDocument("openapi.json/README", doc), false, "directory names never decide");
});

// ---------------------------------------------------------------------------
suite("api-document classifier — YAML");

test("top-level markers qualify, with anything before them", () => {
  assert.ok(isApiDocument("a.yaml", "openapi: 3.0.0\npaths: {}\n"));
  assert.ok(isApiDocument("a.yml", "swagger: '2.0'\n"));
  assert.ok(isApiDocument("a.yaml", 'asyncapi: "2.6.0"\nchannels: {}\n'));
  assert.ok(isApiDocument("a.yaml", "# generated\n# do not edit\nopenapi: 3.0.0\n"));
  assert.ok(isApiDocument("a.yaml", "---\nopenapi: 3.0.0\n"));
  assert.ok(isApiDocument("a.yaml", "%YAML 1.2\n---\ninfo:\n  title: x\nopenapi: 3.0.0\n"));
  assert.ok(isApiDocument("a.yaml", "﻿info: x\nopenapi: 3.0.0\n"), "BOM only blocks a line-1 marker");
});

test("indented, upper-case, non-numeric, late, BOM-line-1 and extensionless do not qualify", () => {
  assert.strictEqual(isApiDocument("a.yaml", "spec:\n  openapi: 3.0.0\n"), false, "nested");
  assert.strictEqual(isApiDocument("a.yaml", "OpenAPI: 3.0.0\n"), false, "upper-case");
  assert.strictEqual(isApiDocument("a.yaml", "openapi: v3\n"), false, "first value character must be a digit");
  assert.strictEqual(isApiDocument("a.yaml", "openapi:\n"), false, "no value");
  assert.strictEqual(isApiDocument("a.yaml", "﻿openapi: 3.0.0\n"), false, "BOM is not stripped");
  assert.strictEqual(isApiDocument("a.yaml", "# x\n".repeat(API_DOCUMENT_YAML_HEAD / 4 + 1) + "openapi: 3.0.0\n"), false, "beyond the head");
  assert.ok(isApiDocument("a.yaml", "# x\n".repeat(100) + "openapi: 3.0.0\n"), "inside the head");
  assert.strictEqual(isApiDocument("a.yaml", "just: text\n"), false);
  assert.strictEqual(isApiDocument("openapi", "openapi: 3.0.0\n"), false, "extensionless");
  assert.strictEqual(isApiDocument("openapi.txt", "openapi: 3.0.0\n"), false);
});

test("never throws on garbage under any extension", () => {
  const junk = ["", "\0\0\0", "﻿", "{", "[", "---", "\xff\xfe", "openapi:", "a".repeat(200000), "\n".repeat(70000) + "openapi: 3"];
  for (const ext of ["x.json", "x.yaml", "x.yml", "x", "x.JSON"]) {
    for (const j of junk) assert.strictEqual(typeof isApiDocument(ext, j), "boolean");
  }
});

// ---------------------------------------------------------------------------
suite("whole-document suppression in scanText");

test("entropy off: nothing reported, nothing counted, restore switch inert", () => {
  for (const config of [mergeConfig({}), mergeConfig({ includeApiDocumentEntropy: true })]) {
    let scoped = 0;
    const fs = scanText(openapi(SEED), { config, filePath: "api/openapi.json", onApiDocumentScoped: () => scoped++ });
    assert.deepStrictEqual(generic(fs), []);
    assert.strictEqual(scoped, 0);
  }
});

test("entropy on: the document is scoped out whole and counted once", () => {
  let scoped = 0;
  const text = openapi(SEED, { "x-seal": SEED2 });
  const fs = scanText(text, { config: entropyOn, filePath: "api/openapi.json", onApiDocumentScoped: () => scoped++ });
  assert.deepStrictEqual(generic(fs), [], "no field-level exception: example and x-extension both withheld");
  assert.strictEqual(scoped, 1);
  // The same text under a path the classifier does not read (no eligible
  // extension) is scanned as before: the directory never decides anything.
  const plain = scanText(text, { config: entropyOn, filePath: "api/openapi.txt" });
  assert.strictEqual(generic(plain).length, 2);
});

test("an excluded entropy rule is the tier being off: not counted", () => {
  let scoped = 0;
  const config = mergeConfig({ entropyPassEnabled: true, excludeRules: ["generic-high-entropy"] });
  scanText(openapi(SEED), { config, filePath: "api/openapi.json", onApiDocumentScoped: () => scoped++ });
  assert.strictEqual(scoped, 0);
});

test("restore reproduces the pre-scope finding byte for byte, fingerprint included", () => {
  let scoped = 0;
  const fs = scanText(openapi(SEED), { config: restored, filePath: "api/openapi.json", onApiDocumentScoped: () => scoped++ });
  assert.strictEqual(scoped, 0);
  const g = generic(fs);
  assert.strictEqual(g.length, 1);
  assert.strictEqual(g[0].fingerprint, expectedFingerprint("api/openapi.json", SEED), "no marker in the fingerprint");
  // Identical to what the same scanner produces when the classifier has nothing to say.
  const before = scanText(openapi(SEED).replace('"openapi": "3.0.0"', '"openapx": "3.0.0"'), { config: entropyOn, filePath: "api/openapi.json" });
  assert.deepStrictEqual(g, generic(before));
});

test("YAML, upper-case .JSON and extensionless follow the classifier", () => {
  assert.deepStrictEqual(generic(scanText(openapiYaml(SEED), { config: entropyOn, filePath: "api/openapi.yaml" })), []);
  assert.deepStrictEqual(generic(scanText(openapi(SEED), { config: entropyOn, filePath: "api/Billing.JSON" })), []);
  assert.strictEqual(generic(scanText(openapi(SEED), { config: entropyOn, filePath: "api/openapi" })).length, 1, "extensionless: entropy runs");
  assert.strictEqual(generic(scanText(openapiYaml(SEED), { config: restored, filePath: "api/openapi.yaml" })).length, 1);
});

test("named rules inside an API document are unconditional", () => {
  const text = openapi(SEED, { "x-token": ghp(), [API_KEY_IDENT]: SEED2 });
  for (const config of [mergeConfig({}), entropyOn, restored]) {
    const ids = scanText(text, { config, filePath: "api/openapi.json" }).map((f) => f.ruleId).sort();
    assert.ok(ids.includes("github-token"), ids.join());
    assert.ok(ids.includes("generic-api-key-assignment"), ids.join());
  }
  const on = scanText(text, { config: entropyOn, filePath: "api/openapi.json" });
  assert.deepStrictEqual(generic(on), [], "only the entropy tier is withheld");
  const named = on.find((f) => f.ruleId === "generic-api-key-assignment")!;
  const back = scanText(text, { config: restored, filePath: "api/openapi.json" }).find((f) => f.ruleId === "generic-api-key-assignment")!;
  assert.deepStrictEqual(named, back, "named finding identical under both modes");
});

test("no path (mask's stdin) is never classified", () => {
  assert.strictEqual(generic(scanText(openapi(SEED), { config: entropyOn })).length, 1);
});

// ---------------------------------------------------------------------------
suite("archive members and workspace scans");

test("an archive member is classified on its own path and text, not the container's", () => {
  const dir = tmp();
  try {
    const zip = buildZip([
      { name: "api/openapi.json", data: Buffer.from(openapi(SEED)) },
      { name: "config/app.json", data: Buffer.from(JSON.stringify({ cipher_seed: SEED2 })) },
    ]);
    write(dir, "artifacts/specs.zip", "");
    writeFileSync(path.join(dir, "artifacts/specs.zip"), zip);
    // A plain file named like an archive: the container's name must not classify members.
    const scoped = scanFiles(dir, ["artifacts/specs.zip"], entropyOn);
    assert.strictEqual(scoped.length, 1);
    assert.deepStrictEqual(generic(scoped[0].findings).map((f) => f.file), ["artifacts/specs.zip!/config/app.json"]);
    assert.strictEqual(scoped[0].apiDocumentsScoped, 1);
    const back = scanFiles(dir, ["artifacts/specs.zip"], restored)[0];
    assert.strictEqual(back.apiDocumentsScoped, 0);
    const api = generic(back.findings).find((f) => f.file === "artifacts/specs.zip!/api/openapi.json")!;
    assert.ok(api && api.source && api.source.member === "api/openapi.json");
    // Member identity/fingerprint semantics are the archive-v1 ones, untouched.
    const pre = generic(scanText(openapi(SEED), { config: entropyOn, filePath: "artifacts/specs.zip!/api/openapi.json", source: { kind: "archive-member", container: "artifacts/specs.zip", containerKind: "zip", member: "api/openapi.jsn" } }));
    assert.strictEqual(pre.length, 1, "control: a member whose OWN path is not .json is scanned");
    assert.notStrictEqual(api.fingerprint, undefined);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("workspace scan (VS Code workspace / baseline path) applies the project file, not an editor setting", () => {
  const dir = tmp();
  try {
    write(dir, "api/openapi.json", openapi(SEED));
    write(dir, "api/openapi.yaml", openapiYaml(SEED));
    write(dir, "config/app.json", JSON.stringify({ cipher_seed: SEED2 }));
    write(dir, ".secretloop.json", JSON.stringify({ entropyPassEnabled: true }));
    const a = scanWorkspaceScan(dir, loadConfig(dir));
    assert.deepStrictEqual(generic(a.scanned.flatMap((s) => s.findings)).map((f) => f.file), ["config/app.json"]);
    assert.strictEqual(a.scanned.reduce((n, s) => n + (s.apiDocumentsScoped ?? 0), 0), 2);
    write(dir, ".secretloop.json", JSON.stringify({ entropyPassEnabled: true, includeApiDocumentEntropy: true }));
    const b = scanWorkspaceScan(dir, loadConfig(dir));
    const files = generic(b.scanned.flatMap((s) => s.findings)).map((f) => f.file).sort();
    assert.deepStrictEqual(files, ["api/openapi.json", "api/openapi.yaml", "config/app.json"]);
    assert.strictEqual(b.scanned.reduce((n, s) => n + (s.apiDocumentsScoped ?? 0), 0), 0);
    const api = generic(b.scanned.flatMap((s) => s.findings)).find((f) => f.file === "api/openapi.json")!;
    assert.strictEqual(api.fingerprint, expectedFingerprint("api/openapi.json", SEED));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("open-document scan: the same classifier on the document text and its relative path", () => {
  const config = loadConfig(tmp()); // no project file: defaults
  const on = { ...config, entropyPassEnabled: true };
  assert.deepStrictEqual(generic(scanText(openapiYaml(SEED), { config: on, filePath: "docs/api/openapi.yml" })), []);
  assert.strictEqual(generic(scanText(openapiYaml(SEED), { config: on, filePath: "docs/api/openapi.md" })).length, 1);
});

// ---------------------------------------------------------------------------
suite("disclosure sentence");

test("describeScope carries the document clause only when nonzero, after the fixture clause", () => {
  assert.strictEqual(describeScope(3, "file", { apiDocumentsScoped: 0 }), "3 file(s)");
  assert.strictEqual(
    describeScope(3, "file", { apiDocumentsScoped: 2 }),
    "3 file(s); 2 API description document(s) scanned without generic entropy (--include-api-document-entropy to include them)"
  );
  const both = describeScope(3, "file", { fixtureSuppressed: 1, apiDocumentsScoped: 2, oversizedExcluded: 4 });
  assert.ok(both.indexOf("test/fixture") < both.indexOf("API description"));
  assert.ok(both.indexOf("API description") < both.indexOf("maxFileSizeBytes"));
});

// ---------------------------------------------------------------------------
suite("CLI surfaces");

function project(): string {
  const dir = tmp();
  write(dir, "api/openapi.json", openapi(SEED));
  write(dir, "config/app.json", JSON.stringify({ cipher_seed: SEED2 }, null, 2));
  return dir;
}
const CLAUSE = "1 API description document(s) scanned without generic entropy (--include-api-document-entropy to include them)";

test("scan: entropy off, default, project restore, flag over project false, flag with entropy off", () => {
  const dir = project();
  try {
    const off = cliJson(dir, "scan");
    assert.deepStrictEqual(generic(off.findings), []);
    assert.doesNotMatch(off.summary.scope, /API description/);

    const on = cliJson(dir, "scan", "--include-entropy");
    assert.deepStrictEqual(generic(on.findings).map((f) => f.file), ["config/app.json"]);
    assert.ok(on.summary.scope.endsWith(CLAUSE), on.summary.scope);

    write(dir, ".secretloop.json", JSON.stringify({ entropyPassEnabled: true, includeApiDocumentEntropy: true }));
    const cfg = cliJson(dir, "scan");
    assert.deepStrictEqual(generic(cfg.findings).map((f) => f.file).sort(), ["api/openapi.json", "config/app.json"]);
    assert.doesNotMatch(cfg.summary.scope, /API description/);
    assert.strictEqual(generic(cfg.findings).find((f) => f.file === "api/openapi.json")!.fingerprint, expectedFingerprint("api/openapi.json", SEED));

    write(dir, ".secretloop.json", JSON.stringify({ entropyPassEnabled: true, includeApiDocumentEntropy: false }));
    assert.deepStrictEqual(generic(cliJson(dir, "scan").findings).map((f) => f.file), ["config/app.json"], "project false suppresses");
    const flag = cliJson(dir, "scan", "--include-api-document-entropy");
    assert.deepStrictEqual(generic(flag.findings).map((f) => f.file).sort(), ["api/openapi.json", "config/app.json"], "flag raises over project false");
    assert.doesNotMatch(flag.summary.scope, /API description/);

    write(dir, ".secretloop.json", JSON.stringify({ includeApiDocumentEntropy: true }));
    const inert = cliJson(dir, "scan", "--include-api-document-entropy");
    assert.deepStrictEqual(generic(inert.findings), [], "restore never turns the tier on");
    assert.doesNotMatch(inert.summary.scope, /API description/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("scan: text, JSON and SARIF carry the same clause; no path or value in it", () => {
  const dir = project();
  try {
    const text = cli(dir, "scan", "--include-entropy", "--fail-on", "never");
    assert.match(text.stdout, /Scanned 2 file\(s\); 1 API description document\(s\) scanned without generic entropy/);
    const sarif = JSON.parse(cli(dir, "scan", "--include-entropy", "--format", "sarif", "--fail-on", "never").stdout);
    assert.ok(String(sarif.runs[0].invocations[0].properties.scope).endsWith(CLAUSE));
    const json = cliJson(dir, "scan", "--include-entropy");
    const clause = json.summary.scope.slice(json.summary.scope.indexOf("; 1 API"));
    assert.doesNotMatch(clause, /openapi|api\//, "no path in the disclosure");
    assert.ok(!clause.includes(SEED));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("--help lists the flag and says what it does not do", () => {
  const h = cli(tmpdir(), "--help").stdout;
  assert.match(h, /--include-api-document-entropy/);
  assert.match(h, /Does nothing\s+unless generic entropy is enabled/);
});

function gitRepo(dir: string): void {
  const g = (...a: string[]) => {
    const r = spawnSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", ...a], { cwd: dir, encoding: "utf8" });
    assert.strictEqual(r.status, 0, r.stderr);
  };
  g("init", "-q");
  g("add", "-A");
  g("commit", "-q", "-m", "seed");
}

test("staged: same rule as scan, flag raises", () => {
  const dir = project();
  try {
    gitRepo(dir);
    write(dir, "api/openapi.json", openapi(SEED, { "x-rev": 2 }));
    write(dir, "config/app.json", JSON.stringify({ cipher_seed: SEED2, rev: 2 }, null, 2));
    spawnSync("git", ["add", "-A"], { cwd: dir });
    const on = cliJson(dir, "staged", "--include-entropy");
    assert.deepStrictEqual(generic(on.findings).map((f) => f.file), ["config/app.json"]);
    assert.ok(on.summary.scope.endsWith(CLAUSE), on.summary.scope);
    const back = cliJson(dir, "staged", "--include-entropy", "--include-api-document-entropy");
    assert.deepStrictEqual(generic(back.findings).map((f) => f.file).sort(), ["api/openapi.json", "config/app.json"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("history keeps the pre-scope behaviour; the flag is accepted and inert", () => {
  const dir = project();
  try {
    gitRepo(dir);
    const h = cliJson(dir, "history", "--include-entropy");
    assert.deepStrictEqual(generic(h.findings).map((f) => f.file).sort(), ["api/openapi.json", "config/app.json"], "history still reports the API-document value");
    assert.doesNotMatch(h.summary.scope, /API description/);
    const h2 = cliJson(dir, "history", "--include-entropy", "--include-api-document-entropy");
    assert.deepStrictEqual(generic(h2.findings).map((f) => f.file).sort(), ["api/openapi.json", "config/app.json"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("mask keeps redacting generic values in API-document text; the flag is accepted", () => {
  const r = spawnSync("node", [CLI, "mask", "--entropy"], { input: openapi(SEED), encoding: "utf8" });
  assert.strictEqual(r.status, 0, r.stderr);
  assert.ok(!r.stdout.includes(SEED), "a scanner-scope policy must never weaken redaction");
  const r2 = spawnSync("node", [CLI, "mask", "--entropy", "--include-api-document-entropy"], { input: openapi(SEED), encoding: "utf8" });
  assert.strictEqual(r2.status, 0, r2.stderr);
  assert.ok(!r2.stdout.includes(SEED));
});

test("baseline: written without API-document entropy by default, with it when restored", () => {
  const dir = project();
  try {
    const b1 = path.join(dir, "b1.json");
    const b2 = path.join(dir, "b2.json");
    assert.strictEqual(cli(dir, "scan", "--include-entropy", "--write-baseline", b1).status, 0);
    assert.strictEqual(cli(dir, "scan", "--include-entropy", "--include-api-document-entropy", "--write-baseline", b2).status, 0);
    const fps = (p: string): string[] => JSON.parse(readFileSync(p, "utf8")).fingerprints;
    assert.ok(!fps(b1).includes(expectedFingerprint("api/openapi.json", SEED)));
    assert.ok(fps(b2).includes(expectedFingerprint("api/openapi.json", SEED)));
    assert.ok(fps(b1).includes(expectedFingerprint("config/app.json", SEED2)));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
suite("MCP project scan");

test("follows the project file; discloses the count as a number and in the statement; restores", () => {
  const dir = project();
  try {
    write(dir, ".secretloop.json", JSON.stringify({ entropyPassEnabled: true }));
    setAllowedRoots([dir]);
    const p = payload(toolScan({ path: dir }));
    assert.strictEqual(p.scope.apiDocumentsScoped, 1);
    assert.ok(String(p.scope.statement).includes(CLAUSE), p.scope.statement);
    assert.strictEqual(p.config.includeApiDocumentEntropy, false);
    assert.deepStrictEqual(p.findings.filter((f: any) => f.ruleId === "generic-high-entropy").map((f: any) => f.file), ["config/app.json"]);
    assert.ok(!JSON.stringify(p.scope).includes("openapi"), "no path in the scope metadata");
    assert.ok(!JSON.stringify(p.scope).includes(SEED));

    write(dir, ".secretloop.json", JSON.stringify({ entropyPassEnabled: true, includeApiDocumentEntropy: true }));
    const q = payload(toolScan({ path: dir }));
    assert.strictEqual(q.scope.apiDocumentsScoped, 0);
    assert.doesNotMatch(String(q.scope.statement), /API description/);
    assert.strictEqual(q.config.includeApiDocumentEntropy, true);
    assert.deepStrictEqual(q.findings.filter((f: any) => f.ruleId === "generic-high-entropy").map((f: any) => f.file).sort(), ["api/openapi.json", "config/app.json"]);

    write(dir, ".secretloop.json", JSON.stringify({}));
    const off = payload(toolScan({ path: dir }));
    assert.strictEqual(off.scope.apiDocumentsScoped, 0);
    assert.deepStrictEqual(off.findings.filter((f: any) => f.ruleId === "generic-high-entropy"), []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

finish();
