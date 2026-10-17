import { test, suite, finish, assert } from "./harness";
import { scanText } from "../src/scanner";
import { render } from "../src/report";
import { positiveSamples } from "./fixtures";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { spawnSync } from "child_process";
import * as path from "path";

/**
 * SARIF driver version and precise column locations.
 *
 * Two separate claims, both previously unmet. `tool.driver.version` was absent,
 * so a code-scanning alert could not be attributed to a SecretLoop version. And
 * `region` carried only `startLine`, so GitHub annotated the whole line rather
 * than the matched span -- on a minified bundle or a long URL, that is the whole
 * file's worth of characters for a twenty-character credential.
 *
 * Columns are asserted against the ORIGINAL SOURCE TEXT, never against the
 * masked value: the redacted form has a different length, and inferring width
 * from it would encode the mask into the location.
 */

const SAMPLE = positiveSamples["github-token"];

function sarifOf(text: string, file = "a.txt", opts: Record<string, unknown> = {}) {
  const findings = scanText(text, { filePath: file });
  return {
    findings,
    doc: JSON.parse(render(findings, "sarif", { redact: true, root: "", ...opts } as any)),
  };
}

function firstRegion(doc: any) {
  return doc.runs[0].results[0].locations[0].physicalLocation.region;
}

suite("SARIF — tool.driver.version");

test("the driver version is the version the caller supplies", () => {
  const { doc } = sarifOf(`token = "${SAMPLE}"\n`, "a.txt", { toolVersion: "9.9.9" });
  assert.strictEqual(doc.runs[0].tool.driver.version, "9.9.9");
});

test("no version supplied means the key is absent, not empty", () => {
  const { doc } = sarifOf(`token = "${SAMPLE}"\n`);
  assert.ok(!("version" in doc.runs[0].tool.driver), "an empty version is worse than none");
});

suite("SARIF — precise columns");

test("columnKind is declared, so a consumer knows how to count", () => {
  const { doc } = sarifOf(`token = "${SAMPLE}"\n`);
  assert.strictEqual(doc.runs[0].columnKind, "utf16CodeUnits");
});

test("an ordinary capture gets a 1-based start and an EXCLUSIVE end", () => {
  const line = `token = "${SAMPLE}"`;
  const { findings, doc } = sarifOf(line + "\n");
  const f = findings[0];
  const r = firstRegion(doc);
  // asserted against the original source, not against the masked value
  assert.strictEqual(line.slice(r.startColumn - 1, r.endColumn - 1), f.value);
  assert.strictEqual(r.startColumn, line.indexOf(f.value) + 1);
  assert.strictEqual(r.endColumn, r.startColumn + f.value.length);
});

test("two identical values on one line get distinct, correct columns", () => {
  const line = `a="${SAMPLE}" b="${SAMPLE}"`;
  const { doc } = sarifOf(line + "\n");
  const cols = doc.runs[0].results.map((r: any) => r.locations[0].physicalLocation.region.startColumn);
  assert.strictEqual(new Set(cols).size, cols.length, "identical values collapsed to one column");
  for (const c of cols) assert.strictEqual(line.slice(c - 1, c - 1 + SAMPLE.length), SAMPLE);
});

test("a non-BMP character before the capture shifts the column by its UTF-16 width", () => {
  const line = `x="\u{1F510}" token="${SAMPLE}"`;   // the emoji is 2 UTF-16 code units
  const { doc } = sarifOf(line + "\n");
  const r = firstRegion(doc);
  assert.strictEqual(r.startColumn, line.indexOf(SAMPLE) + 1, "column must count the declared units");
  assert.strictEqual(line.slice(r.startColumn - 1, r.endColumn - 1), SAMPLE);
});

test("a tab before the capture counts as one character, not a tab stop", () => {
  const line = `\ttoken="${SAMPLE}"`;
  const { doc } = sarifOf(line + "\n");
  assert.strictEqual(firstRegion(doc).startColumn, line.indexOf(SAMPLE) + 1);
});

test("CRLF line endings do not shift the column on the following line", () => {
  const text = `first\r\ntoken="${SAMPLE}"\r\n`;
  const { doc } = sarifOf(text);
  const r = firstRegion(doc);
  assert.strictEqual(r.startLine, 2);
  assert.strictEqual(r.startColumn, `token="`.length + 1);
});

test("an archive member omits columns, because the artifact is the container", () => {
  const findings = scanText(`token = "${SAMPLE}"\n`, {
    filePath: "d.zip/inner.txt",
    source: { container: "d.zip", member: "inner.txt" } as any,
  });
  const doc = JSON.parse(render(findings, "sarif", { redact: true, root: "" } as any));
  const r = firstRegion(doc);
  assert.ok(r.startLine >= 1, "the line is still reported");
  assert.ok(!("startColumn" in r), "a member column against a container artifact would be wrong");
});

suite("SARIF — nothing else moved");

test("no credential value appears in the SARIF", () => {
  const { doc } = sarifOf(`token = "${SAMPLE}"\n`, "a.txt", { toolVersion: "9.9.9" });
  assert.ok(!JSON.stringify(doc).includes(SAMPLE), "a raw credential reached the report");
});

test("existing location, fingerprint and scope fields are preserved", () => {
  const { doc } = sarifOf(`token = "${SAMPLE}"\n`, "a.txt", { scope: "1 file(s)" });
  const loc = doc.runs[0].results[0].locations[0].physicalLocation;
  assert.strictEqual(loc.artifactLocation.uri, "a.txt");
  assert.ok(doc.runs[0].results[0].partialFingerprints["secretloopFingerprint/v2"]);
  assert.strictEqual(doc.runs[0].invocations[0].properties.scope, "1 file(s)");
  assert.strictEqual(doc.runs[0].invocations[0].executionSuccessful, true);
});

suite("SARIF — an artifact location is a URI reference that names the file");

/*
 * `artifactLocation.uri` is a URI reference (SARIF 2.1.0 §3.4.3, RFC 3986), and it carried the scan-root-relative
 * path verbatim. A consumer resolving it then names another file: `#` starts a fragment and `?` a query, so
 * `x#1.js` reads as `x`; `%` begins an escape, so `100%25.js` names `100%.js`; a backslash is a separator to the
 * WHATWG parser that code scanning's tooling uses. A space, a control character or a non-ASCII character makes the
 * reference invalid. Each segment is now percent-encoded and `/` kept; the characters RFC 3986 allows in a path
 * stay literal, so an ordinary name -- `src/app.ts`, `@types/x`, `c++/m.cc` -- is byte-identical. Fingerprints are
 * not derived from the URI, and an archive member keeps its container as the artifact and its own names in the
 * logical location.
 */

const PCHAR_NC = "(?:[A-Za-z0-9\\-._~!$&'()*+,;=@]|%[0-9A-Fa-f]{2})";
const PCHAR = "(?:[A-Za-z0-9\\-._~!$&'()*+,;=:@]|%[0-9A-Fa-f]{2})";
// RFC 3986 relative-ref, path-noscheme, with no query or fragment: exactly a path relative to the base.
const PATH_NOSCHEME = new RegExp(`^${PCHAR_NC}+(?:/${PCHAR}*)*$`);

function uriOf(file: string): string {
  const { doc } = sarifOf(`token = "${SAMPLE}"\n`, file);
  return doc.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
}

/** The file a consumer reaches by resolving `uri` against a scan-root base, as a decoded relative path. */
function resolvedName(uri: string): string {
  const u = new URL(uri, "file:///scan-root/");
  assert.strictEqual(u.search + u.hash, "", `${JSON.stringify(uri)} resolves with a query or fragment`);
  return decodeURIComponent(u.pathname.slice("/scan-root/".length));
}

const SPECIAL: Array<[string, string]> = [
  ["a b.js", "a%20b.js"],
  ["x#1.js", "x%231.js"],
  ["q?.js", "q%3F.js"],
  ["100%.js", "100%25.js"],
  ["100%25.js", "100%2525.js"],
  ["café.js", "caf%C3%A9.js"],
  ["back\\slash.js", "back%5Cslash.js"],
  ["tab\tname.js", "tab%09name.js"],
  ["new\nline.js", "new%0Aline.js"],
  ["br[1]|{x}.js", "br%5B1%5D%7C%7Bx%7D.js"],
  ["q\"<>^`.js", "q%22%3C%3E%5E%60.js"],
  ["a:b.js", "a%3Ab.js"],
  ["dir/a:b.js", "dir/a:b.js"],
  ["dir name/sub#/f?.js", "dir%20name/sub%23/f%3F.js"],
];

for (const [name, want] of SPECIAL) {
  test(`${JSON.stringify(name)} is written as ${want} and resolves back to the same file`, () => {
    const uri = uriOf(name);
    assert.strictEqual(uri, want);
    assert.match(uri, PATH_NOSCHEME, "not a valid relative URI reference");
    assert.strictEqual(resolvedName(uri), name, "the URI names another file");
  });
}

test("ordinary names are written exactly as before", () => {
  for (const name of ["a.txt", "src/app.ts", "config/.env", "@types/node/index.d.ts", "c++/main.cc", "a-b_c.d~e/f(1)!.js", "k=v,x;y&z$'*/f.js", "deep/a:b/c.js"]) {
    const uri = uriOf(name);
    assert.strictEqual(uri, name);
    assert.match(uri, PATH_NOSCHEME);
    assert.strictEqual(resolvedName(uri), name);
  }
});

test("a name holding a lone UTF-16 surrogate still renders, as U+FFFD", () => {
  const uri = uriOf("bad\uD800.js");
  assert.strictEqual(uri, "bad%EF%BF%BD.js");
  assert.match(uri, PATH_NOSCHEME);
});

test("the fingerprint does not depend on the URI", () => {
  const { findings, doc } = sarifOf(`token = "${SAMPLE}"\n`, "dir name/x#1.js");
  assert.ok(findings[0].fingerprint);
  assert.strictEqual(doc.runs[0].results[0].partialFingerprints["secretloopFingerprint/v2"], findings[0].fingerprint);
});

test("an archive member: the container is encoded, the logical location keeps the real names", () => {
  const findings = scanText(`token = "${SAMPLE}"\n`, {
    filePath: "my dir/b#.zip/in ner.txt",
    source: { container: "my dir/b#.zip", member: "in ner.txt" } as any,
  });
  const doc = JSON.parse(render(findings, "sarif", { redact: true, root: "" } as any));
  const loc = doc.runs[0].results[0].locations[0];
  assert.strictEqual(loc.physicalLocation.artifactLocation.uri, "my%20dir/b%23.zip");
  assert.strictEqual(resolvedName(loc.physicalLocation.artifactLocation.uri), "my dir/b#.zip");
  assert.deepStrictEqual(loc.logicalLocations, [{ fullyQualifiedName: "my dir/b#.zip/in ner.txt", name: "in ner.txt", kind: "member" }]);
});

test("the document keeps its SARIF 2.1.0 shape, and every result's URI is a relative reference", () => {
  const files = SPECIAL.map(([n]) => n).concat(["src/app.ts"]);
  const findings = files.flatMap((f) => scanText(`token = "${SAMPLE}"\n`, { filePath: f }));
  const doc = JSON.parse(render(findings, "sarif", { redact: true, root: "" } as any));
  assert.strictEqual(doc.version, "2.1.0");
  assert.strictEqual(doc.$schema, "https://json.schemastore.org/sarif-2.1.0.json");
  assert.strictEqual(doc.runs.length, 1);
  assert.strictEqual(doc.runs[0].results.length, files.length);
  for (const r of doc.runs[0].results) {
    assert.strictEqual(r.locations.length, 1);
    const uri = r.locations[0].physicalLocation.artifactLocation.uri;
    assert.strictEqual(typeof uri, "string");
    assert.match(uri, PATH_NOSCHEME);
    assert.ok(!("uriBaseId" in r.locations[0].physicalLocation.artifactLocation), "no base id was introduced");
  }
  assert.deepStrictEqual(doc.runs[0].results.map((r: any) => resolvedName(r.locations[0].physicalLocation.artifactLocation.uri)).sort(), [...files].sort());
});

test("CLI: a real file whose path holds a space, '#' and '%' is located by its encoded URI", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-sarif-uri-"));
  try {
    mkdirSync(path.join(dir, "my dir"));
    writeFileSync(path.join(dir, "my dir", "a b#100%.js"), "pass" + 'word = "Qm7vR2xKp9Lw4Tz8Hc3N"\n', "utf8");
    const cli = path.join(__dirname, "..", "out", "cli.js");
    const r = spawnSync(process.execPath, [cli, "scan", "--path", dir, "--format", "sarif", "--fail-on", "never"], { encoding: "utf8", timeout: 30000 });
    assert.strictEqual(r.status, 0, r.stderr);
    const doc = JSON.parse(r.stdout);
    const uris = doc.runs[0].results.map((x: any) => x.locations[0].physicalLocation.artifactLocation.uri);
    assert.ok(uris.length >= 1, "the file produced no result");
    assert.deepStrictEqual([...new Set(uris)], ["my%20dir/a%20b%23100%25.js"]);
    assert.strictEqual(resolvedName(uris[0]), "my dir/a b#100%.js");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

finish();
