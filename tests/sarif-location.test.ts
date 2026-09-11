import { test, suite, finish, assert } from "./harness";
import { scanText } from "../src/scanner";
import { render } from "../src/report";
import { positiveSamples } from "./fixtures";

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

finish();
