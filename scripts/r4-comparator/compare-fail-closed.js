#!/usr/bin/env node
"use strict";
/*
 * R4 fail-closed comparator (SL-R08). Compares two evidence directories written by the same
 * fixed scan set on two builds, against an explicit inventory, a checksum record, and explicit
 * approvals. Node built-ins only; it imports nothing from the product.
 *
 *   node compare-fail-closed.js --inventory <inventory.json> --base <dir> --candidate <dir>
 *       [--deltas <approvals.json>] [--reproduction <historical.json>]
 *       [--manifest <MANIFEST.txt>]... [--out <dir>]
 *
 * Verdicts and exit codes (a BLOCK overrides any comparison result):
 *   PASS                 (0)  every difference is covered by a release approval.
 *   FAIL                 (1)  at least one difference is covered by no approval.
 *   BLOCK                (2)  an input cannot be trusted, or an approval is invalid, stale or
 *                             over-broad, or the two sides are the same directory. Output-write
 *                             failures are BLOCK too. Usage errors exit 64.
 *   PASS-REPRODUCTION    (3)  the run was given a historical reproduction, and every difference is
 *                             covered. It is never reported as PASS, so a reproduction cannot be
 *                             mistaken for release evidence by a caller that tests only for 0.
 *
 * Approvals (--deltas, schema r4-deltas-1, status "approved") are release authority. Each one
 * names exactly one report, the exact base and candidate bytes it applies to (sha256), the
 * finding or field it matches, and the exact old and/or new values. Each approval covers at most
 * one difference. A historical reproduction (--reproduction, schema r4-reproduction-1, status
 * "historical-reproduction") uses the same rules, is never accepted in the approvals file, and
 * is applied only when that flag is given. It is labelled "reproduction" in the record.
 *
 * Nothing is allowlisted by default. Missing, empty or extra match keys BLOCK. Unknown approval
 * fields BLOCK. A approval that matches no difference BLOCKs as stale.
 *
 * Masked values: finding identity pairing uses the masked `value` the product writes, not the raw
 * credential. Two credentials with the same mask at the same site can be paired on the wrong
 * fingerprint. That is not a false PASS: each base and candidate finding still lands in exactly one
 * category, and an identity change is approvable only by its exact fingerprint pair, so it cannot
 * cover a different site or a lost or new finding. It can mislabel which of two same-mask findings
 * "changed"; a reviewer must read the pinned pair, not infer it from the mask.
 *
 * Output is deterministic: no timestamps, canonical key order, sorted differences.
 */
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const SUMS_NAME = "SHA256SUMS";
const MANIFEST_NAME = "MANIFEST.txt";
const SARIF_IDENTITY = "secretloopFingerprint/v2";
const FINDING_KEY_FIELDS = ["file", "line", "ruleId", "fingerprint", "severity", "confidence", "value"];
const REQUIRED_REPORT_KEYS = ["schemaVersion", "summary", "findings", "incomplete"];
const KINDS = new Set(["json", "sarif", "text", "stderr"]);
const INVENTORY_SCHEMA = "r4-inventory-1";
const APPROVAL_SCHEMA = "r4-deltas-1";
const REPRODUCTION_SCHEMA = "r4-reproduction-1";
const RECORD_SCHEMA = "r4-delta-record-2";
const ENVELOPE_KEYS = ["schema", "note", "approvals"];
const APPROVAL_KEYS = ["id", "status", "reason", "category", "report", "baseSha256", "candidateSha256", "match", "from", "to"];
const NULLABLE_MATCH_KEYS = new Set(["identity", "newIdentity"]);

// Every category an approval may cover, with the match keys it must pin and the value keys
// (from / to) it must carry. Anything not listed here cannot be approved.
const RULES = {
  "json-changed": { match: ["path"], pins: ["from", "to"] },
  "json-added": { match: ["path"], pins: ["to"] },
  "json-removed": { match: ["path"], pins: ["from"] },
  "finding-lost": { match: ["fingerprint"], pins: [] },
  "finding-new": { match: ["fingerprint"], pins: [] },
  "finding-reclassified": { match: ["fingerprint", "detail"], pins: [] },
  "finding-identity-changed": { match: ["fingerprint", "newFingerprint"], pins: [] },
  "finding-field-changed": { match: ["fingerprint", "field"], pins: ["from", "to"] },
  "finding-field-added": { match: ["fingerprint", "field"], pins: ["to"] },
  "finding-field-removed": { match: ["fingerprint", "field"], pins: ["from"] },
  "sarif-changed": { match: ["path"], pins: ["from", "to"] },
  "sarif-added": { match: ["path"], pins: ["to"] },
  "sarif-removed": { match: ["path"], pins: ["from"] },
  "sarif-run-count": { match: ["detail"], pins: [] },
  "sarif-result-lost": { match: ["identity", "uri"], pins: [] },
  "sarif-result-new": { match: ["identity", "uri"], pins: [] },
  "sarif-identity-changed": { match: ["identity", "newIdentity"], pins: [] },
  "sarif-uri-encoding": { match: ["identity", "uri", "candidateUri"], pins: [] },
  "sarif-uri-changed": { match: ["identity", "uri", "candidateUri"], pins: [] },
  "sarif-result-changed": { match: ["identity", "detail"], pins: [] },
  "stderr-output": { match: ["detail"], pins: [] },
  "text-output": { match: ["detail"], pins: [] },
};

// Thrown for every condition that must end in BLOCK. Anything else is also treated as BLOCK.
class Refusal extends Error {}

function refuse(message) {
  throw new Refusal(message);
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasOwn(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key);
}

function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

// Canonical JSON: sorted keys, no whitespace. Every equality test and every output uses it, so a
// string "5" and a number 5 are different, as are null and absent.
function stable(value) {
  if (value === undefined) return "undefined";
  if (Array.isArray(value)) return "[" + value.map(stable).join(",") + "]";
  if (isPlainObject(value)) {
    return (
      "{" +
      Object.keys(value)
        .sort()
        .map((k) => JSON.stringify(k) + ":" + stable(value[k]))
        .join(",") +
      "}"
    );
  }
  return JSON.stringify(value);
}

function union(a, b) {
  return [...new Set([...a, ...b])].sort();
}

// ---------------------------------------------------------------- strict JSON

// Parses JSON and refuses duplicate object keys at every depth. JSON.parse keeps the last of two
// equal keys, which would let a shadowed field escape the schema check. Objects are null-prototype
// so a key named __proto__ is an ordinary key.
function parseStrictJson(text) {
  let i = 0;
  const skip = () => {
    while (i < text.length && " \t\n\r".includes(text[i])) i++;
  };
  const expect = (ch) => {
    if (text[i] !== ch) refuse(`malformed JSON at offset ${i}`);
    i++;
  };
  const str = () => {
    expect('"');
    let out = "";
    const simple = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
    for (;;) {
      if (i >= text.length) refuse("malformed JSON: unterminated string");
      const c = text[i++];
      if (c === '"') return out;
      if (c < " ") refuse("malformed JSON: control character in string");
      if (c !== "\\") {
        out += c;
        continue;
      }
      const e = text[i++];
      if (e !== undefined && hasOwn(simple, e)) {
        out += simple[e];
      } else if (e === "u" && /^[0-9a-fA-F]{4}$/.test(text.slice(i, i + 4))) {
        out += String.fromCharCode(parseInt(text.slice(i, i + 4), 16));
        i += 4;
      } else {
        refuse(`malformed JSON: bad escape at offset ${i}`);
      }
    }
  };
  const num = () => {
    const re = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;
    re.lastIndex = i;
    const m = re.exec(text);
    if (!m) refuse(`malformed JSON value at offset ${i}`);
    i = re.lastIndex;
    return Number(m[0]);
  };
  const value = () => {
    skip();
    const c = text[i];
    if (c === "{") return obj();
    if (c === "[") return arr();
    if (c === '"') return str();
    if (text.startsWith("true", i)) {
      i += 4;
      return true;
    }
    if (text.startsWith("false", i)) {
      i += 5;
      return false;
    }
    if (text.startsWith("null", i)) {
      i += 4;
      return null;
    }
    return num();
  };
  const obj = () => {
    expect("{");
    const o = Object.create(null);
    skip();
    if (text[i] === "}") {
      i++;
      return o;
    }
    for (;;) {
      skip();
      const key = str();
      skip();
      expect(":");
      if (hasOwn(o, key)) refuse(`duplicate JSON key at offset ${i}`);
      o[key] = value();
      skip();
      if (text[i] === ",") {
        i++;
        continue;
      }
      expect("}");
      return o;
    }
  };
  const arr = () => {
    expect("[");
    const a = [];
    skip();
    if (text[i] === "]") {
      i++;
      return a;
    }
    for (;;) {
      a.push(value());
      skip();
      if (text[i] === ",") {
        i++;
        continue;
      }
      expect("]");
      return a;
    }
  };
  const result = value();
  skip();
  if (i !== text.length) refuse("malformed JSON: trailing content");
  return result;
}

function parseJsonBuffer(buffer, label) {
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(buffer);
  } catch {
    refuse(`${label} is not valid UTF-8`);
  }
  return parseStrictJson(text);
}

// ---------------------------------------------------------------- files

// Reads a regular file without following a symbolic link in the final component. A link, a
// directory, or a special file is refused. Where the platform has no O_NOFOLLOW, the fstat check
// still refuses non-regular files, but a link is then followed; the comparator says so in its docs.
function readRegular(file, what) {
  const base = path.basename(file);
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  } catch (err) {
    if (err.code === "ELOOP") refuse(`${what} is a symbolic link: ${base}`);
    refuse(`${what} cannot be read: ${base}`);
  }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) refuse(`${what} is not a regular file: ${base}`);
    return fs.readFileSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

// Windows device names, with or without an extension (CON.json is still CON on Windows).
const WINDOWS_RESERVED = /^(con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³])(\.|$)/i;

// A report name that is safe on every platform the comparator runs on. It refuses colons (NTFS
// alternate data streams and drive-relative names such as C:x), characters Windows forbids,
// control characters, names Windows silently trims, device names and over-long names.
function isSafeReportName(name) {
  return (
    isPlainName(name) &&
    Buffer.byteLength(name, "utf8") <= 255 &&
    !/[\u0000-\u001f\u007f:<>"|?*]/.test(name) &&
    !/^\s|\s$|\.$/.test(name) &&
    !WINDOWS_RESERVED.test(name)
  );
}

// Identity of a report directory: follows the path, so a link to the other side is caught too.
function directoryIdentity(dir, label) {
  try {
    return fs.statSync(path.resolve(dir));
  } catch {
    refuse(`${label} directory cannot be read`);
  }
  return null;
}

function isPlainName(name) {
  return (
    typeof name === "string" &&
    name.length > 0 &&
    name !== "." &&
    name !== ".." &&
    !name.includes("/") &&
    !name.includes("\\") &&
    !name.includes("\0") &&
    name !== SUMS_NAME &&
    name !== MANIFEST_NAME
  );
}

// ---------------------------------------------------------------- inputs

function parseInventory(buffer) {
  const doc = parseJsonBuffer(buffer, "inventory");
  if (!isPlainObject(doc) || doc.schema !== INVENTORY_SCHEMA || !Array.isArray(doc.reports)) {
    refuse(`inventory must declare schema ${INVENTORY_SCHEMA} and a reports array`);
  }
  if (doc.reports.length === 0) refuse("inventory lists no reports");
  const seen = new Set();
  return doc.reports.map((entry) => {
    if (!isPlainObject(entry) || !isSafeReportName(entry.file) || !KINDS.has(entry.kind)) {
      refuse("inventory entry is malformed");
    }
    if (seen.has(entry.file)) refuse(`inventory lists ${entry.file} twice`);
    seen.add(entry.file);
    return { file: entry.file, kind: entry.kind };
  });
}

// Validates one approval or reproduction record. Unknown and misspelt keys, missing or extra match
// keys, unpinned values, wrong status, and reused ids are all refusals.
function validateApproval(a, source, ids) {
  if (!isPlainObject(a)) refuse(`${source} entry is not an object`);
  for (const key of Object.keys(a)) {
    if (!APPROVAL_KEYS.includes(key)) refuse(`${source} entry has an unknown field: ${key}`);
  }
  if (typeof a.id !== "string" || !/^[A-Za-z0-9._-]{1,80}$/.test(a.id)) refuse(`${source} entry has an invalid id`);
  const label = a.id;
  if (ids.has(label)) refuse(`${source} id ${label} is repeated`);
  ids.add(label);
  const wanted = source === "approval" ? "approved" : "historical-reproduction";
  if (a.status !== wanted) refuse(`${source} ${label} status must be "${wanted}" in this file`);
  if (typeof a.reason !== "string" || a.reason.trim().length === 0) refuse(`${source} ${label} has no reason`);
  if (!hasOwn(RULES, a.category)) refuse(`${source} ${label} names an unapprovable category`);
  const rule = RULES[a.category];
  if (typeof a.report !== "string" || a.report.includes("*") || !isSafeReportName(a.report)) {
    refuse(`${source} ${label} must name exactly one report`);
  }
  if (typeof a.baseSha256 !== "string" || !/^[0-9a-f]{64}$/.test(a.baseSha256)) refuse(`${source} ${label} needs baseSha256`);
  if (typeof a.candidateSha256 !== "string" || !/^[0-9a-f]{64}$/.test(a.candidateSha256)) refuse(`${source} ${label} needs candidateSha256`);
  if (!isPlainObject(a.match)) refuse(`${source} ${label} has no match criteria`);
  for (const key of Object.keys(a.match)) {
    if (!rule.match.includes(key)) refuse(`${source} ${label} match has an unknown key: ${key}`);
  }
  for (const key of rule.match) {
    if (!hasOwn(a.match, key)) refuse(`${source} ${label} match lacks ${key}`);
    const v = a.match[key];
    const okNull = v === null && NULLABLE_MATCH_KEYS.has(key);
    if (!okNull && (typeof v !== "string" || v.length === 0)) refuse(`${source} ${label} match ${key} must be a non-empty string`);
  }
  for (const pin of rule.pins) {
    if (!hasOwn(a, pin)) refuse(`${source} ${label} must pin ${pin} for ${a.category}`);
  }
  for (const pin of ["from", "to"]) {
    if (hasOwn(a, pin) && !rule.pins.includes(pin)) refuse(`${source} ${label} may not carry ${pin} for ${a.category}`);
  }
}

function loadApprovals(buffer, source) {
  const doc = parseJsonBuffer(buffer, source);
  const schema = source === "approval" ? APPROVAL_SCHEMA : REPRODUCTION_SCHEMA;
  if (!isPlainObject(doc) || doc.schema !== schema) refuse(`${source} file must declare schema ${schema}`);
  for (const key of Object.keys(doc)) {
    if (!ENVELOPE_KEYS.includes(key)) refuse(`${source} file has an unknown field: ${key}`);
  }
  if (!Array.isArray(doc.approvals)) refuse(`${source} file has no approvals array`);
  if (source === "reproduction" && doc.approvals.length === 0) refuse("reproduction file has no entries");
  const ids = new Set();
  return doc.approvals.map((a) => {
    validateApproval(a, source, ids);
    return { ...a, used: 0 };
  });
}

// A manifest line is "<sha256>  <bytes>  <path relative to the manifest>". Every payload is read
// without following links and verified, so a tampered payload blocks the run whatever the
// directory form.
function loadManifest(file) {
  const abs0 = path.resolve(file);
  const text = readRegular(abs0, "manifest").toString("utf8");
  const entries = new Map();
  for (const raw of text.split("\n")) {
    const line = raw.replace(/\r$/, "");
    if (line === "" || line.startsWith("#")) continue;
    const m = /^([0-9a-f]{64})  (\d+)  (.+)$/.exec(line);
    if (!m) refuse(`manifest ${path.basename(abs0)} has a malformed line`);
    const abs = path.resolve(path.dirname(abs0), m[3]);
    if (entries.has(abs)) refuse(`manifest ${path.basename(abs0)} repeats an entry`);
    entries.set(abs, { sha: m[1], bytes: Number(m[2]) });
  }
  for (const [abs, entry] of entries) {
    const buffer = readRegular(abs, "manifest payload");
    if (buffer.length !== entry.bytes || sha256(buffer) !== entry.sha) {
      refuse(`manifest payload does not match: ${path.basename(abs)}`);
    }
  }
  return entries;
}

function loadSums(buffer) {
  const sums = new Map();
  for (const raw of buffer.toString("utf8").split("\n")) {
    if (raw === "") continue;
    const m = /^([0-9a-f]{64})  (.+)$/.exec(raw);
    if (!m || !isPlainName(m[2])) refuse(`${SUMS_NAME} has a malformed line`);
    if (sums.has(m[2])) refuse(`${SUMS_NAME} repeats ${m[2]}`);
    sums.set(m[2], m[1]);
  }
  return sums;
}

// Reads every report in one directory. The directory itself must be a real directory, not a link.
// Every entry must be an inventory report or the checksum file. Every report must be covered by a
// checksum that matches its bytes, from SHA256SUMS or a manifest. Returns name -> bytes.
function readDirectory(dir, label, reports, manifest) {
  const root = path.resolve(dir);
  let st;
  try {
    st = fs.lstatSync(root);
  } catch {
    refuse(`${label} directory cannot be read`);
  }
  if (st.isSymbolicLink() || !st.isDirectory()) refuse(`${label} must be a real directory, not a link`);
  const expected = new Set(reports.map((r) => r.file));
  let hasSums = false;
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    if (entry.name === SUMS_NAME) {
      hasSums = true;
      continue;
    }
    if (!entry.isFile()) refuse(`${label} holds a non-regular entry: ${entry.name}`);
    if (!expected.has(entry.name)) refuse(`${label} holds an unexpected file: ${entry.name}`);
  }
  const sums = hasSums ? loadSums(readRegular(path.join(root, SUMS_NAME), `${label} ${SUMS_NAME}`)) : new Map();
  for (const name of sums.keys()) {
    if (!expected.has(name)) refuse(`${label} ${SUMS_NAME} lists an unexpected file: ${name}`);
  }
  const buffers = new Map();
  for (const name of expected) {
    const abs = path.join(root, name);
    if (!fs.existsSync(abs)) refuse(`${label} is missing report ${name}`);
    const buffer = readRegular(abs, `${label} report`);
    const digest = sha256(buffer);
    let covered = false;
    if (sums.has(name)) {
      if (sums.get(name) !== digest) refuse(`${label} checksum mismatch: ${name}`);
      covered = true;
    }
    if (manifest.has(abs)) {
      const entry = manifest.get(abs);
      if (entry.sha !== digest || entry.bytes !== buffer.length) refuse(`${label} manifest mismatch: ${name}`);
      covered = true;
    }
    if (!covered) refuse(`${label} report has no checksum record: ${name}`);
    buffers.set(name, buffer);
  }
  return buffers;
}

// ---------------------------------------------------------------- JSON reports

function requireReportShape(name, label, doc) {
  if (!isPlainObject(doc)) refuse(`${name}: ${label} is not a JSON object`);
  for (const key of REQUIRED_REPORT_KEYS) {
    if (!hasOwn(doc, key)) refuse(`${name}: ${label} lacks required field ${key}`);
  }
  requireKnownFields(name, label, "report", doc, KNOWN_TOP_FIELDS);
  if (isPlainObject(doc.summary)) {
    requireKnownFields(name, label, "summary", doc.summary, KNOWN_SUMMARY_FIELDS);
    if (isPlainObject(doc.summary.coverage)) {
      requireKnownFields(name, label, "summary.coverage", doc.summary.coverage, KNOWN_COVERAGE_FIELDS);
    }
  }
  if (!Array.isArray(doc.findings)) refuse(`${name}: ${label} findings is not an array`);
  doc.findings.forEach((f, i) => {
    if (!isPlainObject(f)) refuse(`${name}: ${label} finding ${i} is not an object`);
    for (const key of FINDING_KEY_FIELDS) {
      if (!hasOwn(f, key)) refuse(`${name}: ${label} finding ${i} lacks ${key}`);
    }
    requireKnownFields(name, label, `finding ${i}`, f, KNOWN_FINDING_FIELDS);
  });
}

// Every field a report may carry. A field outside these lists is a schema the comparator does not
// know, so the run BLOCKs. Adding a field to the product means adding it here deliberately.
const KNOWN_TOP_FIELDS = [
  "tool", "schemaVersion", "toolVersion", "root", "configDigest", "ruleSetDigest",
  "suppressionDigest", "scopeDigest", "binaryDigest", "incomplete", "summary", "findings",
  "credentialGroups",
];
// Fields observed in the frozen N10 reports (schemas 4 and 5), plus the 0.8.0 additions named in
// the CHANGELOG draft. The additions are known but unapproved, so a candidate that carries them is
// a FAIL until an approval covers them.
const KNOWN_SUMMARY_FIELDS = [
  "total", "scope", "scannedCount", "scopeNoun", "coverage", "confirmedLive", "bySeverity",
  "byLiveness", "archives", "credentialGroupCount", "groupedFindingCount",
];
const KNOWN_COVERAGE_FIELDS = ["limitations", "suppression", "openedFileChecks"];
const KNOWN_FINDING_FIELDS = [
  "ruleId", "description", "severity", "confidence", "verifyStatus", "verifyReason", "verifyDetail",
  "file", "line", "commit", "fingerprint", "alsoMatched", "value", "id",
];

function requireKnownFields(name, label, where, obj, known) {
  for (const key of Object.keys(obj)) {
    if (!known.includes(key)) refuse(`${name}: ${label} ${where} has an unknown field: ${key}`);
  }
}

function deepDiff(report, p, a, b, diffs, cat) {
  if (isPlainObject(a) && isPlainObject(b)) {
    for (const k of union(Object.keys(a), Object.keys(b))) {
      const q = `${p}.${k}`;
      if (!hasOwn(b, k)) diffs.push({ report, category: `${cat}-removed`, path: q, from: a[k] });
      else if (!hasOwn(a, k)) diffs.push({ report, category: `${cat}-added`, path: q, to: b[k] });
      else deepDiff(report, q, a[k], b[k], diffs, cat);
    }
  } else if (stable(a) !== stable(b)) {
    diffs.push({ report, category: `${cat}-changed`, path: p, from: a, to: b });
  }
}

function findingKey(f) {
  return stable(FINDING_KEY_FIELDS.map((k) => f[k]));
}

function groupBy(list, keyOf) {
  const map = new Map();
  for (const item of list) {
    const k = keyOf(item);
    if (!map.has(k)) map.set(k, []);
    map.get(k).push(item);
  }
  return map;
}

function compareFindingFields(report, a, b, diffs) {
  const keys = union(Object.keys(a), Object.keys(b)).filter((k) => !FINDING_KEY_FIELDS.includes(k));
  for (const k of keys) {
    const base = { report, fingerprint: a.fingerprint, field: k };
    if (!hasOwn(b, k)) diffs.push({ ...base, category: "finding-field-removed", from: a[k] });
    else if (!hasOwn(a, k)) diffs.push({ ...base, category: "finding-field-added", to: b[k] });
    else if (stable(a[k]) !== stable(b[k])) diffs.push({ ...base, category: "finding-field-changed", from: a[k], to: b[k] });
  }
}

function compareFindings(report, baseFindings, candFindings, diffs) {
  const pool = groupBy(candFindings, findingKey);
  const matched = [];
  const baseLeft = [];
  for (const f of baseFindings) {
    const list = pool.get(findingKey(f));
    if (list && list.length > 0) matched.push([f, list.shift()]);
    else baseLeft.push(f);
  }
  for (const [a, b] of matched) compareFindingFields(report, a, b, diffs);

  const candLeft = [...pool.values()].flat();
  // Same fingerprint, different key fields: the same identity whose severity, confidence, rule,
  // file, line or value changed.
  const candByFp = groupBy(candLeft, (f) => f.fingerprint);
  const baseNoFp = [];
  for (const f of baseLeft) {
    const list = candByFp.get(f.fingerprint);
    if (list && list.length > 0) {
      const g = list.shift();
      const fields = FINDING_KEY_FIELDS.filter((k) => stable(f[k]) !== stable(g[k]));
      diffs.push({ report, category: "finding-reclassified", fingerprint: f.fingerprint, detail: fields.join(",") });
      // REQ-1: the key change is one difference; every other changed field is its own difference.
      compareFindingFields(report, f, g, diffs);
    } else baseNoFp.push(f);
  }
  // Same location, rule and value, different fingerprint: an identity change.
  const sameSite = (f) => stable([f.file, f.line, f.ruleId, f.value]);
  const candNoFp = [...candByFp.values()].flat();
  const candBySite = groupBy(candNoFp, sameSite);
  const baseNoSite = [];
  for (const f of baseNoFp) {
    const list = candBySite.get(sameSite(f));
    if (list && list.length > 0) {
      const g = list.shift();
      diffs.push({ report, category: "finding-identity-changed", fingerprint: f.fingerprint, newFingerprint: g.fingerprint });
      // REQ-1: the identity change is one difference; every other changed field is its own difference.
      compareFindingFields(report, f, g, diffs);
    } else baseNoSite.push(f);
  }
  for (const f of baseNoSite) {
    diffs.push({ report, category: "finding-lost", fingerprint: f.fingerprint, file: f.file, line: f.line });
  }
  for (const f of [...candBySite.values()].flat()) {
    diffs.push({ report, category: "finding-new", fingerprint: f.fingerprint, file: f.file, line: f.line });
  }
}

function compareJson(report, base, cand, diffs) {
  requireReportShape(report, "base", base);
  requireReportShape(report, "candidate", cand);
  for (const k of union(Object.keys(base), Object.keys(cand))) {
    if (k === "findings") continue;
    if (!hasOwn(cand, k)) diffs.push({ report, category: "json-removed", path: k, from: base[k] });
    else if (!hasOwn(base, k)) diffs.push({ report, category: "json-added", path: k, to: cand[k] });
    else deepDiff(report, k, base[k], cand[k], diffs, "json");
  }
  compareFindings(report, base.findings, cand.findings, diffs);
}

// ---------------------------------------------------------------- SARIF

function sarifFacts(report, label, result) {
  const loc = Array.isArray(result.locations) ? result.locations[0] : undefined;
  const physical = loc && loc.physicalLocation;
  const uri = physical && physical.artifactLocation ? physical.artifactLocation.uri : undefined;
  const line = physical && physical.region ? physical.region.startLine : undefined;
  if (typeof result.ruleId !== "string" || typeof uri !== "string" || !Number.isInteger(line)) {
    refuse(`${report}: ${label} SARIF result lacks ruleId, artifact uri or startLine`);
  }
  const identity = result.partialFingerprints ? result.partialFingerprints[SARIF_IDENTITY] : undefined;
  return { ruleId: result.ruleId, identity: identity === undefined ? null : identity, line, uri, result };
}

function decodeOrNull(uri) {
  try {
    return decodeURIComponent(uri);
  } catch {
    return null;
  }
}

// The fields a paired result must keep, apart from its identity and its location.
function compareResultRest(report, pair, diffs) {
  const [base, cand] = pair;
  const strip = (r) => {
    const copy = { ...r };
    delete copy.partialFingerprints;
    delete copy.locations;
    return copy;
  };
  if (stable(strip(base.result)) !== stable(strip(cand.result))) {
    diffs.push({ report, category: "sarif-result-changed", identity: base.identity, detail: "result fields" });
  }
  const locStrip = (r) =>
    (Array.isArray(r.locations) ? r.locations : []).map((l) => {
      const copy = JSON.parse(JSON.stringify(l));
      if (copy.physicalLocation) {
        if (copy.physicalLocation.artifactLocation) delete copy.physicalLocation.artifactLocation.uri;
        if (copy.physicalLocation.region) delete copy.physicalLocation.region.startLine;
      }
      return copy;
    });
  if (stable(locStrip(base.result)) !== stable(locStrip(cand.result))) {
    diffs.push({ report, category: "sarif-result-changed", identity: base.identity, detail: "locations" });
  }
}

function compareSarif(report, base, cand, diffs) {
  for (const [label, doc] of [["base", base], ["candidate", cand]]) {
    if (!isPlainObject(doc) || typeof doc.version !== "string" || !Array.isArray(doc.runs)) {
      refuse(`${report}: ${label} is not a SARIF log with version and runs`);
    }
  }
  if (base.version !== cand.version) {
    diffs.push({ report, category: "sarif-changed", path: "version", from: base.version, to: cand.version });
  }
  if (base.runs.length !== cand.runs.length) {
    diffs.push({ report, category: "sarif-run-count", detail: `${base.runs.length} -> ${cand.runs.length}` });
  }
  const runs = Math.min(base.runs.length, cand.runs.length);
  for (let i = 0; i < runs; i++) {
    const br = base.runs[i];
    const cr = cand.runs[i];
    if (!isPlainObject(br) || !isPlainObject(cr)) refuse(`${report}: SARIF run ${i} is not an object`);
    for (const k of union(Object.keys(br), Object.keys(cr))) {
      if (k === "results") continue;
      const q = `runs[${i}].${k}`;
      if (!hasOwn(cr, k)) diffs.push({ report, category: "sarif-removed", path: q, from: br[k] });
      else if (!hasOwn(br, k)) diffs.push({ report, category: "sarif-added", path: q, to: cr[k] });
      else deepDiff(report, q, br[k], cr[k], diffs, "sarif");
    }
    if (!Array.isArray(br.results) || !Array.isArray(cr.results)) refuse(`${report}: SARIF run ${i} has no results array`);
    compareSarifResults(report, br.results, cr.results, diffs);
  }
}

function compareSarifResults(report, baseResults, candResults, diffs) {
  const bf = baseResults.map((r) => sarifFacts(report, "base", r));
  const cf = candResults.map((r) => sarifFacts(report, "candidate", r));
  const full = (f) => stable([f.ruleId, f.identity, f.line, f.uri]);
  const pool = groupBy(cf, full);
  const pairs = [];
  const bLeft = [];
  for (const f of bf) {
    const list = pool.get(full(f));
    if (list && list.length > 0) pairs.push([f, list.shift()]);
    else bLeft.push(f);
  }
  // Same rule, identity and line, different URI: an encoding or path change in artifactLocation.
  const site = (f) => stable([f.ruleId, f.identity, f.line]);
  const cBySite = groupBy([...pool.values()].flat(), site);
  const bNoSite = [];
  for (const f of bLeft) {
    const list = cBySite.get(site(f));
    if (list && list.length > 0) {
      const g = list.shift();
      const category = decodeOrNull(g.uri) === f.uri ? "sarif-uri-encoding" : "sarif-uri-changed";
      diffs.push({ report, category, identity: f.identity, uri: f.uri, candidateUri: g.uri });
      pairs.push([f, g]);
    } else bNoSite.push(f);
  }
  // Same rule, line and URI, different identity: the identity itself changed.
  const sameUri = (f) => stable([f.ruleId, f.line, f.uri]);
  const cByUri = groupBy([...cBySite.values()].flat(), sameUri);
  const bNoUri = [];
  for (const f of bNoSite) {
    const list = cByUri.get(sameUri(f));
    if (list && list.length > 0) {
      const g = list.shift();
      diffs.push({ report, category: "sarif-identity-changed", identity: f.identity, newIdentity: g.identity });
      pairs.push([f, g]);
    } else bNoUri.push(f);
  }
  for (const f of bNoUri) diffs.push({ report, category: "sarif-result-lost", identity: f.identity, uri: f.uri });
  for (const g of [...cByUri.values()].flat()) diffs.push({ report, category: "sarif-result-new", identity: g.identity, uri: g.uri });
  for (const pair of pairs) compareResultRest(report, pair, diffs);
}

// ---------------------------------------------------------------- text and stderr

function compareBytes(report, category, base, cand, diffs) {
  if (Buffer.compare(base, cand) === 0) return;
  const bl = base.toString("utf8").split("\n");
  const cl = cand.toString("utf8").split("\n");
  let line = 0;
  while (line < Math.min(bl.length, cl.length) && bl[line] === cl[line]) line++;
  diffs.push({ report, category, detail: `first difference at line ${line + 1}` });
}

// ---------------------------------------------------------------- approvals

// One approval covers at most one difference. Matching requires the same report, the same
// category, the exact base and candidate bytes of that report, every match key, and every pinned
// value. A pinned value is compared canonically, so 5 and "5" differ.
function approvalMatches(a, d, shaOf) {
  if (a.report !== d.report || a.category !== d.category) return false;
  const shas = shaOf(d.report);
  if (a.baseSha256 !== shas.base || a.candidateSha256 !== shas.candidate) return false;
  for (const key of RULES[d.category].match) {
    if (stable(a.match[key]) !== stable(d[key])) return false;
  }
  for (const pin of ["from", "to"]) {
    if (hasOwn(a, pin) && stable(a[pin]) !== stable(d[pin])) return false;
  }
  return true;
}

function sortDiffs(diffs) {
  const key = (d) => stable([d.report, d.category, d.path || "", d.field || "", d.identity || "", d.fingerprint || "", d.detail || ""]);
  return diffs.slice().sort((x, y) => {
    const kx = key(x);
    const ky = key(y);
    return kx < ky ? -1 : kx > ky ? 1 : 0;
  });
}

// ---------------------------------------------------------------- driver

function compareEvidence(opts) {
  const inventoryBuffer = readRegular(opts.inventory, "inventory");
  const reports = parseInventory(inventoryBuffer);
  const approvalBuffer = opts.deltas ? readRegular(opts.deltas, "approvals") : null;
  const approvals = approvalBuffer ? loadApprovals(approvalBuffer, "approval") : [];
  const reproductionBuffer = opts.reproduction ? readRegular(opts.reproduction, "reproduction") : null;
  const reproductions = reproductionBuffer ? loadApprovals(reproductionBuffer, "reproduction") : [];

  const manifest = new Map();
  const manifestRecords = [];
  for (const file of opts.manifests || []) {
    const entries = loadManifest(file);
    for (const [abs, entry] of entries) {
      if (manifest.has(abs) && manifest.get(abs).sha !== entry.sha) refuse("manifests disagree about a payload");
      manifest.set(abs, entry);
    }
    manifestRecords.push({ file: path.basename(file), sha256: sha256(readRegular(file, "manifest")), entries: entries.size });
  }

  // The same directory on both sides would compare a build with itself and PASS by construction.
  const baseId = directoryIdentity(opts.base, "base");
  const candId = directoryIdentity(opts.candidate, "candidate");
  if (baseId.dev === candId.dev && baseId.ino === candId.ino) {
    refuse("base and candidate are the same directory");
  }
  const baseBuffers = readDirectory(opts.base, "base", reports, manifest);
  const candBuffers = readDirectory(opts.candidate, "candidate", reports, manifest);

  const shas = new Map();
  const reportRecords = [];
  const diffs = [];
  for (const entry of reports) {
    const b = baseBuffers.get(entry.file);
    const c = candBuffers.get(entry.file);
    shas.set(entry.file, { base: sha256(b), candidate: sha256(c) });
    const before = diffs.length;
    if (entry.kind === "json") {
      compareJson(entry.file, parseJsonBuffer(b, `${entry.file} base`), parseJsonBuffer(c, `${entry.file} candidate`), diffs);
    } else if (entry.kind === "sarif") {
      compareSarif(entry.file, parseJsonBuffer(b, `${entry.file} base`), parseJsonBuffer(c, `${entry.file} candidate`), diffs);
    } else if (entry.kind === "stderr") {
      compareBytes(entry.file, "stderr-output", b, c, diffs);
    } else {
      compareBytes(entry.file, "text-output", b, c, diffs);
    }
    reportRecords.push({
      file: entry.file,
      kind: entry.kind,
      baseSha256: shas.get(entry.file).base,
      candidateSha256: shas.get(entry.file).candidate,
      differences: diffs.length - before,
    });
  }
  const shaOf = (report) => shas.get(report);

  const ordered = sortDiffs(diffs);
  const unapproved = [];
  for (const diff of ordered) {
    let hit = approvals.find((a) => a.used === 0 && approvalMatches(a, diff, shaOf));
    let authority = "approved";
    if (!hit) {
      hit = reproductions.find((a) => a.used === 0 && approvalMatches(a, diff, shaOf));
      authority = "reproduction";
    }
    if (hit) {
      hit.used++;
      diff.approvedBy = hit.id;
      diff.authority = authority;
    } else {
      diff.approvedBy = null;
      diff.authority = null;
      unapproved.push(diff);
    }
  }
  const stale = [...approvals, ...reproductions].filter((a) => a.used === 0).map((a) => a.id);
  if (stale.length > 0) refuse(`approvals match no difference (stale): ${stale.join(", ")}`);

  const count = (authority) => ordered.filter((d) => d.authority === authority).length;
  // REQ-2: a run that was given a historical reproduction never reports a normal PASS.
  const verdict = unapproved.length > 0 ? "FAIL" : opts.reproduction ? "PASS-REPRODUCTION" : "PASS";
  const record = {
    schema: RECORD_SCHEMA,
    verdict,
    inventory: { sha256: sha256(inventoryBuffer), reports: reports.length },
    approvals: approvalBuffer
      ? { sha256: sha256(approvalBuffer), count: approvals.length, used: approvals.filter((a) => a.used > 0).length }
      : { sha256: null, count: 0, used: 0 },
    reproduction: reproductionBuffer
      ? { sha256: sha256(reproductionBuffer), count: reproductions.length, used: reproductions.filter((a) => a.used > 0).length }
      : { sha256: null, count: 0, used: 0 },
    manifests: manifestRecords,
    reports: reportRecords,
    differences: ordered,
    unapprovedCount: unapproved.length,
    approvedCount: count("approved"),
    reproductionCount: count("reproduction"),
    blocks: [],
  };
  return { verdict, record };
}

function blockResult(message) {
  return { verdict: "BLOCK", record: { schema: RECORD_SCHEMA, verdict: "BLOCK", blocks: [message] } };
}

function summarize(result) {
  const lines = [`R4 comparator verdict: ${result.verdict}`];
  if (result.verdict === "BLOCK") {
    lines.push(`blocked: ${result.record.blocks.join("; ")}`);
    return lines.join("\n") + "\n";
  }
  const r = result.record;
  lines.push(`inventory reports: ${r.inventory.reports}; manifests verified: ${r.manifests.map((m) => `${m.file} (${m.entries})`).join(", ") || "none"}`);
  for (const rep of r.reports) lines.push(`  ${rep.file} [${rep.kind}] differences ${rep.differences}`);
  lines.push(`differences: ${r.differences.length} (approved ${r.approvedCount}, reproduction ${r.reproductionCount}, unapproved ${r.unapprovedCount})`);
  for (const d of r.differences) {
    const where = d.path || d.field || d.identity || d.fingerprint || "";
    const tag = d.approvedBy ? `${d.authority} ${d.approvedBy}` : "UNAPPROVED";
    lines.push(`  ${tag}  ${d.report}  ${d.category}  ${where}${d.detail ? "  " + d.detail : ""}`);
  }
  return lines.join("\n") + "\n";
}

function parseArgs(argv) {
  const opts = { manifests: [] };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    const take = () => {
      if (argv[i + 1] === undefined) throw new Error(`${flag} needs a value`);
      i++;
      return argv[i];
    };
    if (flag === "--inventory") opts.inventory = take();
    else if (flag === "--base") opts.base = take();
    else if (flag === "--candidate") opts.candidate = take();
    else if (flag === "--deltas") opts.deltas = take();
    else if (flag === "--reproduction") opts.reproduction = take();
    else if (flag === "--manifest") opts.manifests.push(take());
    else if (flag === "--out") opts.out = take();
    else throw new Error(`unknown argument ${flag}`);
  }
  for (const key of ["inventory", "base", "candidate"]) {
    if (!opts[key]) throw new Error(`missing --${key}`);
  }
  return opts;
}

// Runs the comparison. Any refusal, and any unexpected error, ends as BLOCK, never as PASS.
function compare(opts) {
  try {
    return compareEvidence(opts);
  } catch (err) {
    if (err instanceof Refusal) return blockResult(err.message);
    return blockResult(`internal error: ${err && err.message ? err.message : String(err)}`);
  }
}

function exitCodeFor(verdict) {
  if (verdict === "PASS") return 0;
  if (verdict === "FAIL") return 1;
  if (verdict === "PASS-REPRODUCTION") return 3;
  return 2;
}

function main(argv) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (err) {
    process.stderr.write(`usage error: ${err.message}\n`);
    return 64;
  }
  let result = compare(opts);
  if (opts.out) {
    try {
      fs.mkdirSync(opts.out, { recursive: true });
      fs.writeFileSync(path.join(opts.out, "delta-record.json"), stable(result.record) + "\n");
      fs.writeFileSync(path.join(opts.out, "summary.txt"), summarize(result));
    } catch (err) {
      result = blockResult(`cannot write output: ${err.code || "write error"}`);
    }
  }
  process.stdout.write(summarize(result));
  return exitCodeFor(result.verdict);
}

module.exports = { compare, Refusal, stable, sha256, parseArgs, parseStrictJson, exitCodeFor };

if (require.main === module) {
  process.exitCode = main(process.argv.slice(2));
}
