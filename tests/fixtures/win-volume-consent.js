#!/usr/bin/env node
/*
 * Fixture helper for the non-NTFS validation (W3). Not a test, and not product code.
 *
 * Drives the REAL product once -- a scan, then the first verification request, which is the call
 * that inspects the consent store's location and either creates the store or refuses -- against a
 * consent root the caller chooses, and reports what came back as one JSON line. The caller (the CI
 * job) owns the assertions; this file asserts nothing, so the same run can be read for an exFAT
 * refusal and for an NTFS positive control.
 *
 * The outbound boundary is replaced before anything runs: no provider is contacted, and the
 * number of attempts is reported.
 *
 *   node win-volume-consent.js --out <build> --store <consent root> --repo <repo dir>
 *
 * Reported: ok, state (when ok), the refusal CODE (recovered exactly, by matching the product's own
 * fixed sentence for each known problem -- never by guessing), the first 200 characters of the fixed
 * refusal text, outbound attempts, whether the store directory exists afterwards, how many pending
 * records exist, elapsed ms, and the product's refusal detail (component path on the caller's
 * volume, principal SID, rights mask). Never a credential, never a record body.
 */
"use strict";
const fs = require("fs");
const path = require("path");

const arg = (name) => {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
};
const out = arg("--out");
const store = arg("--store");
const repoDir = arg("--repo");
if (!out || !store || !repoDir) {
  console.log("FIXTURE-ERROR: --out, --store and --repo are required");
  process.exit(2);
}

// Every ConsentStoreProblem the product can raise (src/consent.ts). The code is recovered by
// matching the refusal text against describeStoreProblem(problem) -- the product's own words.
const PROBLEMS = [
  "not-a-directory", "not-a-regular-file", "oversized-record", "record-too-large", "extended-acl",
  "acl-tool-unavailable", "acl-unreadable", "unsafe-parent-posix", "parent-unreadable",
  "operation-too-large", "record-permissive", "symlink", "foreign-owner", "permissive", "inaccessible",
  "identity-unreadable", "unsupported-location", "unsafe-parent", "foreign-principal", "deny-ace",
  "null-dacl", "empty-dacl", "owner-not-granted", "insufficient-rights", "owner-unreadable",
  "acl-tooling-unavailable", "acl-inspection-failed", "acl-inspection-malformed", "reparse-point",
];

(async () => {
  const consent = require(path.join(out, "consent.js"));
  const mcp = require(path.join(out, "mcp-core.js"));
  let acl = null;
  try { acl = require(path.join(out, "consent-acl-win.js")); } catch { /* not built, or not this platform's concern */ }

  fs.mkdirSync(repoDir, { recursive: true });
  // Composed at runtime so no credential-shaped literal is ever committed to this repository.
  const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let value = "ghp_";
  for (let i = 0; i < 36; i++) value += alphabet[(i * 13 + 5) % alphabet.length];
  fs.writeFileSync(path.join(repoDir, "app.js"), `const t = "${value}";\n`, "utf8");
  const repo = fs.realpathSync(repoDir);

  consent.setConsentRootForTests(store);
  mcp.setAllowedRoots([repo]);
  mcp.resetSessions();
  let outbound = 0;
  mcp.setVerifyFetchForTests(async () => {
    outbound++;
    return new Response("{}", { status: 401 });
  });

  const scan = mcp.toolScan({ path: repo });
  if (!scan.ok) throw new Error("the fixture scan failed");
  const finding = scan.payload.findings.find((f) => f.ruleId === "github-token");
  if (!finding) throw new Error("the fixture repository produced no verifiable finding");

  const startedAt = Date.now();
  const first = await mcp.toolVerify({ path: repo, fingerprint: finding.fingerprint });
  const elapsedMs = Date.now() - startedAt;

  let refusal = null;
  if (!first.ok) {
    const text = String(first.error);
    const matches = PROBLEMS.filter((p) => {
      try { return text.startsWith(consent.describeStoreProblem(p)); } catch { return false; }
    });
    // Exactly one of the product's sentences must prefix the text; anything else is reported as such.
    refusal = matches.length === 1 ? matches[0] : `unmatched(${matches.length})`;
  }
  const pendingDir = path.join(store, "pending");
  const pendingRecords = fs.existsSync(pendingDir) ? fs.readdirSync(pendingDir).filter((n) => n.endsWith(".json")).length : 0;
  const detail = acl && typeof acl.lastRefusalDetail === "function" ? acl.lastRefusalDetail() ?? null : null;

  console.log("VOLUME-RESULT " + JSON.stringify({
    ok: first.ok,
    state: first.ok ? first.payload.state : null,
    refusal,
    text: first.ok ? null : String(first.error).slice(0, 200),
    outbound,
    storeExists: fs.existsSync(store),
    pendingRecords,
    elapsedMs,
    detail,
  }));
})().catch((err) => {
  console.log("FIXTURE-ERROR: " + ((err && err.stack) || err));
  process.exit(2);
});
