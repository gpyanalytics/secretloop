#!/usr/bin/env node
/*
 * Fixture helper for the two-ordinary-account Windows case. Not a test, and not product code.
 *
 * Runs AS THE ORDINARY OWNER and uses the REAL product to produce the record: a scan, then the
 * first verification request, which is what writes a pending record. Only the three approval
 * fields are then changed, so every other field is the product's own and a later refusal can
 * never be an artefact of a guessed fixture. The job that calls this afterwards hands ownership
 * of the file to the second account, which is the state the policy has to catch.
 *
 * The outbound boundary is replaced before anything runs: no provider is contacted.
 *
 *   node win-twouser-plant.js --out <build> --store <store> --repo <repo>
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

(async () => {
  const consent = require(path.join(out, "consent.js"));
  const mcp = require(path.join(out, "mcp-core.js"));

  fs.mkdirSync(repoDir, { recursive: true });
  // Composed at runtime so no credential-shaped literal is ever committed to this repository.
  const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let value = "ghp_";
  for (let i = 0; i < 36; i++) value += alphabet[(i * 17 + 9) % alphabet.length];
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

  // Timed, because a refusal here has to be attributable. A budget refusal after roughly the
  // 20,000 ms allowance is a DEADLINE; one that arrives promptly is a count or byte cap. Without
  // this the two are indistinguishable, since every category maps to one message.
  const startedAt = Date.now();
  const first = await mcp.toolVerify({ path: repo, fingerprint: finding.fingerprint });
  const verifyMs = Date.now() - startedAt;
  console.log(`PLANT-TIMING first verify took ${verifyMs} ms`);
  if (!first.ok || first.payload.state !== "CONSENT_REQUIRED") {
    // Say what actually came back. A fixture that cannot explain its own failure turns a
    // diagnosable problem into a guess.
    const detail = first.ok ? `state ${first.payload.state}` : `refused: ${String(first.error).slice(0, 160)}`;
    throw new Error(`the first request did not ask for consent after ${verifyMs} ms (${detail})`);
  }
  if (outbound !== 0) throw new Error("the first request attempted to transmit");

  const id = consent.recordId(finding.fingerprint, repo);
  const file = path.join(store, "pending", `${id}.json`);
  const record = JSON.parse(fs.readFileSync(file, "utf8"));
  // Only the approval fields change. Everything else stays exactly as the product wrote it.
  record.state = "approved";
  record.approvedAt = new Date().toISOString();
  record.expiresAt = new Date(Date.now() + 900000).toISOString();
  fs.writeFileSync(file, JSON.stringify(record, null, 2) + "\n", "utf8");

  console.log("PLANTED-RECORD: " + file);
  console.log("PLANTED-REPO: " + repo);
})().catch((err) => {
  console.log("FIXTURE-ERROR: " + ((err && err.stack) || err));
  process.exit(2);
});
