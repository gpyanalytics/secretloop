import { test, suite, finish, assert } from "./harness";
import { execFileSync } from "child_process";
import { mkdtempSync, readFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import * as path from "path";
import { rules } from "../src/rules";
import { isVerifiable, verificationProvider, VERIFIABLE_RULE_IDS } from "../src/verify";
import {
  VERIFIABLE_RULE_IDS as METADATA_IDS,
  VERIFIER_PROVIDERS,
  hasVerifier,
  verifierProvider,
} from "../src/verify-meta";

/**
 * Two halves of one property: the MCP server can say a credential is verifiable
 * without containing the code that would verify it.
 *
 * The first suite pins the copy. src/verify-meta.ts duplicates verify.ts's rule
 * list and provider names on purpose — a re-export would put verify.ts back in
 * the import graph, which is the entire thing being avoided — so a test has to
 * be what stops the two drifting. Same arrangement, same reasoning, as
 * mcp-core's copy of describeScope.
 *
 * The second suite checks the artifact rather than the intent, which is this
 * repository's standing rule for anything a bundler decides. The import graph
 * looking right in the source proves nothing about what esbuild emitted: the
 * first attempt at this fix repointed mcp-core off verify.ts and the AWS SDK
 * was still in out/mcp.js, because workspace.ts imported it too.
 */

const REPO = path.join(__dirname, "..");

suite("verify-meta — pinned to verify.ts");

test("every rule agrees on whether it has a verifier", () => {
  // Across all rules, not just the eighteen: a rule dropped from one list and
  // not the other is the drift this exists to catch, and it shows up as a
  // disagreement about a rule neither list mentions any more.
  const disagreements = rules
    .map((r) => r.id)
    .filter((id) => isVerifiable(id) !== hasVerifier(id));
  assert.deepStrictEqual(disagreements, [], "verify.ts and verify-meta.ts disagree");
  assert.deepStrictEqual(
    [...METADATA_IDS].sort(),
    [...VERIFIABLE_RULE_IDS].sort(),
    "the rule-ID lists have drifted"
  );
  assert.ok(METADATA_IDS.length > 0, "an empty list would satisfy every assertion above");
});

test("every verifiable rule names the same provider on both sides", () => {
  for (const id of VERIFIABLE_RULE_IDS) {
    assert.strictEqual(
      verifierProvider(id),
      verificationProvider(id),
      `provider drift for ${id}`
    );
    assert.ok(verifierProvider(id), `${id} has a verifier but no provider name`);
  }
  assert.deepStrictEqual(
    Object.keys(VERIFIER_PROVIDERS).sort(),
    [...VERIFIABLE_RULE_IDS].sort(),
    "a provider name exists for a rule with no verifier, or the reverse"
  );
});

test("every listed rule ID is a rule that exists", () => {
  const known = new Set(rules.map((r) => r.id));
  const unknown = METADATA_IDS.filter((id) => !known.has(id));
  assert.deepStrictEqual(unknown, [], "verify-meta names rules that are not in rules.ts");
});

suite("out/mcp.js — no credential-transmitting code");

/**
 * The endpoints verify.ts contacts, read out of verify.ts itself.
 *
 * Hard-coding the list here would go stale the first time someone adds a
 * verifier, and go stale silently, which is the failure mode this whole file is
 * about. Reading the source means a nineteenth provider is covered the day it
 * is written.
 *
 * Whole URLs, not bare hostnames. The first version of this probe searched for
 * hosts and reported `slack.com` and `discord.com` in out/mcp.js — both real
 * matches, and both wrong: they are keywords on two rules in rules.ts, which
 * the MCP server needs and which contact nobody. A hostname says a provider was
 * named somewhere; `https://slack.com/api/auth.test` says something knows how
 * to call it.
 */
function verifierEndpoints(): string[] {
  const source = readFileSync(path.join(REPO, "src", "verify.ts"), "utf8");
  return [...new Set([...source.matchAll(/https:\/\/[A-Za-z0-9.\-\/_]+/g)].map((m) => m[0]))];
}

function bundle(entry: string, outDir: string): string {
  const out = path.join(outDir, `${path.basename(entry, ".ts")}.js`);
  execFileSync(
    path.join(REPO, "node_modules", ".bin", "esbuild"),
    [
      path.join(REPO, "src", entry),
      "--bundle",
      `--outfile=${out}`,
      "--external:vscode",
      "--format=cjs",
      "--platform=node",
      "--minify",
    ],
    { stdio: "pipe" }
  );
  return readFileSync(out, "utf8");
}

/**
 * Whether this build's server exposes verification, read from the server.
 *
 * Not from the branch name and not from a constant: mcp-layer ships four
 * read-only tools and must not contain a verifier, verify-consent ships a fifth
 * and must, and the two branches share this file. A test that asserted one of
 * those would be wrong on the other branch, and a test that asserted neither
 * would be worth nothing on both.
 */
function serverVerifies(): boolean {
  return readFileSync(path.join(REPO, "src", "mcp.ts"), "utf8").includes(
    'name: "secretloop_verify"'
  );
}

test("the CLI bundle carries every verifier endpoint", () => {
  // The control for both assertions below. A probe that finds nothing anywhere
  // proves nothing, and string literals are what survives minification —
  // identifier names do not.
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-bundle-"));
  try {
    const hosts = verifierEndpoints();
    assert.ok(hosts.length >= 10, `only ${hosts.length} provider endpoints found — the probe is weak`);
    const cli = bundle("cli.ts", dir);
    assert.deepStrictEqual(
      hosts.filter((h) => !cli.includes(h)),
      [],
      "these endpoints are in verify.ts but not in the CLI bundle, so the probe is unsound"
    );
    assert.ok(cli.includes("@aws-sdk"), "the CLI should carry the AWS SDK it verifies with");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the server bundle matches the capability the server claims", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-bundle-"));
  try {
    const hosts = verifierEndpoints();
    const mcp = bundle("mcp.ts", dir);
    const present = hosts.filter((h) => mcp.includes(h));

    if (!serverVerifies()) {
      assert.deepStrictEqual(
        present,
        [],
        "the read-only MCP server bundles code that transmits credentials to these providers"
      );
      assert.ok(
        !mcp.includes("@aws-sdk"),
        "the AWS SDK is in out/mcp.js — a server with no verification tool can sign requests"
      );
      // rotate.ts is the other outbound module, reached from the editor's
      // quick-fix and from nothing any MCP server exposes.
      assert.ok(
        !mcp.includes("auth.revoke"),
        "revocation code is in out/mcp.js — the read-only server can change a provider's state"
      );
      return;
    }

    // This build declares secretloop_verify, so the transports have to be here.
    // Asserting their presence is not ceremony: it is what makes the absence
    // assertion above meaningful rather than an accident of some other change.
    assert.deepStrictEqual(
      hosts.filter((h) => !mcp.includes(h)),
      [],
      "secretloop_verify is declared but these providers cannot be reached"
    );
    // And that the gate came with it. Verifier code in the bundle without the
    // consent machinery would be an outbound capability with nothing in front
    // of it -- the one arrangement neither branch may ever ship.
    assert.ok(
      mcp.includes("secretloop approve "),
      "the verifier is bundled but the consent path is not — nothing gates the transmission"
    );
    assert.ok(
      !mcp.includes("auth.revoke"),
      "revocation code is in the server bundle; consent covers verification, not state changes"
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

finish();
