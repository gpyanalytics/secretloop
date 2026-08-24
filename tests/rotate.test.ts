// Import order is load-bearing: the shim must be installed before anything
// that reaches `vscode`.
import "./stubs/install-vscode";
import { called, firstCall, reset } from "./stubs/vscode";
import {
  rotateFinding,
  migrateAwsAdminCredentials,
  AWS_ADMIN_ACCESS_KEY_ID,
  AWS_ADMIN_SECRET_ACCESS_KEY,
  LegacyCredentialStore,
} from "../src/rotate";
import { Finding } from "../src/scanner";
import * as assert from "node:assert";

// harness.ts takes `() => void` and would swallow an async failure.
let passed = 0;
let failed = 0;

async function test(name: string, fn: () => Promise<void>) {
  try {
    await fn();
    passed++;
    console.log(`  ok - ${name}`);
  } catch (err: any) {
    failed++;
    console.log(`  FAIL - ${name}`);
    console.log(`    ${err.message}`);
  }
}

function finding(ruleId: string, value = "AKIA2Q7RZDXK4LM9PBWT"): Finding {
  return {
    ruleId,
    description: ruleId,
    value,
    startIndex: 0,
    endIndex: value.length,
    confidence: "format-match",
    severity: "critical",
    line: 1,
  };
}

/** A SecretStorage that records what was asked for. */
function fakeSecrets(initial: Record<string, string> = {}) {
  const values = new Map(Object.entries(initial));
  const reads: string[] = [];
  return {
    values,
    reads,
    get: async (key: string) => {
      reads.push(key);
      return values.get(key);
    },
    store: async (key: string, value: string) => {
      values.set(key, value);
    },
    delete: async (key: string) => {
      values.delete(key);
    },
  };
}

/** Settings that already hold a credential, and record what was inspected. */
function fakeLegacy(present: Record<string, { value: string; scope: string }>) {
  const inspected: string[] = [];
  const cleared: string[] = [];
  const store: LegacyCredentialStore = {
    read(key: string) {
      inspected.push(key);
      return present[key];
    },
    async clear(key: string) {
      cleared.push(key);
      delete present[key];
    },
  };
  return { store, inspected, cleared };
}

async function main() {
  process.exitCode = 1;

  console.log("rotate.ts — credentials come from SecretStorage");

  await test("AWS rotation reads its admin credentials from SecretStorage", async () => {
    // Previously read from settings.json, where a secret access key sits in
    // plaintext, syncs through Settings Sync, and can be committed.
    reset();
    const secrets = fakeSecrets();
    await rotateFinding(finding("aws-access-key"), secrets as any);
    assert.ok(
      secrets.reads.includes(AWS_ADMIN_ACCESS_KEY_ID),
      "the access key id must come from SecretStorage"
    );
    assert.ok(secrets.reads.includes(AWS_ADMIN_SECRET_ACCESS_KEY));
  });

  await test("with nothing stored, rotation opens the IAM console instead", async () => {
    reset();
    const outcome = await rotateFinding(finding("aws-access-key"), fakeSecrets() as any);
    assert.strictEqual(outcome.success, false);
    assert.match(outcome.message, /IAM/i);
    assert.doesNotMatch(
      outcome.message,
      /settings\.json|awsAdminAccessKeyId/,
      "must not send people back to the settings file the fix removed"
    );
  });

  await test("a rule with no rotation path is unchanged", async () => {
    const outcome = await rotateFinding(finding("private-key-block", "----"), fakeSecrets() as any);
    assert.strictEqual(outcome.success, false);
    assert.match(outcome.message, /no rotation path/i);
  });

  console.log("\nrotate.ts — migrating a credential out of settings");

  await test("a credential in settings is moved into SecretStorage and the setting cleared", async () => {
    const secrets = fakeSecrets();
    const legacy = fakeLegacy({
      [AWS_ADMIN_ACCESS_KEY_ID]: { value: "AKIAADMIN", scope: "global" },
      [AWS_ADMIN_SECRET_ACCESS_KEY]: { value: "s3cr3t", scope: "global" },
    });

    const outcome = await migrateAwsAdminCredentials(secrets as any, legacy.store);

    assert.strictEqual(outcome.status, "migrated");
    assert.strictEqual(secrets.values.get(AWS_ADMIN_ACCESS_KEY_ID), "AKIAADMIN");
    assert.strictEqual(secrets.values.get(AWS_ADMIN_SECRET_ACCESS_KEY), "s3cr3t");
    assert.deepStrictEqual(
      legacy.cleared.sort(),
      [AWS_ADMIN_ACCESS_KEY_ID, AWS_ADMIN_SECRET_ACCESS_KEY].sort(),
      "leaving the plaintext copy behind would mean the fix did not happen"
    );
  });

  await test("the pre-rebrand secretguard.* keys are migrated too", async () => {
    const secrets = fakeSecrets();
    const legacy = fakeLegacy({
      "secretguard.awsAdminAccessKeyId": { value: "AKIAOLD", scope: "workspace" },
      "secretguard.awsAdminSecretAccessKey": { value: "old", scope: "workspace" },
    });

    const outcome = await migrateAwsAdminCredentials(secrets as any, legacy.store);

    assert.strictEqual(outcome.status, "migrated");
    assert.strictEqual(secrets.values.get(AWS_ADMIN_ACCESS_KEY_ID), "AKIAOLD");
    assert.strictEqual(legacy.cleared.length, 2);
  });

  await test("migration reports which scope the credential came from", async () => {
    const legacy = fakeLegacy({
      [AWS_ADMIN_ACCESS_KEY_ID]: { value: "AKIAADMIN", scope: "workspace" },
    });
    const outcome = await migrateAwsAdminCredentials(fakeSecrets() as any, legacy.store);
    assert.strictEqual(outcome.status, "migrated");
    assert.ok(
      outcome.status === "migrated" && outcome.moved.some((m) => m.scope === "workspace"),
      "a workspace-scoped value may be in a committed .vscode/settings.json"
    );
  });

  await test("credentials already in SecretStorage are left alone", async () => {
    const secrets = fakeSecrets({
      [AWS_ADMIN_ACCESS_KEY_ID]: "AKIAKEPT",
      [AWS_ADMIN_SECRET_ACCESS_KEY]: "kept",
    });
    const legacy = fakeLegacy({});
    const outcome = await migrateAwsAdminCredentials(secrets as any, legacy.store);
    assert.strictEqual(outcome.status, "already-stored");
    assert.strictEqual(secrets.values.get(AWS_ADMIN_ACCESS_KEY_ID), "AKIAKEPT");
  });

  await test("finding nothing names every key it looked at", async () => {
    // "inspect() returned undefined" and "nothing was ever configured" produce
    // the same result, so the log has to say what was probed — otherwise the
    // manual check in a real extension host cannot tell which happened.
    const legacy = fakeLegacy({});
    const outcome = await migrateAwsAdminCredentials(fakeSecrets() as any, legacy.store);
    assert.strictEqual(outcome.status, "absent");
    assert.ok(outcome.status === "absent" && outcome.inspected.length >= 4);
    assert.ok(outcome.inspected.includes(AWS_ADMIN_ACCESS_KEY_ID));
    assert.ok(outcome.inspected.includes("secretguard.awsAdminAccessKeyId"));
    assert.deepStrictEqual(legacy.inspected.sort(), outcome.inspected.slice().sort());
  });

  await test("only one of the pair present still gets the plaintext out", async () => {
    const secrets = fakeSecrets();
    const legacy = fakeLegacy({
      [AWS_ADMIN_ACCESS_KEY_ID]: { value: "AKIAADMIN", scope: "global" },
    });
    const outcome = await migrateAwsAdminCredentials(secrets as any, legacy.store);
    assert.strictEqual(outcome.status, "migrated");
    assert.strictEqual(legacy.cleared.length, 1);
    assert.ok(outcome.status === "migrated" && outcome.moved.length === 1);
  });

  console.log(`\n${passed} passed, ${failed} failed\n`);
  process.exitCode = failed > 0 ? 1 : 0;
}

main();
