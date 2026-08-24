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
import { test, suite, finish } from "./harness";

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
function fakeLegacy(
  present: Record<string, { value: string; scope: string }>,
  describes?: boolean
) {
  const inspected: string[] = [];
  const cleared: string[] = [];
  const store: LegacyCredentialStore = {
    ...(describes === undefined ? {} : { describes: () => describes }),
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

suite("rotate.ts — credentials come from SecretStorage");

test("AWS rotation reads its admin credentials from SecretStorage", async () => {
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

test("with nothing stored, rotation opens the IAM console instead", async () => {
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

test("a rule with no rotation path is unchanged", async () => {
  const outcome = await rotateFinding(finding("private-key-block", "----"), fakeSecrets() as any);
  assert.strictEqual(outcome.success, false);
  assert.match(outcome.message, /no rotation path/i);
});

suite("\nrotate.ts — migrating a credential out of settings");

test("a credential in settings is moved into SecretStorage and the setting cleared", async () => {
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

test("the pre-rebrand secretguard.* keys are migrated too", async () => {
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

test("migration reports which scope the credential came from", async () => {
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

test("credentials already in SecretStorage are left alone", async () => {
  const secrets = fakeSecrets({
    [AWS_ADMIN_ACCESS_KEY_ID]: "AKIAKEPT",
    [AWS_ADMIN_SECRET_ACCESS_KEY]: "kept",
  });
  const legacy = fakeLegacy({});
  const outcome = await migrateAwsAdminCredentials(secrets as any, legacy.store);
  assert.strictEqual(outcome.status, "already-stored");
  assert.strictEqual(secrets.values.get(AWS_ADMIN_ACCESS_KEY_ID), "AKIAKEPT");
});

test("finding nothing names every key it looked at", async () => {
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

test("only one of the pair present still gets the plaintext out", async () => {
  const secrets = fakeSecrets();
  const legacy = fakeLegacy({
    [AWS_ADMIN_ACCESS_KEY_ID]: { value: "AKIAADMIN", scope: "global" },
  });
  const outcome = await migrateAwsAdminCredentials(secrets as any, legacy.store);
  assert.strictEqual(outcome.status, "migrated");
  assert.strictEqual(legacy.cleared.length, 1);
  assert.ok(outcome.status === "migrated" && outcome.moved.length === 1);
});

suite("\nrotate.ts — can VS Code even see an unregistered key?");

test("absent records whether a configuration descriptor existed at all", () => {
  // The open question before publishing: the AWS keys were removed from the
  // manifest, so if inspect() returns undefined for an unregistered key the
  // migration is dead code for exactly the users it exists for. "Found nothing"
  // and "could not look" produce the same absent outcome otherwise.
  return (async () => {
    const withDescriptors = await migrateAwsAdminCredentials(
      fakeSecrets() as any,
      fakeLegacy({}, true).store
    );
    assert.strictEqual(withDescriptors.status, "absent");
    assert.ok(
      withDescriptors.status === "absent" && withDescriptors.descriptors,
      "the discriminator must be recorded"
    );
    assert.strictEqual(
      withDescriptors.status === "absent" &&
        withDescriptors.descriptors![AWS_ADMIN_ACCESS_KEY_ID],
      true
    );
  })();
});

test("a store that cannot answer records no descriptors rather than guessing", () => {
  return (async () => {
    const outcome = await migrateAwsAdminCredentials(fakeSecrets() as any, fakeLegacy({}).store);
    assert.strictEqual(outcome.status, "absent");
    assert.strictEqual(
      outcome.status === "absent" && outcome.descriptors,
      undefined,
      "absence of the capability is not evidence either way"
    );
  })();
});

test("an unreadable key is distinguishable from an unset one", () => {
  return (async () => {
    const outcome = await migrateAwsAdminCredentials(
      fakeSecrets() as any,
      fakeLegacy({}, false).store
    );
    assert.ok(outcome.status === "absent" && outcome.descriptors);
    assert.strictEqual(
      outcome.status === "absent" && outcome.descriptors!["secretguard.awsAdminAccessKeyId"],
      false
    );
  })();
});

finish();
