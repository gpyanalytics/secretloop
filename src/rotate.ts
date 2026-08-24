import * as vscode from "vscode";
import { Finding } from "./scanner";

/**
 * Where the admin credentials live now: the OS keychain, via SecretStorage.
 *
 * These were settings, which meant a secret access key sat in plaintext in a
 * JSON file — syncing through Settings Sync, and committed outright whenever
 * someone used Workspace scope. The manifest entries are gone, so the settings
 * UI no longer invites anyone to put one there.
 */
export const AWS_ADMIN_ACCESS_KEY_ID = "secretloop.awsAdminAccessKeyId";
export const AWS_ADMIN_SECRET_ACCESS_KEY = "secretloop.awsAdminSecretAccessKey";

/**
 * The keys migration reads and clears.
 *
 * The two `secretguard.*` entries survive the removal of every other
 * SecretGuard compatibility path, and NOT because SecretGuard is supported — it
 * never shipped and nothing else here honours it. They survive because this is
 * a credential sweep, not a compatibility path: its whole job is getting a
 * plaintext AWS secret access key out of a settings file. Deleting them to
 * "finish the job" would strand such a key in someone's settings.json with
 * nothing left in the product able to find it. The cost of keeping them is two
 * extra inspect() calls, once, at activation.
 */
const LEGACY_KEYS: Array<[legacy: string, canonical: string]> = [
  [AWS_ADMIN_ACCESS_KEY_ID, AWS_ADMIN_ACCESS_KEY_ID],
  [AWS_ADMIN_SECRET_ACCESS_KEY, AWS_ADMIN_SECRET_ACCESS_KEY],
  ["secretguard.awsAdminAccessKeyId", AWS_ADMIN_ACCESS_KEY_ID],
  ["secretguard.awsAdminSecretAccessKey", AWS_ADMIN_SECRET_ACCESS_KEY],
];

/** Reads and clears explicitly-set configuration values, whatever scope holds them. */
export interface LegacyCredentialStore {
  read(key: string): { value: string; scope: string } | undefined;
  clear(key: string): Promise<void>;
  /**
   * Whether the configuration system returned a descriptor for the key at all,
   * as opposed to one whose scopes are simply unset.
   *
   * These keys were removed from the manifest, so if inspect() returns
   * undefined for an unregistered key then migration cannot see a value even
   * when one exists — and "found nothing" is indistinguishable from "could not
   * look". Optional: a store that cannot answer records nothing rather than
   * guessing, since absence of the capability is not evidence either way.
   */
  describes?(key: string): boolean;
}

export type MigrationOutcome =
  | { status: "migrated"; moved: Array<{ key: string; scope: string }> }
  | { status: "already-stored" }
  | { status: "absent"; inspected: string[]; descriptors?: Record<string, boolean> };

/**
 * Moves any admin credential still in settings into SecretStorage and clears
 * the setting.
 *
 * Migrating is not the same as making it safe. A value that has been in
 * settings.json may already be in Settings Sync, in a committed
 * .vscode/settings.json, or in a dotfiles repository — clearing it removes
 * today's copy and nothing else. The caller says so, and tells the user to
 * rotate that IAM key. Leaving it readable as a fallback was the alternative,
 * and it would mean the insecure location keeps working forever.
 *
 * CONFIRMED against a running extension host. A value planted under
 * secretloop.awsAdminAccessKeyId — a key removed from the manifest in 9f0d478 —
 * was read through inspect() and migrated, with a registered key probed
 * alongside as a control. Reading a key after its manifest entry is gone works;
 * the API's only requirement is that the name denote a leaf.
 *
 * Getting there took three wrong readings, which is why `descriptors` stays.
 * `inspected` lists the keys that were tried, unconditionally, so on its own it
 * reads identically whether inspect() saw unset scopes or could not look at
 * all. `descriptors` is the discriminator, and keeping it means a future change
 * that breaks readability shows up as a named failure instead of a confident
 * "no credential found".
 */
export async function migrateAwsAdminCredentials(
  secrets: vscode.SecretStorage,
  legacy: LegacyCredentialStore
): Promise<MigrationOutcome> {
  const alreadyStored =
    (await secrets.get(AWS_ADMIN_ACCESS_KEY_ID)) !== undefined &&
    (await secrets.get(AWS_ADMIN_SECRET_ACCESS_KEY)) !== undefined;
  if (alreadyStored) return { status: "already-stored" };

  const moved: Array<{ key: string; scope: string }> = [];
  const inspected: string[] = [];
  const descriptors: Record<string, boolean> = {};

  for (const [legacyKey, canonicalKey] of LEGACY_KEYS) {
    inspected.push(legacyKey);
    if (legacy.describes) descriptors[legacyKey] = legacy.describes(legacyKey);
    const found = legacy.read(legacyKey);
    if (!found?.value) continue;
    // Even half a pair is worth moving: rotation will not work without both,
    // but the point is getting the plaintext out of the settings file.
    await secrets.store(canonicalKey, found.value);
    await legacy.clear(legacyKey);
    moved.push({ key: legacyKey, scope: found.scope });
  }

  if (moved.length > 0) return { status: "migrated", moved };
  return legacy.describes
    ? { status: "absent", inspected, descriptors }
    : { status: "absent", inspected };
}

export interface RotationOutcome {
  success: boolean;
  message: string;
}

/**
 * Rotation capability differs a lot by provider:
 * - Slack tokens can revoke themselves via auth.revoke. Genuinely automatable.
 * - AWS access keys can be deactivated via IAM, but that call must be signed
 *   with SEPARATE admin credentials (an access key can't deactivate itself).
 *   We require the user to configure an admin profile; if absent, we fall
 *   back to opening the IAM console.
 * - GitHub classic PATs, Stripe keys, and Google API keys have no public
 *   self-service revoke API. We open the relevant dashboard page instead of
 *   claiming to automate something we can't.
 */
export async function rotateFinding(
  finding: Finding,
  secrets: vscode.SecretStorage
): Promise<RotationOutcome> {
  switch (finding.ruleId) {
    case "slack-token":
      return rotateSlack(finding.value);
    case "aws-access-key":
      return rotateAws(finding.value, secrets);
    case "github-token":
    case "github-fine-grained-pat":
      return openDashboard(
        "https://github.com/settings/tokens",
        "GitHub doesn't offer self-service token revocation via API. Opened the tokens page — revoke it there, then re-scan."
      );
    case "stripe-secret-key":
      return openDashboard(
        "https://dashboard.stripe.com/apikeys",
        "Stripe doesn't offer a public key-rolling API. Opened the API keys dashboard — roll the key there."
      );
    case "google-api-key":
      return openDashboard(
        "https://console.cloud.google.com/apis/credentials",
        "Google API keys must be regenerated from the Cloud Console. Opened the credentials page."
      );
    default:
      return { success: false, message: "No rotation path available for this secret type yet." };
  }
}

async function rotateSlack(token: string): Promise<RotationOutcome> {
  try {
    const res = await fetch("https://slack.com/api/auth.revoke", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    const body = (await res.json()) as { ok: boolean; revoked?: boolean; error?: string };
    if (body.ok && body.revoked) {
      return { success: true, message: "Slack token revoked successfully." };
    }
    return { success: false, message: `Slack revoke failed: ${body.error ?? "unknown error"}.` };
  } catch (err: any) {
    return { success: false, message: `Network error revoking Slack token: ${err?.message}` };
  }
}

async function rotateAws(
  leakedAccessKeyId: string,
  secrets: vscode.SecretStorage
): Promise<RotationOutcome> {
  const adminKeyId = await secrets.get(AWS_ADMIN_ACCESS_KEY_ID);
  const adminSecret = await secrets.get(AWS_ADMIN_SECRET_ACCESS_KEY);

  if (!adminKeyId || !adminSecret) {
    await vscode.env.openExternal(vscode.Uri.parse("https://console.aws.amazon.com/iam/home#/security_credentials"));
    return {
      success: false,
      message:
        "No admin AWS credentials stored for rotation. Run \"SecretLoop: Set AWS Admin Credentials for Rotation\" to store them in your OS keychain. Opened the IAM console meanwhile — deactivate the key there.",
    };
  }

  try {
    const { IAMClient, UpdateAccessKeyCommand } = await import("@aws-sdk/client-iam");
    const client = new IAMClient({
      region: "us-east-1",
      credentials: { accessKeyId: adminKeyId, secretAccessKey: adminSecret },
    });
    await client.send(
      new UpdateAccessKeyCommand({ AccessKeyId: leakedAccessKeyId, Status: "Inactive" })
    );
    return { success: true, message: `AWS access key ${leakedAccessKeyId} deactivated.` };
  } catch (err: any) {
    return {
      success: false,
      message: `Failed to deactivate AWS key automatically (${err?.message ?? "unknown error"}). Deactivate it manually in IAM.`,
    };
  }
}

async function openDashboard(url: string, message: string): Promise<RotationOutcome> {
  await vscode.env.openExternal(vscode.Uri.parse(url));
  return { success: false, message };
}
