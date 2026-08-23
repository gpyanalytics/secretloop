import * as vscode from "vscode";
import { setting } from "./settings";
import { Finding } from "./scanner";

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
export async function rotateFinding(finding: Finding): Promise<RotationOutcome> {
  switch (finding.ruleId) {
    case "slack-token":
      return rotateSlack(finding.value);
    case "aws-access-key":
      return rotateAws(finding.value);
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

async function rotateAws(leakedAccessKeyId: string): Promise<RotationOutcome> {
  const adminKeyId = setting<string>("awsAdminAccessKeyId", "");
  const adminSecret = setting<string>("awsAdminSecretAccessKey", "");

  if (!adminKeyId || !adminSecret) {
    await vscode.env.openExternal(vscode.Uri.parse("https://console.aws.amazon.com/iam/home#/security_credentials"));
    return {
      success: false,
      message:
        "No admin AWS credentials configured for rotation (secretloop.awsAdminAccessKeyId / awsAdminSecretAccessKey). Opened the IAM console instead — deactivate the key there.",
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
