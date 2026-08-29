/**
 * Which rules have a verifier, and whose provider it contacts — as data only.
 *
 * This file exists so that knowing a credential *could* be checked does not
 * require shipping the code that checks it. src/verify.ts holds eighteen
 * verifier functions, and through them `fetch` calls to eighteen providers and
 * the AWS SDK. Anything that imports verify.ts to ask `isVerifiable(ruleId)`
 * drags all of that into its bundle: the MCP server, which has no verification
 * tool and must not acquire the capability by accident, was 1.3 MB of which
 * most was credential-transmitting code it can never reach.
 *
 * The two lists below are a deliberate copy, not a re-export. A re-export would
 * defeat the purpose — the import is the problem, not the shape of the data.
 * They are kept honest the way mcp-core's copy of describeScope is: a parity
 * test compares them against verify.ts's own tables and fails the build if a
 * verifier is added, removed or renamed on one side only. A test is the right
 * enforcement here because the failure it catches is a stale list, and a stale
 * list is exactly what a build error surfaces and a runtime lookup hides.
 */

/** Every rule whose credential can be checked against a live provider. */
export const VERIFIABLE_RULE_IDS: readonly string[] = [
  "github-token",
  "github-oauth-token",
  "github-app-token",
  "github-fine-grained-pat",
  "gitlab-pat",
  "slack-token",
  "stripe-secret-key",
  "google-api-key",
  "aws-access-key",
  "openai-api-key",
  "anthropic-api-key",
  "huggingface-token",
  "npm-token",
  "digitalocean-token",
  "sendgrid-api-key",
  "discord-bot-token",
  "notion-token",
  "cloudflare-api-token",
];

const verifiableRuleIds = new Set(VERIFIABLE_RULE_IDS);

/**
 * The third party a rule's credential would be checked against, by the name a
 * user would recognise. Naming "the provider" is not naming anyone, so both the
 * consent prompt and the MCP metadata name the company.
 */
export const VERIFIER_PROVIDERS: Readonly<Record<string, string>> = {
  "github-token": "GitHub",
  "github-oauth-token": "GitHub",
  "github-app-token": "GitHub",
  "github-fine-grained-pat": "GitHub",
  "gitlab-pat": "GitLab",
  "slack-token": "Slack",
  "stripe-secret-key": "Stripe",
  "google-api-key": "Google",
  "aws-access-key": "AWS",
  "openai-api-key": "OpenAI",
  "anthropic-api-key": "Anthropic",
  "huggingface-token": "Hugging Face",
  "npm-token": "npm",
  "digitalocean-token": "DigitalOcean",
  "sendgrid-api-key": "SendGrid",
  "discord-bot-token": "Discord",
  "notion-token": "Notion",
  "cloudflare-api-token": "Cloudflare",
};

/** Metadata only. Nothing in this module can contact anyone. */
export function hasVerifier(ruleId: string): boolean {
  return verifiableRuleIds.has(ruleId);
}

export function verifierProvider(ruleId: string): string | undefined {
  return VERIFIER_PROVIDERS[ruleId];
}
