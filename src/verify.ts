import { createHash } from "crypto";
import { Finding } from "./scanner";

export interface VerificationResult {
  verified: boolean;
  /** Human-readable reason, shown in the diagnostic hover. */
  detail: string;
}

/**
 * Verifiers make a minimal, read-only, side-effect-free call to the provider
 * to check whether a credential is currently valid. They must NEVER perform
 * an action that could modify state (no writes, no deletes, no key usage
 * beyond an identity/auth check).
 *
 * Network errors are treated as "unknown" (not verified, not disproven) so
 * a flaky connection never silently downgrades a real finding.
 */
type Verifier = (value: string, context: VerifyContext) => Promise<VerificationResult | null>;

export interface VerifyContext {
  /** Full text of the file being scanned, used to find a paired credential (e.g. AWS secret key near an access key ID). */
  fullText: string;
  fetchImpl: typeof fetch;
  /** Abort a provider call after this long. Defaults to VERIFY_TIMEOUT_MS. */
  timeoutMs?: number;
}

/**
 * No provider call may outlive this. A hung endpoint used to block a CI job
 * indefinitely and leak a pending promise per keystroke in the editor.
 */
export const VERIFY_TIMEOUT_MS = 5000;

/** Enough to be quick, low enough not to look like an attack to a rate limiter. */
export const VERIFY_CONCURRENCY = 5;

/**
 * Adds the abort signal every provider call must carry. A timed-out call throws,
 * which verifyFinding turns into "unknown" — never into "disproven".
 */
function requestInit(ctx: VerifyContext, init: RequestInit = {}): RequestInit {
  return { ...init, signal: AbortSignal.timeout(ctx.timeoutMs ?? VERIFY_TIMEOUT_MS) };
}

const verifiers: Record<string, Verifier> = {
  "github-token": verifyGitHubToken,
  "github-oauth-token": verifyGitHubToken,
  "github-app-token": verifyGitHubToken,
  "github-fine-grained-pat": verifyGitHubToken,
  "gitlab-pat": verifyGitLabToken,
  "slack-token": verifySlackToken,
  "stripe-secret-key": verifyStripeKey,
  "google-api-key": verifyGoogleApiKey,
  "aws-access-key": verifyAwsAccessKey,
  "openai-api-key": verifyOpenAiKey,
  "anthropic-api-key": verifyAnthropicKey,
  "huggingface-token": verifyHuggingFaceToken,
  "npm-token": verifyNpmToken,
  "digitalocean-token": verifyDigitalOceanToken,
  "sendgrid-api-key": verifySendGridKey,
  "discord-bot-token": verifyDiscordBotToken,
  "notion-token": verifyNotionToken,
  "cloudflare-api-token": verifyCloudflareToken,
};

export function isVerifiable(ruleId: string): boolean {
  return ruleId in verifiers;
}

export async function verifyFinding(
  finding: Finding,
  context: VerifyContext
): Promise<VerificationResult | null> {
  const verifier = verifiers[finding.ruleId];
  if (!verifier) return null;
  try {
    return await verifier(finding.value, context);
  } catch {
    return null; // treat as unknown, never as "safe"
  }
}

/** How long a verification outcome stays good before the provider is asked again. */
const DEFAULT_CACHE_TTL_MS = 5 * 60_000;

/**
 * Remembers verification outcomes so the same credential is not re-sent to its
 * provider on every scan. The editor re-scans a document on open and after
 * every 400ms of typing, so without this a single open file means a steady
 * stream of outbound requests carrying a live secret.
 *
 * Keyed on a hash of the value, never the value itself: this map outlives any
 * one scan in the extension host, and it has no business holding plaintext
 * credentials. Outcomes expire so a rotated or revoked key is re-checked.
 */
export class VerificationCache {
  private readonly entries = new Map<string, { result: VerificationResult | null; expiresAt: number }>();

  constructor(
    private readonly ttlMs: number = DEFAULT_CACHE_TTL_MS,
    private readonly now: () => number = Date.now
  ) {}

  async verify(finding: Finding, context: VerifyContext): Promise<VerificationResult | null> {
    const key = this.key(finding);
    const hit = this.entries.get(key);
    if (hit && hit.expiresAt > this.now()) return hit.result;

    const result = await verifyFinding(finding, context);
    this.entries.set(key, { result, expiresAt: this.now() + this.ttlMs });
    return result;
  }

  /** Cache keys, so a test can assert no plaintext secret is retained. */
  keys(): string[] {
    return [...this.entries.keys()];
  }

  private key(finding: Finding): string {
    return `${finding.ruleId}:${createHash("sha256").update(finding.value).digest("hex")}`;
  }
}

export interface VerifyFindingsOptions {
  /** Reuse outcomes across scans. Omit for a one-shot pass. */
  cache?: VerificationCache;
  concurrency?: number;
}

/**
 * Verifies a batch of findings with bounded concurrency, marking each in place.
 *
 * The bound matters as much as the timeout: an unbounded pass fires one request
 * per finding simultaneously, which reads as an attack to a provider's rate
 * limiter and, in the editor, repeats on every keystroke.
 */
export async function verifyFindings(
  findings: Finding[],
  context: VerifyContext,
  options: VerifyFindingsOptions = {}
): Promise<void> {
  const verifiable = findings.filter((f) => isVerifiable(f.ruleId));
  if (verifiable.length === 0) return;

  const { cache } = options;
  const check = cache
    ? (f: Finding) => cache.verify(f, context)
    : (f: Finding) => verifyFinding(f, context);

  let cursor = 0;
  const workers = Array.from(
    { length: Math.min(options.concurrency ?? VERIFY_CONCURRENCY, verifiable.length) },
    async () => {
      while (cursor < verifiable.length) {
        const finding = verifiable[cursor++];
        const result = await check(finding);
        if (!result) continue; // unknown; leave as format-match
        finding.verified = result.verified;
        finding.verifyDetail = result.detail;
        if (result.verified) finding.confidence = "verified-live";
      }
    }
  );
  await Promise.all(workers);
}

async function verifyGitHubToken(value: string, ctx: VerifyContext): Promise<VerificationResult> {
  const res = await ctx.fetchImpl(
    "https://api.github.com/user",
    requestInit(ctx, { headers: { Authorization: `token ${value}`, "User-Agent": "SecretLoop-VSCode" } })
  );
  if (res.status === 200) {
    const scopes = res.headers.get("x-oauth-scopes") ?? "unknown";
    return { verified: true, detail: `Active GitHub token. Scopes: ${scopes}` };
  }
  if (res.status === 401) return { verified: false, detail: "GitHub token is invalid or already revoked." };
  return { verified: false, detail: `GitHub responded ${res.status}; treating as unverified.` };
}

async function verifySlackToken(value: string, ctx: VerifyContext): Promise<VerificationResult> {
  const res = await ctx.fetchImpl(
    "https://slack.com/api/auth.test",
    requestInit(ctx, { method: "POST", headers: { Authorization: `Bearer ${value}` } })
  );
  const body = (await res.json()) as { ok: boolean; team?: string; error?: string };
  if (body.ok) {
    return { verified: true, detail: `Active Slack token for workspace "${body.team}".` };
  }
  return { verified: false, detail: `Slack reports token invalid: ${body.error ?? "unknown"}.` };
}

async function verifyStripeKey(value: string, ctx: VerifyContext): Promise<VerificationResult> {
  // GET /v1/balance is a minimal read-only call sufficient to prove the key works.
  const res = await ctx.fetchImpl(
    "https://api.stripe.com/v1/balance",
    requestInit(ctx, {
      headers: { Authorization: `Basic ${Buffer.from(`${value}:`).toString("base64")}` },
    })
  );
  if (res.status === 200) {
    const isLive = value.startsWith("sk_live_") || value.startsWith("rk_live_");
    return { verified: true, detail: `Active Stripe key (${isLive ? "LIVE mode" : "test mode"}).` };
  }
  if (res.status === 401) return { verified: false, detail: "Stripe key is invalid or revoked." };
  return { verified: false, detail: `Stripe responded ${res.status}; treating as unverified.` };
}

async function verifyGoogleApiKey(value: string, ctx: VerifyContext): Promise<VerificationResult> {
  // Discovery API accepts a key param and is safe/read-only; a bad key returns 400 with API_KEY_INVALID.
  const res = await ctx.fetchImpl(
    `https://www.googleapis.com/discovery/v1/apis?key=${encodeURIComponent(value)}`,
    requestInit(ctx)
  );
  if (res.status === 200) return { verified: true, detail: "Active Google API key." };
  const body = await res.text();
  if (body.includes("API_KEY_INVALID")) {
    return { verified: false, detail: "Google reports this API key is invalid." };
  }
  return { verified: false, detail: `Google responded ${res.status}; treating as unverified.` };
}

/**
 * AWS access keys require a paired secret key for STS verification (SigV4).
 * We only attempt this when a matching aws-secret-key finding exists nearby
 * in the same file; otherwise we can't verify and leave it as format-match.
 * Delegates signing to @aws-sdk/client-sts rather than hand-rolling SigV4.
 */
async function verifyAwsAccessKey(
  accessKeyId: string,
  ctx: VerifyContext
): Promise<VerificationResult | null> {
  const secretMatch = ctx.fullText.match(
    /(?:aws_secret_access_key|aws_secret)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/i
  );
  if (!secretMatch) {
    // Can't verify without the paired secret; caller should keep this as format-match.
    return null;
  }
  const secretAccessKey = secretMatch[1];

  try {
    // Dynamic import keeps this dependency optional at compile time for
    // consumers who strip AWS verification out of their build.
    const { STSClient, GetCallerIdentityCommand } = await import("@aws-sdk/client-sts");
    const client = new STSClient({ region: "us-east-1", credentials: { accessKeyId, secretAccessKey } });
    const identity = await client.send(new GetCallerIdentityCommand({}));
    return { verified: true, detail: `Active AWS credentials. Account: ${identity.Account}, ARN: ${identity.Arn}` };
  } catch (err: any) {
    if (err?.name === "InvalidClientTokenId" || err?.name === "SignatureDoesNotMatch") {
      return { verified: false, detail: "AWS reports these credentials are invalid or revoked." };
    }
    return { verified: false, detail: "Could not verify AWS credentials; treating as unverified." };
  }
}

// ---------------------------------------------------------------------------
// Additional providers. Every endpoint below is a read-only identity/scope
// check — the cheapest call that proves "this credential currently works"
// without touching customer data or incurring usage cost.
// ---------------------------------------------------------------------------

/** Shared shape: a 200 means live, a 401/403 means dead, anything else is unknown. */
async function verifyByStatus(
  ctx: VerifyContext,
  url: string,
  init: RequestInit,
  provider: string,
  liveDetail?: (res: Response) => Promise<string> | string
): Promise<VerificationResult> {
  const res = await ctx.fetchImpl(url, requestInit(ctx, init));
  if (res.status === 200) {
    const detail = liveDetail ? await liveDetail(res) : `Active ${provider} credential.`;
    return { verified: true, detail };
  }
  if (res.status === 401 || res.status === 403) {
    return { verified: false, detail: `${provider} reports this credential is invalid or revoked.` };
  }
  return { verified: false, detail: `${provider} responded ${res.status}; treating as unverified.` };
}

async function verifyGitLabToken(value: string, ctx: VerifyContext): Promise<VerificationResult> {
  return verifyByStatus(
    ctx,
    "https://gitlab.com/api/v4/user",
    { headers: { "PRIVATE-TOKEN": value } },
    "GitLab",
    async (res) => {
      const body = (await res.json()) as { username?: string };
      return `Active GitLab token for user "${body.username ?? "unknown"}".`;
    }
  );
}

async function verifyOpenAiKey(value: string, ctx: VerifyContext): Promise<VerificationResult> {
  // GET /v1/models is free and read-only; no tokens are consumed.
  return verifyByStatus(
    ctx,
    "https://api.openai.com/v1/models",
    { headers: { Authorization: `Bearer ${value}` } },
    "OpenAI"
  );
}

async function verifyAnthropicKey(value: string, ctx: VerifyContext): Promise<VerificationResult> {
  // GET /v1/models is a metadata call — it does not run inference or bill tokens.
  return verifyByStatus(
    ctx,
    "https://api.anthropic.com/v1/models",
    { headers: { "x-api-key": value, "anthropic-version": "2023-06-01" } },
    "Anthropic"
  );
}

async function verifyHuggingFaceToken(value: string, ctx: VerifyContext): Promise<VerificationResult> {
  return verifyByStatus(
    ctx,
    "https://huggingface.co/api/whoami-v2",
    { headers: { Authorization: `Bearer ${value}` } },
    "Hugging Face",
    async (res) => {
      const body = (await res.json()) as { name?: string };
      return `Active Hugging Face token for "${body.name ?? "unknown"}".`;
    }
  );
}

async function verifyNpmToken(value: string, ctx: VerifyContext): Promise<VerificationResult> {
  return verifyByStatus(
    ctx,
    "https://registry.npmjs.org/-/whoami",
    { headers: { Authorization: `Bearer ${value}` } },
    "npm",
    async (res) => {
      const body = (await res.json()) as { username?: string };
      return `Active npm token for "${body.username ?? "unknown"}" — can publish packages.`;
    }
  );
}

async function verifyDigitalOceanToken(value: string, ctx: VerifyContext): Promise<VerificationResult> {
  return verifyByStatus(
    ctx,
    "https://api.digitalocean.com/v2/account",
    { headers: { Authorization: `Bearer ${value}` } },
    "DigitalOcean",
    async (res) => {
      const body = (await res.json()) as { account?: { email?: string } };
      return `Active DigitalOcean token for ${body.account?.email ?? "an account"}.`;
    }
  );
}

async function verifySendGridKey(value: string, ctx: VerifyContext): Promise<VerificationResult> {
  return verifyByStatus(
    ctx,
    "https://api.sendgrid.com/v3/scopes",
    { headers: { Authorization: `Bearer ${value}` } },
    "SendGrid"
  );
}

async function verifyDiscordBotToken(value: string, ctx: VerifyContext): Promise<VerificationResult> {
  return verifyByStatus(
    ctx,
    "https://discord.com/api/v10/users/@me",
    { headers: { Authorization: `Bot ${value}` } },
    "Discord",
    async (res) => {
      const body = (await res.json()) as { username?: string };
      return `Active Discord bot token for "${body.username ?? "unknown"}".`;
    }
  );
}

async function verifyNotionToken(value: string, ctx: VerifyContext): Promise<VerificationResult> {
  return verifyByStatus(
    ctx,
    "https://api.notion.com/v1/users/me",
    { headers: { Authorization: `Bearer ${value}`, "Notion-Version": "2022-06-28" } },
    "Notion"
  );
}

async function verifyCloudflareToken(value: string, ctx: VerifyContext): Promise<VerificationResult> {
  // Cloudflare has a purpose-built endpoint for exactly this check.
  const res = await ctx.fetchImpl(
    "https://api.cloudflare.com/client/v4/user/tokens/verify",
    requestInit(ctx, { headers: { Authorization: `Bearer ${value}` } })
  );
  const body = (await res.json().catch(() => ({}))) as {
    success?: boolean;
    result?: { status?: string };
  };
  if (res.status === 200 && body.success && body.result?.status === "active") {
    return { verified: true, detail: "Active Cloudflare API token." };
  }
  if (res.status === 401 || res.status === 403) {
    return { verified: false, detail: "Cloudflare reports this token is invalid or revoked." };
  }
  return { verified: false, detail: `Cloudflare responded ${res.status}; treating as unverified.` };
}
