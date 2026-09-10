import { createHash } from "crypto";
import { Finding, LivenessStatus, UnknownReason } from "./scanner";

export interface VerificationResult {
  status: LivenessStatus;
  /** Set only when status is "unknown"; says what an operator should do next. */
  reason?: UnknownReason;
  /** Human-readable reason, shown in the diagnostic hover. */
  detail: string;
}

const live = (detail: string): VerificationResult => ({ status: "live", detail });
const dead = (detail: string): VerificationResult => ({ status: "dead", detail });
const unknown = (reason: UnknownReason, detail: string): VerificationResult => ({
  status: "unknown",
  reason,
  detail,
});

/**
 * Classifies a non-conclusive HTTP status.
 *
 * 403 is deliberately never "dead". A credential lacking scope for the check
 * endpoint, one belonging to an unverified org, and one that was revoked all
 * answer 403 — so the only honest reading is that liveness is undetermined.
 * Calling it revoked produces the exact sentence someone uses to decide not to
 * rotate a live credential.
 */
function fromStatus(provider: string, status: number): VerificationResult {
  if (status === 403) {
    return unknown(
      "provider-refused",
      `${provider} refused the check (403), which it returns for a revoked credential ` +
        `and for a live one lacking permission alike. Liveness could not be determined — ` +
        `check this credential directly.`
    );
  }
  if (status === 429) {
    return unknown(
      "provider-unavailable",
      `${provider} rate-limited the check (429). Liveness could not be determined; retry later.`
    );
  }
  return unknown(
    "provider-unavailable",
    `${provider} responded ${status}. Liveness could not be determined; retry later.`
  );
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

/**
 * Rules whose credential format is issued by more than one provider, and the
 * providers that share it.
 *
 * Verification's contract is that a credential goes to the company that issued
 * it and to nobody else. A rule in this table cannot honour that contract,
 * because detection genuinely cannot tell the issuers apart -- so it does not
 * try, and the credential is not sent anywhere.
 *
 * `stripe-secret-key` is the whole table today. Stripe, Clerk and WorkOS all
 * issue secret keys as `sk_live_`/`sk_test_`; the rule's comment in rules.ts
 * records that Clerk documents the collision outright, and 0.1.5's changelog
 * states that no pattern separates the three. Until 0.1.6 this rule sent every
 * match to api.stripe.com, which meant a Clerk or WorkOS secret key -- a live
 * credential -- was handed to an unrelated company by a tool whose entire
 * purpose is preventing exactly that.
 *
 * Not verifying costs a verdict on one rule. Verifying costs a credential
 * disclosure that cannot be recalled, for two providers out of three. The
 * asymmetry is the whole argument, and it is why this is a refusal rather than
 * a guess at which issuer a key belongs to: no published sub-marker separates
 * the formats, and a wrong guess sends the key anyway.
 */
const AMBIGUOUS_ISSUERS: Record<string, string[]> = {
  "stripe-secret-key": ["Stripe", "Clerk", "WorkOS"],
};

/** True when a rule's format is issued by more than one provider. */
export function isAmbiguousIssuer(ruleId: string): boolean {
  return ruleId in AMBIGUOUS_ISSUERS;
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

/** Every rule whose credential can be checked against a live provider. */
export const VERIFIABLE_RULE_IDS: string[] = Object.keys(verifiers);

/**
 * The rules whose credential can actually leave the machine: every rule with a
 * verifier, minus the ones whose issuer is ambiguous and are therefore never
 * sent. This is the honest answer to "what can be transmitted", and it is
 * smaller than VERIFIABLE_RULE_IDS.
 */
export const TRANSMITTING_RULE_IDS: string[] = VERIFIABLE_RULE_IDS.filter(
  (id) => !isAmbiguousIssuer(id)
);

/**
 * The third party a rule's credential is checked against, by the name a user
 * would recognise. Asking permission to contact "the provider" is not asking
 * permission at all, so the consent prompt names the company.
 */
const providers: Record<string, string> = {
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

export function verificationProvider(ruleId: string): string | undefined {
  return providers[ruleId];
}

/** "Stripe, Clerk and WorkOS" — an Oxford-free list for a sentence. */
function listProviders(names: string[]): string {
  if (names.length <= 1) return names[0] ?? "another provider";
  return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
}

export async function verifyFinding(
  finding: Finding,
  context: VerifyContext
): Promise<VerificationResult | null> {
  const verifier = verifiers[finding.ruleId];
  if (!verifier) return null; // no verifier for this rule; caller decides what that means

  // Refused before dispatch. An encoded-derived finding's `value` is the
  // encoded source text, not the credential: handing it to a verifier would
  // send base64 to GitHub under a header claiming it is a token, and the
  // decoded form is deliberately never retained to send instead. Same shape as
  // the ambiguous-issuer refusal below, and for the same reason -- the answer
  // is attached to the finding rather than the finding silently skipped.
  //
  // Not `no-verifier`: this rule HAS one. That reason means nothing can check
  // the credential type at all, and it is the bucket an unknown with no
  // recorded reason falls into. This is the opposite -- a verifier exists and
  // was deliberately not given the finding.
  // An archive member first, ahead of the encoded check: the container reason
  // wins when both apply. No surface can re-read a member from disk to confirm
  // what would be sent, and the consent flow needs exactly that, so one rule
  // covers the CLI, the editor and MCP alike.
  if (finding.source) {
    return unknown(
      "unsupported-container",
      `This finding is inside an archive member (${finding.source.containerKind} container ` +
        `${finding.source.container}, member ${finding.source.member}). Archive-member findings ` +
        `are not verified in this version: the member cannot be re-read from disk to confirm ` +
        `what would be sent, so nothing was sent to ${providers[finding.ruleId] ?? "the provider"}. ` +
        `Liveness could not be determined — confirm it in the provider's own dashboard.`
    );
  }

  if (finding.encoding) {
    return unknown(
      "unsupported-transform",
      `This finding was recovered by decoding a ${finding.encoding}-encoded value in the ` +
        `source. Verification of encoded findings is not supported: the encoded text is not ` +
        `the credential, and SecretLoop does not keep the decoded form, so nothing was sent to ` +
        `${providers[finding.ruleId] ?? "the provider"}. Liveness could not be determined — ` +
        `confirm it in the provider's own dashboard.`
    );
  }

  // Refused before dispatch, so the credential never reaches a verifier that
  // would send it. Returning early rather than filtering upstream keeps the
  // reason attached to the finding: the user is told the check did not happen
  // and why, instead of seeing a silent "never checked".
  const sharedBy = AMBIGUOUS_ISSUERS[finding.ruleId];
  if (sharedBy) {
    return unknown(
      "ambiguous-issuer",
      `This credential format is issued by ${listProviders(sharedBy)}, and nothing in the ` +
        `value says which one issued this key. It was NOT sent to any of them, because ` +
        `checking it would mean handing a live credential to a provider that may not have ` +
        `issued it. Confirm it in the issuing provider's own dashboard.`
    );
  }

  try {
    return await verifier(finding.value, context);
  } catch (err: any) {
    // Timeouts land here too, via the abort signal. Never "safe".
    const cause = err?.name === "TimeoutError" || err?.name === "AbortError" ? "timed out" : "failed";
    return unknown(
      "network",
      `The check ${cause} before reaching the provider. Liveness could not be determined — ` +
        `this is a connectivity problem, not a verdict on the credential.`
    );
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

  /**
   * Requests that have left but not yet answered, keyed exactly as the results
   * are — the same hash, never the plaintext.
   *
   * The result cache can only help once a result exists. Two verifies of one
   * credential issued before either returns are both misses, so both used to
   * reach the provider. The count was never wrong — onOutbound fired twice
   * because two requests really did leave — but a workspace scan verifies at
   * concurrency 5, and one credential copied into five files is the ordinary
   * case rather than the unusual one.
   */
  private readonly inFlight = new Map<string, Promise<VerificationResult | null>>();

  constructor(
    private readonly ttlMs: number = DEFAULT_CACHE_TTL_MS,
    private readonly now: () => number = Date.now
  ) {}

  async verify(
    finding: Finding,
    context: VerifyContext,
    onMiss?: (finding: Finding) => void
  ): Promise<VerificationResult | null> {
    const key = this.key(finding);
    const hit = this.entries.get(key);
    if (hit && hit.expiresAt > this.now()) return hit.result;

    // Joining an outstanding request is not an outbound call, so onMiss does
    // not fire here. The record counts what left the machine, and nothing does.
    const pending = this.inFlight.get(key);
    if (pending) return pending;

    // Only a miss reaches the provider, so only a miss is an outbound call.
    onMiss?.(finding);
    const request = verifyFinding(finding, context)
      .then((result) => {
        this.entries.set(key, { result, expiresAt: this.now() + this.ttlMs });
        return result;
      })
      // Cleared however it settles. A rejected promise left in the map would
      // turn one transient failure into a permanent one: every later caller
      // would await a failure that had already happened, and the credential
      // would never be re-checked. The entries map is what caches an answer;
      // this map only ever holds a question.
      .finally(() => {
        this.inFlight.delete(key);
      });
    this.inFlight.set(key, request);
    return request;
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
  /**
   * Called once per finding whose credential actually leaves this machine.
   *
   * Verification is the one thing here that sends a user's credential to a
   * third party, and nothing recorded that it had happened — a dev host spent a
   * whole session calling api.github.com with a fixture token unnoticed. Cache
   * hits do not fire it, so the record cannot overstate what was sent.
   */
  onOutbound?: (finding: Finding) => void;
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
  context: VerifyContext | ((finding: Finding) => VerifyContext),
  options: VerifyFindingsOptions = {}
): Promise<void> {
  const verifiable = findings.filter((f) => isVerifiable(f.ruleId));
  if (verifiable.length === 0) return;

  // A whole-workspace pass covers many files at once, and the AWS verifier reads
  // ctx.fullText to find the secret key paired with an access key ID — so the
  // context has to be resolvable per finding, not fixed for the batch. Editors
  // scanning one document pass a plain context instead.
  const contextFor = typeof context === "function" ? context : () => context;

  const { cache, onOutbound } = options;
  // A refused check sends nothing, so it must not be recorded as a send. The
  // outbound record's whole value is that it cannot overstate what left the
  // machine -- the same reason a cache hit does not fire it.
  const record = onOutbound && ((f: Finding) => {
    if (!isAmbiguousIssuer(f.ruleId) && !f.encoding && !f.source) onOutbound(f);
  });
  const check = cache
    ? (f: Finding) => cache.verify(f, contextFor(f), record)
    : (f: Finding) => {
        record?.(f);
        return verifyFinding(f, contextFor(f));
      };

  let cursor = 0;
  const workers = Array.from(
    { length: Math.min(options.concurrency ?? VERIFY_CONCURRENCY, verifiable.length) },
    async () => {
      while (cursor < verifiable.length) {
        const finding = verifiable[cursor++];
        const result = await check(finding);
        if (!result) continue; // no verifier; leave as format-match
        finding.verifyStatus = result.status;
        finding.verifyReason = result.reason;
        finding.verifyDetail = result.detail;
        if (result.status === "live") finding.confidence = "verified-live";
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
    // Three cases, and the difference matters to whoever reads the line. A
    // classic PAT always sends the header: populated when scopes are ticked,
    // present-but-empty when none are — `?? "unknown"` only catches null, so
    // that case used to trail off mid-sentence at "Scopes: ". Fine-grained PATs
    // and GitHub App tokens omit the header entirely; they *have* permissions,
    // GitHub just does not report them on this endpoint, so "unknown" claimed
    // something false directly underneath CONFIRMED LIVE.
    const header = res.headers.get("x-oauth-scopes");
    const scopes =
      header === null ? "not reported for fine-grained or app tokens" : header.trim() || "none";
    return live(`Active GitHub token. Scopes: ${scopes}`);
  }
  if (res.status === 401) return dead("GitHub token is invalid or already revoked.");
  // GitHub answers 403 for a primary rate limit, a secondary rate limit and a genuine
  // refusal alike -- and its own documentation names the discriminators: a primary limit
  // sets `x-ratelimit-remaining` to 0, a secondary limit sets `retry-after`. Without them a
  // 403 still proves nothing, which is what fromStatus says. With them it proves something
  // specific, and the remedy is the opposite one: wait, rather than go and inspect the
  // credential.
  //
  // Read HERE and not in fromStatus on purpose. Those headers are documented for GitHub;
  // fromStatus is shared with Stripe, Google, Cloudflare and every caller of
  // verifyByStatus, and nothing documents the same meaning for them. Provider-specific
  // evidence gets provider-specific handling.
  if (res.status === 403) {
    const limited = gitHubRateLimited(res);
    if (limited) return limited;
  }
  return fromStatus("GitHub", res.status);
}

/**
 * The documented rate-limit reading of a GitHub 403, or null when the response carries no
 * such evidence and the 403 keeps its refusal reading unchanged.
 *
 * Only header NAMES and a parsed integer ever reach the message. No header text and no
 * response body is echoed, so a provider can never place arbitrary content in a line a
 * user reads.
 */
function gitHubRateLimited(res: Response): VerificationResult | null {
  const retryAfter = retryAfterSeconds(res);
  if (retryAfter !== null) {
    return unknown(
      "provider-unavailable",
      `GitHub rate-limited the check (403 with a retry-after header). Liveness could not be ` +
        `determined; retry after ${retryAfter} seconds.`
    );
  }
  if (res.headers.get("x-ratelimit-remaining") === "0") {
    return unknown(
      "provider-unavailable",
      `GitHub rate-limited the check (403 with x-ratelimit-remaining: 0). Liveness could ` +
        `not be determined; retry after the time given in the x-ratelimit-reset header.`
    );
  }
  return null;
}

/**
 * `retry-after` in seconds, or null when absent or not a plain integer.
 *
 * Parsed rather than echoed. The header is provider-controlled text, and a message that
 * interpolated it raw would let a response put anything it liked in front of a reader.
 * The HTTP-date form of this header is deliberately not accepted: it would have to be
 * rendered into a wait, and no observed provider response in the review used it.
 */
function retryAfterSeconds(res: Response): number | null {
  const raw = res.headers.get("retry-after");
  if (raw === null) return null;
  const t = raw.trim();
  return /^\d{1,7}$/.test(t) ? Number(t) : null;
}

async function verifySlackToken(value: string, ctx: VerifyContext): Promise<VerificationResult> {
  const res = await ctx.fetchImpl(
    "https://slack.com/api/auth.test",
    requestInit(ctx, { method: "POST", headers: { Authorization: `Bearer ${value}` } })
  );

  // The status is read BEFORE the body, and that order is the fix rather than a style
  // choice. Slack's Web API answers HTTP 200 and carries the outcome in `ok` -- its
  // documentation says callers should always check that field -- with one documented
  // exception: rate limiting arrives as HTTP 429 with a Retry-After header and no JSON
  // payload. Parsing first made that response throw, and the catch upstream reported it as
  // `network`: "failed before reaching the provider", about a provider that had answered.
  if (res.status === 429) {
    const retryAfter = retryAfterSeconds(res);
    return unknown(
      "provider-unavailable",
      `Slack rate-limited the check (429). Liveness could not be determined; ` +
        (retryAfter === null ? `retry later.` : `retry after ${retryAfter} seconds.`)
    );
  }

  let body: { ok?: boolean; team?: string; error?: string };
  try {
    body = (await res.json()) as { ok?: boolean; team?: string; error?: string };
  } catch {
    // The provider answered and the answer was not JSON. That is not a transport failure.
    // `network` stays reserved for a request that never arrived, because the two carry
    // different remedies and only one of them is about this machine's egress.
    return unknown(
      "provider-unavailable",
      `Slack responded ${res.status} with a body that could not be read as JSON. ` +
        `Liveness could not be determined; retry later.`
    );
  }

  if (body.ok) {
    return live(`Active Slack token for workspace "${body.team}".`);
  }
  // Slack reports transport problems through the same ok:false shape as a dead
  // token, so only the errors that actually mean "this token is finished" count.
  const error = safeErrorCode(body.error);
  const REVOKED = ["invalid_auth", "account_inactive", "token_revoked", "token_expired", "not_authed"];
  if (REVOKED.includes(error)) {
    return dead(`Slack reports token invalid: ${error}.`);
  }
  // Documented in Slack's own error table as policy or administrative restrictions, not as
  // transient conditions: access_denied is a denied resource, accesslimited is a network
  // restriction on the method, ekm_access_denied is an administrator suspension, and
  // enterprise_is_restricted is an org-level bar. "Retry later" is the wrong instruction for
  // every one of them -- retrying never lifts a policy -- and the credential may well be
  // live, so the honest reading is the same one a 403 with no rate-limit evidence gets.
  const REFUSED = ["access_denied", "accesslimited", "ekm_access_denied", "enterprise_is_restricted"];
  if (REFUSED.includes(error)) {
    return unknown(
      "provider-refused",
      `Slack refused the check (${error}), which its documentation describes as a policy or ` +
        `administrative restriction rather than a transient failure. Liveness could not be ` +
        `determined — check this credential directly.`
    );
  }
  // Everything else, including an error code this build has never seen, stays indeterminate
  // and retryable. An unrecognised response must not be promoted into a verdict.
  return unknown(
    "provider-unavailable",
    `Slack could not complete the check (${error}). Liveness could not be determined; retry later.`
  );
}

/**
 * A provider-supplied error code, reduced to something safe to place in a line a user reads.
 *
 * Slack's documented codes are short snake_case tokens. Anything else -- a long string, an
 * HTML fragment, a sentence -- is provider-controlled text that has no business being
 * interpolated into a diagnostic, so it is replaced rather than echoed. The message still
 * says the check could not be completed; it just stops the response dictating the wording.
 */
function safeErrorCode(raw: string | undefined): string {
  if (raw === undefined) return "unknown";
  return /^[a-z0-9_]{1,40}$/.test(raw) ? raw : "unrecognised";
}

/**
 * CURRENTLY UNREACHABLE, and deliberately kept.
 *
 * `stripe-secret-key` is in AMBIGUOUS_ISSUERS, so verifyFinding returns before
 * dispatching here and this function sends nothing. It stays because the
 * refusal is a property of the *format's* ambiguity, not of Stripe's API: if
 * Stripe ever publishes a marker that separates its keys from Clerk's and
 * WorkOS's, the fix is to narrow the ambiguity entry and this check works
 * again unchanged.
 *
 * Removing the entry from AMBIGUOUS_ISSUERS re-enables sending to Stripe. Do
 * not do that without a documented way to tell the three issuers apart --
 * tests/issuer-ambiguity.test.ts fails if you do, which is the point.
 */
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
    return live(`Active Stripe key (${isLive ? "LIVE mode" : "test mode"}).`);
  }
  if (res.status === 401) return dead("Stripe key is invalid or revoked.");
  return fromStatus("Stripe", res.status);
}

async function verifyGoogleApiKey(value: string, ctx: VerifyContext): Promise<VerificationResult> {
  // Discovery API accepts a key param and is safe/read-only; a bad key returns 400 with API_KEY_INVALID.
  const res = await ctx.fetchImpl(
    `https://www.googleapis.com/discovery/v1/apis?key=${encodeURIComponent(value)}`,
    requestInit(ctx)
  );
  if (res.status === 200) return live("Active Google API key.");
  const body = await res.text();
  if (body.includes("API_KEY_INVALID")) {
    return dead("Google reports this API key is invalid.");
  }
  return fromStatus("Google", res.status);
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
    return unknown(
      "missing-pair",
      "No AWS secret access key found alongside this access key ID, and AWS cannot be " +
        "asked about one without the other. Liveness could not be determined."
    );
  }
  const secretAccessKey = secretMatch[1];

  try {
    // Dynamic import keeps this dependency optional at compile time for
    // consumers who strip AWS verification out of their build.
    const { STSClient, GetCallerIdentityCommand } = await import("@aws-sdk/client-sts");
    const client = new STSClient({ region: "us-east-1", credentials: { accessKeyId, secretAccessKey } });
    const identity = await client.send(new GetCallerIdentityCommand({}));
    return live(`Active AWS credentials. Account: ${identity.Account}, ARN: ${identity.Arn}`);
  } catch (err: any) {
    if (err?.name === "InvalidClientTokenId" || err?.name === "SignatureDoesNotMatch") {
      return dead("AWS reports these credentials are invalid or revoked.");
    }
    return unknown(
      "provider-unavailable",
      `AWS could not complete the check (${err?.name ?? "unknown error"}). ` +
        "Liveness could not be determined."
    );
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
    return live(detail);
  }
  if (res.status === 401) {
    return dead(`${provider} reports this credential is invalid or revoked.`);
  }
  return fromStatus(provider, res.status);
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
    return live("Active Cloudflare API token.");
  }
  if (res.status === 401) {
    return dead("Cloudflare reports this token is invalid or revoked.");
  }
  return fromStatus("Cloudflare", res.status);
}
