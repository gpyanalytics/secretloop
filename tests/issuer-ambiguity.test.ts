import { test, suite, finish, assert } from "./harness";
import {
  verifyFinding,
  verifyFindings,
  isVerifiable,
  verificationProvider,
  VERIFIABLE_RULE_IDS,
} from "../src/verify";
import { Finding, scanText } from "../src/scanner";

/**
 * 0.1.6 — a credential is only ever sent to the provider that issued it.
 *
 * `stripe-secret-key` matches a `sk_live_`/`sk_test_` format that Stripe, Clerk
 * and WorkOS all issue. The rule's own comment in rules.ts records why no
 * pattern separates them: Clerk documents the collision outright, calling the
 * shape "common among developer tools to provide a more familiar developer
 * experience". Detection therefore cannot know which of the three issued a
 * given key -- and 0.1.5 sent every one of them to `api.stripe.com` anyway.
 *
 * That is a data-handling defect rather than a false positive. Verification's
 * whole contract is "this credential goes to its own issuer and nowhere else",
 * and for two of the three providers sharing this format it was sending a live
 * secret to an unrelated company.
 *
 * The fix is to refuse: an ambiguous issuer is not verified at all. Detection
 * is untouched -- the finding still reports, with the same rule ID, severity
 * and fingerprint -- and only the liveness check changes, to `unknown` with a
 * reason that says why. Verification is opt-in and low-frequency, so declining
 * to check costs little; sending a Clerk key to Stripe cannot be undone.
 */

function makeFinding(ruleId: string, value: string): Finding {
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

/** A fetch stub that records every host it is asked to contact. */
function recordingFetch(hosts: string[], status = 200, jsonBody: any = {}) {
  return (async (url: any, _init?: any) => {
    hosts.push(new URL(String(url)).host);
    return {
      status,
      json: async () => jsonBody,
      text: async () => "",
      headers: { get: () => null },
    } as unknown as Response;
  }) as typeof fetch;
}

// A Clerk secret key: same prefix as Stripe's, issued by a different company.
const CLERK_KEY = "sk_live_" + "Y2xlcmtBbWJpZ3VvdXNLZXlTYW1wbGUwMDAwMDAwMA";
// A value shaped the way Stripe's own documentation shows.
const STRIPE_SHAPED = "sk_live_" + "51H8xKfLpQr7TvWnZmB3cJd9";

// ------------------------------------------- the security-defining assertion

suite("N9 — an ambiguous issuer is never transmitted");

test("a Clerk-style key under stripe-secret-key reaches NO provider", async () => {
  const hosts: string[] = [];
  await verifyFinding(makeFinding("stripe-secret-key", CLERK_KEY), {
    fetchImpl: recordingFetch(hosts),
  } as any);
  assert.deepStrictEqual(
    hosts,
    [],
    `the credential was sent to ${hosts.join(", ")} — it must reach no provider at all`
  );
});

test("api.stripe.com is contacted for no stripe-secret-key value", async () => {
  const hosts: string[] = [];
  for (const value of [CLERK_KEY, STRIPE_SHAPED, "sk_test_" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"]) {
    await verifyFinding(makeFinding("stripe-secret-key", value), {
      fetchImpl: recordingFetch(hosts),
    } as any);
  }
  assert.ok(
    !hosts.includes("api.stripe.com"),
    "no value matched by a shared format may be sent to one of the sharers"
  );
});

test("the refusal is reported as unknown, with a reason that names the ambiguity", async () => {
  const result = await verifyFinding(makeFinding("stripe-secret-key", CLERK_KEY), {
    fetchImpl: recordingFetch([]),
  } as any);
  assert.ok(result, "a result is still returned; this is not silence");
  assert.strictEqual(result!.status, "unknown", "not live, not dead — unknown");
  assert.strictEqual(result!.reason, "ambiguous-issuer", "the reason must be its own kind");
  assert.match(
    result!.detail,
    /Stripe|Clerk|WorkOS/,
    "the detail should name the providers that share the format"
  );
});

test("a genuinely Stripe-shaped key is also not auto-verified, and says so", async () => {
  // Mechanism (B): no documented sub-marker separates the three formats, so a
  // real Stripe key is declined too rather than guessed at. Recorded here so
  // the cost of the fix is visible rather than implied.
  const hosts: string[] = [];
  const result = await verifyFinding(makeFinding("stripe-secret-key", STRIPE_SHAPED), {
    fetchImpl: recordingFetch(hosts),
  } as any);
  assert.deepStrictEqual(hosts, [], "still no outbound call");
  assert.strictEqual(result!.status, "unknown");
  assert.strictEqual(result!.reason, "ambiguous-issuer");
});

// ------------------------------------------------------- detection unchanged

suite("N9 — detection is untouched");

test("a Stripe-format key is still detected, with the same rule id", () => {
  const findings = scanText(`const stripeKey = "${STRIPE_SHAPED}";\n`);
  const hit = findings.find((f) => f.ruleId === "stripe-secret-key");
  assert.ok(hit, "the rule must still fire — this slice changes verification only");
  assert.strictEqual(hit!.severity, "critical", "severity unchanged");
});

test("stripe-secret-key still counts as a verifiable rule id", () => {
  assert.strictEqual(isVerifiable("stripe-secret-key"), true);
  assert.strictEqual(verificationProvider("stripe-secret-key"), "Stripe");
});

// ------------------------------------------------ the outbound record is true

suite("N9 — the outbound record does not overstate what was sent");

test("onOutbound does not fire for a credential that is never sent", async () => {
  const sent: Finding[] = [];
  const hosts: string[] = [];
  const finding = makeFinding("stripe-secret-key", CLERK_KEY);
  await verifyFindings([finding], { fetchImpl: recordingFetch(hosts) } as any, {
    onOutbound: (f) => sent.push(f),
  });
  assert.deepStrictEqual(hosts, [], "nothing left the machine");
  assert.strictEqual(
    sent.length,
    0,
    "the record counts what left the machine; nothing did, so it must stay empty"
  );
});

test("onOutbound still fires for a credential that IS sent", async () => {
  const sent: Finding[] = [];
  const hosts: string[] = [];
  await verifyFindings([makeFinding("github-token", "ghp_fake")], {
    fetchImpl: recordingFetch(hosts),
  } as any, { onOutbound: (f) => sent.push(f) });
  assert.strictEqual(sent.length, 1, "an ordinary verification is still recorded");
  assert.ok(hosts.includes("api.github.com"));
});

// -------------------------------------------- the general guard across rules

suite("N9 — no verifier contacts a provider other than its own issuer");

/**
 * The host each rule's credential may be sent to. Written out rather than
 * derived from the source, so that changing a URL in verify.ts without
 * thinking fails here instead of shipping.
 *
 * `aws-access-key` reaches AWS through the SDK rather than fetchImpl, so this
 * stub records nothing for it; the assertion below is still meaningful,
 * because it requires the empty set rather than allowing it.
 */
const ALLOWED_HOSTS: Record<string, string[]> = {
  "github-token": ["api.github.com"],
  "github-oauth-token": ["api.github.com"],
  "github-app-token": ["api.github.com"],
  "github-fine-grained-pat": ["api.github.com"],
  "gitlab-pat": ["gitlab.com"],
  "slack-token": ["slack.com"],
  "stripe-secret-key": [], // ambiguous issuer — nothing at all
  "google-api-key": ["www.googleapis.com"],
  "aws-access-key": [], // via @aws-sdk/client-sts, not fetchImpl
  "openai-api-key": ["api.openai.com"],
  "anthropic-api-key": ["api.anthropic.com"],
  "huggingface-token": ["huggingface.co"],
  "npm-token": ["registry.npmjs.org"],
  "digitalocean-token": ["api.digitalocean.com"],
  "sendgrid-api-key": ["api.sendgrid.com"],
  "discord-bot-token": ["discord.com"],
  "notion-token": ["api.notion.com"],
  "cloudflare-api-token": ["api.cloudflare.com"],
};

test("every verifiable rule has a declared host allowlist", () => {
  const missing = VERIFIABLE_RULE_IDS.filter((id) => !(id in ALLOWED_HOSTS));
  assert.deepStrictEqual(
    missing,
    [],
    `a rule gained a verifier with no declared destination: ${missing.join(", ")}`
  );
});

test("no rule's credential reaches a host outside its own provider", async () => {
  const offenders: string[] = [];
  for (const ruleId of VERIFIABLE_RULE_IDS) {
    const hosts: string[] = [];
    try {
      await verifyFinding(makeFinding(ruleId, "verification-probe-value-0000000000"), {
        fetchImpl: recordingFetch(hosts, 401),
        fullText: "",
      } as any);
    } catch {
      // A verifier that throws sent nothing; the recorded hosts still stand.
    }
    const allowed = new Set(ALLOWED_HOSTS[ruleId] ?? []);
    for (const host of hosts) {
      if (!allowed.has(host)) offenders.push(`${ruleId} -> ${host}`);
    }
  }
  assert.deepStrictEqual(
    offenders,
    [],
    `a credential was sent to a provider that did not issue it: ${offenders.join("; ")}`
  );
});

finish();
