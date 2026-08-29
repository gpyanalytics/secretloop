import {
  verifyFinding,
  isVerifiable,
  verifyFindings,
  verificationProvider,
  VerificationCache,
  VERIFIABLE_RULE_IDS,
} from "../src/verify";
import { Finding } from "../src/scanner";
import * as assert from "node:assert";
import { test, suite, finish } from "./harness";

function mockFetch(response: { status: number; jsonBody?: any; textBody?: string; headers?: Record<string, string> }) {
  return (async (_url: any, _init?: any) => {
    return {
      status: response.status,
      json: async () => response.jsonBody,
      text: async () => response.textBody ?? "",
      headers: {
        get: (key: string) => response.headers?.[key.toLowerCase()] ?? null,
      },
    } as unknown as Response;
  }) as typeof fetch;
}

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

suite("verify.ts");

test("isVerifiable returns true only for supported rule ids", () => {
  return (async () => {
    assert.strictEqual(isVerifiable("github-token"), true);
    assert.strictEqual(isVerifiable("private-key-block"), false);
  })();
});

test("GitHub: 200 response marks token verified with scopes", async () => {
  const finding = makeFinding("github-token", "ghp_fake");
  const result = await verifyFinding(finding, {
    fullText: "",
    fetchImpl: mockFetch({ status: 200, headers: { "x-oauth-scopes": "repo, read:org" } }),
  });
  assert.ok(result);
  assert.strictEqual(result!.status, "live");
  assert.match(result!.detail, /repo, read:org/);
});

test("GitHub: a scopeless classic PAT says 'none', not a dangling colon", async () => {
  // GitHub sends X-OAuth-Scopes present-but-empty for a classic PAT with no
  // scopes ticked. `?? "unknown"` only catches null, so the detail line ended
  // mid-sentence at "Scopes: " — directly under CONFIRMED LIVE.
  const result = await verifyFinding(makeFinding("github-token", "ghp_fake"), {
    fullText: "",
    fetchImpl: mockFetch({ status: 200, headers: { "x-oauth-scopes": "" } }),
  });
  assert.ok(result);
  assert.strictEqual(result!.status, "live");
  assert.match(result!.detail, /Scopes: none/);
});

test("GitHub: an absent scopes header does not claim the scopes are unknown", async () => {
  // Fine-grained PATs and GitHub App tokens omit the header entirely. They do
  // have permissions; GitHub just does not report them on this endpoint, so
  // "unknown" states something false rather than merely unhelpful — and it read
  // as a contradiction sitting under CONFIRMED LIVE.
  const result = await verifyFinding(makeFinding("github-fine-grained-pat", "github_pat_fake"), {
    fullText: "",
    fetchImpl: mockFetch({ status: 200 }),
  });
  assert.ok(result);
  assert.strictEqual(result!.status, "live");
  assert.doesNotMatch(result!.detail, /unknown/i, "the permissions are not unknown to GitHub");
  assert.match(result!.detail, /not reported/);
});

test("GitHub: no live detail ever ends on a dangling separator", async () => {
  // The shape of the bug, not just its three known instances: whatever the
  // header holds, the sentence has to finish.
  for (const headers of [{ "x-oauth-scopes": "" }, { "x-oauth-scopes": "repo" }, undefined]) {
    const result = await verifyFinding(makeFinding("github-token", "ghp_fake"), {
      fullText: "",
      fetchImpl: mockFetch({ status: 200, headers }),
    });
    assert.doesNotMatch(result!.detail, /[:,-]\s*$/, `dangling end for ${JSON.stringify(headers)}`);
  }
});

test("GitHub: 401 response marks the token dead", async () => {
  const finding = makeFinding("github-token", "ghp_fake");
  const result = await verifyFinding(finding, { fullText: "", fetchImpl: mockFetch({ status: 401 }) });
  assert.ok(result);
  assert.strictEqual(result!.status, "dead");
});

test("Slack: ok:true response marks token verified with team name", async () => {
  const finding = makeFinding("slack-token", "xoxb-fake");
  const result = await verifyFinding(finding, {
    fullText: "",
    fetchImpl: mockFetch({ status: 200, jsonBody: { ok: true, team: "Acme Corp" } }),
  });
  assert.ok(result);
  assert.strictEqual(result!.status, "live");
  assert.match(result!.detail, /Acme Corp/);
});

test("Slack: ok:false response marks token not verified", async () => {
  const finding = makeFinding("slack-token", "xoxb-fake");
  const result = await verifyFinding(finding, {
    fullText: "",
    fetchImpl: mockFetch({ status: 200, jsonBody: { ok: false, error: "invalid_auth" } }),
  });
  assert.ok(result);
  assert.strictEqual(result!.status, "dead");
  assert.match(result!.detail, /invalid_auth/);
});

test("Stripe: 200 on /v1/balance means key is active", async () => {
  const finding = makeFinding("stripe-secret-key", "sk_live_fake");
  const result = await verifyFinding(finding, { fullText: "", fetchImpl: mockFetch({ status: 200 }) });
  assert.ok(result);
  assert.strictEqual(result!.status, "live");
  assert.match(result!.detail, /LIVE mode/);
});

test("Stripe: test-mode key is verified but flagged as test mode", async () => {
  const finding = makeFinding("stripe-secret-key", "sk_test_fake");
  const result = await verifyFinding(finding, { fullText: "", fetchImpl: mockFetch({ status: 200 }) });
  assert.ok(result);
  assert.strictEqual(result!.status, "live");
  assert.match(result!.detail, /test mode/);
});

test("Stripe: 401 means the key is dead", async () => {
  const finding = makeFinding("stripe-secret-key", "sk_live_fake");
  const result = await verifyFinding(finding, { fullText: "", fetchImpl: mockFetch({ status: 401 }) });
  assert.ok(result);
  assert.strictEqual(result!.status, "dead");
});

test("Google: 200 means API key is active", async () => {
  const finding = makeFinding("google-api-key", "AIzaFake");
  const result = await verifyFinding(finding, { fullText: "", fetchImpl: mockFetch({ status: 200 }) });
  assert.ok(result);
  assert.strictEqual(result!.status, "live");
});

test("Google: API_KEY_INVALID body means key is not verified", async () => {
  const finding = makeFinding("google-api-key", "AIzaFake");
  const result = await verifyFinding(finding, {
    fullText: "",
    fetchImpl: mockFetch({ status: 400, textBody: '{"error": {"status": "API_KEY_INVALID"}}' }),
  });
  assert.ok(result);
  assert.strictEqual(result!.status, "dead");
});

test("network error is unknown/network, never dead", async () => {
  const finding = makeFinding("github-token", "ghp_fake");
  const throwingFetch = (async () => {
    throw new Error("network unreachable");
  }) as unknown as typeof fetch;
  const result = await verifyFinding(finding, { fullText: "", fetchImpl: throwingFetch });
  assert.ok(result);
  assert.strictEqual(result!.status, "unknown", "a network failure disproves nothing");
  assert.strictEqual(result!.reason, "network", "an operator needs to know this is an infra fix");
});

test("unverifiable rule id returns null without calling fetch", async () => {
  const finding = makeFinding("private-key-block", "-----BEGIN...-----");
  let called = false;
  const spyFetch = (async () => {
    called = true;
    return { status: 200, json: async () => ({}), text: async () => "", headers: { get: () => null } } as any;
  }) as typeof fetch;
  const result = await verifyFinding(finding, { fullText: "", fetchImpl: spyFetch });
  assert.strictEqual(result, null);
  assert.strictEqual(called, false, "fetch should never be called for a non-verifiable rule");
});

suite("\nverify.ts — 403 is not a revocation");

test("OpenAI 403 is unknown, not dead", async () => {
  // A live key lacking model-list scope, a key in an unverified org, and a
  // revoked key all return 403. Reading that as "revoked" hands someone the
  // exact sentence they use to decide not to rotate a live credential.
  const result = await verifyFinding(makeFinding("openai-api-key", "sk-fake"), {
    fullText: "",
    fetchImpl: mockFetch({ status: 403 }),
  });
  assert.ok(result);
  assert.strictEqual(result!.status, "unknown");
  assert.strictEqual(result!.reason, "provider-refused");
});

test("no 403 detail claims the credential is invalid or revoked", async () => {
  for (const ruleId of ["gitlab-pat", "openai-api-key", "huggingface-token", "npm-token",
                        "digitalocean-token", "sendgrid-api-key", "notion-token"]) {
    const result = await verifyFinding(makeFinding(ruleId, "fake-value"), {
      fullText: "",
      fetchImpl: mockFetch({ status: 403 }),
    });
    assert.ok(result, `${ruleId} returned no result`);
    assert.strictEqual(result!.status, "unknown", `${ruleId} must not resolve a 403`);
    assert.doesNotMatch(
      result!.detail,
      /invalid or revoked/i,
      `${ruleId}: a 403 detail must not read as a revocation`
    );
    assert.match(result!.detail, /could not|cannot|unable/i, `${ruleId}: say liveness is undetermined`);
  }
});

test("401 still reads as a revocation, and still means dead", async () => {
  const result = await verifyFinding(makeFinding("openai-api-key", "sk-fake"), {
    fullText: "",
    fetchImpl: mockFetch({ status: 401 }),
  });
  assert.ok(result);
  assert.strictEqual(result!.status, "dead");
  assert.match(result!.detail, /invalid or revoked/i);
});

test("a rate-limited provider is unknown/provider-unavailable", async () => {
  // Retrying later fixes this; going to look at the credential does not.
  const result = await verifyFinding(makeFinding("openai-api-key", "sk-fake"), {
    fullText: "",
    fetchImpl: mockFetch({ status: 429 }),
  });
  assert.ok(result);
  assert.strictEqual(result!.status, "unknown");
  assert.strictEqual(result!.reason, "provider-unavailable");
});

test("a 5xx from the provider is unknown/provider-unavailable", async () => {
  const result = await verifyFinding(makeFinding("notion-token", "secret_fake"), {
    fullText: "",
    fetchImpl: mockFetch({ status: 503 }),
  });
  assert.ok(result);
  assert.strictEqual(result!.status, "unknown");
  assert.strictEqual(result!.reason, "provider-unavailable");
});

test("GitHub 403 is unknown, since it also means rate-limited", async () => {
  const result = await verifyFinding(makeFinding("github-token", "ghp_fake"), {
    fullText: "",
    fetchImpl: mockFetch({ status: 403 }),
  });
  assert.ok(result);
  assert.strictEqual(result!.status, "unknown");
  assert.strictEqual(result!.reason, "provider-refused");
});

test("Cloudflare 403 is unknown; 401 is dead", async () => {
  const refused = await verifyFinding(makeFinding("cloudflare-api-token", "cf-fake"), {
    fullText: "",
    fetchImpl: mockFetch({ status: 403, jsonBody: {} }),
  });
  assert.ok(refused);
  assert.strictEqual(refused!.status, "unknown");
  const dead = await verifyFinding(makeFinding("cloudflare-api-token", "cf-fake"), {
    fullText: "",
    fetchImpl: mockFetch({ status: 401, jsonBody: {} }),
  });
  assert.ok(dead);
  assert.strictEqual(dead!.status, "dead");
});

test("Slack distinguishes a revoked token from a rate-limited one", async () => {
  const dead = await verifyFinding(makeFinding("slack-token", "xoxb-fake"), {
    fullText: "",
    fetchImpl: mockFetch({ status: 200, jsonBody: { ok: false, error: "token_revoked" } }),
  });
  assert.ok(dead);
  assert.strictEqual(dead!.status, "dead");

  const unknown = await verifyFinding(makeFinding("slack-token", "xoxb-fake"), {
    fullText: "",
    fetchImpl: mockFetch({ status: 200, jsonBody: { ok: false, error: "ratelimited" } }),
  });
  assert.ok(unknown);
  assert.strictEqual(unknown!.status, "unknown", "ratelimited says nothing about the token");
  assert.strictEqual(unknown!.reason, "provider-unavailable");
});

test("Google: a non-200 that is not API_KEY_INVALID is unknown", async () => {
  const result = await verifyFinding(makeFinding("google-api-key", "AIzaFake"), {
    fullText: "",
    fetchImpl: mockFetch({ status: 500, textBody: "upstream boom" }),
  });
  assert.ok(result);
  assert.strictEqual(result!.status, "unknown");
});

test("an AWS key with no secret key beside it is unknown/missing-pair", async () => {
  // Nothing an operator can fix by retrying, and nothing to go look at either.
  const result = await verifyFinding(makeFinding("aws-access-key", "AKIA2Q7RZDXK4LM9PBWT"), {
    fullText: "no secret key anywhere in this file",
    fetchImpl: mockFetch({ status: 200 }),
  });
  assert.ok(result, "an unpairable AWS key is a result, not a silent null");
  assert.strictEqual(result!.status, "unknown");
  assert.strictEqual(result!.reason, "missing-pair");
});

suite("\nverify.ts — timeouts");

test("every request carries an abort signal", async () => {
  let seenSignal: unknown = "never called";
  const capturingFetch = (async (_url: any, init?: any) => {
    seenSignal = init?.signal;
    return { status: 200, json: async () => ({}), text: async () => "", headers: { get: () => null } } as any;
  }) as typeof fetch;
  await verifyFinding(makeFinding("github-token", "ghp_fake"), {
    fullText: "",
    fetchImpl: capturingFetch,
  });
  assert.ok(seenSignal instanceof AbortSignal, "requests must be abortable");
});

test("a provider that never responds aborts instead of hanging forever", async () => {
  // Without this the CLI hangs a CI job indefinitely and the editor leaks a
  // pending promise per keystroke.
  // AbortSignal.timeout uses an unref'd timer, so it only fires while the loop
  // is alive. A real hung request holds a socket open; this holds a handle to
  // match, otherwise the process just exits before the abort lands.
  const hangingFetch = ((_url: any, init?: any) =>
    new Promise((_resolve, reject) => {
      const socket = setInterval(() => {}, 1000);
      init?.signal?.addEventListener("abort", () => {
        clearInterval(socket);
        reject(new Error("aborted"));
      });
    })) as unknown as typeof fetch;
  const result = await verifyFinding(makeFinding("github-token", "ghp_fake"), {
    fullText: "",
    fetchImpl: hangingFetch,
    timeoutMs: 5,
  });
  assert.ok(result);
  assert.strictEqual(result!.status, "unknown", "a timed-out check is unknown, never disproven");
  assert.strictEqual(result!.reason, "network");
});

suite("\nverify.ts — result cache");

test("the same secret is not sent to its provider twice", async () => {
  let calls = 0;
  const countingFetch = (async () => {
    calls++;
    return { status: 200, json: async () => ({}), text: async () => "", headers: { get: () => null } } as any;
  }) as typeof fetch;
  const cache = new VerificationCache();
  const context = { fullText: "", fetchImpl: countingFetch };
  await cache.verify(makeFinding("github-token", "ghp_same"), context);
  await cache.verify(makeFinding("github-token", "ghp_same"), context);
  assert.strictEqual(calls, 1, "a re-scan of unchanged text must not re-send the credential");
});

test("different secrets are cached separately", async () => {
  let calls = 0;
  const countingFetch = (async () => {
    calls++;
    return { status: 200, json: async () => ({}), text: async () => "", headers: { get: () => null } } as any;
  }) as typeof fetch;
  const cache = new VerificationCache();
  const context = { fullText: "", fetchImpl: countingFetch };
  await cache.verify(makeFinding("github-token", "ghp_one"), context);
  await cache.verify(makeFinding("github-token", "ghp_two"), context);
  assert.strictEqual(calls, 2);
});

test("a cached result is re-checked once it expires", async () => {
  let calls = 0;
  const countingFetch = (async () => {
    calls++;
    return { status: 200, json: async () => ({}), text: async () => "", headers: { get: () => null } } as any;
  }) as typeof fetch;
  let clock = 0;
  const cache = new VerificationCache(1000, () => clock);
  const context = { fullText: "", fetchImpl: countingFetch };
  await cache.verify(makeFinding("github-token", "ghp_same"), context);
  clock = 999;
  await cache.verify(makeFinding("github-token", "ghp_same"), context);
  assert.strictEqual(calls, 1, "still fresh");
  clock = 1001;
  await cache.verify(makeFinding("github-token", "ghp_same"), context);
  assert.strictEqual(calls, 2, "a revoked credential must not stay cached forever");
});

test("the cache keys on a hash, never the secret itself", async () => {
  const cache = new VerificationCache();
  await cache.verify(makeFinding("github-token", "ghp_plaintext_value"), {
    fullText: "",
    fetchImpl: mockFetch({ status: 200 }),
  });
  assert.ok(
    !cache.keys().some((k) => k.includes("ghp_plaintext_value")),
    "a long-lived map in the extension host must not hold plaintext secrets"
  );
});

suite("\nverify.ts — bounded concurrency");

test("no more than the configured number of requests are in flight", async () => {
  let inFlight = 0;
  let peak = 0;
  const slowFetch = (async () => {
    inFlight++;
    peak = Math.max(peak, inFlight);
    await new Promise((r) => setTimeout(r, 1));
    inFlight--;
    return { status: 200, json: async () => ({}), text: async () => "", headers: { get: () => null } } as any;
  }) as typeof fetch;
  const findings = Array.from({ length: 20 }, (_, i) => makeFinding("github-token", `ghp_${i}`));
  await verifyFindings(findings, { fullText: "", fetchImpl: slowFetch }, { concurrency: 5 });
  assert.ok(peak <= 5, `expected at most 5 concurrent requests, saw ${peak}`);
  assert.strictEqual(findings.filter((f) => f.verifyStatus === "live").length, 20, "all still verified");
});

test("verifyFindings skips rules that have no verifier", async () => {
  let calls = 0;
  const countingFetch = (async () => {
    calls++;
    return { status: 200, json: async () => ({}), text: async () => "", headers: { get: () => null } } as any;
  }) as typeof fetch;
  await verifyFindings(
    [makeFinding("private-key-block", "-----BEGIN...-----")],
    { fullText: "", fetchImpl: countingFetch }
  );
  assert.strictEqual(calls, 0);
});

test("verifyFindings reuses a cache across calls", async () => {
  let calls = 0;
  const countingFetch = (async () => {
    calls++;
    return { status: 200, json: async () => ({}), text: async () => "", headers: { get: () => null } } as any;
  }) as typeof fetch;
  const cache = new VerificationCache();
  const context = { fullText: "", fetchImpl: countingFetch };
  await verifyFindings([makeFinding("github-token", "ghp_same")], context, { cache });
  await verifyFindings([makeFinding("github-token", "ghp_same")], context, { cache });
  assert.strictEqual(calls, 1, "re-scanning the same document must not re-send the secret");
});

suite("\nverify.ts — per-finding context");

test("verifyFindings resolves a fresh context for each finding", async () => {
  // The CLI scans many files in one pass, and the AWS verifier reads
  // ctx.fullText to find the secret key paired with an access key ID. One
  // shared blob would pair a key in a.ts with a secret in b.ts.
  const asked: string[] = [];
  const findings = [
    { ...makeFinding("github-token", "ghp_a"), file: "a.ts" },
    { ...makeFinding("github-token", "ghp_b"), file: "b.ts" },
  ];
  await verifyFindings(
    findings,
    (finding) => {
      asked.push(finding.file ?? "?");
      return { fullText: `contents of ${finding.file}`, fetchImpl: mockFetch({ status: 200 }) };
    },
    { concurrency: 1 }
  );
  assert.deepStrictEqual(asked, ["a.ts", "b.ts"]);
});

test("verifyFindings still accepts a single shared context", async () => {
  const findings = [makeFinding("github-token", "ghp_x")];
  await verifyFindings(findings, { fullText: "shared", fetchImpl: mockFetch({ status: 200 }) });
  assert.strictEqual(findings[0].verifyStatus, "live");
});

suite("\nverify.ts — provider names");

test("every verifiable rule can name its provider", async () => {
  // The first-run prompt asks permission to contact a named third party.
  // A rule with no name would degrade that to "the provider", which is
  // exactly the vagueness the prompt exists to avoid.
  const unnamed = VERIFIABLE_RULE_IDS.filter((id) => !verificationProvider(id));
  assert.deepStrictEqual(unnamed, [], `rules missing a provider name: ${unnamed.join(", ")}`);
});

test("a rule with no verifier has no provider name", async () => {
  assert.strictEqual(verificationProvider("private-key-block"), undefined);
});

test("provider names are the ones a user would recognise", async () => {
  assert.strictEqual(verificationProvider("github-token"), "GitHub");
  assert.strictEqual(verificationProvider("aws-access-key"), "AWS");
  assert.strictEqual(verificationProvider("huggingface-token"), "Hugging Face");
});

suite("\nverify.ts — recording outbound calls");

test("onOutbound fires once per credential that actually reaches a provider", async () => {
  // The opt-in work was entirely about outbound calls carrying someone's
  // credential, and nothing recorded that they happened.
  const sent: string[] = [];
  const findings = [makeFinding("github-token", "ghp_a"), makeFinding("slack-token", "xoxb-b")];
  await verifyFindings(
    findings,
    { fullText: "", fetchImpl: mockFetch({ status: 200, jsonBody: { ok: true } }) },
    { onOutbound: (f) => sent.push(f.ruleId) }
  );
  assert.deepStrictEqual(sent.sort(), ["github-token", "slack-token"]);
});

test("a cache hit is not an outbound call", async () => {
  // Otherwise the log would claim a credential was sent when it never left.
  const sent: string[] = [];
  const cache = new VerificationCache();
  const context = { fullText: "", fetchImpl: mockFetch({ status: 200 }) };
  const opts = { cache, onOutbound: (f: Finding) => sent.push(f.ruleId) };
  await verifyFindings([makeFinding("github-token", "ghp_same")], context, opts);
  await verifyFindings([makeFinding("github-token", "ghp_same")], context, opts);
  assert.deepStrictEqual(sent, ["github-token"], "the second scan sent nothing");
});

test("a rule with no verifier is never counted as outbound", async () => {
  const sent: string[] = [];
  await verifyFindings(
    [makeFinding("private-key-block", "-----BEGIN...-----")],
    { fullText: "", fetchImpl: mockFetch({ status: 200 }) },
    { onOutbound: (f) => sent.push(f.ruleId) }
  );
  assert.deepStrictEqual(sent, []);
});

suite("\nverify.ts — concurrent misses share one request");

/**
 * The TTL cache only helps once a result exists.
 *
 * Two verifies of the same credential issued before either returns are both
 * misses, so both reach the provider. Nothing was ever wrong about the count --
 * onOutbound fires twice because two requests really do leave -- but a
 * workspace scan verifies a whole scan at concurrency 5, and one credential
 * copied into five files is the ordinary case rather than the unusual one.
 *
 * A second request for a credential already in flight now awaits the first.
 */

/** A fetch that answers only when released, so overlap is deterministic. */
function gatedFetch(): { fetch: typeof fetch; calls: () => number; release: () => void } {
  let calls = 0;
  const waiters: Array<() => void> = [];
  const fetchImpl = (async () => {
    calls++;
    await new Promise<void>((resolve) => waiters.push(resolve));
    return { status: 200, json: async () => ({}), text: async () => "", headers: { get: () => null } } as any;
  }) as typeof fetch;
  return {
    fetch: fetchImpl,
    calls: () => calls,
    release: () => waiters.splice(0).forEach((w) => w()),
  };
}

test("two concurrent verifies of the same credential make one request", async () => {
  const gate = gatedFetch();
  const cache = new VerificationCache();
  const context = { fullText: "", fetchImpl: gate.fetch };
  let outbound = 0;
  const bump = () => void outbound++;

  const a = cache.verify(makeFinding("github-token", "ghp_shared"), context, bump);
  const b = cache.verify(makeFinding("github-token", "ghp_shared"), context, bump);
  // Both started before either could finish; releasing now lets them settle.
  gate.release();
  const [ra, rb] = await Promise.all([a, b]);

  assert.strictEqual(gate.calls(), 1, "the credential left this machine twice");
  assert.strictEqual(outbound, 1, "the outbound record disagrees with what was sent");
  assert.deepStrictEqual(ra, rb, "the second caller got a different answer than the first");
});

test("two concurrent verifies of different credentials make two requests", async () => {
  const gate = gatedFetch();
  const cache = new VerificationCache();
  const context = { fullText: "", fetchImpl: gate.fetch };
  let outbound = 0;
  const bump = () => void outbound++;

  const a = cache.verify(makeFinding("github-token", "ghp_one"), context, bump);
  const b = cache.verify(makeFinding("github-token", "ghp_two"), context, bump);
  gate.release();
  await Promise.all([a, b]);

  assert.strictEqual(gate.calls(), 2, "dedup collapsed two different credentials into one check");
  assert.strictEqual(outbound, 2);
});

test("a verify after the first settles still hits the TTL cache", async () => {
  const gate = gatedFetch();
  const cache = new VerificationCache();
  const context = { fullText: "", fetchImpl: gate.fetch };
  let outbound = 0;
  const bump = () => void outbound++;

  const first = cache.verify(makeFinding("github-token", "ghp_shared"), context, bump);
  gate.release();
  await first;
  await cache.verify(makeFinding("github-token", "ghp_shared"), context, bump);

  assert.strictEqual(gate.calls(), 1, "the in-flight map replaced the result cache instead of fronting it");
  assert.strictEqual(outbound, 1);
});

test("a network failure is a result, and is cached like any other", async () => {
  let calls = 0;
  const failing = (async () => {
    calls++;
    throw new Error("socket hang up");
  }) as typeof fetch;
  const cache = new VerificationCache();
  const context = { fullText: "", fetchImpl: failing };

  const first = await cache.verify(makeFinding("github-token", "ghp_flaky"), context);
  assert.strictEqual(first?.status, "unknown", "a thrown request must not read as a verdict");
  assert.strictEqual(first?.reason, "network");
  await cache.verify(makeFinding("github-token", "ghp_flaky"), context);
  assert.strictEqual(calls, 1, "unknown/network is a result and the TTL cache holds it");
});

test("a request that fails after the response still frees the key", async () => {
  // The failure mode an in-flight map introduces: a rejected promise left in
  // the map turns one transient failure into a permanent one, because every
  // later caller awaits a failure that already happened.
  //
  // Reaching it takes care. verifyFinding catches everything, so it never
  // rejects, and a test that throws inside a verifier proves nothing about
  // this map — the first version of this test did exactly that and passed with
  // the fix deliberately broken. What can still reject is the bookkeeping
  // AFTER the response: the clock the cache stamps its entry with.
  let ticks = 0;
  const cache = new VerificationCache(1000, () => {
    ticks++;
    if (ticks === 1) throw new Error("clock failed");
    return 0;
  });
  let calls = 0;
  const counting = (async () => {
    calls++;
    return { status: 200, json: async () => ({}), text: async () => "", headers: { get: () => null } } as any;
  }) as typeof fetch;
  const context = { fullText: "", fetchImpl: counting };
  const finding = makeFinding("github-token", "ghp_poison");

  let firstFailed = false;
  await cache.verify(finding, context).catch(() => (firstFailed = true));
  assert.ok(firstFailed, "the fixture did not produce a rejected request; the test would be vacuous");

  // Same key. If the map still holds the rejected promise, this rejects too and
  // the credential is never checked again for the life of the process.
  const second = await cache.verify(finding, context).catch(() => "still poisoned");
  assert.notStrictEqual(second, "still poisoned", "the key stayed occupied by a failed request");
  assert.strictEqual(calls, 2, "the retry never reached the provider");
});

finish();
