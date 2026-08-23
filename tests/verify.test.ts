import { verifyFinding, isVerifiable, verifyFindings, VerificationCache } from "../src/verify";
import { Finding } from "../src/scanner";
import * as assert from "node:assert";

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

async function main() {
  console.log("verify.ts");

  await test("isVerifiable returns true only for supported rule ids", () => {
    return (async () => {
      assert.strictEqual(isVerifiable("github-token"), true);
      assert.strictEqual(isVerifiable("private-key-block"), false);
    })();
  });

  await test("GitHub: 200 response marks token verified with scopes", async () => {
    const finding = makeFinding("github-token", "ghp_fake");
    const result = await verifyFinding(finding, {
      fullText: "",
      fetchImpl: mockFetch({ status: 200, headers: { "x-oauth-scopes": "repo, read:org" } }),
    });
    assert.ok(result);
    assert.strictEqual(result!.verified, true);
    assert.match(result!.detail, /repo, read:org/);
  });

  await test("GitHub: 401 response marks token invalid, not verified", async () => {
    const finding = makeFinding("github-token", "ghp_fake");
    const result = await verifyFinding(finding, { fullText: "", fetchImpl: mockFetch({ status: 401 }) });
    assert.ok(result);
    assert.strictEqual(result!.verified, false);
  });

  await test("Slack: ok:true response marks token verified with team name", async () => {
    const finding = makeFinding("slack-token", "xoxb-fake");
    const result = await verifyFinding(finding, {
      fullText: "",
      fetchImpl: mockFetch({ status: 200, jsonBody: { ok: true, team: "Acme Corp" } }),
    });
    assert.ok(result);
    assert.strictEqual(result!.verified, true);
    assert.match(result!.detail, /Acme Corp/);
  });

  await test("Slack: ok:false response marks token not verified", async () => {
    const finding = makeFinding("slack-token", "xoxb-fake");
    const result = await verifyFinding(finding, {
      fullText: "",
      fetchImpl: mockFetch({ status: 200, jsonBody: { ok: false, error: "invalid_auth" } }),
    });
    assert.ok(result);
    assert.strictEqual(result!.verified, false);
    assert.match(result!.detail, /invalid_auth/);
  });

  await test("Stripe: 200 on /v1/balance means key is active", async () => {
    const finding = makeFinding("stripe-secret-key", "sk_live_fake");
    const result = await verifyFinding(finding, { fullText: "", fetchImpl: mockFetch({ status: 200 }) });
    assert.ok(result);
    assert.strictEqual(result!.verified, true);
    assert.match(result!.detail, /LIVE mode/);
  });

  await test("Stripe: test-mode key is verified but flagged as test mode", async () => {
    const finding = makeFinding("stripe-secret-key", "sk_test_fake");
    const result = await verifyFinding(finding, { fullText: "", fetchImpl: mockFetch({ status: 200 }) });
    assert.ok(result);
    assert.strictEqual(result!.verified, true);
    assert.match(result!.detail, /test mode/);
  });

  await test("Stripe: 401 means key is invalid", async () => {
    const finding = makeFinding("stripe-secret-key", "sk_live_fake");
    const result = await verifyFinding(finding, { fullText: "", fetchImpl: mockFetch({ status: 401 }) });
    assert.ok(result);
    assert.strictEqual(result!.verified, false);
  });

  await test("Google: 200 means API key is active", async () => {
    const finding = makeFinding("google-api-key", "AIzaFake");
    const result = await verifyFinding(finding, { fullText: "", fetchImpl: mockFetch({ status: 200 }) });
    assert.ok(result);
    assert.strictEqual(result!.verified, true);
  });

  await test("Google: API_KEY_INVALID body means key is not verified", async () => {
    const finding = makeFinding("google-api-key", "AIzaFake");
    const result = await verifyFinding(finding, {
      fullText: "",
      fetchImpl: mockFetch({ status: 400, textBody: '{"error": {"status": "API_KEY_INVALID"}}' }),
    });
    assert.ok(result);
    assert.strictEqual(result!.verified, false);
  });

  await test("network error during verification returns null (unknown), not false", async () => {
    const finding = makeFinding("github-token", "ghp_fake");
    const throwingFetch = (async () => {
      throw new Error("network unreachable");
    }) as unknown as typeof fetch;
    const result = await verifyFinding(finding, { fullText: "", fetchImpl: throwingFetch });
    assert.strictEqual(result, null, "network failure must not be reported as a disproven secret");
  });

  await test("unverifiable rule id returns null without calling fetch", async () => {
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

  console.log("\nverify.ts — timeouts");

  await test("every request carries an abort signal", async () => {
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

  await test("a provider that never responds aborts instead of hanging forever", async () => {
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
    assert.strictEqual(result, null, "a timed-out check is unknown, never disproven");
  });

  console.log("\nverify.ts — result cache");

  await test("the same secret is not sent to its provider twice", async () => {
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

  await test("different secrets are cached separately", async () => {
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

  await test("a cached result is re-checked once it expires", async () => {
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

  await test("the cache keys on a hash, never the secret itself", async () => {
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

  console.log("\nverify.ts — bounded concurrency");

  await test("no more than the configured number of requests are in flight", async () => {
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
    assert.strictEqual(findings.filter((f) => f.verified === true).length, 20, "all still verified");
  });

  await test("verifyFindings skips rules that have no verifier", async () => {
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

  await test("verifyFindings reuses a cache across calls", async () => {
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

  console.log(`\n${passed} passed, ${failed} failed\n`);
  if (failed > 0) process.exit(1);
}

main();
