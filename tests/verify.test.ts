import { verifyFinding, isVerifiable } from "../src/verify";
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
  return { ruleId, description: ruleId, value, startIndex: 0, endIndex: value.length, confidence: "format-match" };
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

  console.log(`\n${passed} passed, ${failed} failed\n`);
  if (failed > 0) process.exit(1);
}

main();
