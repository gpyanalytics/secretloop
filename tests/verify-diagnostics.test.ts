/**
 * The ten acceptance tests specified in verifier-403-review-a §5.
 *
 * Every fixture models a response the provider's own documentation describes, retrieved
 * 2026-09-10 and quoted in that review. No HTTP status is borrowed from one provider and
 * replayed against another: GitHub's documented statuses for `GET /user` are 200, 304, 401
 * and 403, while Slack's `auth.test` answers HTTP 200 carrying `ok` in the body and uses
 * HTTP 429 with `Retry-After` for rate limiting.
 *
 * Each test asserts the outcome, the reason AND the actionable remedy, because the defect
 * these cover was never a wrong status — it was a correct status carrying the wrong advice.
 * Request counts are asserted so a correction cannot smuggle in a retry or a second call.
 *
 * No real credential and no live provider call. Every value below is a synthetic shape.
 */
import { verifyFinding } from "../src/verify";
import { Finding } from "../src/scanner";
import * as assert from "node:assert";
import { test, suite, finish } from "./harness";
import { readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * What a stubbed response looks like here. Deliberately NOT `Partial<Response>`: the DOM
 * types make `headers` a `Headers` and `body` a stream, which is the wrong shape for
 * declaring a fixture and would push every case through a cast.
 */
type StubShape = {
  status?: number;
  headers?: Record<string, string>;
  body?: unknown;
  text?: string;
  /** Model a response whose body is not JSON, which is what Slack's 429 sends. */
  jsonThrows?: boolean;
};

/**
 * A counting stub. `calls` is asserted so no correction may add a request, and `jsonCalls`
 * is asserted so "handled the status first" cannot be faked by a handler that parses the
 * body and swallows the exception. A throwing json() alone would not prove the order:
 * counting the calls does.
 */
function stub(build: () => StubShape) {
  const state = { calls: 0, jsonCalls: 0 };
  const impl = (async () => {
    state.calls++;
    const r = build();
    return {
      status: r.status ?? 200,
      json: async () => {
        state.jsonCalls++;
        if (r.jsonThrows) throw new SyntaxError("Unexpected token < in JSON at position 0");
        return r.body;
      },
      text: async () => r.text ?? "",
      headers: { get: (k: string) => r.headers?.[k.toLowerCase()] ?? null },
    } as unknown as Response;
  }) as unknown as typeof fetch;
  return { impl, state };
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
  } as unknown as Finding;
}

const GH = "ghp_fake";
const SL = "xoxb-fake";

async function run(ruleId: string, value: string, s: ReturnType<typeof stub>) {
  return verifyFinding(makeFinding(ruleId, value), { fullText: "", fetchImpl: s.impl } as any);
}

suite("verify.ts — GitHub and Slack failure diagnostics");

// -------------------------------------------------------------------- test 1
test("GitHub 403 carrying x-ratelimit-remaining: 0 is a rate limit, not a refusal", async () => {
  const s = stub(() => ({ status: 403, headers: { "x-ratelimit-remaining": "0", "x-ratelimit-reset": "1789000000" } }));
  const r: any = await run("github-token", GH, s);
  assert.strictEqual(r.status, "unknown");
  assert.strictEqual(r.reason, "provider-unavailable", "a documented primary rate limit is not a refusal");
  assert.match(r.detail, /x-ratelimit-reset/, "the remedy must name the header that says when to retry");
  assert.doesNotMatch(r.detail, /check this credential directly/, "rate limiting must not send the reader to inspect the credential");
  assert.strictEqual(s.state.calls, 1, "exactly one request");
});

// -------------------------------------------------------------------- test 2
test("GitHub 403 carrying retry-after is a secondary rate limit, not a refusal", async () => {
  const s = stub(() => ({ status: 403, headers: { "retry-after": "60" } }));
  const r: any = await run("github-token", GH, s);
  assert.strictEqual(r.status, "unknown");
  assert.strictEqual(r.reason, "provider-unavailable");
  assert.match(r.detail, /60/, "the remedy must name the wait the provider asked for");
  assert.match(r.detail, /retry-after/i);
  assert.strictEqual(s.state.calls, 1);
});

// -------------------------------------------------------------------- test 3
test("GitHub 403 with no rate-limit evidence keeps the refusal wording byte for byte", async () => {
  const s = stub(() => ({ status: 403, headers: {} }));
  const r: any = await run("github-token", GH, s);
  assert.strictEqual(r.status, "unknown");
  assert.strictEqual(r.reason, "provider-refused");
  assert.strictEqual(
    r.detail,
    "GitHub refused the check (403), which it returns for a revoked credential and for a " +
      "live one lacking permission alike. Liveness could not be determined — check this " +
      "credential directly."
  );
  assert.strictEqual(s.state.calls, 1);
});

// -------------------------------------------------------------------- test 4
test("GitHub live and dead classifications are unchanged", async () => {
  const ok = stub(() => ({ status: 200, headers: { "x-oauth-scopes": "repo, read:org" } }));
  const a: any = await run("github-token", GH, ok);
  assert.strictEqual(a.status, "live");
  assert.match(a.detail, /Scopes: repo, read:org/);
  assert.strictEqual(ok.state.calls, 1);

  const no = stub(() => ({ status: 401 }));
  const b: any = await run("github-token", GH, no);
  assert.strictEqual(b.status, "dead");
  assert.strictEqual(b.detail, "GitHub token is invalid or already revoked.");
  assert.strictEqual(no.state.calls, 1);
});

// -------------------------------------------------------------------- test 5
test("Slack: every documented revoked error still reads dead, unchanged", async () => {
  for (const error of ["invalid_auth", "account_inactive", "token_revoked", "token_expired", "not_authed"]) {
    const s = stub(() => ({ status: 200, body: { ok: false, error } }));
    const r: any = await run("slack-token", SL, s);
    assert.strictEqual(r.status, "dead", `${error} must remain dead`);
    assert.strictEqual(r.detail, `Slack reports token invalid: ${error}.`);
    assert.strictEqual(s.state.calls, 1);
  }
});

// -------------------------------------------------------------------- test 6
test("Slack: documented non-transient refusals are refusals, not transient failures", async () => {
  for (const error of ["access_denied", "accesslimited", "ekm_access_denied", "enterprise_is_restricted"]) {
    const s = stub(() => ({ status: 200, body: { ok: false, error } }));
    const r: any = await run("slack-token", SL, s);
    assert.strictEqual(r.status, "unknown", `${error} says nothing about liveness`);
    assert.strictEqual(r.reason, "provider-refused", `${error} is documented as non-transient`);
    assert.doesNotMatch(r.detail, /retry later/i, `${error} will not be fixed by retrying`);
    assert.match(r.detail, new RegExp(error));
    assert.strictEqual(s.state.calls, 1);
  }
});

// -------------------------------------------------------------------- test 7
test("Slack: documented transient errors keep provider-unavailable and retry-later", async () => {
  for (const error of ["internal_error", "fatal_error", "ratelimited", "service_unavailable"]) {
    const s = stub(() => ({ status: 200, body: { ok: false, error } }));
    const r: any = await run("slack-token", SL, s);
    assert.strictEqual(r.status, "unknown");
    assert.strictEqual(r.reason, "provider-unavailable", `${error} is transient`);
    assert.match(r.detail, /retry later/i);
    assert.strictEqual(s.state.calls, 1);
  }
});

// -------------------------------------------------------------------- test 8
test("Slack HTTP 429 is handled before the body is touched: json() is never called", async () => {
  const s = stub(() => ({ status: 429, headers: { "retry-after": "30" }, jsonThrows: true }));
  const r: any = await run("slack-token", SL, s);
  // The load-bearing assertion. Slack documents a 429 with Retry-After and no JSON payload,
  // so the status has to be read first. A handler that parsed anyway and swallowed the
  // throw would still produce the right answer here, and would still be wrong -- it would
  // break the moment the body were absent rather than malformed. Counting catches that.
  assert.strictEqual(s.state.jsonCalls, 0, "the 429 must be handled without parsing the body at all");
  assert.strictEqual(r.status, "unknown");
  assert.strictEqual(r.reason, "provider-unavailable");
  assert.notStrictEqual(r.reason, "network");
  assert.doesNotMatch(r.detail, /before reaching the provider/i, "the provider answered; it was reached");
  assert.match(r.detail, /30/, "the remedy must name the wait Slack asked for");
  assert.strictEqual(s.state.calls, 1, "exactly one request, so no retry was added");
});

test("no changed path introduces a retry, a sleep or a second request", async () => {
  // Request counts above already rule out a retry. This rules out a delay, structurally
  // rather than by timing, which would be flaky: the two verifier bodies and the two
  // helpers this pass added must contain no timer of their own. The shared request timeout
  // in requestInit is untouched and is not part of these bodies.
  const src = readFileSync(join(__dirname, "..", "src", "verify.ts"), "utf8");
  const bodies = ["async function verifySlackToken", "async function verifyGitHubToken",
                  "function gitHubRateLimited", "function retryAfterSeconds"];
  for (const marker of bodies) {
    const start = src.indexOf(marker);
    assert.ok(start >= 0, `${marker} not found`);
    const body = src.slice(start, src.indexOf("\n}", start));
    for (const banned of ["setTimeout", "setInterval", "sleep(", "delay(", "await new Promise"]) {
      assert.ok(!body.includes(banned), `${marker} must not contain ${banned}`);
    }
  }
});

test("an unexpected Slack HTTP 403 falls back safely — NOT a documented invalid credential", async () => {
  // Slack does not document HTTP 403 for auth.test; its Web API answers 200 and carries the
  // outcome in `ok`. This case exists only to pin robust behaviour for a response the
  // documentation does not describe. It is deliberately NOT asserted to mean the credential
  // is invalid, which is exactly the mistake the earlier experimental fixture made.
  const s = stub(() => ({ status: 403, body: {} }));
  const r: any = await run("slack-token", SL, s);
  assert.strictEqual(r.status, "unknown", "an undocumented response is never a verdict");
  assert.strictEqual(r.reason, "provider-unavailable");
  assert.notStrictEqual(r.status, "dead", "403 must not be read as an invalid Slack credential");
  assert.strictEqual(s.state.calls, 1);
});

// -------------------------------------------------------------------- test 8b
test("Slack: an unrecognised response body still falls back to an indeterminate answer", async () => {
  const s = stub(() => ({ status: 200, body: { ok: false, error: "some_future_error" } }));
  const r: any = await run("slack-token", SL, s);
  assert.strictEqual(r.status, "unknown");
  assert.strictEqual(r.reason, "provider-unavailable");
  assert.strictEqual(s.state.calls, 1);

  const bad = stub(() => ({ status: 200, jsonThrows: true }));
  const q: any = await run("slack-token", SL, bad);
  assert.strictEqual(q.status, "unknown");
  assert.strictEqual(q.reason, "provider-unavailable", "an unparseable 200 is still a provider answer");
  assert.doesNotMatch(q.detail, /before reaching the provider/i);
  assert.strictEqual(bad.state.calls, 1);
});

// -------------------------------------------------------------------- test 9
test("a genuine transport failure still reads network for both providers", async () => {
  for (const rule of ["github-token", "slack-token"]) {
    let calls = 0;
    const impl = (async () => {
      calls++;
      throw new Error("getaddrinfo ENOTFOUND api.invalid");
    }) as unknown as typeof fetch;
    const r: any = await verifyFinding(makeFinding(rule, rule === "github-token" ? GH : SL), {
      fullText: "",
      fetchImpl: impl,
    } as any);
    assert.strictEqual(r.status, "unknown");
    assert.strictEqual(r.reason, "network", `${rule}: a request that never arrived is a network failure`);
    assert.match(r.detail, /before reaching the provider/i);
    assert.strictEqual(calls, 1);
  }
});

// ------------------------------------------------------------------- test 10
test("the validity mapping is pinned separately: no diagnostic change moves live or dead", async () => {
  const cases: Array<[string, () => StubShape, "live" | "dead"]> = [
    ["github-token", () => ({ status: 200, headers: { "x-oauth-scopes": "repo" } }), "live"],
    ["github-token", () => ({ status: 200, headers: {} }), "live"],
    ["github-token", () => ({ status: 401 }), "dead"],
    ["slack-token", () => ({ status: 200, body: { ok: true, team: "T" } }), "live"],
    ["slack-token", () => ({ status: 200, body: { ok: false, error: "invalid_auth" } }), "dead"],
    ["slack-token", () => ({ status: 200, body: { ok: false, error: "token_revoked" } }), "dead"],
  ];
  for (const [rule, build, want] of cases) {
    const s = stub(build);
    const r: any = await run(rule, rule === "github-token" ? GH : SL, s);
    assert.strictEqual(r.status, want, `${rule} ${want} classification must not move`);
    assert.strictEqual(s.state.calls, 1);
  }
  // And nothing that is merely indeterminate may be promoted into a verdict.
  const indeterminate: Array<() => StubShape> = [
    () => ({ status: 403, headers: { "x-ratelimit-remaining": "0" } }),
    () => ({ status: 403, headers: {} }),
    () => ({ status: 429, headers: { "retry-after": "1" }, jsonThrows: true }),
  ];
  for (const build of indeterminate) {
    for (const rule of ["github-token", "slack-token"]) {
      const s = stub(build);
      const r: any = await run(rule, rule === "github-token" ? GH : SL, s);
      assert.strictEqual(r.status, "unknown", "an indeterminate answer is never live or dead");
    }
  }
});


// ---------------------------------------------------------------- test 14
/**
 * Hostile provider responses, driven through the same injected fetch as every test
 * above. These close a REGRESSION-COVERAGE gap found by the RELEASING.md section 5
 * re-review at 53b5750: the sanitiser was correct, but the suite only ever fed it a
 * well-formed code, which it echoes. The replacement branch had no test, so a future
 * change could have widened it without anything failing.
 *
 * Representative and boundary cases are selected from the 49-check review probe rather
 * than transcribed wholesale: one case per hostile shape, plus the two length boundaries
 * that decide which branch runs.
 *
 * No production code is exported or changed to observe this. Every assertion reads the
 * public result of verifyFinding.
 */
const ESC = String.fromCharCode(27);
const NUL = String.fromCharCode(0);

/** True if any character is a C0 control or DEL, which must never reach a rendered line. */
function hasControlByte(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 32 || c === 127) return true;
  }
  return false;
}

test("a hostile Slack error code is replaced, never echoed", async () => {
  const hostile: Array<[string, string]> = [
    ["markup", "<script>alert(1)</script>"],
    ["newline injection", "invalid_auth" + String.fromCharCode(10) + "SecretLoop: this credential is SAFE"],
    ["ansi escape", ESC + "[31mDANGER" + ESC + "[0m"],
    ["nul byte", "invalid" + NUL + "auth"],
    ["uppercase and punctuation", "Access-Denied! (contact admin)"],
    ["angle brackets", "</untrusted>"],
    ["over-length boundary: 41 characters", "a".repeat(41)],
  ];
  for (const [label, code] of hostile) {
    const s = stub(() => ({ status: 200, body: { ok: false, error: code } }));
    const r: any = await run("slack-token", SL, s);
    assert.ok(!r.detail.includes(code), `${label}: the response text was echoed`);
    assert.match(r.detail, /unrecognised/, `${label}: no replacement token in the message`);
    assert.strictEqual(r.status, "unknown", `${label}: must stay indeterminate`);
    assert.strictEqual(r.reason, "provider-unavailable", `${label}: unrecognised is not a verdict`);
    assert.ok(!hasControlByte(r.detail), `${label}: a control byte reached the message`);
    assert.strictEqual(s.state.calls, 1, `${label}: exactly one request`);
  }
});

// ---------------------------------------------------------------- test 15
test("the replacement is not over-broad: a documented-shape code is still echoed", async () => {
  // The accept side of the same boundary. 40 characters is the longest code the
  // sanitiser admits; 41 is rejected by the case above. Both sides are asserted so a
  // future widening OR narrowing of the bound fails here.
  for (const code of ["some_future_error", "a".repeat(40), "ratelimited", "x"]) {
    const s = stub(() => ({ status: 200, body: { ok: false, error: code } }));
    const r: any = await run("slack-token", SL, s);
    assert.ok(r.detail.includes(code), `a documented-shape code (${code.length} chars) was not echoed`);
    assert.strictEqual(r.status, "unknown");
    assert.strictEqual(s.state.calls, 1);
  }
});

// ---------------------------------------------------------------- test 16
test("a hostile retry-after is never echoed, and a documented one still is", async () => {
  const hostile: Array<[string, string]> = [
    ["markup", "<b>99</b>"],
    ["http-date form", "Wed, 21 Oct 2026 07:28:00 GMT"],
    ["sentence", "60 seconds please"],
    ["negative", "-5"],
    ["over-length boundary: 8 digits", "9".repeat(8)],
  ];
  for (const [label, raw] of hostile) {
    const s = stub(() => ({ status: 403, headers: { "retry-after": raw } }));
    const r: any = await run("github-token", GH, s);
    assert.ok(!r.detail.includes(raw), `${label}: the header text was echoed`);
    assert.ok(!hasControlByte(r.detail), `${label}: a control byte reached the message`);
    assert.strictEqual(s.state.calls, 1, `${label}: exactly one request`);
  }
  // The accept side: 7 digits is the longest accepted, and is reported as a wait.
  for (const good of ["30", "9".repeat(7)]) {
    const s = stub(() => ({ status: 403, headers: { "retry-after": good } }));
    const r: any = await run("github-token", GH, s);
    assert.match(r.detail, new RegExp(`retry after ${good} seconds`), "a numeric retry-after must be reported");
    assert.strictEqual(r.reason, "provider-unavailable");
    assert.strictEqual(s.state.calls, 1);
  }
});

// ---------------------------------------------------------------- test 17
test("a hostile x-ratelimit-remaining is neither echoed nor read as a rate limit", async () => {
  // Only the literal "0" means the primary limit was hit. Anything else keeps the
  // documented refusal reading, and must not appear in the message either way.
  for (const raw of ["<script>0</script>", "0 ", "00", "nil"]) {
    const s = stub(() => ({ status: 403, headers: { "x-ratelimit-remaining": raw } }));
    const r: any = await run("github-token", GH, s);
    assert.ok(!r.detail.includes(raw), `${raw}: the header text was echoed`);
    assert.strictEqual(r.reason, "provider-refused", `${raw}: must keep the refusal reading`);
    assert.strictEqual(s.state.calls, 1);
  }
});

// ---------------------------------------------------------------- test 18
test("hostile responses move no validity outcome, and leak no credential", async () => {
  // The live and dead paths are unchanged by any of the above.
  const liveStub = stub(() => ({ status: 200, headers: { "x-oauth-scopes": "repo" }, body: { login: "someone" } }));
  const live: any = await run("github-token", GH, liveStub);
  assert.strictEqual(live.status, "live");
  const deadStub = stub(() => ({ status: 200, body: { ok: false, error: "invalid_auth" } }));
  const dead: any = await run("slack-token", SL, deadStub);
  assert.strictEqual(dead.status, "dead");

  // And no diagnostic carries the finding's value, whatever the provider said.
  //
  // A deliberately NON-credential-shaped marker. The finding is built by makeFinding, so the
  // value never has to match the rule for this to mean anything -- and planting a real token
  // shape here would make the repository's own self-scan fail on a fixture, which is the
  // mechanism in .github/secretloop.ci.json working rather than something to exempt.
  const secret = "MARKER-NEVER-IN-A-DIAGNOSTIC-000000";
  const s = stub(() => ({ status: 200, body: { ok: false, error: "<script>" + secret + "</script>" } }));
  const r: any = await run("slack-token", secret, s);
  assert.ok(!JSON.stringify(r).includes("NEVER-IN-A-DIAGNOSTIC"), "the credential reached a diagnostic");
  assert.strictEqual(s.state.calls, 1);
});

finish();
