import { test, suite, finish, assert } from "./harness";
import { scanText } from "../src/scanner";
import { defaultConfig } from "../src/config";
import { rules } from "../src/rules";

/**
 * 0.1.3 — new provider rules, and the misattributions they fix.
 *
 * Every format in this file was re-verified against the provider's own
 * documentation before its pattern was written, and the source is recorded
 * beside each rule. Three providers surveyed alongside these were DROPPED for
 * exactly that reason: MongoDB Atlas, Deno Deploy and Render publish no page
 * stating their credential format, and a pattern built on a third-party
 * write-up is a guess wearing a citation.
 *
 * Minimum lengths are conservative floors, not documented values, because none
 * of these providers publishes a length. A floor that is too long misses real
 * credentials, so each is set at or below the shortest plausible issued token
 * and the entropy floor carries the rest.
 */

// Deterministic, credential-shaped, generated rather than written -- so this
// file needs no CI self-scan declaration.
let seed = 20260901;
function rand(): number {
  seed ^= seed << 13;
  seed ^= seed >>> 17;
  seed ^= seed << 5;
  return Math.abs(seed) / 2 ** 31;
}
const ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const HEX = "0123456789abcdef";
function gen(n: number, alphabet = ALNUM): string {
  let out = "";
  for (let i = 0; i < n; i++) out += alphabet[Math.floor(rand() * alphabet.length)];
  return out;
}

/** Which NAMED rules report this value. The entropy pass is off so a
 *  generic-tier finding cannot stand in for a named one. */
function ruleIdsFor(text: string): string[] {
  const config = { ...defaultConfig, entropyPassEnabled: false };
  return scanText(text, { config }).map((f) => f.ruleId);
}
const describe = (id: string) => rules.find((r) => r.id === id)?.description ?? "";

// ---------------------------------------------------------------------------
suite("0.1.3 — OpenRouter keys were reported as OpenAI keys");

/**
 * The defect. `openai-api-key` is /\bsk-(?:proj|svcacct|admin)?-?[A-Za-z0-9_-]{32,}\b/,
 * and an OpenRouter key is `sk-or-...`, so every character after `sk-` falls
 * inside that class and OpenRouter keys matched OpenAI's rule.
 *
 * A wrong provider name is worse than a generic finding. The provider is what
 * selects the verifier, names the consent prompt and picks the rotation
 * deeplink, so a misattributed finding sends the user to the wrong console with
 * the wrong instructions.
 *
 * Fixed the way the same overlap was already fixed for Anthropic: an allowlist
 * entry on the broader rule, not a tiebreak. See /^sk-ant-/ in rules.ts.
 *
 * Format source: https://openrouter.ai/docs/features/provisioning-api-keys
 * shows a created key as "sk-or-v1-abc...123"; the OpenRouter blog states that
 * "OpenRouter keys start with sk-or-". The rule anchors on the documented
 * `sk-or-` rather than on `v1` from the example.
 */
const OPENROUTER_KEY = "sk-or-v1-" + gen(64, HEX);

test("an OpenRouter key reports as openrouter-api-key, not openai-api-key", () => {
  const ids = ruleIdsFor(`OPENROUTER_API_KEY = "${OPENROUTER_KEY}"`);
  assert.ok(ids.includes("openrouter-api-key"), `no openrouter rule matched: ${ids.join(",")}`);
  assert.ok(
    !ids.includes("openai-api-key"),
    "an OpenRouter key is still being attributed to OpenAI"
  );
});

test("the OpenAI rule still matches OpenAI's own key shapes", () => {
  for (const [label, v] of [
    ["project key", "sk-proj-" + gen(48)],
    ["service account key", "sk-svcacct-" + gen(48)],
    ["admin key", "sk-admin-" + gen(48)],
    ["classic key", "sk-" + gen(48)],
  ] as const) {
    const ids = ruleIdsFor(`OPENAI_API_KEY = "${v}"`);
    assert.ok(ids.includes("openai-api-key"), `openai-api-key stopped matching its ${label}`);
  }
});

test("the Anthropic carve-out that set the precedent still holds", () => {
  const ids = ruleIdsFor(`ANTHROPIC_API_KEY = "sk-ant-api03-${gen(95)}"`);
  assert.ok(ids.includes("anthropic-api-key"));
  assert.ok(!ids.includes("openai-api-key"), "sk-ant- leaked back into the OpenAI rule");
});

// ---------------------------------------------------------------------------
suite("\n0.1.3 — the Stripe rule says whose format it is");

/**
 * Clerk and WorkOS both issue secret keys as `sk_live_`/`sk_test_` -- Clerk's
 * documentation says so outright, calling the shape "common among developer
 * tools to provide a more familiar developer experience".
 *
 * There is no shape that separates them, so no rule can. What can be fixed is
 * the claim: the description now names the ambiguity instead of asserting
 * Stripe. A finding that says "Stripe" and means Clerk sends someone to rotate
 * a key in the wrong dashboard.
 */
test("stripe-secret-key's description names the providers that share the format", () => {
  const d = describe("stripe-secret-key");
  assert.ok(/clerk/i.test(d), `description does not mention Clerk: ${d}`);
  assert.ok(/workos/i.test(d), `description does not mention WorkOS: ${d}`);
});

test("the Stripe rule still matches both its own key shapes", () => {
  for (const v of ["sk_live_" + gen(32), "rk_live_" + gen(32), "sk_test_" + gen(32)]) {
    assert.ok(ruleIdsFor(`k = "${v}"`).includes("stripe-secret-key"), `stopped matching ${v.slice(0, 8)}`);
  }
});

// ---------------------------------------------------------------------------
suite("\n0.1.3 — code identifiers that must never be credentials");

/**
 * Permanent guards, not a one-time check.
 *
 * Each of these is a real identifier shape from a language or ecosystem that
 * collides with a provider prefix considered in this slice. `napi_` is the
 * Node-API prefix and appears throughout every native Node addon; `rnd_` and
 * `ddp_` are ordinary variable prefixes; `re_` is Python's regex module bound
 * to a name. Two of the four providers behind those prefixes were dropped from
 * this slice, and these stay anyway -- the next slice that adds them has to
 * pass this file first.
 */
const IDENTIFIER_PROBES: Array<[label: string, code: string]> = [
  ["Node-API native addon", 'napi_status rc = napi_create_string_utf8(env, buf, len, &out);'],
  ["rnd_ variable prefix", 'const rnd_seed = 12345; let rnd_generator = makeRng(rnd_seed);'],
  ["Python re module", 'import re\nre_match = re.compile(r"^x")\nre_search_result = re_match.search(s)'],
  ["ddp_ variable prefix", 'const ddp_handler = require("./ddp"); export default ddp_handler;'],
];

for (const [label, code] of IDENTIFIER_PROBES) {
  test(`stays quiet on ${label}`, () => {
    const ids = ruleIdsFor(code);
    assert.deepStrictEqual(ids, [], `a rule fired on ordinary source: ${ids.join(",")}`);
  });
}

finish();
