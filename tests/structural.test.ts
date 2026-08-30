import { test, suite, finish, assert } from "./harness";
import { findHighEntropyStrings, shannonEntropy } from "../src/entropy";
import { scanText } from "../src/scanner";

/**
 * 0.1.2 — the structural pre-filter.
 *
 * The entropy tier's false positives are not random. They are STRUCTURED text
 * that happens to score well: mangled symbols, source filenames, paths,
 * reverse-DNS identifiers, build settings, module specifiers. A real secret is
 * high-entropy AND structureless, so the shape is the discriminator.
 *
 * Every matcher here is paired. One half asserts the structured shape is
 * SKIPPED; the other asserts real credentials STILL REPORT through that same
 * filter. The pairing is mandatory: a structural skip that also hides a
 * credential is a regression worse than the noise it removes, and a skip test
 * alone cannot tell the two apart.
 *
 * Evidence is from scans of two real repositories, recorded per matcher.
 */

const THRESHOLD = 4.3;

/** Did the entropy tier decline this value? */
function skipped(value: string): boolean {
  return findHighEntropyStrings(`x = "${value}"`, THRESHOLD).length === 0;
}

const alnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
function gen(n: number, alphabet = alnum, salt = 3): string {
  let out = "";
  for (let i = 0; i < n; i++) out += alphabet[(i * 17 + salt * 7 + 5) % alphabet.length];
  return out;
}

/**
 * Credential-shaped values that must survive every filter in this file.
 *
 * Generated rather than written literally, so this file carries no credential
 * constant -- and deterministic, so a failure is reproducible rather than a
 * once-in-a-run fluke.
 */
export const REAL_SECRETS: Array<[label: string, value: string]> = [
  ["github token", "ghp_" + gen(36, alnum, 1)],
  ["aws secret key", gen(40, alnum + "+/", 2)],
  ["slack bot token", "xoxb-" + gen(12, "0123456789", 3) + "-" + gen(12, "0123456789", 4) + "-" + gen(24, alnum, 5)],
  ["random 32-byte base64", gen(43, alnum + "+/", 6) + "="],
];

/**
 * A guard on the guards. If a sample stopped clearing the entropy bar, every
 * "still reports" assertion below would pass while proving nothing -- the exact
 * failure mode the PRIMER calls a test that passes in RED.
 */
test("preflight: every real-secret sample actually clears the entropy bar", () => {
  for (const [label, value] of REAL_SECRETS) {
    const e = shannonEntropy(value);
    assert.ok(
      e >= THRESHOLD,
      `${label} scores ${e.toFixed(2)}, below ${THRESHOLD}; it cannot prove a filter lets secrets through`
    );
    assert.ok(!skipped(value), `${label} is already skipped before any 0.1.2 matcher was added`);
  }
});

/** The paired half every matcher suite runs. */
function assertRealSecretsStillReport(matcher: string): void {
  for (const [label, value] of REAL_SECRETS) {
    assert.ok(!skipped(value), `${matcher} swallowed a ${label}`);
  }
}

// ---------------------------------------------------------------------------
suite("0.1.2 (a) — C++/ObjC mangled symbols");

/**
 * Evidence: bugsnag-cocoa. 80 of 132 tree-scan entropy findings and 22 of its
 * history findings are Itanium ABI mangled names, out of
 * report-react-native-promise-rejection.json and android_native_crash.json --
 * crash reports, where a symbol table is the whole point of the file. One value
 * alone hit 10 locations.
 */
test("Itanium mangled symbols are skipped", () => {
  const mangled = [
    "_ZN3WTF6Thread10entryPointEPNS0_16NewThreadContextE",
    "_ZNSt3__114__thread_proxyINS_5tupleIJNS_10unique_ptrINS_15__thread_structENS_14default_deleteIS3_EEEEEEEEEPvSP_",
    "_ZN12_GLOBAL__N_116EventBaseBackend18eb_event_base_loopEi",
    "_ZN3art11interpreterL7ExecuteEPNS_6ThreadERKNS_20CodeItemDataAccessorE",
    "___ZN8facebook5react15RCTNativeModule6invokeEjON5folly7dynamicEi_block_invoke",
    "_ZL21__cxx_global_var_initv",
    "_ZTVN10__cxxabiv117__class_type_infoE",
    "_ZSt9terminatev",
  ];
  for (const m of mangled) assert.ok(skipped(m), `mangled symbol still fired: ${m}`);
});

test("(a) real credentials still report", () => assertRealSecretsStillReport("(a)"));

test("(a) is anchored: a credential that merely contains _Z still reports", () => {
  // The grammar is a prefix, not a substring. A key with _Z in the middle is
  // not a mangled name and must not be treated as one.
  const embedded = gen(20, alnum, 7) + "_ZN" + gen(20, alnum, 8);
  assert.ok(!skipped(embedded), "a value containing _ZN was skipped as if mangled");
});

// ---------------------------------------------------------------------------
suite("0.1.2 (a2) — leading-underscore C/ObjC symbols");

/**
 * Evidence: bugsnag-cocoa, 6 tree findings and 4 history findings that are not
 * Itanium-mangled at all -- plain C symbols out of the same crash reports.
 *
 * Deliberately narrow: a leading underscore AND letters/underscores only. No
 * digits, no +, no /, no =. A generated credential essentially never has that
 * shape, and the measurement below is the proof rather than the claim.
 */
test("leading-underscore C/ObjC symbols are skipped", () => {
  for (const s of [
    "_BlockUntilNextEventMatchingListInModeWithFilter",
    "_cleanUpAfterCAFlushAndRunDeferredBlocks",
    "_dispatch_client_callout",
  ]) {
    assert.ok(skipped(s), `C symbol still fired: ${s}`);
  }
});

test("(a2) real credentials still report", () => assertRealSecretsStillReport("(a2)"));

test("(a2) does not skip an underscore-led value carrying digits or base64 punctuation", () => {
  // The narrowing that makes (a2) safe, asserted rather than assumed.
  for (const v of ["_" + gen(40, alnum, 9), "_" + gen(40, alnum + "+/", 10)]) {
    assert.ok(!skipped(v), `an underscore-led credential was skipped: ${v}`);
  }
});

finish();
