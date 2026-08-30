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

// ---------------------------------------------------------------------------
suite("0.1.2 (b) — source filenames and #import targets");

/**
 * Evidence: bugsnag-cocoa, 17 tree findings and 27 history findings. Every one
 * is the operand of an #import in a .m/.mm/.c file --
 * BSGEventUploader.m:11 `#import "BSGEventUploadKSCrashReportOperation.h"` --
 * so the value is a filename the compiler resolves, never a credential.
 *
 * The extension alternation is closed and anchors the end, matching the
 * existing hashed-asset-filename filter's philosophy: this stays "a name ending
 * in a known source extension", not "anything with a dot in it".
 */
test("bare source filenames are skipped, including inside a real #import line", () => {
  const headers = [
    "BSGEventUploadKSCrashReportOperation.h",
    "BSG_KSCrashSentry_CPPException.h",
    "BSGURLSessionTracingProxy.h",
    "BSGEventDiscardRuleFactory.h",
    "BugsnagClient+Private.hpp",
    "KSCrashReportConverter.mm",
    "BugsnagConfiguration.swift",
  ];
  for (const h of headers) assert.ok(skipped(h), `source filename still fired: ${h}`);
  // The real polyglot shape, not just the bare value.
  const objc = headers.map((h) => `#import "${h}"`).join("\n");
  assert.strictEqual(
    findHighEntropyStrings(objc, THRESHOLD).length,
    0,
    "an ObjC #import block still produced entropy findings"
  );
});

test("(b) real credentials still report", () => assertRealSecretsStillReport("(b)"));

test("(b) extension list is closed: other extensions still report", () => {
  // The filter is named for source files. A high-entropy value ending .exe or
  // .sql is not one, and the existing asset filter makes the same promise.
  for (const ext of ["exe", "sql", "pem", "key"]) {
    const v = gen(36, alnum, 11) + "." + ext;
    assert.ok(!skipped(v), `a value ending .${ext} was skipped as a source file`);
  }
});

test("(b) does not skip a padded base64 value that happens to end in .c", () => {
  // The stem class is [\w+-], which excludes = and /. A base64 blob carrying
  // either cannot reach the extension alternation by accident.
  //
  // A *slash-bearing* value ending .c is deliberately not asserted here. It is
  // already skipped, by 0.1.1's relative-path arm rather than by anything in
  // this commit -- "segment/segment.ext" is precisely that arm's shape, and its
  // 0.823% cost against random keys was measured and accepted then. Asserting
  // it here would have made this test a claim about (b) that (b) does not make;
  // it failed in RED for that reason, which is how the mis-specification
  // surfaced.
  assert.ok(!skipped(gen(38, alnum + "+/", 14) + "=.c"), "a padded base64 value was skipped");
});

// ---------------------------------------------------------------------------
suite("0.1.2 (c) — absolute paths with doubled slashes or + in a segment");

/**
 * Evidence: bugsnag-cocoa Tests/BugsnagTests/report.json, 7 tree findings and
 * 84 history findings. These are dyld image paths in a crash report.
 *
 * They are NOT a new filter. 0.1.1 already skips absolute paths; these seven
 * escaped for two mechanical reasons, both visible in the values themselves:
 *
 *   Frameworks//CoreData.framework   -- a doubled slash, and the 0.1.1 segment
 *                                       class is [\w.-]+, which cannot be empty
 *   usr/lib/libc++.1.dylib           -- "+" is not in [\w.-]
 *
 * So the amendment is: let a segment be empty, and add one arm that permits +
 * provided the final segment carries an extension. Measured over 1,000,000
 * random 40-character base64 keys, the skip rate goes 0.3488% (shipped) ->
 * 0.3684% (proposed): a delta of 0.0196%. The extension requirement is what
 * keeps the + arm free -- without it the same arm cost 0.68%.
 */
test("dyld image paths with doubled slashes or + are skipped", () => {
  const prefix =
    "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneSimulator.platform" +
    "/Developer/SDKs/iPhoneSimulator.sdk";
  const paths = [
    prefix + "/System/Library/Frameworks//CoreData.framework/CoreData",
    prefix + "/System/Library/Frameworks/Accelerate.framework/Frameworks/vecLib.framework//libBLAS.dylib",
    prefix + "/System/Library/Frameworks/Accelerate.framework/Frameworks/vecLib.framework//libLAPACK.dylib",
    prefix + "/System/Library/Frameworks/Accelerate.framework/Frameworks/vecLib.framework//libLinearAlgebra.dylib",
    prefix + "/System/Library/Frameworks/OpenGLES.framework//libLLVMContainer.dylib",
    prefix + "/usr/lib/libc++.1.dylib",
    prefix + "/usr/lib/libc++abi.dylib",
  ];
  for (const p of paths) assert.ok(skipped(p), `dyld image path still fired: ${p}`);
});

test("(c) real credentials still report", () => assertRealSecretsStillReport("(c)"));

test("(c) the + arm requires an extension, so a +-bearing absolute blob still reports", () => {
  // This is the condition that keeps the arm from costing 0.68% instead of
  // 0.0196%. If someone drops the extension requirement, this fails.
  const blob = "/" + gen(20, alnum, 21) + "+" + gen(20, alnum, 22);
  assert.ok(!skipped(blob), `a +-bearing absolute value with no extension was skipped: ${blob}`);
});

test("(c) a base64 blob that merely starts with / still reports", () => {
  // Base64 contains slashes, and 1 in 64 keys opens with one. The arms are
  // segment-shaped, not "contains a slash", and this pins that.
  const b64 = "/" + gen(42, alnum + "+/", 23) + "=";
  assert.ok(!skipped(b64), `a slash-led base64 blob was skipped: ${b64}`);
});

finish();
