import { readFileSync, existsSync } from "fs";
import * as path from "path";
import { createHash } from "crypto";
import { baseExcludePaths, generatedExcludePaths } from "./rules";

/**
 * Project-level configuration, read from `.secretloop.json` at the repo root.
 * Everything here exists to answer one question: "is this finding worth
 * interrupting a developer over?" Getting that wrong in the noisy direction is
 * how scanners get muted, so allowlisting is a first-class feature, not a flag.
 */
export interface SecretLoopConfig {
  /** Shannon entropy floor for the generic high-entropy pass. */
  entropyThreshold: number;
  /** Glob patterns (relative to repo root) that are never scanned. */
  excludePaths: string[];
  /**
   * The generated-file group, kept separate from excludePaths so
   * `--include-generated` can empty this one without touching the other.
   * Empty means the caller asked for generated files to be scanned.
   */
  generatedExcludePaths: string[];
  /**
   * Glob patterns that win over every exclusion above.
   *
   * The escape hatch for a project that genuinely keeps a credential-bearing
   * file behind one of these patterns. An explicit include is a deliberate act,
   * so it outranks a default — including the base group, which nothing else
   * can reach.
   */
  includePaths: string[];
  /** Rule IDs disabled for this project. */
  excludeRules: string[];
  /** Regex source strings; any finding whose value matches is dropped. */
  allowValues: string[];
  /** Files larger than this are skipped (generated blobs, fixtures, bundles). */
  maxFileSizeBytes: number;
  /** Disable the generic entropy pass entirely (rule matches only). */
  entropyPassEnabled: boolean;
}

export const defaultConfig: SecretLoopConfig = {
  entropyThreshold: 4.3,
  excludePaths: [...baseExcludePaths],
  generatedExcludePaths: [...generatedExcludePaths],
  includePaths: [],
  excludeRules: [],
  allowValues: [],
  maxFileSizeBytes: 1_000_000,
  entropyPassEnabled: true,
};

export const CONFIG_FILENAME = ".secretloop.json";

export interface ResolvedConfigFile {
  path: string;
}

/** Locates the project's config file, if it has one. */
export function resolveConfigFile(repoRoot: string): ResolvedConfigFile | null {
  const current = path.join(repoRoot, CONFIG_FILENAME);
  return existsSync(current) ? { path: current } : null;
}

export function loadConfig(repoRoot: string): SecretLoopConfig {
  const found = resolveConfigFile(repoRoot);
  if (!found) return { ...defaultConfig };
  const name = path.basename(found.path);

  let raw: Partial<SecretLoopConfig>;
  try {
    raw = JSON.parse(readFileSync(found.path, "utf8")) as Partial<SecretLoopConfig>;
  } catch (err) {
    throw new Error(`Could not parse ${name}: ${(err as Error).message}`);
  }

  // Separated from the parse above so the message fits the fault. A file that
  // is valid JSON and asks for something impossible is not a parse failure, and
  // saying "could not parse" sends someone hunting for a syntax error that is
  // not there.
  try {
    return mergeConfig(raw);
  } catch (err) {
    throw new Error(`${name}: ${(err as Error).message}`);
  }
}


export function mergeConfig(raw: Partial<SecretLoopConfig>): SecretLoopConfig {
  return {
    entropyThreshold: raw.entropyThreshold ?? defaultConfig.entropyThreshold,
    // User excludes ADD to the built-in generated/vendored list rather than
    // replacing it — nobody wants to re-list node_modules to add one path.
    excludePaths: [...defaultConfig.excludePaths, ...(raw.excludePaths ?? [])],
    // Not user-extensible: this group exists so one flag can switch it off, and
    // a user pattern mixed into it would be switched off with it.
    generatedExcludePaths: [...defaultConfig.generatedExcludePaths],
    includePaths: raw.includePaths ?? [],
    excludeRules: raw.excludeRules ?? [],
    allowValues: checkAllowValues(raw.allowValues ?? []),
    maxFileSizeBytes: raw.maxFileSizeBytes ?? defaultConfig.maxFileSizeBytes,
    entropyPassEnabled: raw.entropyPassEnabled ?? defaultConfig.entropyPassEnabled,
  };
}

/**
 * Rejects an allowValues pattern that is not a usable regular expression.
 *
 * Checked once here rather than wherever it is used. scanText compiles all of
 * them with `new RegExp` on every single scan, and the editor scans a document
 * on open and after every 400ms of typing — so one bad pattern in a project
 * config was a throw per keystroke from inside an event handler: an unhandled
 * rejection, no diagnostics, and nothing on screen to say why. The CLI failed
 * on it too, with a message that named neither the file nor the field.
 *
 * Throwing is right where returning a filtered list is not. Silently dropping a
 * pattern would widen what gets reported, and an allowlist that quietly stops
 * allowing is how a scanner earns a reputation for noise.
 */
function checkAllowValues(patterns: string[]): string[] {
  for (const pattern of patterns) {
    try {
      new RegExp(pattern);
    } catch (err) {
      throw new Error(
        `allowValues entry ${JSON.stringify(pattern)} is not a valid regular expression: ` +
          `${(err as Error).message}`
      );
    }
  }
  return patterns;
}

/**
 * Minimal glob matcher covering the subset that actually appears in ignore
 * files: `**` (any path segments), `*` (any chars but `/`), and `?`.
 * Avoids pulling a dependency into a security tool people have to audit.
 */
export function globToRegExp(glob: string): RegExp {
  let out = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === "*") {
      if (glob[i + 1] === "*") {
        // `**/` should also match zero segments, so `**/foo` matches `foo`.
        if (glob[i + 2] === "/") {
          out += "(?:.*/)?";
          i += 2;
        } else {
          out += ".*";
          i += 1;
        }
      } else {
        out += "[^/]*";
      }
    } else if (c === "?") {
      out += "[^/]";
    } else if ("\\^$.|+()[]{}".includes(c)) {
      out += "\\" + c;
    } else {
      out += c;
    }
  }
  return new RegExp(`^${out}$`);
}

/**
 * Why a path was skipped, or that it was not.
 *
 * Three states rather than a boolean because the report has to say how many
 * files the *generated* group cost, and a boolean cannot tell that from the
 * node_modules that were already being skipped before this release. Reporting
 * "12 generated files excluded" when eleven of them were node_modules would be
 * the same class of overstatement as calling a 403 a revocation.
 */
export type ExclusionReason = "none" | "excluded" | "generated";

export function classifyPath(relPath: string, config: SecretLoopConfig): ExclusionReason {
  const normalized = relPath.split(path.sep).join("/").replace(/^\.\//, "");
  const matches = (globs: string[]) => globs.some((g) => globToRegExp(g).test(normalized));

  // An explicit include outranks every exclusion, default or otherwise.
  if (matches(config.includePaths)) return "none";
  // Base first, so a file both groups match is attributed to the group that was
  // already skipping it. Otherwise `out/results.sarif` would be counted as a
  // generated-file skip that this release caused, which it did not.
  if (matches(config.excludePaths)) return "excluded";
  if (matches(config.generatedExcludePaths)) return "generated";
  return "none";
}

export function isPathExcluded(relPath: string, config: SecretLoopConfig): boolean {
  return classifyPath(relPath, config) !== "none";
}

/**
 * How a finding's baseline identity is derived.
 *
 * `value` hashes the captured secret. That is fine for a provider-generated
 * token — brute-forcing one means searching the token space — but not for a
 * human-chosen password, where a truncated hash in a committed file is a
 * wordlist away from the plaintext.
 *
 * `context` hashes secret-free structure instead, so the password never enters
 * the fingerprint in any form.
 */
export type FingerprintStrategy = "value" | "context";

export interface FingerprintInput {
  filePath: string;
  ruleId: string;
  strategy: FingerprintStrategy;
  /** The captured secret. Used only by the `value` strategy. */
  value: string;
  /** Secret-free context. Required by `context`, and never contains a secret. */
  context?: string;
}

/** Baseline schema version. Bumped to 2 because fingerprint semantics changed. */
export const BASELINE_VERSION = 2;

function normalizePath(filePath: string): string {
  return filePath.split(path.sep).join("/").replace(/^\.\//, "");
}

function digest(input: string): string {
  return createHash("sha256").update(input).digest("hex").slice(0, 16);
}

/**
 * Stable identity for a finding, used by the baseline file. Keyed on
 * (path, rule, value) and NOT on line number, so reformatting or inserting code
 * above an accepted finding doesn't resurrect it as "new".
 */
export function fingerprint(filePath: string, ruleId: string, value: string): string {
  return `${normalizePath(filePath)}:${ruleId}:${digest(value)}`;
}

/**
 * Same shape and same truncation as the value strategy, over secret-free input.
 *
 * No KDF, salt or per-scan randomness: the password is absent from the input
 * entirely, so there is nothing to slow an attacker down against — and a
 * per-finding KDF would be paid on the extension's scan-on-keystroke path to
 * protect four rules.
 */
export function createContextFingerprint(
  filePath: string,
  ruleId: string,
  context: string
): string {
  return `${normalizePath(filePath)}:${ruleId}:${digest(context)}`;
}

/** The single entry point; strategy is a property of the finding. */
export function createFingerprint(input: FingerprintInput): string {
  switch (input.strategy) {
    case "context":
      return createContextFingerprint(input.filePath, input.ruleId, input.context ?? "");
    case "value":
    default:
      return fingerprint(input.filePath, input.ruleId, input.value);
  }
}

/**
 * A baseline records findings that already exist and have been accepted, so a
 * team can adopt scanning on a repo with pre-existing findings and still fail
 * CI on anything *new*. Without this, adoption on a real codebase means either
 * a red build forever or turning the tool off.
 */
export interface LoadedBaseline {
  fingerprints: Set<string>;
  /** Declared schema version. 1 for the pre-v2 format, and 1 for a bare array. */
  version: number;
  /** True when the file predates the current fingerprint semantics. */
  outdated: boolean;
  /** Set when outdated: what happened and what to do, for the caller to surface. */
  notice?: string;
}

export function loadBaseline(file: string): LoadedBaseline {
  if (!existsSync(file)) {
    return { fingerprints: new Set(), version: BASELINE_VERSION, outdated: false };
  }
  // Named like loadConfig's, so a corrupt baseline says which file and why
  // instead of surfacing a bare token error from somewhere in the call stack.
  let parsed: any;
  try {
    parsed = JSON.parse(readFileSync(file, "utf8"));
  } catch (err) {
    throw new Error(`Could not parse ${path.basename(file)}: ${(err as Error).message}`);
  }
  const list: string[] = Array.isArray(parsed) ? parsed : (parsed.fingerprints ?? []);
  const version: number = Array.isArray(parsed) ? 1 : (parsed.version ?? 1);

  if (version >= BASELINE_VERSION) {
    return { fingerprints: new Set(list), version, outdated: false };
  }

  // A v1 fingerprint hashed the captured value; a v2 one hashes secret-free
  // context for password-bearing rules. Loading v1 entries as if they were v2
  // would match nothing and resurface every triaged finding with no
  // explanation — so the entries are kept (harmlessly non-matching) and the
  // caller is told plainly. Loudly, but not fatally: refusing to scan would
  // block CI on a format migration, which is worse than a noisy run.
  return {
    fingerprints: new Set(list),
    version,
    outdated: true,
    notice:
      `${path.basename(file)} is a version ${version} baseline and this is version ` +
      `${BASELINE_VERSION}. Password fingerprints no longer hash the password, so the old ` +
      `entries cannot match and every finding will be reported again. Regenerate it with ` +
      `--write-baseline once you have reviewed them.`,
  };
}
