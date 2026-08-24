import { readFileSync, existsSync } from "fs";
import * as path from "path";
import { createHash } from "crypto";
import { defaultExcludePaths } from "./rules";

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
  excludePaths: [...defaultExcludePaths],
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
  try {
    const raw = JSON.parse(readFileSync(found.path, "utf8")) as Partial<SecretLoopConfig>;
    return mergeConfig(raw);
  } catch (err) {
    throw new Error(`Could not parse ${path.basename(found.path)}: ${(err as Error).message}`);
  }
}


export function mergeConfig(raw: Partial<SecretLoopConfig>): SecretLoopConfig {
  return {
    entropyThreshold: raw.entropyThreshold ?? defaultConfig.entropyThreshold,
    // User excludes ADD to the built-in generated/vendored list rather than
    // replacing it — nobody wants to re-list node_modules to add one path.
    excludePaths: [...defaultConfig.excludePaths, ...(raw.excludePaths ?? [])],
    excludeRules: raw.excludeRules ?? [],
    allowValues: raw.allowValues ?? [],
    maxFileSizeBytes: raw.maxFileSizeBytes ?? defaultConfig.maxFileSizeBytes,
    entropyPassEnabled: raw.entropyPassEnabled ?? defaultConfig.entropyPassEnabled,
  };
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

export function isPathExcluded(relPath: string, config: SecretLoopConfig): boolean {
  const normalized = relPath.split(path.sep).join("/").replace(/^\.\//, "");
  return config.excludePaths.some((g) => globToRegExp(g).test(normalized));
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
  const parsed = JSON.parse(readFileSync(file, "utf8"));
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
