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

/**
 * The pre-rebrand filename. Still read when no `.secretloop.json` is present so
 * an existing checkout keeps its allowlists, excluded rules, and entropy
 * threshold after upgrading. A config file silently ceasing to apply is exactly
 * the failure that makes a scanner start reporting findings a team already
 * triaged away.
 */
export const LEGACY_CONFIG_FILENAME = ".secretguard.json";

export interface ResolvedConfigFile {
  path: string;
  /** True when the config was found under the pre-rebrand filename. */
  legacy: boolean;
}

/** Locates the config file, preferring the current name over the legacy one. */
export function resolveConfigFile(repoRoot: string): ResolvedConfigFile | null {
  const current = path.join(repoRoot, CONFIG_FILENAME);
  if (existsSync(current)) return { path: current, legacy: false };
  const legacy = path.join(repoRoot, LEGACY_CONFIG_FILENAME);
  if (existsSync(legacy)) return { path: legacy, legacy: true };
  return null;
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

/** Deprecation notice for a legacy config file, or null when none applies. */
export function legacyConfigNotice(repoRoot: string): string | null {
  const found = resolveConfigFile(repoRoot);
  if (!found?.legacy) return null;
  return (
    `Using ${LEGACY_CONFIG_FILENAME}, which is deprecated. ` +
    `Rename it to ${CONFIG_FILENAME} — the contents are unchanged.`
  );
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
 * Stable identity for a finding, used by the baseline file. Deliberately keyed
 * on (path, rule, value) and NOT on line number, so reformatting or inserting
 * code above an accepted finding doesn't resurrect it as "new".
 */
export function fingerprint(filePath: string, ruleId: string, value: string): string {
  const normalized = filePath.split(path.sep).join("/").replace(/^\.\//, "");
  const digest = createHash("sha256").update(value).digest("hex").slice(0, 16);
  return `${normalized}:${ruleId}:${digest}`;
}

/**
 * A baseline records findings that already exist and have been accepted, so a
 * team can adopt scanning on a repo with pre-existing findings and still fail
 * CI on anything *new*. Without this, adoption on a real codebase means either
 * a red build forever or turning the tool off.
 */
export function loadBaseline(file: string): Set<string> {
  if (!existsSync(file)) return new Set();
  const parsed = JSON.parse(readFileSync(file, "utf8"));
  const list: string[] = Array.isArray(parsed) ? parsed : (parsed.fingerprints ?? []);
  return new Set(list);
}

/** @deprecated Renamed to SecretLoopConfig in the SecretLoop rebrand. */
export type SecretGuardConfig = SecretLoopConfig;
