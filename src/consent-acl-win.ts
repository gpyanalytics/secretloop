/**
 * Windows access checks for the consent store.
 *
 * On Windows the POSIX fields Node reports for a file — uid, gid, mode — are not
 * meaningful, so the private-store check that protects the store on macOS and Linux
 * establishes nothing there. What protects a record on Windows is its security
 * descriptor: an owner and a discretionary access control list (DACL). This module
 * reads both and decides whether the store may be trusted.
 *
 * THE ADVERSARY. One adversary class, stated so the rules below can be judged against
 * it: another ordinary local account on the same machine, one that is not SYSTEM and
 * not a member of Administrators. That account might reach the store because the
 * profile was relocated, because the store was created outside the profile, or because
 * a parent directory grants it. Nothing here defends against an administrator, against
 * SYSTEM, against a compromised Windows service, or against code already running as the
 * user — those are inside the documented trust boundary and no claim is made about them.
 *
 * TWO RULES, DELIBERATELY DIFFERENT.
 *
 *   Store objects — `.secretloop`, `.secretloop\pending`, and every record file — must
 *   be principal-clean (every access control entry allows, and names only the current
 *   user, SYSTEM or Administrators), owner-clean (owned by one of those three), must
 *   grant the current user full access through an entry that is not inherit-only, and
 *   must not be a reparse point. Nothing else may appear, at all.
 *
 *   Ancestors — every path component from the volume root down to the store's parent —
 *   are held to a rights rule instead. They must not be reparse points, their owners
 *   must be platform-or-self principals, and no principal outside that set may hold a
 *   right that lets it replace or re-permission a component: DELETE, FILE_DELETE_CHILD,
 *   WRITE_DAC, WRITE_OWNER, GENERIC_ALL or GENERIC_WRITE. The immediate parent
 *   additionally forbids create-child rights, so no other account can pre-create the
 *   store name. A principal-clean rule cannot be used above the store: a stock volume
 *   root grants Users create-file and create-folder and is owned by TrustedInstaller,
 *   so requiring principal-cleanliness there would refuse every stock installation.
 *   That was measured, not assumed (windows-consent-acl-revised-validation).
 *
 * WHY THE ANCESTORS AT ALL. A private final directory establishes nothing about the
 * path that reaches it: a private `.secretloop` inside a profile directory another
 * account may rename can be swapped wholesale without its own DACL ever changing.
 * Replacing a component needs DELETE on it or FILE_DELETE_CHILD on its parent;
 * re-permissioning one needs WRITE_DAC, or ownership, which confers it. The ancestor
 * rule denies exactly those to everyone outside the trusted set.
 *
 * WHAT THIS DOES NOT ESTABLISH.
 *   - Applying a DACL does not revoke a handle another process already holds; access is
 *     checked when a handle is opened. The trusted-parent check prevents that situation
 *     for a store this code creates — the directory is new, under a parent no other
 *     ordinary account can write, so no foreign handle to it can pre-exist — but it
 *     revokes nothing, and for a store that already existed it cannot.
 *   - For an existing store these checks describe the present. They do not establish
 *     that it was always private, nor that no handle was opened while it was not.
 *   - Inspection is by path and the operation that follows is by path; a replacement
 *     between the two is not detected. The bounded claim is that no OTHER ORDINARY
 *     ACCOUNT can perform it, because the rights that allow it are what these rules deny.
 */

import { spawnSync } from "child_process";
import { existsSync } from "fs";
import * as nodePath from "path";

/**
 * Windows path arithmetic, stated explicitly. These rules are about Windows objects, so the
 * separator, the drive root and the notion of a parent are Windows ones wherever this code is
 * evaluated. On Windows this is the same module `path` would give; naming it keeps the rules
 * testable, and correct, on any host.
 */
const path = nodePath.win32;

/** Every way a Windows access check can refuse. Closed, and each maps to a fixed sentence. */
export type WindowsAclProblem =
  | "identity-unreadable"
  | "unsupported-location"
  | "unsafe-parent"
  | "reparse-point"
  | "not-a-directory"
  | "foreign-owner"
  | "foreign-principal"
  | "deny-ace"
  | "null-dacl"
  | "empty-dacl"
  | "owner-not-granted"
  | "insufficient-rights"
  | "owner-unreadable"
  | "acl-tooling-unavailable"
  | "acl-inspection-failed"
  | "acl-inspection-malformed"
  | "acl-enforcement-failed";

export const SID_SYSTEM = "S-1-5-18";
export const SID_ADMINISTRATORS = "S-1-5-32-544";
const SID_LOCAL_SERVICE = "S-1-5-19";
const SID_NETWORK_SERVICE = "S-1-5-20";

/** Bounds on the inspection subprocess. A slow or noisy helper refuses; it never blocks forever. */
const HELPER_TIMEOUT_MS = 60_000;
const HELPER_MAX_OUTPUT = 1 << 20;
const ENFORCE_TIMEOUT_MS = 30_000;

/**
 * SDDL string-SID aliases, as the .NET SDDL form emits them. Closed on purpose: an alias
 * outside this table is reported as unknown and refused. Guessing a mapping would silently
 * widen the set of principals the rules accept.
 */
const SDDL_ALIAS: Record<string, string> = {
  BA: "S-1-5-32-544", BU: "S-1-5-32-545", BG: "S-1-5-32-546", PU: "S-1-5-32-547",
  AO: "S-1-5-32-548", SO: "S-1-5-32-549", PO: "S-1-5-32-550", BO: "S-1-5-32-551",
  RE: "S-1-5-32-552", RU: "S-1-5-32-554", RD: "S-1-5-32-555", NO: "S-1-5-32-556",
  MU: "S-1-5-32-558", LU: "S-1-5-32-559", CY: "S-1-5-32-569", ES: "S-1-5-32-573",
  SY: "S-1-5-18", LS: "S-1-5-19", NS: "S-1-5-20", WD: "S-1-1-0", AU: "S-1-5-11",
  IU: "S-1-5-4", NU: "S-1-5-2", AN: "S-1-5-7", RC: "S-1-5-12", IS: "S-1-5-17",
  CO: "S-1-3-0", CG: "S-1-3-1", OW: "S-1-3-4", AC: "S-1-15-2-1",
  LW: "S-1-16-4096", ME: "S-1-16-8192", HI: "S-1-16-12288", SI: "S-1-16-16384",
};

/**
 * Domain-relative aliases: these name a principal by its identifier within whatever domain the
 * object belongs to, so they have no fixed value. LA -- the built-in Administrator, which a stock
 * Windows profile is granted through -- is one, and its absence here is what made a real profile
 * look like an unknown principal before the decision moved to structured rules. They are
 * canonicalised to a relative form so the predicates can still recognise them in the SDDL
 * adapters; the real path never sees an alias at all.
 */
const SDDL_DOMAIN_RELATIVE: Record<string, number> = {
  LA: 500, LG: 501, CA: 517, DA: 512, DU: 513, DG: 514, DC: 516, DD: 521,
  SA: 518, EA: 519, PA: 520, RO: 498, RS: 553,
};

/** An SDDL principal as a SID. An unrecognised alias becomes a value no rule can accept. */
export function canonicalSid(raw: string): string {
  if (/^S-1-/.test(raw)) return raw;
  const mapped = SDDL_ALIAS[raw];
  if (mapped) return mapped;
  const rid = SDDL_DOMAIN_RELATIVE[raw];
  if (rid !== undefined) return `domain-relative:${rid}`;
  return `unknown-alias:${raw}`;
}

/**
 * SDDL access-rights tokens to bits. For a file or directory the generic two-letter codes
 * name bit positions: CC is 0x1 (list/read data), DC is 0x2 (add file), LC is 0x4 (add
 * subdirectory), DT is 0x40 (delete child), SD is DELETE, WD is WRITE_DAC.
 */
const RIGHT_BITS: Record<string, number> = {
  CC: 0x00000001, DC: 0x00000002, LC: 0x00000004, SW: 0x00000008, RP: 0x00000010,
  WP: 0x00000020, DT: 0x00000040, LO: 0x00000080, CR: 0x00000100,
  SD: 0x00010000, RC: 0x00020000, WDAC: 0x00040000, WO: 0x00080000,
  GA: 0x10000000, GX: 0x20000000, GW: 0x40000000, GR: 0x80000000,
  FA: 0x001f01ff, FR: 0x00120089, FW: 0x00120116, FX: 0x001200a0,
};
const FILE_ALL_ACCESS = 0x1f01ff;
/** DELETE | FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER: replace or re-permission a component. */
const NAMESPACE_BITS = 0x00010000 | 0x00000040 | 0x00040000 | 0x00080000;
/** FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY: create the store name itself. */
const CREATE_CHILD_BITS = 0x00000002 | 0x00000004;
const GENERIC_WRITEISH = 0x10000000 | 0x40000000;

export function rightsMask(text: string): { mask: number; unknown: string[] } {
  const raw = (text ?? "").trim();
  if (raw.length === 0) return { mask: 0, unknown: [] };
  if (/^0x[0-9a-f]+$/i.test(raw)) {
    const value = Number.parseInt(raw, 16);
    return Number.isFinite(value) ? { mask: value, unknown: [] } : { mask: 0, unknown: [raw] };
  }
  let mask = 0;
  const unknown: string[] = [];
  // WDAC is four characters and must be consumed before the two-character tokens.
  let rest = raw.toUpperCase().replace(/WDAC/g, () => {
    mask |= RIGHT_BITS.WDAC;
    return "";
  });
  while (rest.length > 0) {
    const token = rest.slice(0, 2);
    rest = rest.slice(2);
    if (token === "WD") {
      mask |= RIGHT_BITS.WDAC; // in SDDL, WD is WRITE_DAC
      continue;
    }
    const bits = RIGHT_BITS[token];
    if (bits === undefined) unknown.push(token);
    else mask |= bits;
  }
  return { mask, unknown };
}

export interface Ace {
  type: string;
  flags: string;
  rightsText: string;
  mask: number;
  unknownRights: string[];
  sid: string;
  inheritOnly: boolean;
}
export interface Dacl {
  /** A NULL DACL: documented to grant full access to every caller. Never acceptable. */
  nullDacl?: boolean;
  flags?: string;
  aces?: Ace[];
}

/**
 * Parses the DACL portion of an SDDL string.
 *
 * Three outcomes, deliberately distinct: a NULL DACL (the `D:NO_ACCESS_CONTROL` spelling,
 * or a descriptor that carries other components and no `D:` at all) grants everyone full
 * access and is its own refusal; an empty DACL grants no one anything; and text that is
 * not a descriptor is malformed. Collapsing them would report the wrong reason.
 */
export function parseDacl(sddl: unknown): Dacl | null {
  if (typeof sddl !== "string") return null;
  const text = sddl.trim();
  if (/^D:NO_ACCESS_CONTROL$/i.test(text)) return { nullDacl: true };
  if (!/^D:/.test(text)) return /^[OGS]:/.test(text) ? { nullDacl: true } : null;
  const shape = /^D:([A-Z]*)((?:\([^)]*\))*)$/.exec(text);
  if (!shape) return null;
  const aces = [...shape[2].matchAll(/\(([^)]*)\)/g)].map((match) => {
    const field = match[1].split(";");
    const rights = rightsMask(field[2] ?? "");
    return {
      type: field[0] ?? "",
      flags: field[1] ?? "",
      rightsText: field[2] ?? "",
      mask: rights.mask,
      unknownRights: rights.unknown,
      sid: canonicalSid(field[5] ?? ""),
      inheritOnly: /IO/.test(field[1] ?? ""),
    };
  });
  return { flags: shape[1], aces };
}

/** A discriminated union: a refusal always carries its reason, and the compiler enforces it. */
export type Decision = { ok: true } | { ok: false; problem: WindowsAclProblem };

/**
 * The store rule, over the structured rules the platform reports. Identities are security
 * identifiers, so nothing here depends on an alias spelling or a display language.
 */
export function decideStoreRules(rules: AceRule[], userSid: string): Decision {
  if (rules.length === 0) return { ok: false, problem: "empty-dacl" };
  const allowed = new Set([userSid, SID_SYSTEM, SID_ADMINISTRATORS]);
  for (const rule of rules) {
    if (!rule.allow) return { ok: false, problem: "deny-ace" };
    if (!allowed.has(rule.sid)) return { ok: false, problem: "foreign-principal" };
  }
  const mine = rules.filter((rule) => rule.sid === userSid);
  if (mine.length === 0) return { ok: false, problem: "owner-not-granted" };
  // An inherit-only entry confers nothing on the object carrying it, so it cannot supply the
  // access the store needs. A descriptor that parses is not proof that access works.
  const usable = mine.some(
    (rule) => !rule.inheritOnly && ((rule.rights & FILE_ALL_ACCESS) === FILE_ALL_ACCESS || (rule.rights & RIGHT_BITS.GA) !== 0)
  );
  if (!usable) return { ok: false, problem: "insufficient-rights" };
  return { ok: true };
}

/** The ancestor rule, over structured rules. */
export function decideAncestorRules(
  rules: AceRule[],
  userSid: string,
  immediateParent: boolean,
  note?: (principal: string, rights: string) => void
): Decision {
  for (const rule of rules) {
    if (ancestorPrincipalAllowed(rule.sid, userSid)) continue;
    if (!rule.allow) continue; // a deny entry only removes access
    const effective = rule.inheritOnly ? 0 : rule.rights;
    const forbidden = NAMESPACE_BITS | GENERIC_WRITEISH | (immediateParent ? CREATE_CHILD_BITS : 0);
    if ((effective & forbidden) !== 0) {
      if (note) note(rule.sid, `0x${((effective & forbidden) >>> 0).toString(16)}`);
      return { ok: false, problem: "unsafe-parent" };
    }
  }
  return { ok: true };
}

/**
 * The store rule expressed over an SDDL string. The real path uses `decideStoreRules`; this
 * exists because the SDDL form is the only place a NULL access list is distinguishable from an
 * empty one, and because the edge cases are worth testing on every platform.
 */
export function decideStoreDacl(sddl: unknown, userSid: string): Decision {
  const dacl = parseDacl(sddl);
  if (!dacl) return { ok: false, problem: "acl-inspection-malformed" };
  if (dacl.nullDacl) return { ok: false, problem: "null-dacl" };
  const aces = dacl.aces ?? [];
  if (aces.some((ace) => ace.unknownRights.length > 0)) return { ok: false, problem: "acl-inspection-malformed" };
  return decideStoreRules(acesToRules(aces), userSid);
}

/** SDDL entries as structured rules, for the adapters above. */
function acesToRules(aces: Ace[]): AceRule[] {
  return aces.map((ace) => ({ sid: ace.sid, allow: ace.type === "A", rights: ace.mask, inheritOnly: ace.inheritOnly }));
}

/** True when the descriptor says the access list is NULL, which grants everyone full access. */
export function isNullDacl(sddl: string): boolean {
  const parsed = parseDacl(sddl);
  return !!parsed && parsed.nullDacl === true;
}
/** True when the descriptor cannot be understood at all. */
export function isMalformedDacl(sddl: string): boolean {
  return parseDacl(sddl) === null;
}

/**
 * Principals trusted ABOVE the store. Wider than the store set, and tied to the adversary
 * class: a service identity or the platform installer cannot be assumed by an ordinary
 * account. Measured: `C:\` is owned by NT SERVICE\TrustedInstaller and grants it full
 * control, so a narrower set refuses every real machine.
 */
export function ancestorPrincipalAllowed(sid: string, userSid: string): boolean {
  if (sid === userSid || sid === SID_SYSTEM || sid === SID_ADMINISTRATORS) return true;
  if (sid === SID_LOCAL_SERVICE || sid === SID_NETWORK_SERVICE) return true;
  if (/^S-1-5-80-/.test(sid)) return true; // NT SERVICE\*, including TrustedInstaller
  if (/^S-1-5-21-[\d-]+-500$/.test(sid)) return true; // the built-in Administrator account
  if (sid === "domain-relative:500") return true; // the same account, named by an SDDL alias
  return false;
}

/** The ancestor rule expressed over an SDDL string. The real path uses `decideAncestorRules`. */
export function decideAncestorDacl(
  sddl: unknown,
  userSid: string,
  immediateParent: boolean,
  note?: (principal: string, rights: string) => void
): Decision {
  const dacl = parseDacl(sddl);
  if (!dacl) return { ok: false, problem: "acl-inspection-malformed" };
  if (dacl.nullDacl) return { ok: false, problem: "null-dacl" };
  const aces = dacl.aces ?? [];
  if (aces.some((ace) => ace.unknownRights.length > 0 && !ancestorPrincipalAllowed(ace.sid, userSid))) {
    return { ok: false, problem: "acl-inspection-malformed" };
  }
  return decideAncestorRules(acesToRules(aces), userSid, immediateParent, note);
}

// --------------------------------------------------------------------------- the helper

/**
 * The inspection script. A CONSTANT: paths arrive on standard input, one per line, and are
 * never interpolated into this source, so no path can alter what runs. It is delivered with
 * -EncodedCommand, which carries a command rather than a file — nothing is written to disk
 * and no execution-policy change is requested or needed. It reports exception TYPE names
 * only, never a message, so no operating-system text can reach a caller.
 */
/**
 * EVERY CMDLET HERE IS MODULE-QUALIFIED, and that is a performance requirement, not a style
 * choice.
 *
 * An unqualified command name has to be RESOLVED before PowerShell can dispatch it, and on some
 * machines that resolution is extraordinarily expensive. Measured on a GitHub `windows-11-arm`
 * runner, whose `PSModulePath` lists the Azure PowerShell module set ahead of the system module
 * directory:
 *
 *     powershell.exe -NoProfile -NonInteractive -Command "exit 0"            ~820 ms
 *     ... -Command "Get-Item -LiteralPath 'C:\' -Force"                   ~41,800 ms
 *     ... -Command "Microsoft.PowerShell.Management\Get-Item ... "            ~900 ms
 *     ... -Command "ConvertTo-Json -InputObject 1"                        ~43,700 ms
 *     ... -Command "Microsoft.PowerShell.Utility\ConvertTo-Json ... "        ~950 ms
 *
 * Resolving the .NET types this script uses costs nothing (~785 ms, i.e. the same as doing
 * nothing), so the cost was never the security work: it is paid when a COMMAND NAME is resolved,
 * and naming the module removes it. What PowerShell does internally during that resolution was
 * not traced, so no claim is made about it beyond the timings above. The whole helper
 * went from 22,361 ms to 341 ms on an empty path list, 22,416 to 442 ms on four real paths and
 * 22,456 to 375 ms on a refusal, with BYTE-IDENTICAL output and the same exit status in each
 * case.
 *
 * What this does NOT do: a qualified name still resolves through `PSModulePath`, so it does not
 * by itself guarantee the module is the built-in one. The first entry on that path is inside the
 * user's own profile and is user-writable — which is equally true of the unqualified form this
 * replaces, and sits inside the documented trust boundary (the OS user account). Constraining
 * `PSModulePath` is a separate hardening with its own evidence; it is not done here.
 *
 * If a cmdlet is ever added below, qualify it. `tests/consent-acl-win.test.ts` fails otherwise.
 */
const HELPER_SOURCE = [
  "$ErrorActionPreference='Stop'",
  "$ProgressPreference='SilentlyContinue'",
  "$raw=[Console]::In.ReadToEnd()",
  "$paths=@($raw -split \"`r?`n\" | Microsoft.PowerShell.Core\\Where-Object { $_.Length -gt 0 })",
  "$out=Microsoft.PowerShell.Utility\\New-Object System.Collections.ArrayList",
  "foreach($p in $paths){",
  "  $o=[ordered]@{path=[string]$p;ok=$false;exists=$false}",
  "  try{",
  "    $item=Microsoft.PowerShell.Management\\Get-Item -LiteralPath $p -Force",
  "    $o.exists=$true",
  "    $o.isDirectory=[bool]$item.PSIsContainer",
  "    $o.isReparsePoint=[bool](($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)",
  "    if($item.PSIsContainer){$sec=Microsoft.PowerShell.Utility\\New-Object System.Security.AccessControl.DirectorySecurity($p,'Access,Owner')}",
  "    else{$sec=Microsoft.PowerShell.Utility\\New-Object System.Security.AccessControl.FileSecurity($p,'Access,Owner')}",
  "    $o.ownerSid=$sec.GetOwner([System.Security.Principal.SecurityIdentifier]).Value",
    // The SDDL form is kept because it is the only place a NULL access list is distinguishable
    // from an empty one. The DECISION uses the structured rules below, whose identities are
    // already security identifiers, so no alias table and no account name is ever involved.
  "    $o.sddl=$sec.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access)",
  "    $rules=Microsoft.PowerShell.Utility\\New-Object System.Collections.ArrayList",
  "    foreach($r in $sec.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier])){",
  "      [void]$rules.Add([ordered]@{sid=[string]$r.IdentityReference.Value;allow=($r.AccessControlType -eq 'Allow');rights=[int]$r.FileSystemRights;inheritOnly=(($r.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0)})",
  "    }",
  "    $o.rules=@($rules)",
  "    $o.ok=$true",
    // The catch must still say whether the object is THERE. Leaving `exists` false would make a
    // failed inspection indistinguishable from an absent object, and an absent target is skipped.
  "  }catch{ $o.errorType=$_.Exception.GetType().FullName; try{ $o.exists=[bool](Microsoft.PowerShell.Management\\Test-Path -LiteralPath $p) }catch{ $o.exists=$true } }",
  "  [void]$out.Add((Microsoft.PowerShell.Utility\\New-Object psobject -Property $o))",
  "}",
  // One compact object per line: PowerShell 5.1 unwraps a single-element array, so an array
  // would change shape with the number of paths.
  "foreach($r in $out){ Microsoft.PowerShell.Utility\\ConvertTo-Json -InputObject $r -Depth 4 -Compress }",
].join("\n");

export const HELPER_SCRIPT_FOR_TESTS = HELPER_SOURCE;

/** Executable locations. Resolved from the system directory, never searched for on PATH. */
interface Tools {
  powershell: string;
  icacls: string;
}
let toolsOverride: Tools | undefined;
/**
 * Test seam only. Never reachable from a tool argument or a record: the consent module
 * exposes no path from a request into this module.
 */
export function setWindowsAclToolsForTests(tools: Tools | undefined): void {
  toolsOverride = tools;
}
function tools(): Tools {
  if (toolsOverride) return toolsOverride;
  const systemRoot = process.env.SystemRoot || "C:\\Windows";
  const system32 = path.join(systemRoot, "System32");
  return {
    powershell: path.join(system32, "WindowsPowerShell", "v1.0", "powershell.exe"),
    icacls: path.join(system32, "icacls.exe"),
  };
}

/** One access-control entry, as the platform reports it: a SID, a verdict and an access mask. */
export interface AceRule {
  sid: string;
  allow: boolean;
  rights: number;
  inheritOnly: boolean;
}
export interface ObjectInfo {
  exists: boolean;
  isDirectory: boolean;
  isReparsePoint: boolean;
  ownerSid: string;
  sddl: string;
  rules: AceRule[];
  unreadable: boolean;
}
export type InspectResult = { ok: true; byPath: Map<string, ObjectInfo> } | { ok: false; problem: WindowsAclProblem };

const key = (p: string): string => path.resolve(p).toLowerCase();

/**
 * Validates the helper's complete response. Every requested path must come back, and every
 * entry must carry fields of the right type. A partial or surprising answer refuses.
 */
export function parseHelperOutput(stdout: string, requested: string[]): InspectResult {
  const byPath = new Map<string, ObjectInfo>();
  for (const line of stdout.split(/\r?\n/)) {
    if (line.trim().length === 0) continue;
    let entry: unknown;
    try {
      entry = JSON.parse(line);
    } catch {
      return { ok: false, problem: "acl-inspection-malformed" };
    }
    if (typeof entry !== "object" || entry === null) return { ok: false, problem: "acl-inspection-malformed" };
    const e = entry as Record<string, unknown>;
    if (typeof e.path !== "string") return { ok: false, problem: "acl-inspection-malformed" };
    if (typeof e.exists !== "boolean" || typeof e.ok !== "boolean") {
      return { ok: false, problem: "acl-inspection-malformed" };
    }
    let rules: AceRule[] = [];
    if (e.ok === true) {
      if (
        typeof e.isDirectory !== "boolean" ||
        typeof e.isReparsePoint !== "boolean" ||
        typeof e.ownerSid !== "string" ||
        !/^S-1-[0-9-]+$/.test(e.ownerSid) ||
        typeof e.sddl !== "string" ||
        !Array.isArray(e.rules)
      ) {
        return { ok: false, problem: "acl-inspection-malformed" };
      }
      for (const raw of e.rules as unknown[]) {
        if (typeof raw !== "object" || raw === null) return { ok: false, problem: "acl-inspection-malformed" };
        const r = raw as Record<string, unknown>;
        // Every field is required and typed. A rule whose identity is not a security identifier
        // is not something this code will reason about.
        if (
          typeof r.sid !== "string" ||
          !/^S-1-[0-9-]+$/.test(r.sid) ||
          typeof r.allow !== "boolean" ||
          typeof r.rights !== "number" ||
          !Number.isInteger(r.rights) ||
          typeof r.inheritOnly !== "boolean"
        ) {
          return { ok: false, problem: "acl-inspection-malformed" };
        }
        rules.push({ sid: r.sid, allow: r.allow, rights: r.rights >>> 0, inheritOnly: r.inheritOnly });
      }
    }
    if (byPath.has(key(e.path))) return { ok: false, problem: "acl-inspection-malformed" };
    byPath.set(key(e.path), {
      exists: e.exists === true,
      isDirectory: e.isDirectory === true,
      isReparsePoint: e.isReparsePoint === true,
      ownerSid: typeof e.ownerSid === "string" ? e.ownerSid : "",
      sddl: typeof e.sddl === "string" ? e.sddl : "",
      rules,
      unreadable: e.ok !== true && e.exists === true,
    });
  }
  for (const p of requested) {
    if (!byPath.has(key(p))) return { ok: false, problem: "acl-inspection-malformed" };
  }
  return { ok: true, byPath };
}

export interface HelperResult {
  error?: { code?: string } | null;
  signal?: string | null;
  status?: number | null;
  stdout?: string | null;
}

/**
 * Turns one helper invocation into a verdict. Separated from the spawn so every failure mode --
 * timeout, output past the cap, a non-zero exit, silence, unparsable or incomplete output -- is
 * exercised directly by tests on any platform, rather than being reasoned about.
 * There is no permissive branch: every path here either yields a validated response or refuses.
 */
export function classifyHelperResult(result: HelperResult, paths: string[]): InspectResult {
  if (result.error) {
    const code = result.error.code;
    if (code === "ETIMEDOUT" || result.signal) return { ok: false, problem: "acl-inspection-failed" };
    if (code === "ENOBUFS") return { ok: false, problem: "acl-inspection-failed" };
    return { ok: false, problem: "acl-tooling-unavailable" };
  }
  if (result.status !== 0) return { ok: false, problem: "acl-inspection-failed" };
  const stdout = result.stdout ?? "";
  if (stdout.length === 0 || stdout.length > HELPER_MAX_OUTPUT) {
    return { ok: false, problem: "acl-inspection-failed" };
  }
  return parseHelperOutput(stdout, paths);
}

/** Owner, DACL and reparse state for every path, in one bounded call. */
export function inspectPaths(paths: string[]): InspectResult {
  if (paths.length === 0) return { ok: true, byPath: new Map() };
  // A path carrying a line break could not be delivered unambiguously to the helper.
  if (paths.some((p) => /[\r\n]/.test(p))) return { ok: false, problem: "acl-inspection-failed" };
  const exe = tools().powershell;
  if (!existsSync(exe)) return { ok: false, problem: "acl-tooling-unavailable" };
  let result;
  try {
    result = spawnSync(
      exe,
      ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(HELPER_SOURCE, "utf16le").toString("base64")],
      {
        input: paths.join("\r\n") + "\r\n",
        encoding: "utf8",
        timeout: HELPER_TIMEOUT_MS,
        maxBuffer: HELPER_MAX_OUTPUT,
        windowsHide: true,
      }
    );
  } catch {
    return { ok: false, problem: "acl-tooling-unavailable" };
  }
  return classifyHelperResult(
    {
      error: result.error ? { code: (result.error as NodeJS.ErrnoException).code } : null,
      signal: result.signal,
      status: result.status,
      stdout: result.stdout,
    },
    paths
  );
}

/** The current process user's SID, from its own token. Not an object's owner. */
export function currentUserSid(): string | null {
  const systemRoot = process.env.SystemRoot || "C:\\Windows";
  const whoami = path.join(systemRoot, "System32", "whoami.exe");
  if (!existsSync(whoami)) return null;
  const result = spawnSync(whoami, ["/user", "/fo", "csv", "/nh"], {
    encoding: "utf8",
    timeout: ENFORCE_TIMEOUT_MS,
    windowsHide: true,
  });
  if (result.error || result.status !== 0) return null;
  const match = /"(S-1-[0-9-]+)"/.exec(result.stdout ?? "");
  return match ? match[1] : null;
}

/**
 * Replaces a directory's DACL with exactly the three allowed principals and breaks
 * inheritance. The only write this module performs, on a directory this process just
 * created. Arguments are passed as an array: no shell, no command string.
 */
export function protectDirectory(dir: string, userSid: string): Decision {
  const exe = tools().icacls;
  if (!existsSync(exe)) return { ok: false, problem: "acl-tooling-unavailable" };
  const result = spawnSync(
    exe,
    [
      dir,
      "/inheritance:r",
      "/grant:r",
      `*${userSid}:(OI)(CI)F`,
      `*${SID_SYSTEM}:(OI)(CI)F`,
      `*${SID_ADMINISTRATORS}:(OI)(CI)F`,
      "/q",
    ],
    { encoding: "utf8", timeout: ENFORCE_TIMEOUT_MS, windowsHide: true }
  );
  if (result.error || result.status !== 0) return { ok: false, problem: "acl-enforcement-failed" };
  // A partially applied run reports its failures on standard output; any is a failure.
  const failed = /Failed processing (\d+) files/.exec(result.stdout ?? "");
  if (failed && failed[1] !== "0") return { ok: false, problem: "acl-enforcement-failed" };
  return { ok: true };
}

/** Every path component from the volume root down to `dir`, inclusive, outermost first. */
export function ancestorChainOf(dir: string): string[] | null {
  const resolved = path.resolve(dir);
  const root = path.parse(resolved).root;
  // A UNC or otherwise non-drive root is not a location these rules have been established
  // for; refuse rather than walk a namespace whose semantics were never measured.
  if (!/^[A-Za-z]:\\$/.test(root)) return null;
  const chain: string[] = [];
  for (let p = resolved; ; p = path.dirname(p)) {
    chain.unshift(p);
    if (path.dirname(p) === p) break;
  }
  return chain;
}

export interface CheckTarget {
  path: string;
  kind: "directory" | "record";
}

/**
 * The complete check: the ancestor chain of `storeDir`, then each named object under the
 * store rule. One helper call covers all of them.
 *
 * `targets` is what the caller is about to touch — the store directory, its pending
 * directory when present, and the specific record files in play. A directory that passes
 * licenses nothing about its children: a record planted by another account and later caught
 * by a parent's protection has its inherited DACL rewritten to look private while its owner
 * stays the attacker, so every record is checked on its own.
 */
/**
 * Why a check refused, for diagnostics only. The product never prints any of this: its refusals
 * are fixed sentences. Tests and evidence jobs use it so a refusal can be understood rather than
 * guessed at.
 */
export interface RefusalDetail {
  component: string;
  principal?: string;
  rights?: string;
}
let lastDetail: RefusalDetail | undefined;
/** The detail of the most recent refusal in this process. Diagnostic only; never user-facing. */
export function lastRefusalDetail(): RefusalDetail | undefined {
  return lastDetail;
}
function refuse(problem: WindowsAclProblem, detail: RefusalDetail): { ok: false; problem: WindowsAclProblem } {
  lastDetail = detail;
  return { ok: false, problem };
}

export function checkWindowsStore(
  storeDir: string,
  targets: CheckTarget[],
  userSid: string
): { ok: true } | { ok: false; problem: WindowsAclProblem } {
  const parent = path.dirname(path.resolve(storeDir));
  const chain = ancestorChainOf(parent);
  if (!chain) return { ok: false, problem: "unsupported-location" };
  const targetPaths = targets.map((t) => path.resolve(t.path));
  const inspected = inspectPaths([...chain, ...targetPaths]);
  if (!inspected.ok) return { ok: false, problem: inspected.problem };
  return evaluateInspected(chain, targets, inspected.byPath, userSid);
}

/**
 * The decision over an already-inspected set. Separated from the subprocess so every branch --
 * including the ones a live Windows machine will not produce on demand, such as an object that
 * exists but could not be inspected -- is exercised directly by tests on any platform.
 */
export function evaluateInspected(
  chain: string[],
  targets: CheckTarget[],
  byPath: Map<string, ObjectInfo>,
  userSid: string
): { ok: true } | { ok: false; problem: WindowsAclProblem } {
  const parent = chain[chain.length - 1];
  const inspected = { byPath };

  for (const component of chain) {
    const info = inspected.byPath.get(key(component));
    if (!info) return refuse("acl-inspection-malformed", { component });
    if (!info.exists) return refuse("unsafe-parent", { component, principal: "absent" });
    if (info.unreadable) return refuse("owner-unreadable", { component });
    if (info.isReparsePoint) return refuse("unsafe-parent", { component, principal: "reparse-point" });
    if (!info.isDirectory) return refuse("unsafe-parent", { component, principal: "not-a-directory" });
    if (!ancestorPrincipalAllowed(info.ownerSid, userSid)) {
      return refuse("unsafe-parent", { component, principal: `owner:${info.ownerSid}` });
    }
    if (isNullDacl(info.sddl)) return refuse("null-dacl", { component });
    if (isMalformedDacl(info.sddl)) return refuse("acl-inspection-malformed", { component });
    let offender: RefusalDetail = { component };
    const decision = decideAncestorRules(info.rules, userSid, key(component) === key(parent), (principal, rights) => {
      offender = { component, principal, rights };
    });
    if (!decision.ok) return refuse(decision.problem, offender);
  }

  for (const target of targets) {
    const info = inspected.byPath.get(key(target.path));
    if (!info) return refuse("acl-inspection-malformed", { component: target.path });
    if (!info.exists) continue; // the caller decides what an absent object means
    if (info.unreadable) return refuse("owner-unreadable", { component: target.path });
    if (info.isReparsePoint) return refuse("reparse-point", { component: target.path });
    if (target.kind === "directory" && !info.isDirectory) return refuse("not-a-directory", { component: target.path });
    if (target.kind === "record" && info.isDirectory) return refuse("not-a-directory", { component: target.path });
    if (info.ownerSid !== userSid && info.ownerSid !== SID_SYSTEM && info.ownerSid !== SID_ADMINISTRATORS) {
      return refuse("foreign-owner", { component: target.path, principal: `owner:${info.ownerSid}` });
    }
    if (isNullDacl(info.sddl)) return refuse("null-dacl", { component: target.path });
    if (isMalformedDacl(info.sddl)) return refuse("acl-inspection-malformed", { component: target.path });
    const decision = decideStoreRules(info.rules, userSid);
    if (!decision.ok) return refuse(decision.problem, { component: target.path, principal: info.sddl });
  }
  lastDetail = undefined;
  return { ok: true };
}
