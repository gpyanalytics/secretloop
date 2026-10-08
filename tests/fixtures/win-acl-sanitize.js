#!/usr/bin/env node
"use strict";
/**
 * STRICT SANITIZER for Windows consent-chain diagnostics. Everything a fixture prints about an
 * access-control chain passes through here FIRST; nothing is printed and then checked.
 *
 * What survives: well-known identities (by fixed label), role labels for the accounts the job
 * created, rights masks that parse as hex or as SDDL rights letters, ACE types and inheritance
 * flags, owner role, directory / reparse state, and a component's depth plus an allowlisted
 * fixed directory name. What never survives: machine-local SIDs (S-1-5-21-<machine>-RID is
 * reduced to a role or to its RID class), VM or account names, arbitrary path text, arbitrary
 * error text, and any SDDL whose shape the parser does not recognise (replaced by a label).
 *
 * Roles are supplied by the caller from the job's own environment (ACL_SID1 = slprobe,
 * ACL_SID2 = slprobe2) plus the running process's own SID; nothing is looked up by name.
 *
 * DISCLOSURE ON COLLAPSED IDENTITIES. Labels such as LOCAL-ACCOUNT:RID-1005, NT-SERVICE,
 * APP-CAPABILITY and UNKNOWN-PRINCIPAL are CLASSES, not identities. Two identical sanitized labels
 * do not establish that the same principal was seen -- not across machines, not across runs, and
 * for class labels not even within one run -- and collapsing can make distinct principals share a
 * label. Only the role labels (SELF, SLPROBE, SLPROBE2) and the well-known identities name one
 * specific principal, and the roles only for the run that supplied them.
 */
const WELL_KNOWN = {
  "S-1-5-18": "SYSTEM", "S-1-5-32-544": "ADMINISTRATORS", "S-1-5-32-545": "USERS", "S-1-5-32-546": "GUESTS",
  "S-1-5-32-547": "POWER-USERS", "S-1-5-32-551": "BACKUP-OPERATORS", "S-1-5-32-555": "REMOTE-DESKTOP-USERS",
  "S-1-5-11": "AUTHENTICATED-USERS", "S-1-1-0": "EVERYONE", "S-1-3-0": "CREATOR-OWNER", "S-1-3-1": "CREATOR-GROUP",
  "S-1-3-4": "OWNER-RIGHTS", "S-1-5-19": "LOCAL-SERVICE", "S-1-5-20": "NETWORK-SERVICE", "S-1-5-4": "INTERACTIVE",
  "S-1-5-2": "NETWORK", "S-1-5-7": "ANONYMOUS", "S-1-5-12": "RESTRICTED", "S-1-5-17": "IUSR", "S-1-15-2-1": "ALL-APP-PACKAGES",
};
// Two-letter SDDL aliases pass through unchanged: they are the well-known identities by definition.
const ALIAS = /^(BA|BU|BG|PU|AO|SO|PO|BO|RE|RU|RD|NO|MU|LU|CY|ES|SY|LS|NS|WD|AU|IU|NU|AN|RC|IS|CO|CG|OW|AC|LW|ME|HI|SI|LA|LG|CA|DA|DU|DG|DC|DD|SA|EA|PA|RO|RS)$/;
// Directory names a diagnostic may print. Anything else is "<dir>".
const FIXED_NAMES = new Set(["a", "_temp", "acl-lab", "private", "permissive", ".secretloop", "pending", "repo", "rxstore",
  "probe-store", "Users", "AppData", "Local", "Temp", "Windows"]);
// SDDL rights tokens, explicit allowlist (generic, standard, file and key rights). A rights field
// survives only as a strictly validated hex mask or as a complete concatenation of these tokens.
const RIGHTS_TOKENS = new Set(["GA", "GR", "GW", "GX", "RC", "SD", "WD", "WO", "RP", "WP", "CC", "DC", "LC", "SW", "LO", "DT", "CR",
  "FA", "FR", "FW", "FX", "KA", "KR", "KW", "KX", "NR", "NW", "NX"]);
const HEX_MASK = /^0x[0-9a-fA-F]{1,8}$/;
function rightsTokensValid(v) {
  if (v.length === 0 || v.length % 2 !== 0) return false;
  for (let i = 0; i < v.length; i += 2) if (!RIGHTS_TOKENS.has(v.slice(i, i + 2))) return false;
  return true;
}
const FLAGS = /^[A-Z]{0,12}$/;

function principal(raw, roles) {
  if (raw === null || raw === undefined || raw === "") return "NONE";
  const v = String(raw);
  if (WELL_KNOWN[v]) return WELL_KNOWN[v];
  if (ALIAS.test(v)) return v;
  if (roles) {
    if (roles.self && v === roles.self) return "SELF";
    if (roles.slprobe && v === roles.slprobe) return "SLPROBE";
    if (roles.slprobe2 && v === roles.slprobe2) return "SLPROBE2";
  }
  if (/^S-1-5-21-[0-9-]+-500$/.test(v) || v === "domain-relative:500") return "BUILTIN-ADMINISTRATOR";
  const local = /^S-1-5-21-[0-9-]+-([0-9]{1,10})$/.exec(v);
  if (local) return Number(local[1]) >= 1000 ? "LOCAL-ACCOUNT:RID-" + local[1] : "LOCAL-WELLKNOWN:RID-" + local[1];
  if (/^S-1-5-80-[0-9-]+$/.test(v)) return "NT-SERVICE";
  if (/^S-1-15-2-[0-9-]+$/.test(v)) return "APP-PACKAGE";
  if (/^S-1-15-3-[0-9-]+$/.test(v)) return "APP-CAPABILITY";
  if (/^S-1-16-[0-9]+$/.test(v)) return "INTEGRITY-LEVEL";
  if (/^S-1-5-5-[0-9-]+$/.test(v)) return "LOGON-SESSION";
  if (/^domain-relative:[0-9]+$/.test(v)) return "DOMAIN-RELATIVE";
  if (/^unknown-alias:[A-Z]{2}$/.test(v)) return "UNKNOWN-ALIAS";
  return "UNKNOWN-PRINCIPAL";
}

/** The product's RefusalDetail.principal field: a fixed word, or "owner:<sid>", or a SID. */
function refusalPrincipal(raw, roles) {
  if (raw === null || raw === undefined) return "NONE";
  const v = String(raw);
  if (v === "absent" || v === "reparse-point" || v === "not-a-directory") return v;
  if (v.startsWith("owner:")) return "owner:" + principal(v.slice(6), roles);
  return principal(v, roles);
}

function rights(raw) {
  if (raw === null || raw === undefined || raw === "") return "NONE";
  const v = String(raw);
  if (HEX_MASK.test(v) || rightsTokensValid(v)) return v;
  if (/^[0-9]{1,10}$/.test(v)) return "0x" + Number(v).toString(16);
  return "RIGHTS-UNPARSED";
}

/** depth within the chain plus an allowlisted name; the root is "<drive-root>", anything unknown "<dir>". */
function component(raw, chain) {
  if (raw === null || raw === undefined || raw === "") return "NONE";
  const v = String(raw);
  const norm = (s) => String(s).replace(/\//g, "\\").replace(/\\+$/, "").toLowerCase();
  let depth = -1;
  if (Array.isArray(chain)) depth = chain.findIndex((c) => norm(c) === norm(v));
  const parts = v.replace(/\//g, "\\").split("\\").filter((p) => p.length > 0);
  const isRoot = /^[A-Za-z]:\\?$/.test(v) || parts.length === 1 && /^[A-Za-z]:$/.test(parts[0]);
  const last = parts.length ? parts[parts.length - 1] : "";
  const name = isRoot ? "<drive-root>" : FIXED_NAMES.has(last) ? last : /^RUNNER~1$|^runneradmin$/i.test(last) ? "<runner-home>" : "<dir>";
  return (depth >= 0 ? "depth " + depth : "depth ?") + " " + name;
}

/** SDDL DACL string -> "D:<flags> (type;flags;rights;principal)..." with every SID replaced. */
function sddl(raw, roles) {
  if (raw === null || raw === undefined || raw === "") return "NONE";
  const v = String(raw);
  const m = /^D:([A-Z]*)((?:\([^()]*\))*)$/.exec(v);
  if (!m) return "SDDL-UNPARSED(" + v.length + " chars)";
  const aces = m[2].match(/\([^()]*\)/g) || [];
  const out = [];
  for (const ace of aces) {
    const f = ace.slice(1, -1).split(";");
    if (f.length !== 6) { out.push("(ACE-UNPARSED)"); continue; }
    const type = /^[A-Z]{1,2}$/.test(f[0]) ? f[0] : "?";
    const flags = FLAGS.test(f[1]) ? f[1] : "?";
    out.push("(" + type + ";" + flags + ";" + rights(f[2]) + ";" + principal(f[5], roles) + ")");
  }
  return "D:" + m[1] + out.join("");
}

function refusalDetail(detail, chain, roles) {
  if (!detail || typeof detail !== "object") return "no refusal detail recorded";
  return "component " + component(detail.component, chain) + "; principal " + refusalPrincipal(detail.principal, roles) +
    "; rights " + rights(detail.rights);
}

function rolesFromEnv(env, selfSid) {
  const sid = (s) => (typeof s === "string" && /^S-1-5-21-[0-9-]+$/.test(s) ? s : undefined);
  return { self: sid(selfSid), slprobe: sid(env.ACL_SID1), slprobe2: sid(env.ACL_SID2) };
}

module.exports = { principal, refusalPrincipal, rights, component, sddl, refusalDetail, rolesFromEnv };
