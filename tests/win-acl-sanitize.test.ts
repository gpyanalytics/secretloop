import { test, suite, finish, assert } from "./harness";
import * as path from "path";

/**
 * THE CI ACL SANITIZER, TESTED ON ITS OWN.
 *
 * `tests/fixtures/win-acl-sanitize.js` stands between the Windows CI jobs and their public logs:
 * the two-account and chain diagnostics pass every owner, SDDL string, rights mask and path
 * through it before printing. Until now nothing tested it directly, so a regression would have
 * surfaced only as a raw machine SID in a log -- after the fact, and only if someone looked.
 *
 * Pure functions, no Windows API, so every case runs on every platform.
 *
 * The machine SIDs here are synthetic and assembled at runtime. No test name and no failure
 * message prints one: a failed comparison reports both sides with every machine SID replaced, so
 * a sanitizer that started leaking would not leak a second time through its own test.
 */

type Roles = { self?: string; slprobe?: string; slprobe2?: string };
interface Sanitizer {
  principal(raw: unknown, roles?: Roles): string;
  refusalPrincipal(raw: unknown, roles?: Roles): string;
  rights(raw: unknown): string;
  component(raw: unknown, chain?: unknown): string;
  sddl(raw: unknown, roles?: Roles): string;
  refusalDetail(detail: unknown, chain?: unknown, roles?: Roles): string;
  rolesFromEnv(env: Record<string, string | undefined>, selfSid: unknown): Roles;
}

const s: Sanitizer = require(path.join(__dirname, "fixtures", "win-acl-sanitize.js"));

const MACHINE_SID_TEXT = /S-1-5-21-[0-9-]*/g;

function shown(v: unknown): string {
  return JSON.stringify(String(v)).replace(MACHINE_SID_TEXT, "<machine-sid>");
}

function same(actual: string, expected: string, what: string): void {
  assert.ok(actual === expected, `${what}: expected ${shown(expected)}, got ${shown(actual)}`);
}

/** A machine-local SID, S-1-5-21-<a>-<b>-<c>-<rid>, built so no literal one sits in the source. */
function machineSid(...parts: Array<number | string>): string {
  return ["S", 1, 5, 21, ...parts].join("-");
}

const DOMAIN = [3141592653, 2718281828, 1414213562];
const SELF = machineSid(...DOMAIN, 1000);
const SLPROBE = machineSid(...DOMAIN, 1001);
const SLPROBE2 = machineSid(...DOMAIN, 1002);
const OTHER = machineSid(...DOMAIN, 1003);
const ROLES: Roles = { self: SELF, slprobe: SLPROBE, slprobe2: SLPROBE2 };

// The chain the x64 two-account job builds under RUNNER_TEMP's drive, root first.
const CHAIN = ["C:\\", "C:\\a", "C:\\a\\_temp", "C:\\a\\_temp\\acl-lab", "C:\\a\\_temp\\acl-lab\\private"];

suite("\nwin-acl-sanitize — principals");

test("every well-known identity maps to its fixed label", () => {
  const table: Array<[string, string]> = [
    ["S-1-5-18", "SYSTEM"], ["S-1-5-32-544", "ADMINISTRATORS"], ["S-1-5-32-545", "USERS"],
    ["S-1-5-32-546", "GUESTS"], ["S-1-5-32-547", "POWER-USERS"], ["S-1-5-32-551", "BACKUP-OPERATORS"],
    ["S-1-5-32-555", "REMOTE-DESKTOP-USERS"], ["S-1-5-11", "AUTHENTICATED-USERS"], ["S-1-1-0", "EVERYONE"],
    ["S-1-3-0", "CREATOR-OWNER"], ["S-1-3-1", "CREATOR-GROUP"], ["S-1-3-4", "OWNER-RIGHTS"],
    ["S-1-5-19", "LOCAL-SERVICE"], ["S-1-5-20", "NETWORK-SERVICE"], ["S-1-5-4", "INTERACTIVE"],
    ["S-1-5-2", "NETWORK"], ["S-1-5-7", "ANONYMOUS"], ["S-1-5-12", "RESTRICTED"], ["S-1-5-17", "IUSR"],
    ["S-1-15-2-1", "ALL-APP-PACKAGES"],
  ];
  for (const [sid, label] of table) same(s.principal(sid, ROLES), label, `well-known ${label}`);
});

test("SDDL aliases pass through; an unlisted alias-shaped token does not", () => {
  for (const alias of ["BA", "BU", "SY", "AU", "WD", "CO", "OW", "AC"]) same(s.principal(alias), alias, `alias ${alias}`);
  for (const bogus of ["ZZ", "QQ", "BAX", "ba", "B"]) same(s.principal(bogus), "UNKNOWN-PRINCIPAL", `token ${bogus}`);
});

test("the job's own accounts map to their role labels", () => {
  same(s.principal(SELF, ROLES), "SELF", "the running account");
  same(s.principal(SLPROBE, ROLES), "SLPROBE", "the first ordinary account");
  same(s.principal(SLPROBE2, ROLES), "SLPROBE2", "the second ordinary account");
});

test("a role never relabels a well-known identity", () => {
  const hostile: Roles = { self: "S-1-5-18", slprobe: "S-1-5-32-544", slprobe2: "S-1-1-0" };
  same(s.principal("S-1-5-18", hostile), "SYSTEM", "SYSTEM under a role claiming it");
  same(s.principal("S-1-5-32-544", hostile), "ADMINISTRATORS", "Administrators under a role claiming it");
  same(s.principal("S-1-1-0", hostile), "EVERYONE", "Everyone under a role claiming it");
});

test("an unrecognised machine account is reduced to its RID class", () => {
  same(s.principal(OTHER, ROLES), "LOCAL-ACCOUNT:RID-1003", "an account outside the roles");
  same(s.principal(SELF), "LOCAL-ACCOUNT:RID-1000", "a role account when no roles are supplied");
  same(s.principal(machineSid(...DOMAIN, 501)), "LOCAL-WELLKNOWN:RID-501", "RID 501");
  same(s.principal(machineSid(...DOMAIN, 999)), "LOCAL-WELLKNOWN:RID-999", "RID 999");
  same(s.principal(machineSid(...DOMAIN, 4294967295)), "LOCAL-ACCOUNT:RID-4294967295", "a ten-digit RID");
});

test("the built-in administrator is named by its RID on any machine, unless it is a role", () => {
  const admin = machineSid(...DOMAIN, 500);
  same(s.principal(admin), "BUILTIN-ADMINISTRATOR", "RID 500");
  same(s.principal(machineSid(7, 8, 9, 500)), "BUILTIN-ADMINISTRATOR", "RID 500 in another domain");
  same(s.principal("domain-relative:500"), "BUILTIN-ADMINISTRATOR", "domain-relative 500");
  same(s.principal(admin, { self: admin }), "SELF", "RID 500 when it is the running account");
});

test("other SID families collapse to class labels", () => {
  same(s.principal(["S", 1, 5, 80, 956008885, 3418522649, 1831038044].join("-")), "NT-SERVICE", "service SID");
  same(s.principal("S-1-15-2-1-2-3-4"), "APP-PACKAGE", "app package SID");
  same(s.principal("S-1-15-3-1024-1-2"), "APP-CAPABILITY", "capability SID");
  same(s.principal("S-1-16-12288"), "INTEGRITY-LEVEL", "integrity level");
  same(s.principal("S-1-5-5-0-123456"), "LOGON-SESSION", "logon session");
  same(s.principal("domain-relative:1105"), "DOMAIN-RELATIVE", "domain-relative RID");
  same(s.principal("unknown-alias:QQ"), "UNKNOWN-ALIAS", "unknown alias");
});

test("everything else becomes a fixed word, never the input", () => {
  same(s.principal(""), "NONE", "empty string");
  same(s.principal(null), "NONE", "null");
  same(s.principal(undefined), "NONE", "undefined");
  for (const raw of ["RUNNERVM\\runneradmin", "slprobe", machineSid(...DOMAIN, "12345678901"), machineSid(""),
    OTHER + "x", " " + OTHER, "unknown-alias:Q1", 42]) {
    same(s.principal(raw), "UNKNOWN-PRINCIPAL", "an unrecognised principal");
  }
});

suite("\nwin-acl-sanitize — refusal labels");

test("refusalPrincipal keeps only the product's own fixed words", () => {
  for (const word of ["absent", "reparse-point", "not-a-directory"]) same(s.refusalPrincipal(word), word, word);
  same(s.refusalPrincipal(null), "NONE", "null");
  same(s.refusalPrincipal(undefined), "NONE", "undefined");
  same(s.refusalPrincipal(""), "NONE", "empty string");
  same(s.refusalPrincipal("Absent"), "UNKNOWN-PRINCIPAL", "a look-alike word");
  same(s.refusalPrincipal("absent "), "UNKNOWN-PRINCIPAL", "a word with trailing text");
});

test("refusalPrincipal sanitizes an owner exactly like a principal", () => {
  same(s.refusalPrincipal("owner:" + SLPROBE2, ROLES), "owner:SLPROBE2", "owner that is a role");
  same(s.refusalPrincipal("owner:S-1-5-32-544", ROLES), "owner:ADMINISTRATORS", "well-known owner");
  same(s.refusalPrincipal("owner:" + OTHER), "owner:LOCAL-ACCOUNT:RID-1003", "unrecognised owner");
  same(s.refusalPrincipal("owner:"), "owner:NONE", "owner with nothing after it");
  same(s.refusalPrincipal(SLPROBE, ROLES), "SLPROBE", "a bare principal");
});

test("refusalDetail renders component, principal and rights, each sanitized", () => {
  same(s.refusalDetail({ component: "C:\\", principal: "S-1-5-11", rights: "0x1301bf" }, CHAIN, ROLES),
    "component depth 0 <drive-root>; principal AUTHENTICATED-USERS; rights 0x1301bf", "a drive-root grant");
  same(s.refusalDetail({ component: "C:\\a\\_temp\\acl-lab\\private", principal: "owner:" + SLPROBE2, rights: null },
    CHAIN, ROLES), "component depth 4 private; principal owner:SLPROBE2; rights NONE", "a foreign owner");
  same(s.refusalDetail({ component: "E:\\clients\\acme", principal: OTHER, rights: "FA" }, CHAIN),
    "component depth ? <dir>; principal LOCAL-ACCOUNT:RID-1003; rights FA", "a component outside the chain");
});

test("refusalDetail without a detail object says so", () => {
  for (const d of [null, undefined, "unsafe-parent", 42]) same(s.refusalDetail(d, CHAIN, ROLES), "no refusal detail recorded", "no detail");
});

suite("\nwin-acl-sanitize — rights");

test("validated hex masks pass through unchanged", () => {
  for (const m of ["0x1301bf", "0x1200a9", "0xFFFFFFFF", "0x4", "0x0"]) same(s.rights(m), m, `mask ${m}`);
});

test("complete concatenations of allowlisted rights tokens pass through", () => {
  for (const t of ["FA", "GRGX", "CCDCLCSWRPWPDTLOCRSDRCWDWO", "FRFWFX", "KAKRKWKX", "NRNWNX", "GA"]) same(s.rights(t), t, `tokens ${t}`);
});

test("decimal masks are normalised to hex", () => {
  same(s.rights("1179817"), "0x1200a9", "decimal string");
  same(s.rights("0"), "0x0", "zero");
  same(s.rights(4), "0x4", "number");
});

test("anything outside the allowlist is replaced, never echoed", () => {
  for (const bad of ["ZZ", "FAZZ", "FAX", "fa", "0x123456789", "0xg", "0x", "12345678901", "-1", "FA;;;SY",
    "FA)(A;;FA;;;" + OTHER, OTHER]) {
    same(s.rights(bad), "RIGHTS-UNPARSED", "an unlisted rights field");
  }
  same(s.rights(""), "NONE", "empty string");
  same(s.rights(null), "NONE", "null");
});

suite("\nwin-acl-sanitize — path components");

test("a chain member is reported by depth and allowlisted name", () => {
  same(s.component("C:\\", CHAIN), "depth 0 <drive-root>", "the drive root");
  same(s.component("C:\\a", CHAIN), "depth 1 a", "depth 1");
  same(s.component("C:\\a\\_temp\\acl-lab\\private", CHAIN), "depth 4 private", "the store's parent");
});

test("chain matching ignores case, slash direction and trailing separators", () => {
  same(s.component("c:/A/_TEMP/acl-lab/", CHAIN), "depth 3 acl-lab", "a differently written chain member");
});

test("the name allowlist is exact: a differently cased name is not printed", () => {
  same(s.component("C:\\A\\_TEMP", CHAIN), "depth 2 <dir>", "upper-cased _temp");
  same(s.component("C:\\Users\\appdata"), "depth ? <dir>", "lower-cased AppData");
});

test("drive roots are labelled, not printed", () => {
  same(s.component("D:\\", CHAIN), "depth ? <drive-root>", "D:\\");
  same(s.component("E:"), "depth ? <drive-root>", "E:");
  same(s.component("z:/"), "depth ? <drive-root>", "z:/");
});

test("a runner home directory is labelled, not printed", () => {
  for (const home of ["C:\\Users\\RUNNER~1", "C:\\Users\\runneradmin", "C:\\Users\\RunnerAdmin"]) {
    same(s.component(home), "depth ? <runner-home>", "runner home");
  }
});

test("any other directory name is replaced", () => {
  for (const p of ["C:\\Users\\alice", "D:\\clients\\acme-merger", "\\\\fileserver\\share\\payroll", "relative\\name",
    "C:\\a\\_temp\\acl-lab\\private\\customer-x"]) {
    same(s.component(p, CHAIN), "depth ? <dir>", "an unlisted directory");
  }
});

test("without a usable chain, depth is unknown and the name rules still apply", () => {
  same(s.component("C:\\a\\_temp\\acl-lab\\private"), "depth ? private", "no chain");
  same(s.component("C:\\customer-x", "not an array"), "depth ? <dir>", "a chain that is not an array");
  same(s.component(""), "NONE", "empty string");
  same(s.component(null), "NONE", "null");
});

suite("\nwin-acl-sanitize — SDDL");

const LAB_DACL = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;" + SLPROBE + ")(A;OICI;0x1200a9;;;" + SLPROBE2 + ")";

test("an ACL is re-emitted with every principal sanitized", () => {
  same(s.sddl(LAB_DACL, ROLES), "D:PAI(A;OICI;FA;SY)(A;OICI;FA;BA)(A;OICI;0x1200a9;SLPROBE)(A;OICI;0x1200a9;SLPROBE2)",
    "the lab DACL with roles");
});

test("without roles, the same ACL keeps only RID classes", () => {
  same(s.sddl(LAB_DACL), "D:PAI(A;OICI;FA;SY)(A;OICI;FA;BA)(A;OICI;0x1200a9;LOCAL-ACCOUNT:RID-1001)" +
    "(A;OICI;0x1200a9;LOCAL-ACCOUNT:RID-1002)", "the lab DACL without roles");
});

test("object-ACE GUID fields are dropped", () => {
  same(s.sddl("D:(OA;CI;RP;bf967aba-0de6-11d0-a285-00aa003049e2;;" + OTHER + ")"),
    "D:(OA;CI;RP;LOCAL-ACCOUNT:RID-1003)", "an object ACE");
});

test("malformed ACEs and fields are replaced, not echoed", () => {
  same(s.sddl("D:(A;OICI;FA;" + OTHER + ")"), "D:(ACE-UNPARSED)", "an ACE with four fields");
  same(s.sddl("D:(a1;oici;ZZ;;;" + OTHER + ")"), "D:(?;?;RIGHTS-UNPARSED;LOCAL-ACCOUNT:RID-1003)", "bad type, flags and rights");
});

test("SDDL the parser does not recognise is reduced to its length", () => {
  for (const raw of ["O:" + OTHER + "D:(A;;FA;;;SY)", "D:PAI(A;;FA;;;SY)" + OTHER, "D:(XA;;FA;;;WD;(@User.x == 1))",
    "d:(A;;FA;;;SY)"]) {
    same(s.sddl(raw), "SDDL-UNPARSED(" + raw.length + " chars)", "an unrecognised SDDL shape");
  }
});

test("an empty DACL and empty input", () => {
  same(s.sddl("D:"), "D:", "empty DACL");
  same(s.sddl("D:P"), "D:P", "protected empty DACL");
  same(s.sddl(""), "NONE", "empty string");
  same(s.sddl(null), "NONE", "null");
});

suite("\nwin-acl-sanitize — roles from the environment");

test("accepts machine SIDs from the job's environment", () => {
  const r = s.rolesFromEnv({ ACL_SID1: SLPROBE, ACL_SID2: SLPROBE2 }, SELF);
  assert.ok(r.self === SELF && r.slprobe === SLPROBE && r.slprobe2 === SLPROBE2, "all three roles must be read");
});

test("ignores names, well-known SIDs, trailing text and non-strings", () => {
  const r = s.rolesFromEnv({ ACL_SID1: "slprobe", ACL_SID2: "S-1-5-32-544" }, "S-1-5-18");
  assert.ok(r.self === undefined && r.slprobe === undefined && r.slprobe2 === undefined, "none of these is a role");
  const t = s.rolesFromEnv({ ACL_SID1: SLPROBE + ";x", ACL_SID2: " " + SLPROBE2 }, 42);
  assert.ok(t.self === undefined && t.slprobe === undefined && t.slprobe2 === undefined, "decorated values are not roles");
  const e = s.rolesFromEnv({}, undefined);
  assert.ok(e.self === undefined && e.slprobe === undefined && e.slprobe2 === undefined, "an empty environment has no roles");
});

test("roles read from the environment drive the labels end to end", () => {
  const roles = s.rolesFromEnv({ ACL_SID1: SLPROBE, ACL_SID2: SLPROBE2 }, SELF);
  same(s.principal(SELF, roles), "SELF", "self");
  same(s.sddl(LAB_DACL, roles), "D:PAI(A;OICI;FA;SY)(A;OICI;FA;BA)(A;OICI;0x1200a9;SLPROBE)(A;OICI;0x1200a9;SLPROBE2)", "the lab DACL");
  same(s.refusalPrincipal("owner:" + SLPROBE, roles), "owner:SLPROBE", "an owner");
});

test("an environment cannot relabel a well-known identity", () => {
  const roles = s.rolesFromEnv({ ACL_SID1: "S-1-5-32-544", ACL_SID2: "S-1-5-11" }, "S-1-5-18");
  same(s.principal("S-1-5-32-544", roles), "ADMINISTRATORS", "Administrators");
  same(s.principal("S-1-5-11", roles), "AUTHENTICATED-USERS", "Authenticated Users");
});

suite("\nwin-acl-sanitize — properties over generated input (fixed seed)");

/** mulberry32: a small deterministic generator, so a failure reproduces exactly. */
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function int(r: () => number, lo: number, hi: number): number {
  return lo + Math.floor(r() * (hi - lo + 1));
}

/** Nine or ten digits: never confusable with a RID printed in a class label (at most six here). */
function subAuthority(r: () => number): string {
  return String(int(r, 100000000, 4294967295));
}

function generatedSid(r: () => number): { sid: string; domain: string[] } {
  const domain = [subAuthority(r), subAuthority(r), subAuthority(r)];
  const rid = [500, int(r, 0, 999), int(r, 1000, 999999)][int(r, 0, 2)];
  return { sid: machineSid(...domain, rid), domain };
}

test("no generated machine SID survives any function, with or without roles", () => {
  const r = rng(0x5ec7100f);
  let checked = 0;
  const leaks: string[] = [];
  for (let i = 0; i < 400; i++) {
    const { sid, domain } = generatedSid(r);
    const roles = [undefined, ROLES, { self: SELF, slprobe: sid, slprobe2: SLPROBE2 }][i % 3];
    const outputs: Array<[string, string]> = [
      ["principal", s.principal(sid, roles)],
      ["refusalPrincipal", s.refusalPrincipal(sid, roles)],
      ["refusalPrincipal owner", s.refusalPrincipal("owner:" + sid, roles)],
      ["sddl", s.sddl("D:PAI(A;OICI;FA;;;" + sid + ")(A;;0x1301bf;;;" + sid + ")", roles)],
      ["refusalDetail", s.refusalDetail({ component: sid, principal: sid, rights: sid }, CHAIN, roles)],
      ["rights", s.rights(sid)],
      ["component", s.component("C:\\Users\\" + sid, CHAIN)],
    ];
    for (const [fn, out] of outputs) {
      checked++;
      if (/S-1-5-21/.test(out) || domain.some((d) => out.includes(d))) leaks.push(fn);
    }
  }
  assert.ok(leaks.length === 0, `${leaks.length} of ${checked} outputs carried machine-SID text (first from ${leaks[0]})`);
});

test("no generated directory name survives component or refusalDetail", () => {
  const r = rng(0x0d1ec7);
  const fixedParents = ["a", "_temp", "acl-lab", "Users"];
  let checked = 0;
  let leaks = 0;
  for (let i = 0; i < 400; i++) {
    const names: string[] = [];
    for (let d = int(r, 1, 4); d > 0; d--) {
      names.push("zq" + Math.floor(r() * 0xffffffff).toString(16) + ["", ".bak", " copy", "-prod"][int(r, 0, 3)]);
    }
    const drive = String.fromCharCode(int(r, 67, 90)) + ":";
    const parts = [drive, ...fixedParents.slice(0, int(r, 0, 4)), ...names];
    const p = (i % 4 === 0 ? "\\\\" + names[0] + "\\" : "") + parts.join(i % 2 ? "/" : "\\");
    const chain = i % 5 === 0 ? [drive + "\\", p] : CHAIN;
    for (const out of [s.component(p, chain), s.refusalDetail({ component: p, principal: "S-1-5-11", rights: "FA" }, chain)]) {
      checked++;
      if (names.some((n) => out.toLowerCase().includes(n.toLowerCase()))) leaks++;
    }
  }
  assert.ok(leaks === 0, `${leaks} of ${checked} outputs carried a generated directory name`);
});

const RIGHTS_TOKENS = new Set(["GA", "GR", "GW", "GX", "RC", "SD", "WD", "WO", "RP", "WP", "CC", "DC", "LC", "SW", "LO", "DT",
  "CR", "FA", "FR", "FW", "FX", "KA", "KR", "KW", "KX", "NR", "NW", "NX"]);

function allowlistedTokens(v: string): boolean {
  if (v.length === 0 || v.length % 2 !== 0) return false;
  for (let i = 0; i < v.length; i += 2) if (!RIGHTS_TOKENS.has(v.slice(i, i + 2))) return false;
  return true;
}

test("rights output is always a fixed word, a hex mask or allowlisted tokens", () => {
  const r = rng(0x417e5);
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789x;:()-S";
  let bad = 0;
  let echoedInvalid = 0;
  for (let i = 0; i < 1000; i++) {
    let raw = "";
    for (let n = int(r, 0, 12); n > 0; n--) raw += alphabet[int(r, 0, alphabet.length - 1)];
    if (i % 10 === 0) raw = String(int(r, 0, 2147483647));
    const out = s.rights(raw);
    const shapeOk = out === "NONE" || out === "RIGHTS-UNPARSED" || /^0x[0-9a-fA-F]{1,9}$/.test(out) || allowlistedTokens(out);
    if (!shapeOk) bad++;
    if (out === raw && !(/^0x[0-9a-fA-F]{1,8}$/.test(raw) || allowlistedTokens(raw))) echoedInvalid++;
  }
  assert.ok(bad === 0, `${bad} rights outputs fell outside the allowed shapes`);
  assert.ok(echoedInvalid === 0, `${echoedInvalid} invalid rights fields were echoed unchanged`);
});

test("generated SDDL never carries machine-SID text", () => {
  const r = rng(0x5dd1);
  const fixed = ["SY", "BA", "AU", "WD", "S-1-5-18", "S-1-5-11", "S-1-5-32-545", "garbage", ""];
  const rightsPool = ["FA", "0x1200a9", "GRGX", "ZZ", "1179817", ""];
  let leaks = 0;
  for (let i = 0; i < 300; i++) {
    const domains: string[] = [];
    let raw = "D:" + ["", "P", "PAI", "AI"][int(r, 0, 3)];
    for (let a = int(r, 0, 5); a > 0; a--) {
      let who = fixed[int(r, 0, fixed.length - 1)];
      if (r() < 0.6) {
        const g = generatedSid(r);
        domains.push(...g.domain);
        who = g.sid;
      }
      const fields = ["A", "OICI", rightsPool[int(r, 0, rightsPool.length - 1)], "", "", who];
      if (r() < 0.1) fields.pop();
      raw += "(" + fields.join(";") + ")";
    }
    if (r() < 0.1) raw += domains.length ? "-" + domains[0] : "x";
    const out = s.sddl(raw, i % 2 ? ROLES : undefined);
    if (/S-1-5-21/.test(out) || domains.some((d) => out.includes(d))) leaks++;
  }
  assert.ok(leaks === 0, `${leaks} generated SDDL strings carried machine-SID text`);
});

finish();
