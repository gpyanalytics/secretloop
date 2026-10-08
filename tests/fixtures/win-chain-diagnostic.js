#!/usr/bin/env node
"use strict";
/**
 * Where the ancestor rule draws the line, as the CURRENT account sees it. Diagnostic only; it
 * asserts nothing. Usage:
 *   node win-chain-diagnostic.js <out/consent-acl-win.js>                  the three profile/temp probes
 *   node win-chain-diagnostic.js <out/consent-acl-win.js> --base <dir>...  the chain above each <dir>
 * Every printed value passes through tests/fixtures/win-acl-sanitize.js BEFORE it is written:
 * components as depth + allowlisted name, identities as fixed labels or job roles, SDDL with every
 * SID replaced, rights as validated masks. No path text, machine SID, account or VM name is printed.
 */
const os = require("os"), path = require("path");
const acl = require(process.argv[2]);
const sanitize = require(path.join(__dirname, "win-acl-sanitize.js"));
const bases = [];
for (let i = 3; i < process.argv.length; i++) if (process.argv[i] === "--base" && process.argv[i + 1]) bases.push(process.argv[++i]);
const sid = acl.currentUserSid();
const roles = sanitize.rolesFromEnv(process.env, sid);
console.log("user:", sanitize.principal(sid, roles));
const probes = bases.length
  ? bases.map((b) => ({ label: "fixture chain", probe: b }))
  : [
      { label: "os temp", probe: path.join(os.tmpdir(), "probe-store") },
      { label: "profile .secretloop", probe: path.join(os.homedir(), ".secretloop") },
      { label: "profile", probe: path.join(os.homedir(), "probe-store") },
    ];
for (const { label, probe } of probes) {
  let verdict;
  try {
    const r = acl.checkWindowsStore(probe, [], sid);
    verdict = r.ok ? "chain-trusted" : r.problem;
  } catch {
    verdict = "check threw";
  }
  const chain = acl.ancestorChainOf(path.dirname(path.resolve(probe))) || [];
  console.log(label, "=>", verdict, "|", sanitize.refusalDetail(acl.lastRefusalDetail(), chain, roles), "| chain depth", chain.length);
  let info;
  try { info = acl.inspectPaths(chain); } catch { info = { ok: false, problem: "inspect threw" }; }
  if (!info.ok) { console.log("    inspection:", String(info.problem).replace(/[^a-z-]/g, "")); continue; }
  chain.forEach((c, depth) => {
    const e = info.byPath.get(path.win32.resolve(c).toLowerCase());
    if (!e) { console.log("    depth", depth, sanitize.component(c, chain), "=> not inspected"); return; }
    console.log("    " + sanitize.component(c, chain), "| owner", sanitize.principal(e.ownerSid, roles),
      "| dir", e.isDirectory === true, "| reparse", e.isReparsePoint === true, "| exists", e.exists === true,
      "| unreadable", e.unreadable === true, "|", sanitize.sddl(e.sddl, roles));
  });
}
