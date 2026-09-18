#!/usr/bin/env node
/*
 * Diagnostic fixture: which directory on the way to a store the ancestor rule objects to, and why.
 * Not a test and not product code. The product's refusals are fixed sentences that name nothing;
 * this exists so a refusal in CI can be understood instead of guessed at.
 *
 *   node win-chain-diagnostic.js <path to the built consent-acl-win.js>
 */
"use strict";
const os = require("os"), path = require("path");
const acl = require(process.argv[2]);
const sid = acl.currentUserSid();
console.log("user sid:", sid);
for (const base of [os.tmpdir(), path.join(os.homedir(), ".secretloop"), os.homedir()]) {
  const probe = path.join(base, "probe-store");
  const r = acl.checkWindowsStore(probe, [], sid);
  console.log(base, "=>", r.ok ? "chain-trusted" : r.problem, JSON.stringify(acl.lastRefusalDetail() || {}));
  const chain = acl.ancestorChainOf(path.dirname(path.resolve(probe))) || [];
  const info = acl.inspectPaths(chain);
  if (info.ok) for (const c of chain) {
    const e = info.byPath.get(path.win32.resolve(c).toLowerCase());
    console.log("   ", c, "owner", e && e.ownerSid, "sddl", e && e.sddl);
  }
}
