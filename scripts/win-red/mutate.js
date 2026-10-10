#!/usr/bin/env node
"use strict";
// Applies or restores ONE mutation of src/consent-acl-win.ts in a disposable copy (rev4).
// Refuses to apply unless the file equals the bound original; verifies the restore returns it.
//
// usage: node mutate.js <copy-root> <bound.json> apply|restore W1|W2|W3 [diff-out-path]
//   W1: the marker helper writes to stdout instead of stderr
//   W2: a fifth marker line (a second "end") is appended
//   W3: the cmdlet marker's once-only guard is removed
// Each mutation is one exact-string replacement whose anchor must occur exactly once.
const fs = require("fs"), path = require("path"), crypto = require("crypto");
const [root, boundPath, mode, id, diffOut] = process.argv.slice(2);
if (!root || !boundPath || !/^(apply|restore)$/.test(mode || "") || !/^W[123]$/.test(id || "")) { console.log("MUTATE-ERROR: usage <copy-root> <bound.json> apply|restore W1|W2|W3 [diff-out]"); process.exit(2); }
const bound = JSON.parse(fs.readFileSync(boundPath, "utf8"));
const rel = "src/consent-acl-win.ts";
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");
const srcPath = path.join(root, rel);
const MUT = {
  W1: ["\"try{[Console]::Error.WriteLine('\" + HELPER_MARKER_PREFIX + \" \" + stage +",
       "\"try{[Console]::Out.WriteLine('\" + HELPER_MARKER_PREFIX + \" \" + stage +"],
  W2: ['  helperMarker("end"),\n].join("\\n");',
       '  helperMarker("end"),\n  helperMarker("end"),\n].join("\\n");'],
  W3: ['"    if(-not $marked){$marked=$true;" + helperMarker("cmdlet") + "}",',
       '"    " + helperMarker("cmdlet"),'],
};
const [oldText, newText] = MUT[id];
const current = fs.readFileSync(srcPath, "utf8").replace(/\r\n/g, "\n");
if (mode === "apply") {
  if (sha(Buffer.from(current, "utf8")) !== bound.boundFiles[rel]) { console.log("MUTATE-ERROR: " + rel + " is not the bound original; refusing to apply " + id); process.exit(3); }
  const n = current.split(oldText).length - 1;
  if (n !== 1) { console.log("MUTATE-ERROR: anchor for " + id + " occurs " + n + " times (need exactly 1)"); process.exit(4); }
  const mutated = current.replace(oldText, newText);
  fs.writeFileSync(srcPath, mutated);
  if (diffOut) {
    const lineNo = current.slice(0, current.indexOf(oldText)).split("\n").length;
    const out = ["--- " + rel + "@bound", "+++ " + rel + "@" + id, "@@ line " + lineNo + " @@"];
    for (const l of oldText.split("\n")) out.push("-" + l);
    for (const l of newText.split("\n")) out.push("+" + l);
    fs.writeFileSync(diffOut, out.join("\n") + "\n");
  }
  console.log("MUTATE-OK: " + id + " applied (src sha256 now " + sha(Buffer.from(mutated, "utf8")).slice(0, 16) + "...)");
} else {
  const restored = current.replace(newText, oldText);
  fs.writeFileSync(srcPath, restored);
  const ok = sha(Buffer.from(restored, "utf8")) === bound.boundFiles[rel];
  console.log(ok ? "RESTORE-OK: " + rel + " equals the bound original" : "RESTORE-ERROR: " + rel + " does NOT equal the bound original after restoring " + id);
  process.exit(ok ? 0 : 5);
}
