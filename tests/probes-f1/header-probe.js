/**
 * Does the REAL binary header probe read bytes of an outside object before any shared-reader protection
 * could act? Uses the product's compiled readBinaryCandidate (out/walk.js) with a headerAccepts callback that
 * records what it was handed. Parent swap fires after the product's own lstat gate (A2'). argv: OUT dir.
 */
const fs = require("fs"), os = require("os"), path = require("path"), crypto = require("crypto");
const OUT = process.argv[2]; const walk = require(path.join(OUT, "walk.js"));
const MARK = "OUTSIDE_" + "MARKER_" + crypto.randomBytes(4).toString("hex");
const LAB = fs.mkdtempSync(path.join(os.tmpdir(), "f1hdr-")); const root = path.join(LAB, "root"), out = path.join(LAB, "out");
fs.mkdirSync(path.join(root, "sub"), { recursive: true }); fs.mkdirSync(out); fs.writeFileSync(path.join(root, "sub", "c.bin"), "INSIDE-INSIDE-INSIDE"); fs.writeFileSync(path.join(out, "c.bin"), MARK + "-outside-bytes");
const cfg = { maxFileSizeBytes: 1e6, excludePaths: [], excludeRules: [], allowValues: [], includeGenerated: true, includeEntropy: false };
const real = fs.lstatSync; let fired = false, calls = 0;
fs.lstatSync = function (...a) { const r = real.apply(this, a); calls++; if (!fired && calls === 1) { fired = true; fs.rmSync(path.join(root, "sub"), { recursive: true, force: true }); fs.symlinkSync(out, path.join(root, "sub")); } return r; };
let headSeen = null, headCalls = 0;
let res; try { res = walk.readBinaryCandidate(root, "sub/c.bin", cfg, (head) => { headCalls++; headSeen = head.toString("utf8"); return false; /* "not this format": the bulk read is never reached */ }, 16); } finally { fs.lstatSync = real; }
console.log(`HEADER PROBE (real product, out/walk.js ${crypto.createHash("sha256").update(fs.readFileSync(path.join(OUT, "walk.js"))).digest("hex").slice(0, 16)}) platform=${process.platform}`);
console.log(`  trigger fired=${fired} (lstat calls=${calls}); headerAccepts called ${headCalls}x with ${headSeen === null ? "nothing" : headSeen.length + " bytes"}; head contains OUTSIDE marker: ${headSeen !== null && headSeen.includes(MARK.slice(0, 16)) ? "YES -- outside bytes were READ by the header probe before any bulk-read protection" : "no"}; reader verdict: ${"bytes" in res ? "BYTES" : "skipped=" + res.skipped}`);
fs.rmSync(LAB, { recursive: true, force: true });
