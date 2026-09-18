/**
 * F-1 Concern A -- deterministic challenges to the PROPOSED contained reader (a prototype in this
 * file, NOT product code). No product module is loaded. Every filesystem change is made by a wrapper
 * around one fs function that fires ONCE after the Nth real call, in this process only, so ordering is
 * by construction. Every case prints: the trigger(s) and whether each fired, the verdict, the opened
 * object's (dev,ino) versus the approved identity, the kernel path (Linux), and whether OUTSIDE bytes
 * were returned. A case whose trigger did not fire is a NON-MEASUREMENT and is printed as such.
 *
 * Synthetic markers only; nothing credential-shaped is written or printed.
 *
 * PROPOSED SEQUENCE UNDER TEST (text reader shape; --nofollow adds O_NOFOLLOW):
 *   realRoot = realpath(root); R = realpath(join(root, rel)); inside(realRoot, R) [component boundary]
 *   Y = lstat(R) identity; must be a regular file
 *   fd = open(join(root, rel), O_RDONLY | O_NONBLOCK [| O_NOFOLLOW])
 *   st = fstat(fd); require st.isFile() && (st.dev, st.ino) == (Y.dev, Y.ino)          -> "identity-mismatch"
 *   [linux] kp = readlink("/proc/self/fd/" + fd); require inside(realRoot, kp) on the RAW string -> "outside(kernel-path)"
 *          (no " (deleted)" stripping: a suffix never makes an outside path inside, and an inside path
 *           with the suffix still starts with realRoot + "/")
 *   bounded read from fd
 */
const fs = require("fs"), os = require("os"), path = require("path"), crypto = require("crypto");
const C = fs.constants;
const KP = process.platform === "linux" && !process.argv.includes("--no-kernel-path");
const NOFOLLOW = process.argv.includes("--nofollow");
const NAIVE = process.argv.includes("--naive-prefix"); // deliberately weak boundary, to show what it accepts
const MARK = "OUTSIDE_" + "MARKER_" + crypto.randomBytes(4).toString("hex");
const LAB = fs.mkdtempSync(path.join(os.tmpdir(), "f1chal-"));
const LABR = fs.realpathSync(LAB);

function inside(realRoot, p) {
  if (NAIVE) return p.startsWith(realRoot);
  // Component boundary: equal, or realRoot + separator prefix. Never a bare string prefix.
  return p === realRoot || p.startsWith(realRoot + path.sep);
}
function readContained(root, rel) {
  const full = path.join(root, rel); let realRoot, R;
  try { realRoot = fs.realpathSync(path.resolve(root)); R = fs.realpathSync(full); } catch (e) { return { v: "vanished(" + e.code + ")" }; }
  if (!inside(realRoot, R)) return { v: "outside(realpath)" };
  let Y; try { Y = fs.lstatSync(R); } catch (e) { return { v: "vanished(" + e.code + ")" }; }
  if (!Y.isFile()) return { v: "not-a-file(pre)" };
  let fd; try { fd = fs.openSync(full, C.O_RDONLY | (C.O_NONBLOCK ?? 0) | (NOFOLLOW ? C.O_NOFOLLOW : 0)); } catch (e) { return { v: "open-failed(" + e.code + ")" }; }
  const info = { approved: `${Y.dev}:${Y.ino}` };
  try {
    const st = fs.fstatSync(fd); info.opened = `${st.dev}:${st.ino}`;
    if (!st.isFile()) return { v: "not-a-file(fstat)", ...info };
    if (st.dev !== Y.dev || st.ino !== Y.ino) return { v: "identity-mismatch", ...info };
    if (KP) {
      let kp; try { kp = fs.readlinkSync("/proc/self/fd/" + fd); } catch (e) { return { v: "kernel-path-unavailable(" + e.code + ")", ...info }; }
      info.kp = kp.replace(LABR, "<lab>");
      if (!inside(realRoot, kp)) return { v: "outside(kernel-path)", ...info };
    }
    const b = Buffer.alloc(65536); let n, total = 0; const chunks = [];
    while ((n = fs.readSync(fd, b, 0, b.length, null)) > 0) { chunks.push(Buffer.from(b.subarray(0, n))); total += n; if (total > 1e6) return { v: "oversized", ...info }; }
    return { v: "TEXT", text: Buffer.concat(chunks).toString("utf8"), ...info };
  } catch (e) { return { v: "unreadable(" + e.code + ")", ...info }; } finally { try { fs.closeSync(fd); } catch {} }
}
function trig(name, nth, fn) { const real = fs[name]; let calls = 0, fired = false; fs[name] = function (...a) { const r = real.apply(this, a); calls++; if (!fired && calls === nth) { fired = true; fn(); } return r; }; return { name, undo: () => { fs[name] = real; return fired; } }; }
let id = 0;
function lab(parent) { const d = path.join(LAB, "c" + (++id)); const root = path.join(d, "root"), out = path.join(d, "out"); fs.mkdirSync(parent ? path.join(root, "sub") : root, { recursive: true }); fs.mkdirSync(out, { recursive: true }); const rel = parent ? "sub/t.txt" : "t.txt"; fs.writeFileSync(path.join(root, rel), "INSIDE"); fs.writeFileSync(path.join(out, "t.txt"), MARK); return { d, root, out, rel, v: path.join(root, rel) }; }
const swapFinal = (L) => { fs.unlinkSync(L.v); fs.symlinkSync(path.join(L.out, "t.txt"), L.v); };
const swapParent = (L) => { fs.rmSync(path.join(L.root, "sub"), { recursive: true, force: true }); fs.symlinkSync(L.out, path.join(L.root, "sub")); };
const restoreParent = (L) => { fs.unlinkSync(path.join(L.root, "sub")); fs.mkdirSync(path.join(L.root, "sub")); fs.writeFileSync(L.v, "INSIDE"); };
const results = [];
function run(code, label, L, arm, expectRefuse) {
  const ts = arm(); let res; try { res = readContained(L.root, L.rel); } finally { var fired = ts.map((t) => t.undo()); }
  const crossed = res.v === "TEXT" && res.text.includes(MARK);
  const nm = ts.length > 0 && !fired.every(Boolean);
  const line = `  ${code} ${label.padEnd(64)} fired=${JSON.stringify(fired)} verdict=${res.v.padEnd(26)} approved=${res.approved || "-"} opened=${res.opened || "-"} kp=${res.kp || "-"} outside-bytes=${crossed ? "YES" : "no"}${nm ? "  <- NON-MEASUREMENT" : ""}`;
  console.log(line); results.push({ code, verdict: res.v, crossed, fired, nonMeasurement: nm, expectRefuse });
}
console.log(`POSIX CHALLENGES platform=${process.platform} ${os.release()} ${process.arch} node=${process.version} kernel-path=${KP} nofollow=${NOFOLLOW} naive-prefix=${NAIVE}`);
// realpathSync call order inside readContained: 1=root, 2=full. lstatSync: 1. openSync: 1. fstatSync: 1. readlinkSync: 1 (linux).
{ const L = lab(false); run("C1 ", "control: unchanged regular file is read", L, () => [], false); }
{ const L = lab(false); fs.unlinkSync(L.v); fs.writeFileSync(path.join(L.root, "real.txt"), "INSIDE"); fs.symlinkSync(path.join(L.root, "real.txt"), L.v); run("C2 ", "control: in-root symlink (legitimate)", L, () => [], NOFOLLOW); }
{ const L = lab(false); fs.unlinkSync(L.v); fs.symlinkSync(path.join(L.out, "t.txt"), L.v); run("C3 ", "control: static outside symlink", L, () => [], true); }
{ const L = lab(false); run("A1 ", "final swap after realpath #2 (before capture)", L, () => [trig("realpathSync", 2, () => swapFinal(L))], true); }
{ const L = lab(false); run("A1'", "final swap after identity capture (after lstat)", L, () => [trig("lstatSync", 1, () => swapFinal(L))], true); }
{ const L = lab(true); run("A2 ", "parent swap after realpath #2 (between realpath and capture)", L, () => [trig("realpathSync", 2, () => swapParent(L))], true); }
{ const L = lab(true); run("A2'", "parent swap after identity capture", L, () => [trig("lstatSync", 1, () => swapParent(L))], true); }
{ const L = lab(true); run("SB ", "parent swap after capture, swapped BACK after open", L, () => [trig("lstatSync", 1, () => swapParent(L)), trig("openSync", 1, () => restoreParent(L))], true); }
{ const L = lab(true); run("DI2", "parent swap between realpath and capture, restored after fstat", L, () => [trig("realpathSync", 2, () => swapParent(L)), trig("fstatSync", 1, () => restoreParent(L))], true); }
// Movement after the containment check / after open
{ const L = lab(true); run("M1 ", "inside parent dir RENAMED within root after open (legit move)", L, () => [trig("fstatSync", 1, () => fs.renameSync(path.join(L.root, "sub"), path.join(L.root, "sub2")))], false); }
{ const L = lab(true); run("M2 ", "inside parent dir MOVED OUT of root after open", L, () => [trig("fstatSync", 1, () => fs.renameSync(path.join(L.root, "sub"), path.join(L.out, "moved")))], "kp-only"); }
{ const L = lab(true); run("M3 ", "outside dir MOVED INTO root at sub after realpath #2 (rename, not symlink)", L, () => [trig("realpathSync", 2, () => { fs.rmSync(path.join(L.root, "sub"), { recursive: true, force: true }); fs.renameSync(L.out, path.join(L.root, "sub")); })], "?"); }
{ const L = lab(false); run("D1 ", "opened inside file DELETED after open", L, () => [trig("fstatSync", 1, () => fs.unlinkSync(L.v))], false); }
{ const L = lab(false); run("D2 ", "opened inside file RENAMED within root after open", L, () => [trig("fstatSync", 1, () => fs.renameSync(L.v, path.join(L.root, "u.txt")))], false); }
// Root replacement / movement (actor with write access to the ROOT'S PARENT -- outside the tree threat model)
{ const L = lab(false); run("R1 ", "root replaced by SYMLINK to outside dir after realpath #2", L, () => [trig("realpathSync", 2, () => { fs.renameSync(L.root, L.root + ".moved"); fs.symlinkSync(L.out, L.root); })], true); }
{ const L = lab(false); run("R2 ", "root MOVED away and outside dir RENAMED into its place after realpath #2", L, () => [trig("realpathSync", 2, () => { fs.renameSync(L.root, L.root + ".moved"); fs.renameSync(L.out, L.root); })], "?"); }
{ const L = lab(false); run("R3 ", "root dir RENAMED (moved) after open", L, () => [trig("fstatSync", 1, () => fs.renameSync(L.root, L.root + ".moved"))], "kp-only"); }
// Component boundary: sibling directory whose name has the root as a string prefix
{ const L = lab(true); const sib = L.root + "2"; fs.mkdirSync(sib); fs.writeFileSync(path.join(sib, "t.txt"), MARK); run("B1 ", "parent swapped to symlink -> SIBLING dir named <root>2 (prefix trap)", L, () => [trig("realpathSync", 2, () => { fs.rmSync(path.join(L.root, "sub"), { recursive: true, force: true }); fs.symlinkSync(sib, path.join(L.root, "sub")); })], true); }
// /proc behaviour probes (linux only; informational)
if (process.platform === "linux") {
  const L = lab(false); const fd = fs.openSync(L.v, "r"); const kp1 = fs.readlinkSync("/proc/self/fd/" + fd); fs.unlinkSync(L.v); const kp2 = fs.readlinkSync("/proc/self/fd/" + fd); fs.closeSync(fd);
  let closed; try { closed = fs.readlinkSync("/proc/self/fd/" + fd); } catch (e) { closed = "throws " + e.code; }
  let bogus; try { bogus = fs.readlinkSync("/proc/self/fd/99999"); } catch (e) { bogus = "throws " + e.code; }
  const p2 = fs.openSync(path.join(L.d, "n\nl.txt"), "w"); fs.writeSync(p2, "x"); const kpn = fs.readlinkSync("/proc/self/fd/" + p2); fs.closeSync(p2);
  console.log(`  P1  /proc/self/fd: open file -> ${kp1.replace(LABR, "<lab>")}; after unlink -> ${kp2.replace(LABR, "<lab>")}; after close -> ${closed}; nonexistent fd -> ${bogus}; name with newline -> ${JSON.stringify(kpn.replace(LABR, "<lab>"))}`);
}
console.log("SUMMARY " + JSON.stringify(results.map((r) => ({ c: r.code.trim(), v: r.verdict, x: r.crossed, nm: r.nonMeasurement }))));
fs.rmSync(LAB, { recursive: true, force: true });
