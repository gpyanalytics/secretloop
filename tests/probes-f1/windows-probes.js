/**
 * F-1 Concern A -- native WINDOWS probes W1..W6 (no product code). Runs on every platform but the
 * Windows-specific items report NOT APPLICABLE elsewhere. Every potentially blocking or privileged
 * operation runs in THIS process only where it cannot block; anything that could block runs in a child
 * with a hard timeout. Expected platform refusals are printed with their error code; an UNEXPECTED
 * error is printed as such and makes the process exit non-zero (never a skip).
 */
const fs = require("fs"), os = require("os"), path = require("path"), cp = require("child_process"), crypto = require("crypto");
const C = fs.constants; const WIN = process.platform === "win32";
const LAB = fs.mkdtempSync(path.join(os.tmpdir(), "f1win-")); const MARK = "OUTSIDE_" + "MARKER_" + crypto.randomBytes(4).toString("hex");
let unexpected = 0;
const say = (s) => console.log("  " + s);
const attempt = (label, fn, expectedCodes) => { try { const r = fn(); say(`${label}: OK ${r === undefined ? "" : r}`); return { ok: true, r }; } catch (e) { const code = e.code || e.message; if (expectedCodes && expectedCodes.includes(code)) { say(`${label}: refused ${code} (an expected platform refusal)`); } else { say(`${label}: ERROR ${code} (unexpected)`); unexpected++; } return { ok: false, code }; } };
console.log(`WINDOWS PROBES platform=${process.platform} ${os.release()} ${process.arch} node=${process.version} libuv=${process.versions.uv} tmp=${os.tmpdir()}`);
// Environment: filesystem and privilege (Windows only; informational)
if (WIN) {
  const drive = path.parse(LAB).root; const fsinfo = cp.spawnSync("fsutil", ["fsinfo", "volumeinfo", drive], { encoding: "utf8" });
  say(`W0 volume ${drive}: ${(fsinfo.stdout || "").split(/\r?\n/).filter((l) => /File System Name/i.test(l)).join("") || "fsutil unavailable: " + (fsinfo.error || fsinfo.stderr || "").toString().slice(0, 80)}`);
  const elev = cp.spawnSync("powershell", ["-NoProfile", "-Command", "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"], { encoding: "utf8" });
  say(`W0 elevated (Administrator role): ${(elev.stdout || "").trim() || "unknown"}; symlink privilege probe below`);
}
// W1 constants and numeric flags
say(`W1 constants: O_RDONLY=${C.O_RDONLY} O_NONBLOCK=${C.O_NONBLOCK} O_NOFOLLOW=${C.O_NOFOLLOW} O_DIRECTORY=${C.O_DIRECTORY} O_SYMLINK=${C.O_SYMLINK}`);
{ const f = path.join(LAB, "w1.txt"); fs.writeFileSync(f, "A".repeat(100000)); const fd = fs.openSync(f, C.O_RDONLY | (C.O_NONBLOCK ?? 0)); const b = Buffer.alloc(65536); let n, t = 0; while ((n = fs.readSync(fd, b, 0, b.length, null)) > 0) t += n; const st = fs.fstatSync(fd); fs.closeSync(fd); say(`W1 open with numeric flags ${C.O_RDONLY | (C.O_NONBLOCK ?? 0)}: read ${t}/100000, fstat.isFile=${st.isFile()}`); }
// W2 dev/ino identity semantics
{ const a = path.join(LAB, "w2a.txt"), b = path.join(LAB, "w2b.txt"); fs.writeFileSync(a, "1"); fs.writeFileSync(b, "2");
  const fd1 = fs.openSync(a, "r"); const s1 = fs.fstatSync(fd1); const l1 = fs.lstatSync(a); const st1 = fs.statSync(a); fs.closeSync(fd1); const fd2 = fs.openSync(a, "r"); const s2 = fs.fstatSync(fd2); fs.closeSync(fd2); const lb = fs.lstatSync(b);
  say(`W2 identity: fstat=${s1.dev}:${s1.ino} lstat=${l1.dev}:${l1.ino} stat=${st1.dev}:${st1.ino} -> agree=${s1.dev===l1.dev&&s1.ino===l1.ino&&s1.ino===st1.ino}; second open fstat=${s2.dev}:${s2.ino} stable=${s1.ino===s2.ino&&s1.dev===s2.dev}; other file ${lb.dev}:${lb.ino} distinct=${lb.ino!==l1.ino}; nonzero=${l1.ino!==0&&l1.dev!==0}; ino is ${typeof l1.ino} (bigint-safe: ${Number.isSafeInteger(l1.ino)})`);
  fs.unlinkSync(a); fs.writeFileSync(a, "3"); const l3 = fs.lstatSync(a); say(`W2 after unlink+recreate same name: ${l3.dev}:${l3.ino} same-as-before=${l3.ino===l1.ino&&l3.dev===l1.dev}`);
  const fdo = fs.openSync(a, "r"); const so = fs.fstatSync(fdo); const rr = attempt("W2 unlink while open (delete semantics)", () => fs.unlinkSync(a), ["EPERM", "EBUSY"]); const rc = attempt("W2 re-create same name while old handle open", () => { fs.writeFileSync(a, "4"); return fs.lstatSync(a).ino; }, ["EPERM", "EBUSY", "EACCES"]); fs.closeSync(fdo); say(`W2 opened object during that: ${so.dev}:${so.ino}${rc.ok ? " ; re-created object ino=" + rc.r + " differs=" + (rc.r !== so.ino) : ""}`); }
// W3 links: what can be created, what open follows; then the identity prototype challenges
function inside(rr, p) { return p === rr || p.startsWith(rr + path.sep); }
function readContained(root, rel) { const full = path.join(root, rel); let realRoot, R; try { realRoot = fs.realpathSync(path.resolve(root)); R = fs.realpathSync(full); } catch (e) { return "vanished(" + e.code + ")"; } if (!inside(realRoot, R)) return "outside(realpath)"; let Y; try { Y = fs.lstatSync(R); } catch (e) { return "vanished(" + e.code + ")"; } if (!Y.isFile()) return "not-a-file(pre)"; let fd; try { fd = fs.openSync(full, C.O_RDONLY | (C.O_NONBLOCK ?? 0)); } catch (e) { return "open-failed(" + e.code + ")"; } try { const st = fs.fstatSync(fd); if (!st.isFile()) return "not-a-file(fstat)"; if (st.dev !== Y.dev || st.ino !== Y.ino) return "identity-mismatch"; const t = fs.readFileSync(fd, "utf8"); return t.includes(MARK) ? "TEXT(OUTSIDE BYTES)" : "TEXT(inside)"; } catch (e) { return "unreadable(" + e.code + ")"; } finally { try { fs.closeSync(fd); } catch {} } }
function trig(name, nth, fn) { const real = fs[name]; let calls = 0, fired = false; fs[name] = function (...a) { const r = real.apply(this, a); calls++; if (!fired && calls === nth) { fired = true; fn(); } return r; }; return () => { fs[name] = real; return fired; }; }
{ const d = path.join(LAB, "w3"); const root = path.join(d, "root"), out = path.join(d, "out"); fs.mkdirSync(path.join(root, "sub"), { recursive: true }); fs.mkdirSync(out); fs.writeFileSync(path.join(out, "t.txt"), MARK); fs.writeFileSync(path.join(root, "sub", "t.txt"), "INSIDE"); fs.writeFileSync(path.join(root, "f.txt"), "INSIDE");
  const fileLink = attempt("W3 create FILE symlink", () => fs.symlinkSync(path.join(out, "t.txt"), path.join(root, "fl.txt"), "file"), ["EPERM"]);
  const dirLink = attempt("W3 create DIRECTORY symlink", () => fs.symlinkSync(out, path.join(root, "dl"), "dir"), ["EPERM"]);
  const junc = attempt("W3 create JUNCTION", () => fs.symlinkSync(out, path.join(root, "jn"), "junction"), ["EPERM"]);
  if (fileLink.ok) say(`W3 open through FILE symlink: ${(() => { try { return fs.readFileSync(path.join(root, "fl.txt"), "utf8").includes(MARK) ? "followed (outside bytes)" : "?"; } catch (e) { return "refused " + e.code; } })()}`);
  if (dirLink.ok) say(`W3 open through DIRECTORY-symlink parent: ${(() => { try { return fs.readFileSync(path.join(root, "dl", "t.txt"), "utf8").includes(MARK) ? "followed (outside bytes)" : "?"; } catch (e) { return "refused " + e.code; } })()}`);
  if (junc.ok) say(`W3 open through JUNCTION parent: ${(() => { try { return fs.readFileSync(path.join(root, "jn", "t.txt"), "utf8").includes(MARK) ? "followed (outside bytes)" : "?"; } catch (e) { return "refused " + e.code; } })()}; realpath(jn)=${(() => { try { return fs.realpathSync(path.join(root, "jn")) === fs.realpathSync(out) ? "resolves to out (containment check sees it)" : "?"; } catch (e) { return "realpath " + e.code; } })()}`);
  // prototype challenges with the mechanism available: junction for parent swaps (no privilege), file symlink for final swaps (if permitted)
  const mkParent = (mech) => (L) => { fs.rmSync(path.join(L.root, "sub"), { recursive: true, force: true }); fs.symlinkSync(L.out, path.join(L.root, "sub"), mech); };
  const restore = (L) => { fs.rmSync(path.join(L.root, "sub"), { recursive: true, force: true }); fs.mkdirSync(path.join(L.root, "sub")); fs.writeFileSync(path.join(L.root, "sub", "t.txt"), "INSIDE"); };
  let n = 0; const lab = () => { const dd = path.join(d, "L" + (++n)); const r = path.join(dd, "root"), o = path.join(dd, "out"); fs.mkdirSync(path.join(r, "sub"), { recursive: true }); fs.mkdirSync(o); fs.writeFileSync(path.join(o, "t.txt"), MARK); fs.writeFileSync(path.join(r, "sub", "t.txt"), "INSIDE"); return { root: r, out: o }; };
  for (const mech of ["junction", "dir"]) {
    if ((mech === "junction" && !junc.ok) || (mech === "dir" && !dirLink.ok)) { say(`W3 ${mech} challenges: NOT RUN (this runner cannot create a ${mech})`); continue; }
    const cases = [["A2  parent swap after realpath #2", (L) => [trig("realpathSync", 2, () => mkParent(mech)(L))]], ["A2' parent swap after lstat", (L) => [trig("lstatSync", 1, () => mkParent(mech)(L))]], ["SB  parent swap after lstat, restored after open", (L) => [trig("lstatSync", 1, () => mkParent(mech)(L)), trig("openSync", 1, () => restore(L))]], ["DI2 parent swap after realpath #2, restored after fstat", (L) => [trig("realpathSync", 2, () => mkParent(mech)(L)), trig("fstatSync", 1, () => restore(L))]]];
    for (const [label, arm] of cases) { const L = lab(); const us = arm(L); let v; try { v = readContained(L.root, "sub/t.txt"); } catch (e) { v = "THREW " + e.code; unexpected++; } finally { var fired = us.map((u) => u()); } say(`W3 [${mech}] ${label.padEnd(52)} fired=${JSON.stringify(fired)} -> ${v}${fired.every(Boolean) ? "" : "  <- NON-MEASUREMENT"}`); }
  }
  if (fileLink.ok) { const L = lab(); fs.writeFileSync(path.join(L.root, "f.txt"), "INSIDE"); const u = trig("lstatSync", 1, () => { fs.unlinkSync(path.join(L.root, "f.txt")); fs.symlinkSync(path.join(L.out, "t.txt"), path.join(L.root, "f.txt"), "file"); }); let v; try { v = readContained(L.root, "f.txt"); } finally { var f1 = u(); } say(`W3 [file symlink] A1' final swap after lstat                       fired=${JSON.stringify([f1])} -> ${v}`); } else say("W3 [file symlink] A1 challenges: NOT RUN (no symlink privilege)"); }
// W4 directory replacement / movement with an OPEN child handle (runs in a child with a hard timeout)
{ const script = `
  const fs=require("fs"),path=require("path"); const d=process.argv[1]; const root=path.join(d,"root"),out=path.join(d,"out");
  fs.mkdirSync(path.join(root,"sub"),{recursive:true}); fs.mkdirSync(out); fs.writeFileSync(path.join(root,"sub","t.txt"),"INSIDE"); fs.writeFileSync(path.join(out,"t.txt"),"OUT");
  const fd=fs.openSync(path.join(root,"sub","t.txt"),"r"); const r={};
  const t=(k,f)=>{try{f();r[k]="OK";}catch(e){r[k]=e.code||String(e);}};
  t("rename parent dir while child open",()=>fs.renameSync(path.join(root,"sub"),path.join(root,"sub2")));
  t("rename it back",()=>fs.renameSync(path.join(root,"sub2"),path.join(root,"sub")));
  t("rmdir parent while child open",()=>fs.rmSync(path.join(root,"sub"),{recursive:true,force:false}));
  t("replace parent with junction while child open",()=>{fs.rmSync(path.join(root,"sub"),{recursive:true,force:true});fs.symlinkSync(out,path.join(root,"sub"),"junction");});
  t("read from the still-open child handle",()=>{const b=Buffer.alloc(16);const n=fs.readSync(fd,b,0,16,0);r.bytes=b.toString("utf8",0,n);});
  t("move ROOT while child open",()=>fs.renameSync(root,root+".moved"));
  fs.closeSync(fd); process.stdout.write(JSON.stringify(r));`;
  const d = path.join(LAB, "w4"); fs.mkdirSync(d); const c = cp.spawnSync(process.execPath, ["-e", script, d], { encoding: "utf8", timeout: 20000 });
  if (c.error && c.error.code === "ETIMEDOUT") { say("W4 BLOCKED: child killed after 20 s"); unexpected++; } else if (c.status !== 0) { say("W4 child failed: " + (c.stderr || "").slice(-200)); unexpected++; } else { const r = JSON.parse(c.stdout); for (const k of Object.keys(r)) say(`W4 ${k}: ${r[k]}`); } }
// W5 FIFO analogue on this platform
{ const r = cp.spawnSync(WIN ? "where" : "which", ["mkfifo"], { encoding: "utf8" }); say(`W5 mkfifo on PATH: ${r.status === 0 ? "yes" : "no"}; a Windows named pipe lives under \\\\.\\pipe\\ and cannot be a directory entry inside a repository; the FIFO window has no NTFS-path form (documented, not measurable as a file)`); if (WIN) { let e; try { fs.realpathSync(path.join(LAB, "\\\\.\\pipe\\f1probe")); e = "resolved?!"; } catch (x) { e = x.code; } say(`W5 realpath of a pipe-namespace name joined under the lab: ${e}`); } }
// W6 kernel path of an open handle
{ const f = path.join(LAB, "w6.txt"); fs.writeFileSync(f, "x"); const fd = fs.openSync(f, "r"); let a, b; try { a = fs.readlinkSync("/proc/self/fd/" + fd); } catch (e) { a = "throws " + e.code; } try { b = fs.realpathSync.native("/dev/fd/" + fd); } catch (e) { b = "throws " + e.code; } fs.closeSync(fd); say(`W6 kernel path of an open handle: /proc/self/fd -> ${String(a).replace(LAB, "<lab>")}; /dev/fd realpath -> ${String(b).replace(LAB, "<lab>")}`); }
fs.rmSync(LAB, { recursive: true, force: true });
console.log(`WINDOWS PROBES DONE unexpected-errors=${unexpected}`);
process.exitCode = unexpected > 0 ? 1 : 0;
