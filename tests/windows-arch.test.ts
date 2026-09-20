import { test, suite, finish, assert, skip } from "./harness";
import { existsSync, openSync, readSync, closeSync, statSync } from "fs";
import { spawnSync } from "child_process";
import * as os from "os";
import * as path from "path";
import * as acl from "../src/consent-acl-win";

/**
 * WHERE THE WINDOWS HELPERS COME FROM, AND WHETHER THEY MATCH THE PROCESS.
 *
 * `src/consent-acl-win.ts` does not search PATH. It builds absolute paths under
 * `%SystemRoot%\System32` for powershell.exe, icacls.exe and whoami.exe. On x64 Windows that is
 * unambiguous. On **Windows on ARM64 it is not**: System32 holds the NATIVE binaries, and a
 * process running under emulation is redirected elsewhere by the WOW layer, so the same literal
 * path can resolve to a different architecture depending on what is asking.
 *
 * That makes two things worth pinning, and neither was covered before:
 *
 *   1. the helper the product will actually spawn EXISTS at the path it computes, and
 *   2. its machine type MATCHES the process's own architecture -- so a native process gets
 *      native tools and there is no silent redirection.
 *
 * (2) is read from the executable's own PE COFF header rather than inferred from environment
 * variables, because `PROCESSOR_ARCHITECTURE` describes what the process was told, which is
 * exactly the thing under suspicion. The header is the file's own statement about itself.
 *
 * Deliberately NOT asserted here: that the architecture is arm64. This file must pass on x64
 * Windows too, and pinning an architecture would turn a portability test into a platform gate.
 * The ARM64 claim is asserted by the CI job that runs on the ARM64 runner, where it is a
 * property of the environment rather than of the product.
 *
 * Nothing here touches a real consent store. The one end-to-end case builds a disposable
 * directory and asks the product's own checker about it.
 */

const WINDOWS = process.platform === "win32";

/** PE COFF machine types, from the PE format the loader itself reads. */
const MACHINE: Record<number, string> = {
  0x014c: "i386",
  0x8664: "x64",
  0xaa64: "arm64",
  0x01c4: "armv7",
};

/**
 * The machine type an executable declares, read from its own PE header.
 *
 * Layout, all little-endian: bytes 0..1 are "MZ"; the 4-byte offset at 0x3C points at the PE
 * signature "PE\0\0"; the COFF header follows it and opens with the 2-byte machine field.
 * Returns null rather than throwing for anything that is not a PE file, so a surprising path
 * produces a legible failure instead of a stack trace.
 */
function peMachine(file: string): string | null {
  let fd: number;
  try {
    fd = openSync(file, "r");
  } catch {
    return null;
  }
  try {
    const head = Buffer.alloc(0x40);
    if (readSync(fd, head, 0, head.length, 0) < head.length) return null;
    if (head[0] !== 0x4d || head[1] !== 0x5a) return null; // not "MZ"
    const peAt = head.readUInt32LE(0x3c);
    const sig = Buffer.alloc(6);
    if (readSync(fd, sig, 0, sig.length, peAt) < sig.length) return null;
    if (sig.readUInt32LE(0) !== 0x00004550) return null; // not "PE\0\0"
    return MACHINE[sig.readUInt16LE(4)] ?? `unknown(0x${sig.readUInt16LE(4).toString(16)})`;
  } finally {
    closeSync(fd);
  }
}

/** The three absolute helper paths the product computes, resolved the same way it resolves them. */
function helperPaths(): { name: string; file: string }[] {
  const systemRoot = process.env.SystemRoot || "C:\\Windows";
  const system32 = path.join(systemRoot, "System32");
  return [
    { name: "powershell.exe", file: path.join(system32, "WindowsPowerShell", "v1.0", "powershell.exe") },
    { name: "icacls.exe", file: path.join(system32, "icacls.exe") },
    { name: "whoami.exe", file: path.join(system32, "whoami.exe") },
  ];
}

suite("Windows helper architecture");

test("the environment is recorded, so a later reader knows what these results describe", () => {
  // Never a pass/fail on the values: this case exists so the log carries the environment the
  // other cases were measured in. A result with no environment is not evidence.
  const lines = [
    `platform=${process.platform}`,
    `process.arch=${process.arch}`,
    `os.arch=${os.arch()}`,
    `os.release=${os.release()}`,
    `node=${process.version}`,
    `execPath=${process.execPath}`,
    `SystemRoot=${process.env.SystemRoot ?? "(unset)"}`,
    `PROCESSOR_ARCHITECTURE=${process.env.PROCESSOR_ARCHITECTURE ?? "(unset)"}`,
    `PROCESSOR_ARCHITEW6432=${process.env.PROCESSOR_ARCHITEW6432 ?? "(unset)"}`,
  ];
  for (const l of lines) console.log(`      env: ${l}`);
  assert.strictEqual(process.arch, os.arch(), "the process and the OS must agree about the architecture");
});

test("PROCESSOR_ARCHITEW6432 is the emulation tell, and it is reported rather than trusted", () => {
  if (!WINDOWS) return skip("Windows-only. The WOW layer does not exist elsewhere.");
  // Windows sets PROCESSOR_ARCHITEW6432 only for a process running under emulation, where
  // PROCESSOR_ARCHITECTURE reports the EMULATED architecture and ARCHITEW6432 the real machine.
  // It is recorded because it is the cheapest signal, and it is NOT the basis of the decision:
  // the PE header check below does not depend on any environment variable.
  const emulated = Boolean(process.env.PROCESSOR_ARCHITEW6432);
  console.log(`      emulation indicated by PROCESSOR_ARCHITEW6432: ${emulated ? "YES" : "no"}`);
  assert.ok(true, "recorded, not asserted");
});

test("every helper the product will spawn exists at the absolute path the product computes", () => {
  if (!WINDOWS) return skip("Windows-only. These paths exist on no other platform.");
  for (const { name, file } of helperPaths()) {
    assert.ok(existsSync(file), `${name} must exist at ${file}; the product does not search PATH`);
    assert.ok(statSync(file).isFile(), `${name} must be a regular file, not a directory or link target`);
  }
});

test("each helper's PE machine type matches the process architecture, so nothing is redirected", () => {
  if (!WINDOWS) return skip("Windows-only. PE headers are a Windows executable format.");
  // THE ARM64 CASE THIS FILE EXISTS FOR. A native arm64 process must get arm64 helpers. If the
  // WOW layer redirected the literal System32 path, the machine type would disagree and this
  // fails with both values named.
  for (const { name, file } of helperPaths()) {
    const m = peMachine(file);
    assert.ok(m !== null, `${name} at ${file} is not a readable PE image`);
    assert.strictEqual(
      m,
      process.arch,
      `${name} is a ${m} image while this process is ${process.arch}: the literal System32 path ` +
        `resolved to a differently built binary, which is what WOW redirection looks like`
    );
  }
});

test("the helper really runs here and returns a response the product's own parser accepts", () => {
  if (!WINDOWS) return skip("Windows-only. There is no helper to invoke elsewhere.");
  // Existence and architecture are not execution. This spawns the same whoami.exe the product
  // spawns, with the product's own argument shape, and requires a SID out of it -- so a helper
  // that is present but unusable on this architecture is caught here rather than surfacing as a
  // consent refusal with no explanation.
  const systemRoot = process.env.SystemRoot || "C:\\Windows";
  const whoami = path.join(systemRoot, "System32", "whoami.exe");
  const r = spawnSync(whoami, ["/user", "/fo", "csv", "/nh"], {
    encoding: "utf8",
    timeout: 20_000,
    windowsHide: true,
  });
  assert.strictEqual(r.error, undefined, `whoami.exe failed to start: ${r.error?.message}`);
  assert.strictEqual(r.status, 0, `whoami.exe exited ${r.status}`);
  const sid = /(S-1-5-21-[0-9-]+)/.exec(r.stdout ?? "");
  assert.ok(sid, `whoami.exe produced no parseable SID; got ${JSON.stringify((r.stdout ?? "").slice(0, 120))}`);
});

test("the product's own Windows checker reaches a decision on this architecture", () => {
  if (!WINDOWS) return skip("Windows-only. checkWindowsStore is a no-op elsewhere.");
  // End to end through the product, on a disposable directory, with no real store involved.
  // What is asserted is that a DECISION is reached -- accept or a named refusal -- and
  // specifically NOT `acl-tool-unavailable`, which is what a helper that cannot run here would
  // produce. Whether this particular temp directory is acceptable is not the point and is not
  // asserted: the runner's TEMP shape is an environment fact, not a product property.
  const dir = path.join(os.tmpdir(), `sl-arch-${process.pid}`);
  // The same three arguments the product passes: the store directory, the targets in scope, and
  // the current user's SID as the helper itself reports it. An empty target list is the shape
  // `ensureDirWindows` uses before the store exists, so the ancestor rule alone is exercised.
  const sid = acl.currentUserSid();
  assert.ok(sid, "the helper could not report this account's SID on this architecture");
  const verdict = acl.checkWindowsStore(dir, [], sid as string);
  const outcome = verdict.ok ? "accept" : verdict.problem;
  console.log(`      checkWindowsStore(${dir}) -> ${outcome}`);
  assert.notStrictEqual(
    outcome,
    "acl-tool-unavailable",
    "the helper could not be run on this architecture, so no store check is possible here"
  );
});

finish();
