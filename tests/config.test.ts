import {
  globToRegExp,
  isPathExcluded,
  mergeConfig,
  fingerprint,
  defaultConfig,
  resolveConfigFile,
  loadConfig,
  loadConfigWithSource,
  ConfigReadError,
  CONFIG_FILENAME,
} from "../src/config";
import { mkdtempSync, mkdirSync, symlinkSync, writeFileSync, chmodSync, rmSync } from "node:fs";
import { execFileSync, spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { test, suite, finish, assert, skip } from "./harness";

suite("config.ts");

test("** matches across directory segments", () => {
  assert.ok(globToRegExp("**/node_modules/**").test("a/b/node_modules/c/d.js"));
  assert.ok(globToRegExp("**/node_modules/**").test("node_modules/c.js"));
});

test("* does not cross a directory separator", () => {
  assert.ok(globToRegExp("*.min.js").test("bundle.min.js"));
  assert.strictEqual(globToRegExp("*.min.js").test("dist/bundle.min.js"), false);
});

test("dots in a glob are literal, not wildcards", () => {
  assert.strictEqual(globToRegExp("*.min.js").test("bundleXminXjs"), false);
});

test("default excludes cover lockfiles and vendored code", () => {
  const config = defaultConfig;
  assert.ok(isPathExcluded("package-lock.json", config));
  assert.ok(isPathExcluded("frontend/node_modules/pkg/index.js", config));
  assert.ok(isPathExcluded("dist/app.min.js", config));
  assert.strictEqual(isPathExcluded("src/index.ts", config), false);
});

test("user excludes add to defaults rather than replacing them", () => {
  const config = mergeConfig({ excludePaths: ["testdata/**"] });
  assert.ok(isPathExcluded("testdata/keys.json", config), "user pattern applies");
  assert.ok(isPathExcluded("node_modules/x.js", config), "built-in defaults survive");
});

test("fingerprint is path-normalized and value-derived", () => {
  const a = fingerprint("./src/app.ts", "github-token", "ghp_abc");
  const b = fingerprint("src/app.ts", "github-token", "ghp_abc");
  assert.strictEqual(a, b, "./ prefix must not create a distinct identity");
  assert.ok(!a.includes("ghp_abc"), "fingerprint must not embed the raw secret");
});

suite("\nconfig.ts — rebrand compatibility");

function withTempRepo(files: Record<string, string>, fn: (dir: string) => void): void {
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-test-"));
  try {
    for (const [name, body] of Object.entries(files)) {
      writeFileSync(path.join(dir, name), body, "utf8");
    }
    fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("reads the current .secretloop.json config filename", () => {
  withTempRepo({ [CONFIG_FILENAME]: JSON.stringify({ entropyThreshold: 5.1 }) }, (dir) => {
    const found = resolveConfigFile(dir);
    assert.ok(found);
    assert.strictEqual(found!.path.endsWith(CONFIG_FILENAME), true);
  });
});

test("no config file yields no notice and no error", () => {
  withTempRepo({}, (dir) => {
    assert.strictEqual(resolveConfigFile(dir), null);
  });
});

suite("\nconfig.ts — allowValues are regexes, and are checked once");

test("an invalid allowValues pattern is rejected at load", () => {
  // scanner.ts compiles these with `new RegExp` on every scan, and the editor
  // scans after every 400ms of typing. Unchecked, one bad pattern in a project
  // config is an unhandled rejection per keystroke with no diagnostics and no
  // visible symptom.
  assert.throws(
    () => mergeConfig({ allowValues: ["[unclosed"] }),
    (err: Error) => {
      assert.match(err.message, /allowValues/, "the message should name the field");
      assert.match(err.message, /\[unclosed/, "and quote the pattern that failed");
      return true;
    }
  );
});

test("loadConfig names the file a bad pattern came from", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "secretloop-cfg-"));
  try {
    writeFileSync(path.join(dir, ".secretloop.json"), JSON.stringify({ allowValues: ["a(b"] }), "utf8");
    assert.throws(
      () => loadConfig(dir),
      (err: Error) => {
        assert.match(err.message, /\.secretloop\.json/);
        assert.match(err.message, /allowValues/);
        // Valid JSON that means something impossible is not a parse failure,
        // and saying so sends people looking for a syntax error they will not
        // find.
        assert.doesNotMatch(err.message, /could not parse/i);
        return true;
      }
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("valid patterns still load", () => {
  const config = mergeConfig({ allowValues: ["^EXAMPLE_", "test-[0-9]+$"] });
  assert.deepStrictEqual(config.allowValues, ["^EXAMPLE_", "test-[0-9]+$"]);
});

test("loadConfigWithSource keeps absent distinguishable from explicit false", () => {
  // The merged boolean cannot carry this once the default is false: absent and
  // explicit-false both merge to false. The VS Code precedence rules depend on
  // telling them apart, so `raw` is what they consult.
  const dir = mkdtempSync(path.join(tmpdir(), "sl-cfg-src-"));
  try {
    assert.strictEqual(loadConfigWithSource(dir).raw, null, "no config file at all");

    writeFileSync(path.join(dir, CONFIG_FILENAME), JSON.stringify({ excludeRules: [] }));
    const silent = loadConfigWithSource(dir);
    assert.strictEqual(silent.config.entropyPassEnabled, false, "merged: default false");
    assert.strictEqual(silent.raw?.entropyPassEnabled, undefined, "raw: field absent");

    writeFileSync(path.join(dir, CONFIG_FILENAME), JSON.stringify({ entropyPassEnabled: false }));
    const explicit = loadConfigWithSource(dir);
    assert.strictEqual(explicit.config.entropyPassEnabled, false, "merged: identical false");
    assert.strictEqual(explicit.raw?.entropyPassEnabled, false, "raw: explicitly false");

    writeFileSync(path.join(dir, CONFIG_FILENAME), JSON.stringify({ entropyPassEnabled: true }));
    const on = loadConfigWithSource(dir);
    assert.strictEqual(on.config.entropyPassEnabled, true, "merged: true");
    assert.strictEqual(on.raw?.entropyPassEnabled, true, "raw: explicitly true");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("loadConfig still returns just the merged config", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sl-cfg-compat-"));
  try {
    writeFileSync(path.join(dir, CONFIG_FILENAME), JSON.stringify({ entropyPassEnabled: true }));
    assert.deepStrictEqual(loadConfig(dir), loadConfigWithSource(dir).config);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// A FIFO has no bytes to read: opening one for reading waits for a writer that
// never comes. Each case runs in a child process under a hard timeout, so a hang
// fails the assertion instead of stopping the test runner. READY is written
// before the call, so a child that never started is reported as a harness fault
// and not as the defect.
const TS_NODE = require.resolve("ts-node/register/transpile-only");
const CONFIG_MODULE = path.join(__dirname, "..", "src", "config.ts");

function loadInChild(call: string): { started: boolean; hung: boolean; out: string } {
  const script =
    `const fs = require("fs"); const c = require(${JSON.stringify(CONFIG_MODULE)});` +
    ` fs.writeSync(1, "READY\\n");` +
    ` try { ${call}; fs.writeSync(1, "LOADED\\n"); }` +
    ` catch (err) { fs.writeSync(1, "REFUSED: " + err.message + "\\n"); fs.writeSync(1, "CODE: " + err.code + "\\n"); }`;
  const r = spawnSync(process.execPath, ["-r", TS_NODE, "-e", script], {
    encoding: "utf8",
    timeout: 15000,
    killSignal: "SIGKILL",
  });
  const out = r.stdout ?? "";
  const error = r.error as NodeJS.ErrnoException | undefined;
  return { started: out.includes("READY"), hung: error?.code === "ETIMEDOUT", out };
}

test("loadConfig refuses a FIFO named .secretloop.json rather than waiting on it", () => {
  if (process.platform === "win32") skip("FIFOs are POSIX; Windows has no named pipe at a config path");
  const dir = mkdtempSync(path.join(tmpdir(), "sl-cfg-fifo-"));
  try {
    execFileSync("mkfifo", [path.join(dir, CONFIG_FILENAME)], { stdio: "ignore", timeout: 5000 });
    const r = loadInChild(`c.loadConfig(${JSON.stringify(dir)})`);
    assert.ok(r.started, `the child never started; this is a harness fault, not the defect:\n${r.out}`);
    assert.ok(!r.hung, "loadConfig blocked on a FIFO named .secretloop.json: the read never returned");
    assert.ok(/^REFUSED: .*regular file/m.test(r.out), `expected a refusal, got:\n${r.out}`);
    assert.ok(r.out.includes("CODE: not-regular\n"), `expected the not-regular code, got:\n${r.out}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("loadBaseline refuses a FIFO at the baseline path rather than waiting on it", () => {
  if (process.platform === "win32") skip("FIFOs are POSIX; Windows has no named pipe at a baseline path");
  const dir = mkdtempSync(path.join(tmpdir(), "sl-base-fifo-"));
  try {
    const file = path.join(dir, "baseline.json");
    execFileSync("mkfifo", [file], { stdio: "ignore", timeout: 5000 });
    const r = loadInChild(`c.loadBaseline(${JSON.stringify(file)})`);
    assert.ok(r.started, `the child never started; this is a harness fault, not the defect:\n${r.out}`);
    assert.ok(!r.hung, "loadBaseline blocked on a FIFO at the baseline path: the read never returned");
    assert.ok(/^REFUSED: .*regular file/m.test(r.out), `expected a refusal, got:\n${r.out}`);
    assert.ok(r.out.includes("CODE: not-regular\n"), `expected the not-regular code, got:\n${r.out}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a symlink to a FIFO is refused as a FIFO is, without waiting on it", () => {
  if (process.platform === "win32") skip("FIFOs are POSIX; Windows has no named pipe to link to");
  const dir = mkdtempSync(path.join(tmpdir(), "sl-cfg-symfifo-"));
  try {
    const fifo = path.join(dir, "target.fifo");
    execFileSync("mkfifo", [fifo], { stdio: "ignore", timeout: 5000 });
    symlinkSync(fifo, path.join(dir, CONFIG_FILENAME));
    const r = loadInChild(`c.loadConfig(${JSON.stringify(dir)})`);
    assert.ok(r.started, `the child never started; this is a harness fault, not the defect:\n${r.out}`);
    assert.ok(!r.hung, "loadConfig blocked on a symlink to a FIFO: the read never returned");
    assert.ok(
      r.out.includes("REFUSED: Could not read configuration .secretloop.json: it is not a regular file."),
      `expected the named refusal, got:\n${r.out}`
    );
    assert.ok(r.out.includes("CODE: not-regular\n"), `expected the not-regular code, got:\n${r.out}`);
    assert.ok(!r.out.includes(dir), "the refusal names the absolute path");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a symlink to an ordinary JSON config still loads, and the parsed values are the file's", () => {
  // Creating a symlink needs a privilege on Windows, so this is POSIX-only. The FIFO
  // symlink test above is the negative case for the same link shape.
  if (process.platform === "win32") skip("creating a symlink needs a privilege on Windows");
  const dir = mkdtempSync(path.join(tmpdir(), "sl-cfg-symjson-"));
  try {
    const target = path.join(dir, "shared-config.json");
    writeFileSync(target, JSON.stringify({ entropyPassEnabled: true, maxFileSizeBytes: 12345 }));
    symlinkSync(target, path.join(dir, CONFIG_FILENAME));
    const { config, raw } = loadConfigWithSource(dir);
    assert.deepStrictEqual(raw, { entropyPassEnabled: true, maxFileSizeBytes: 12345 });
    assert.strictEqual(config.entropyPassEnabled, true);
    assert.strictEqual(config.maxFileSizeBytes, 12345);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a directory at the config path is refused by name, without the absolute path", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "sl-cfg-dir-"));
  try {
    mkdirSync(path.join(dir, CONFIG_FILENAME));
    let caught: unknown;
    try {
      loadConfig(dir);
    } catch (err) {
      caught = err;
    }
    assert.ok(caught instanceof ConfigReadError, `expected a ConfigReadError, got: ${String(caught)}`);
    const message = (caught as ConfigReadError).message;
    assert.ok(
      /^Could not read configuration \.secretloop\.json: it (is not a regular file|cannot be read)\.$/.test(message),
      `unexpected message: ${message}`
    );
    assert.ok(!message.includes(dir), "the message names the absolute path");
    // POSIX opens a directory and fstat refuses it, so not-regular. Windows may refuse
    // the open instead, which is unreadable. Both are refusals; only the category varies.
    const allowed = process.platform === "win32" ? ["unreadable", "not-regular"] : ["not-regular"];
    assert.ok(allowed.includes((caught as ConfigReadError).code), `wrong error category: ${(caught as ConfigReadError).code}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an unreadable config is refused by category, without the OS message or the path", () => {
  if (process.platform === "win32") skip("file modes are not enforced the same way on Windows");
  if (process.getuid?.() === 0) skip("root reads files regardless of their mode bits");
  const dir = mkdtempSync(path.join(tmpdir(), "sl-cfg-eacces-"));
  const file = path.join(dir, CONFIG_FILENAME);
  try {
    writeFileSync(file, "{}");
    chmodSync(file, 0o000);
    let caught: unknown;
    try {
      loadConfig(dir);
    } catch (err) {
      caught = err;
    }
    assert.ok(caught instanceof ConfigReadError, `expected a ConfigReadError, got: ${String(caught)}`);
    assert.strictEqual((caught as ConfigReadError).code, "unreadable");
    assert.strictEqual(
      (caught as Error).message,
      "Could not read configuration .secretloop.json: it cannot be read."
    );
  } finally {
    try {
      chmodSync(file, 0o600);
    } catch {
      // The file may not exist; the directory removal below does not need it.
    }
    rmSync(dir, { recursive: true, force: true });
  }
});

finish();
