import {
  globToRegExp,
  isPathExcluded,
  mergeConfig,
  fingerprint,
  defaultConfig,
  resolveConfigFile,
  legacyConfigNotice,
  CONFIG_FILENAME,
  LEGACY_CONFIG_FILENAME,
} from "../src/config";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { test, suite, finish, assert } from "./harness";

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
    assert.strictEqual(found!.legacy, false);
    assert.strictEqual(legacyConfigNotice(dir), null, "no notice for the current filename");
  });
});

test("falls back to a pre-rebrand .secretguard.json config", () => {
  // An existing checkout must keep its allowlists and threshold after upgrading.
  withTempRepo({ [LEGACY_CONFIG_FILENAME]: JSON.stringify({ entropyThreshold: 5.1 }) }, (dir) => {
    const found = resolveConfigFile(dir);
    assert.ok(found, "legacy config must still be found");
    assert.strictEqual(found!.legacy, true);
    assert.ok(legacyConfigNotice(dir)?.includes(CONFIG_FILENAME), "notice names the new filename");
  });
});

test("prefers the new filename when both are present", () => {
  withTempRepo(
    {
      [CONFIG_FILENAME]: JSON.stringify({ entropyThreshold: 1.1 }),
      [LEGACY_CONFIG_FILENAME]: JSON.stringify({ entropyThreshold: 9.9 }),
    },
    (dir) => {
      const found = resolveConfigFile(dir);
      assert.strictEqual(found!.legacy, false);
    }
  );
});

test("no config file yields no notice and no error", () => {
  withTempRepo({}, (dir) => {
    assert.strictEqual(resolveConfigFile(dir), null);
    assert.strictEqual(legacyConfigNotice(dir), null);
  });
});

finish();
