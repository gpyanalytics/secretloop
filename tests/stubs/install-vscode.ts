/**
 * Redirects `require("vscode")` to the stub in this directory.
 *
 * The extension-facing sources — remediate.ts, rotate.ts, hooks.ts,
 * extension.ts — import `vscode`, a module that only exists inside an extension
 * host. Without this they cannot be loaded by a test at all, which is why they
 * have had no coverage.
 *
 * Importing this module is load-bearing and must come FIRST in a test file,
 * before anything that reaches `vscode` transitively. TypeScript emits requires
 * in source order and never elides a side-effect import, so import order in the
 * test is preserved in the emitted CommonJS.
 *
 * Type-checking is unaffected: `tsc` still resolves `vscode` to the real
 * `@types/vscode`. Only the runtime module is swapped, which is why the stub
 * carries its own conformance assertions.
 */
const Module = require("module");

const resolveFilename = Module._resolveFilename;
Module._resolveFilename = function (request: string, ...rest: unknown[]): string {
  if (request === "vscode") return require.resolve("./vscode");
  return resolveFilename.call(this, request, ...rest);
};

export {};
