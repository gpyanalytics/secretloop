/**
 * A stand-in for the `vscode` module, so the extension-facing sources can be
 * tested outside an extension host.
 *
 * Deliberately minimal: it implements only what the code under test actually
 * calls, and grows when a test needs more. Every member carries a compile-time
 * conformance check against the real `@types/vscode` (see the bottom of this
 * file) — a stub with a convenient-but-wrong shape would let a test pass while
 * the extension breaks, and that failure would not surface until someone
 * installed the VSIX.
 */
import type * as vscode from "vscode";
import { readFileSync, writeFileSync, statSync, unlinkSync } from "fs";

export interface StubCall {
  api: string;
  args: unknown[];
}

/** Every stubbed API call, in order, for a test to assert on. */
export const calls: StubCall[] = [];

function record(api: string, ...args: unknown[]): void {
  calls.push({ api, args });
}

export function reset(): void {
  calls.length = 0;
  outputLines.length = 0;
  applyEditResult = true;
}

/**
 * What workspace.applyEdit reports back.
 *
 * VS Code returns false for an edit it declined — a read-only file, or a
 * document that moved under the edit. Defaults to true and is restored by
 * reset(), so a test has to ask for the failure explicitly.
 */
let applyEditResult = true;

export function setApplyEditResult(result: boolean): void {
  applyEditResult = result;
}

/** True when the named API was called at least once. */
export function called(api: string): boolean {
  return calls.some((c) => c.api === api);
}

/** Arguments of the first call to the named API, or undefined if never called. */
export function firstCall(api: string): unknown[] | undefined {
  return calls.find((c) => c.api === api)?.args;
}

export const env = {
  clipboard: {
    writeText: async (value: string): Promise<void> => {
      record("env.clipboard.writeText", value);
    },
  },
  openExternal: async (target: { toString(): string }): Promise<boolean> => {
    record("env.openExternal", target.toString());
    return true;
  },
};

/** Set by a test to whatever the code under test should see as the open folder. */
export let workspaceFolders: Array<{ uri: { fsPath: string } }> | undefined;

export function setWorkspaceFolder(fsPath: string | undefined): void {
  workspaceFolders = fsPath === undefined ? undefined : [{ uri: { fsPath } }];
}

export const window = {
  showInformationMessage: async <T extends string>(
    message: string,
    ...items: T[]
  ): Promise<T | undefined> => {
    record("window.showInformationMessage", message, ...items);
    return undefined;
  },
  showErrorMessage: async <T extends string>(
    message: string,
    ...items: T[]
  ): Promise<T | undefined> => {
    record("window.showErrorMessage", message, ...items);
    return undefined;
  },
  showWarningMessage: async <T extends string>(
    message: string,
    ...items: T[]
  ): Promise<T | undefined> => {
    record("window.showWarningMessage", message, ...items);
    return undefined;
  },
  createOutputChannel: (name: string) => {
    record("window.createOutputChannel", name);
    return {
      name,
      appendLine: (line: string) => {
        outputLines.push(line);
        record("output.appendLine", line);
      },
      append: (value: string) => record("output.append", value),
      clear: () => record("output.clear"),
      show: (..._a: unknown[]) => record("output.show"),
      hide: () => record("output.hide"),
      replace: (value: string) => record("output.replace", value),
      dispose: () => record("output.dispose"),
    };
  },
};

/** Only the `file` factory is used, and only its fsPath is read back. */
export const Uri = {
  file: (fsPath: string) => ({ fsPath, scheme: "file", toString: () => `file://${fsPath}` }),
  parse: (value: string) => ({ fsPath: value, scheme: value.split(":")[0], toString: () => value }),
};

/** Only what extension.ts touches at module load and when rendering. */
export const languages = {
  createDiagnosticCollection: (name: string) => {
    record("languages.createDiagnosticCollection", name);
    return {
      name,
      set: (..._a: unknown[]) => record("diagnostics.set"),
      delete: (..._a: unknown[]) => record("diagnostics.delete"),
      clear: () => record("diagnostics.clear"),
      dispose: () => record("diagnostics.dispose"),
    };
  },
};

/** The lines an OutputChannel was given, so a test can read what was logged. */
export const outputLines: string[] = [];

export class Range {
  constructor(
    readonly start: vscode.Position,
    readonly end: vscode.Position
  ) {}
}

export class WorkspaceEdit {
  replace(uri: vscode.Uri, range: vscode.Range, newText: string): void {
    record("WorkspaceEdit.replace", uri, range, newText);
  }
}

/** Configuration state a test can set up, mirroring inspect()'s scopes. */
export interface StubConfigEntry {
  defaultValue?: unknown;
  globalValue?: unknown;
  workspaceValue?: unknown;
  workspaceFolderValue?: unknown;
}

const configuration = new Map<string, StubConfigEntry>();

export function setConfiguration(namespace: string, key: string, entry: StubConfigEntry): void {
  configuration.set(`${namespace}.${key}`, entry);
}

export function resetConfiguration(): void {
  configuration.clear();
}

export const workspace = {
  getConfiguration: (namespace: string) => ({
    get: <T>(key: string, fallback?: T): T | undefined => {
      const e = configuration.get(`${namespace}.${key}`);
      const v =
        e?.workspaceFolderValue ?? e?.workspaceValue ?? e?.globalValue ?? e?.defaultValue;
      return (v === undefined ? fallback : v) as T | undefined;
    },
    inspect: <T>(key: string) => {
      const e = configuration.get(`${namespace}.${key}`);
      return e === undefined ? undefined : { key: `${namespace}.${key}`, ...(e as object) };
    },
    has: (key: string) => configuration.has(`${namespace}.${key}`),
    update: async (key: string, value: unknown, target?: unknown) => {
      record("configuration.update", `${namespace}.${key}`, value, target);
    },
  }),
  applyEdit: async (edit: WorkspaceEdit): Promise<boolean> => {
    record("workspace.applyEdit", edit);
    return applyEditResult;
  },
  get workspaceFolders() {
    return workspaceFolders;
  },
  getWorkspaceFolder: (_uri: unknown) => workspaceFolders?.[0],
  // Backed by the real filesystem: these are genuine file operations and
  // faking them would only test the fake.
  fs: {
    readFile: async (uri: { fsPath: string }): Promise<Uint8Array> => {
      record("workspace.fs.readFile", uri.fsPath);
      return readFileSync(uri.fsPath);
    },
    writeFile: async (uri: { fsPath: string }, content: Uint8Array): Promise<void> => {
      record("workspace.fs.writeFile", uri.fsPath, Buffer.from(content).toString("utf8"));
      writeFileSync(uri.fsPath, content);
    },
    stat: async (uri: { fsPath: string }): Promise<{ type: number }> => {
      record("workspace.fs.stat", uri.fsPath);
      statSync(uri.fsPath); // throws exactly as vscode.workspace.fs.stat does
      return { type: 1 };
    },
    delete: async (uri: { fsPath: string }): Promise<void> => {
      record("workspace.fs.delete", uri.fsPath);
      unlinkSync(uri.fsPath);
    },
  },
};

// ---------------------------------------------------------------------------
// Compile-time conformance. No runtime purpose: these exist so `tsc` over
// tests/ fails when a stub drifts from the signature the extension really gets.
// ---------------------------------------------------------------------------

/**
 * showInformationMessage has four overloads; this is the one the sources under
 * test use. Asserting against the full overloaded type is not possible for a
 * single implementation, so the specific shape is pinned instead.
 */
type ShowMessage = <T extends string>(message: string, ...items: T[]) => Thenable<T | undefined>;

export const conformsToRealApi = {
  clipboardWriteText: env.clipboard.writeText satisfies typeof vscode.env.clipboard.writeText,
  applyEdit: workspace.applyEdit satisfies typeof vscode.workspace.applyEdit,
  showInformationMessage: window.showInformationMessage satisfies ShowMessage,
  showErrorMessage: window.showErrorMessage satisfies ShowMessage,
  openExternal: env.openExternal satisfies (target: { toString(): string }) => Thenable<boolean>,
  workspaceEditReplace: new WorkspaceEdit().replace satisfies OmitLast<
    typeof vscode.WorkspaceEdit.prototype.replace
  >,
};

/** The real `replace` takes an optional trailing metadata argument we ignore. */
type OmitLast<F> = F extends (a: infer A, b: infer B, c: infer C, ...rest: any[]) => infer R
  ? (a: A, b: B, c: C) => R
  : never;
