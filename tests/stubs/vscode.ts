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
};

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
};

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

export const workspace = {
  applyEdit: async (edit: WorkspaceEdit): Promise<boolean> => {
    record("workspace.applyEdit", edit);
    return true;
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
  workspaceEditReplace: new WorkspaceEdit().replace satisfies OmitLast<
    typeof vscode.WorkspaceEdit.prototype.replace
  >,
};

/** The real `replace` takes an optional trailing metadata argument we ignore. */
type OmitLast<F> = F extends (a: infer A, b: infer B, c: infer C, ...rest: any[]) => infer R
  ? (a: A, b: B, c: C) => R
  : never;
