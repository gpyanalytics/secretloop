import * as vscode from "vscode";

export const SETTINGS_NAMESPACE = "secretloop";

/** The scopes VS Code lets a user set a value in, narrowest first. */
export type SettingScope = "workspace folder" | "workspace" | "user";

export type SettingOrigin =
  | { kind: "explicit"; namespace: string; scope: SettingScope }
  | { kind: "default" };

export interface ResolvedSetting<T> {
  value: T;
  origin: SettingOrigin;
}

function explicitFrom<T>(
  namespace: string,
  key: string
): { value: T; scope: SettingScope } | undefined {
  const inspected = vscode.workspace.getConfiguration(namespace).inspect<T>(key);
  if (!inspected) return undefined;
  // Narrowest scope wins, and an explicit `false` is a value — hence the
  // undefined checks rather than truthiness.
  if (inspected.workspaceFolderValue !== undefined) {
    return { value: inspected.workspaceFolderValue, scope: "workspace folder" };
  }
  if (inspected.workspaceValue !== undefined) {
    return { value: inspected.workspaceValue, scope: "workspace" };
  }
  if (inspected.globalValue !== undefined) {
    return { value: inspected.globalValue, scope: "user" };
  }
  return undefined;
}

/**
 * A setting's value together with where it came from.
 *
 * Reporting only the value is what made a leftover user setting
 * indistinguishable from a package default, and cost three rounds of debugging
 * to find: flipping enableLiveVerification's default to false changed nothing
 * for a profile that already had an explicit true, and nothing said so.
 *
 */
export function resolveSetting<T>(key: string, fallback: T): ResolvedSetting<T> {
  const found = explicitFrom<T>(SETTINGS_NAMESPACE, key);
  if (found) {
    return {
      value: found.value,
      origin: { kind: "explicit", namespace: SETTINGS_NAMESPACE, scope: found.scope },
    };
  }
  return {
    value: vscode.workspace.getConfiguration(SETTINGS_NAMESPACE).get<T>(key, fallback),
    origin: { kind: "default" },
  };
}

export function setting<T>(key: string, fallback: T): T {
  return resolveSetting(key, fallback).value;
}

/** Where a value came from, phrased for a log line. */
export function describeOrigin(key: string, origin: SettingOrigin): string {
  return origin.kind === "explicit"
    ? `${origin.scope} setting ${origin.namespace}.${key}`
    : `package default for ${SETTINGS_NAMESPACE}.${key}`;
}

