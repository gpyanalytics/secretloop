import * as vscode from "vscode";

export const SETTINGS_NAMESPACE = "secretloop";

/**
 * The pre-rebrand settings namespace. Still read so an existing install keeps
 * its configuration after upgrading.
 */
export const LEGACY_SETTINGS_NAMESPACE = "secretguard";

/**
 * Reads a setting under `secretloop.*`, falling back to the pre-rebrand
 * `secretguard.*` key when the user has not explicitly set the new one.
 *
 * VS Code offers no built-in aliasing for settings, so without this every
 * existing install would silently revert to defaults on upgrade — someone who
 * lowered their entropy threshold or disabled outbound verification would have
 * that quietly undone, which for a security tool means either a flood of new
 * findings or unexpected network calls.
 *
 * Only *explicitly set* values are considered on either namespace; a package
 * default never shadows a real user value on the other one.
 */
export function setting<T>(key: string, fallback: T): T {
  const explicit = explicitValue<T>(SETTINGS_NAMESPACE, key);
  if (explicit !== undefined) return explicit;

  const legacy = explicitValue<T>(LEGACY_SETTINGS_NAMESPACE, key);
  if (legacy !== undefined) return legacy;

  return vscode.workspace.getConfiguration(SETTINGS_NAMESPACE).get<T>(key, fallback);
}

function explicitValue<T>(namespace: string, key: string): T | undefined {
  const inspected = vscode.workspace.getConfiguration(namespace).inspect<T>(key);
  return (
    inspected?.workspaceFolderValue ?? inspected?.workspaceValue ?? inspected?.globalValue
  );
}

/** True when a value is set only under the deprecated `secretguard.*` namespace. */
export function usesLegacySetting(key: string): boolean {
  return (
    explicitValue(SETTINGS_NAMESPACE, key) === undefined &&
    explicitValue(LEGACY_SETTINGS_NAMESPACE, key) !== undefined
  );
}
