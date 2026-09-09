# VS Code extension

The extension runs the same engine as the CLI on the file you are editing, on
save, and on demand across the workspace. Applies to **published 0.5.0**.

## Findings as diagnostics

- A **format match** is a warning. A credential **confirmed live** is an
  error, and so is one the provider **refused to answer for** (a 403 leans live
  and no retry resolves it). An **entropy heuristic** finding is a hint, never an
  error. A **confirmed dead** credential is reported quietly and last.
- The hover states which of those happened and what to do next.
- Scans run on save (`secretloop.autoScanOnSave`) and from the Command Palette.
- A finding inside an archive member is anchored to the
  archive file itself, at its start, and the message names the member and the
  member-relative line, because no open document holds the member's text.

## Quick-fixes

On any finding the lightbulb offers:

- **SecretLoop: Redact this secret** — replaces the value with a placeholder.
- **SecretLoop: Copy to clipboard, then redact** — offered second and named for
  its risk: anything running on the machine can read the clipboard, and it
  syncs across devices.
- **SecretLoop: Move to `.env` and reference it** — writes the value into the
  file named by `secretloop.envFilePath`, replaces the literal with a
  language-aware reference (`process.env.X`, `os.environ["X"]`,
  `os.Getenv("X")`, `System.getenv("X")`, `ENV["X"]`), and adds `.env` to
  `.gitignore` if it is missing. It refuses when the `.env` file is already
  tracked by git, because writing a secret into a tracked file would commit it.

On a confirmed-live or provider-refused finding for a rule with a rotation path,
the lightbulb adds **Rotate / revoke this LIVE credential** or **Inspect /
revoke this possibly-active credential**. Slack tokens are revoked through
Slack's own API; GitHub, Stripe and Google open the provider console; AWS opens
the IAM console unless admin credentials for rotation are stored, in which case
the leaked key is deactivated with an IAM call. This is a VS Code action, not a
CLI or MCP capability.

No rotation and no `.env` extraction is offered for an
archive-member finding: there is no document to rewrite and archives are never
rewritten.

## Commands

All under **SecretLoop** in the Command Palette:

| command | what it does |
|---|---|
| Scan Entire Workspace | Scans every file git would track, through the same enumeration the CLI uses |
| Scan Staged Files | Checks what you are about to commit |
| Scan Git History for Secrets | Walks commits and opens the report as a document |
| Accept Current Findings as Baseline | Writes `.secretloop-baseline.json` so only new findings fail |
| Install Pre-commit Hook | Wires `secretloop staged` into `.git/hooks/pre-commit`, chaining an existing hook |
| Uninstall Pre-commit Hook | Removes it and restores any hook it displaced |
| Set AWS Admin Credentials for Rotation | Stores them in the OS keychain through VS Code's SecretStorage |
| Clear Stored AWS Admin Credentials | Removes them from the keychain |
| Mask Secrets in Clipboard | Rewrites the clipboard with every secret masked |
| Reset Prompt Preferences | Undoes a "Never" answer to the verification offer |

## Settings

| setting | default | description |
|---|---|---|
| `secretloop.entropyThreshold` | `4.3` | Shannon entropy cutoff for the generic tier |
| `secretloop.autoScanOnSave` | `true` | Re-scan a file when it is saved |
| `secretloop.blockCommitOnSecret` | `true` | Warn in Source Control when staged files contain unresolved secrets |
| `secretloop.envFilePath` | `.env` | Where extracted secrets are written |
| `secretloop.excludePaths` | `[]` | Extra globs never scanned, added to the built-in excludes |
| `secretloop.entropyPassEnabled` | `false` | Opt in to the generic high-entropy tier. A `.secretloop.json` value for `entropyPassEnabled` overrides this setting |
| `secretloop.enableLiveVerification` | `false` | Make read-only provider calls to confirm a credential is active. The extension offers to turn this on the first time it finds a credential it could check |

There is no editor setting for `includeFixtures`, `keyContextRequired` or
`includeApiDocumentEntropy`; set those in the project file. See
[Configuration](configuration.md#precedence).

## The verification prompt

Verification is off by default because a repository you just cloned may hold
credentials belonging to someone else, and failed authentication attempts show
up in *their* audit logs. The first time a scan finds a credential SecretLoop
could check, it offers to turn verification on and names the provider it would
contact. Answering **Never** is permanent until **Reset Prompt Preferences** is
run, which clears that answer and this session's prompt state and nothing else.

Every decision is written to **View > Output > SecretLoop**: which guard fired,
whether an offer was made and how it was answered, and how many credentials
actually left the machine and to whom:

```
live verification is on (user setting secretloop.enableLiveVerification);
  checking 1 of 2 finding(s) in app.js.
sent 1 credential(s) to GitHub from app.js.
```

Cache hits are not counted as sends, so the number never overstates what was
transmitted. Results are cached in memory for five minutes, keyed by a SHA-256
of the value, and every provider call is abandoned after five seconds; a
timed-out check is unknown, never "not a secret".

## Staged-file warnings

With `secretloop.blockCommitOnSecret` on, Source Control shows one warning that
counts what the checks established — live, needing a look, unverified, dead —
and escalates only for a confirmed-live secret, so commit-time friction is
proportional to actual risk.

## AWS admin credentials

The admin credentials used for AWS rotation are the one privileged secret the
extension can hold. They live in the OS keychain through VS Code's
SecretStorage, never in a settings file. Scope that IAM identity to
`iam:UpdateAccessKey` only. These used to be settings: if you ever put an admin
key in `settings.json`, treat it as exposed and rotate it. The extension
migrates the value into the keychain and clears the setting on first launch,
but that removes only today's copy, not Settings Sync history or a committed
`.vscode/settings.json`.

## Running it from source

```bash
npm install
npm run compile
```

Then press `F5` to launch an Extension Development Host. Open a file containing
a fake credential to see it flagged; hover for the quick-fixes.

## Limitations

- The live extension host is validated by hand, not by the automated suite: the
  code paths for archive-member diagnostics, the verification prompt and the
  quick-fixes are covered by unit tests through the shared scanner, and the
  editor-side wiring was compiled and inspected but not exercised in a real
  editor for the `main` changes. See [Development](development.md#open-items).
