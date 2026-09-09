# Quickstart

Applies to **published 0.4.0** unless a line says otherwise — that is what the
unversioned commands below install. **0.5.0 is a release candidate: prepared,
not published**, so nothing here downloads it yet. Needs Node 18 or newer: the
CLI refuses to start on an older runtime and says so, because the liveness
checks use the runtime's built-in `fetch`.

## 1. Scan without installing anything

```bash
npx secretloop scan            # the working tree
npx secretloop staged          # what you are about to commit
npx secretloop history         # every commit, for secrets already pushed
```

All three are offline by default: nothing is transmitted, no account is needed.
Findings print with severity, rule id, file and line, a masked value, and a
fingerprint. The last line of the report states the scan's scope — how many
files were read and, separately, how many were skipped and why — so a scan that
could not look never reads like a clean one.

Add `--verify` to ask each supported provider whether a credential still works.
That sends the credential to its own provider, so it is explicit, never a
default. See [Verification](verification.md) before turning it on for a
repository you did not write.

## 2. Read the output

Each finding carries a confidence tier:

| tier | meaning |
|---|---|
| format match | the value matches a known credential format; liveness not checked |
| verified live | the provider confirmed it works (only with `--verify`) |
| entropy heuristic | a random-looking string with no known format (only with `--include-entropy`) |
| confirmed dead | checked, and the provider says it no longer works |

A check that ran but reached no verdict is reported as *unknown* with a reason;
unknown never means safe. [Verification](verification.md) lists every reason.

## 3. Gate a build

```bash
secretloop scan --format sarif -o results.sarif --fail-on high
```

Exit `0` means nothing met the gate, `1` means something did, and any other
code is a real failure. To adopt scanning on a repository with a backlog,
accept what is there today and fail only on what is new:

```bash
secretloop scan --write-baseline .secretloop-baseline.json
secretloop scan --baseline .secretloop-baseline.json --fail-on high
```

Details, including why `--fail-on verified` requires `--verify`, are in the
[CLI reference](cli.md).

## 4. Install it

```bash
npm install -g secretloop
```

For the editor, install **SecretLoop** from the VS Code Marketplace or from a
`.vsix`:

```bash
code --install-extension secretloop-0.5.0.vsix
```

That filename names the release being prepared. Until 0.5.0 is published, the
Marketplace and any `.vsix` you can download are **0.4.0**; substitute that
filename.

The extension scans on save and puts *redact*, *extract to `.env`* and, for some
providers, *rotate* on the lightbulb. Live verification stays off until you turn
it on. See [VS Code](vscode.md).

## 5. Add the pre-commit hook

From the Command Palette, **SecretLoop: Install Pre-commit Hook** wires
`secretloop staged` into `.git/hooks/pre-commit`. It makes no network calls, so
a commit is never blocked on a provider being reachable. An existing hook is
kept and run first. Bypass a single commit with `git commit --no-verify`.
Details and the CLI-only route are in [Integrations](integrations.md).

## 6. Connect an AI coding agent

SecretLoop ships an MCP server. Add it to your client and the assistant can
scan, list and explain findings with values masked, and can *ask* for a liveness
check that only you can approve in a terminal:

```bash
claude mcp add secretloop -- npx -y --package=secretloop secretloop-mcp
```

Every client's configuration is in [Integrations](integrations.md); what the
tools do and do not do is in [MCP server](mcp.md).

## 7. Mask a log before pasting it anywhere

```bash
cat deploy.log | npx secretloop mask | pbcopy
```

Every credential is replaced with `[REDACTED:<rule-id>]`; the summary goes to
stderr so the masked stream stays clean. Generic high-entropy strings are not
masked unless you pass `--entropy`, because masking every digest and UUID in a
log destroys the log while protecting nothing.

## Where next

- Something printed that you did not expect: [Troubleshooting](troubleshooting.md).
- Too many findings in test fixtures: [Configuration](configuration.md#suppressing-findings).
- What is and is not scanned: [Coverage](coverage.md).
