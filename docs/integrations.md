# Integrations

Every integration runs the same engine with the same `.secretloop.json`. This
page collects the wiring; the semantics are in the [CLI reference](cli.md) and
the [MCP server](mcp.md) page. Applies to **published 0.5.1**.

## CI

Fail the build on findings at or above a severity, and publish SARIF to GitHub
code scanning:

```bash
npx secretloop scan --format sarif -o results.sarif --fail-on high
```

Gate on credentials that still work, and on any the scan could not vouch for
(requires network egress to the provider APIs on the runner):

```bash
npx secretloop scan --verify --fail-on verified --format sarif -o results.sarif
```

Report-only, never failing:

```bash
npx secretloop scan --format sarif -o results.sarif --fail-on never
```

Write the report outside the scanned tree or add it to `excludePaths`: a report
left in the working tree is a scan input on the next run, and SecretLoop already
excludes `*.sarif` from the generated-file group for that reason.

This repository's own CI is the reference: the `self-scan` job copies
`.github/secretloop.ci.json` to `.secretloop.json`, runs
`node out/cli.js scan --format sarif --output secretloop.sarif --fail-on high`
and `node out/cli.js history --fail-on critical`.

## Pre-commit hook

From VS Code, **SecretLoop: Install Pre-commit Hook** writes
`.git/hooks/pre-commit` running `secretloop staged`. If a hook already exists it
is moved to `.git/secretloop/pre-commit.foreign` and run first, as its own
process, so `set -e`, `exit 0`, `exec` and a Python shebang stay scoped to it.
Uninstalling restores it. Bypass one commit with `git commit --no-verify`.

Without the extension, the equivalent hook is:

```sh
#!/bin/sh
npx secretloop staged
```

The hook makes no network calls. Add `--verify` yourself if you want liveness
at commit time and can accept the latency.

## SARIF

`--format sarif` emits SARIF 2.1.0. Each result carries the rule id, a masked
value in its message, the finding's `secretloopFingerprint/v2` as a partial
fingerprint, and the scan's scope sentence in `invocations[0].properties.scope`.
An archive-member result names the archive as the physical artifact and the
member as a logical location, with the line relative to the member, and the
invocation properties carry the archive accounting. This has shipped since
0.5.0 (PR #47); the marker calling it unreleased was stale from that release
onwards, not a 0.5.1 change.

## MCP clients

The server invocation never changes; only the file it goes in and the key it
goes under differ:

```
npx -y --package=secretloop secretloop-mcp
```

To scan a directory other than the client's working directory, append it:
`npx -y --package=secretloop secretloop-mcp /path/to/repo`. Allowed roots are
fixed at launch and cannot be changed over the protocol.

**Claude Desktop** (`claude_desktop_config.json`) and **Cursor** (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "secretloop": {
      "command": "npx",
      "args": ["-y", "--package=secretloop", "secretloop-mcp"]
    }
  }
}
```

**Claude Code**, on one line:

```bash
claude mcp add secretloop -- npx -y --package=secretloop secretloop-mcp
```

**VS Code with GitHub Copilot** (`.vscode/mcp.json`; the top-level key is
`servers`):

```json
{
  "servers": {
    "secretloop": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "--package=secretloop", "secretloop-mcp"]
    }
  }
}
```

**Visual Studio 2022 17.14+ and Visual Studio 2026** take the same shape and
discover it in `%USERPROFILE%\.mcp.json`, `<SolutionDir>\.vs\mcp.json`,
`<SolutionDir>\.mcp.json`, `<SolutionDir>\.vscode\mcp.json` or
`<SolutionDir>\.cursor\mcp.json`. In both, MCP tools are available to Copilot
only in agent mode.

**Windsurf** (`~/.codeium/windsurf/mcp_config.json`) and **Cline**
(`~/.cline/mcp.json` or the MCP Servers panel) use the `mcpServers` shape above.

**Zed** uses `context_servers` in its settings file:

```json
{
  "context_servers": {
    "secretloop": {
      "command": "npx",
      "args": ["-y", "--package=secretloop", "secretloop-mcp"],
      "env": {}
    }
  }
}
```

**Validation status.** VS Code with GitHub Copilot was exercised in a real
agent-mode session during development. Claude Desktop, Claude Code, Cursor,
Visual Studio, Windsurf, Cline and Zed are documented from each client's own
documentation (config paths and keys checked 2026-09-05 for Windsurf, Cline and
Zed: [Windsurf](https://docs.devin.ai/desktop/cascade/mcp) ·
[Cline](https://docs.cline.bot/mcp/configuring-mcp-servers) ·
[Zed](https://zed.dev/docs/ai/mcp)) and not individually validated. Clients
move these paths; the client's own documentation is the authority, and the
invocation above is the only part that is SecretLoop's.

## Other editors

The CLI runs in any editor's integrated terminal and reads the same
`.secretloop.json`, so a JetBrains or Neovim user gets identical verdicts without
the inline UI. Native ports are demand-gated; see the
[backlog](project/backlog.md#native-editor-ports-demand-gated).
