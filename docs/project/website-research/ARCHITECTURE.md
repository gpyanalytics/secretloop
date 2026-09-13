# Website Architecture Research

## Stage 1 — static/local-first

Preferred initial architecture while budget is constrained:

```text
gpyanalytics.com
      │
 static site / CDN
      │
 ┌────┼───────────┐
 demo docs MCP setup
      │
 exact commands
      │
      ▼
 USER MACHINE
      │
 SecretLoop
      │
 scan / history / verify / MCP
```

Benefits:

- negligible GPY compute;
- no repository ingestion;
- no account system required;
- no scan quota required;
- aligns with local-first positioning;
- user code and findings stay local.

## Stage 2 — hosted public-repository scanner

Only after demand/budget justifies it:

```text
Website
  ↓
public GitHub URL
  ↓
validation / limits
  ↓
ephemeral isolated worker
  ↓
SecretLoop core/CLI
  ↓
structured events/results
  ↓
web console + findings UI
  ↓
workspace/results cleanup
```

### Mandatory safety properties

- public GitHub repositories only initially;
- GitHub URL allowlisting rather than arbitrary fetch URLs;
- strict repository/file/history/archive/runtime/memory limits;
- rate limits and global concurrency limits;
- isolated ephemeral workers;
- no execution of repository code;
- no `npm install`, build scripts or repository hooks;
- restricted worker network access;
- no live verification for arbitrary public findings;
- automatic cleanup;
- no credential plaintext persistence;
- findings/results short-lived by default;
- archive-bomb/resource-exhaustion protections;
- adversarial testing before public launch.

## Same engine, multiple surfaces

The website should not reimplement SecretLoop detection logic. The web experience must consume the same SecretLoop core/CLI result model so CLI, VS Code, MCP and web do not drift into different security claims.

As P0/P1 ship, web should consume the same credential identity, observations, fan-out, investigation and remediation models rather than creating web-specific equivalents.

## Realtime console

The worker can eventually emit structured progress events rather than parsing human terminal output. The web UI can render both:

- a console-like event stream for curiosity;
- structured findings/evidence for comprehension.

## Hosted scan identity/cache — future optimization

A safe short-lived cache may key on public repository identity + commit SHA + SecretLoop version + scan profile. This can avoid repeatedly computing an identical public scan. Privacy/security implications must be reviewed before implementation.

## Browser-local scanning — research only

A future browser/WASM-compatible engine could potentially scan permitted content without sending it to GPY infrastructure. This is strategically attractive but should not block initial delivery because current Node/git/filesystem behavior may make it expensive.

## Private repositories — future enterprise

Do not ask users to paste GitHub personal access tokens into a form.

Potential future approaches:

1. GitHub App / least-privilege authorization for hosted enterprise scanning; or preferably
2. local SecretLoop runner/bridge where source remains in the customer's environment and only contractually configured structured exposure metadata is shared.

## Hosted scan billing — not initial architecture

Do not add billing infrastructure until real users demonstrate demand for hosted scans beyond a free allowance. Initial conversion path after hosted quota exhaustion should include unlimited local scanning and a team/design-partner pilot.
