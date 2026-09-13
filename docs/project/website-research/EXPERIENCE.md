# Website Product Experience

## Principle

The visitor should not merely read about SecretLoop. They should see it run and be able to reproduce the same shipped workflow locally.

Template for every capability:

**What is it? → Watch it run → Copy command/config → Run it yourself → Expected output → Understand result → Next step**

## Interactive console

The website can provide a deterministic interactive terminal backed by synthetic examples. It should use real current SecretLoop command syntax and clearly label simulated results.

The console can teach scanning, history, verification concepts, masking/remediation and MCP without requiring hosted repository processing.

## Follow-along mode

Use a split-screen experience:

```text
LIVE DEMO                  DO THIS ON YOUR COMPUTER

$ npx secretloop scan      1. Open terminal
scanning...                2. Copy command
finding...                 3. Compare output
```

Each step should explain *why* the command is being run in plain language.

## Synthetic demo repository

Create a dedicated public demonstration repository containing only deliberately synthetic/non-sensitive fixtures. The website should know the expected findings and use it for reproducible onboarding.

The demo must never contain a real credential or a value that can become live.

## Public repository experience — future hosted layer

A future hosted flow can allow an authenticated or rate-limited visitor to submit a **public GitHub repository URL** and receive a real SecretLoop scan.

Safe web profile may include:

- current-tree scan;
- Git history;
- named rules;
- entropy;
- encoded-secret detection;
- archives;
- duplicate merging;
- scope accounting;
- structured report;
- credential grouping/fan-out/investigation only after those capabilities ship.

Public hosted scanning must exclude:

- live credential verification;
- credential rotation;
- repository modification;
- hook installation;
- arbitrary local-file access;
- execution of repository code.

A web result should always offer a local reproduction path.

## Public scanner quota — optional future commercial model

If hosted scanning is later justified:

- account required;
- no credit card for initial free tier;
- candidate initial quota: three full standard scans;
- one repository analysis counts as one scan, not separate credits for history/entropy/archive/report;
- failed infrastructure scans do not consume a credit;
- repeated identical commit/configuration may use a short-lived cached result rather than consuming compute again;
- oversized repositories should be redirected to local scanning or an enterprise/pilot path.

Do not build billing until post-quota demand demonstrates the need. Local SecretLoop remains the free path.

## MCP website experience

### Public education/demo

Show the full chain explicitly:

```text
User
 ↓
AI Agent
 ↓
MCP tool call
 ↓
SecretLoop
 ↓
Deterministic evidence
 ↓
AI explanation
```

The key message:

> The AI explains; SecretLoop establishes security evidence.

Show tool activity and allow "View evidence" on AI statements.

### Consent demonstration

Sensitive operations should visibly demonstrate consent boundaries. A simulated verification flow may show a masked credential and an "Allow once / Deny" choice, but must clearly state that no real public-web verification occurs.

### Real read-only web MCP — future

A hosted public-repo workbench may expose read-only SecretLoop analysis through MCP-compatible tooling, but public visitors must not be able to trigger live verification, rotation or write operations against credentials discovered in arbitrary public repositories.

### MCP setup wizard

The website should let the visitor choose an AI client and receive:

1. exact current installation command;
2. exact current documented configuration;
3. exact example prompt;
4. expected interaction;
5. validation status (validated vs merely documented) stated accurately.

Never present a documented-but-unvalidated client as equivalent to a validated client.

### Local bridge — future product research

A later local bridge could allow a browser workbench to act as UI while SecretLoop and private repository processing remain on the user's machine. This is a product capability, not required for the initial website.

## Explain this finding

Each result should have a plain-language explanation answering:

- Why was this flagged?
- Where was it observed?
- Does detection mean it is usable?
- Was verification performed?
- What should the user do next?

## Expected-output guidance

Every tutorial should show expected output and explain that "no findings" can be a successful scan. Users who want a guaranteed demonstration should be directed to the synthetic demo repository.

## Reports

Future hosted reports should be private/short-lived by default even for public repositories. Public source does not make security findings harmless.
