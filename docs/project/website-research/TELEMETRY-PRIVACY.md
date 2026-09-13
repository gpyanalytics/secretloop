# Telemetry and Privacy Research

## Goal

Understand which SecretLoop commands/features are actually used without learning who used them or what they scanned.

The initial north-star activation signal is successful command execution / successful first scan among telemetry-enabled usage, not repository identity.

## Aggregate Usage Counters V1

Preferred minimal event dimensions:

```text
command
surface
SecretLoop version
outcome
day
```

Examples of aggregate counters:

```text
scan.started
scan.completed
history.completed
mask.completed
verification_requested
mcp.scan.completed
```

The server should aggregate as early as practical rather than build a detailed behavioral event warehouse.

## Explicit non-collection

Do not collect through product telemetry:

- user identity;
- email/account identity;
- installation identifier (not required for V1 counters);
- machine/hardware identifier;
- repository name;
- repository URL;
- organization/user name from Git;
- file paths;
- source code;
- command argument values;
- findings or finding counts initially;
- fingerprints;
- credential values;
- credential provider;
- commit hashes;
- verification result counts such as number of LIVE credentials.

For a command such as `secretloop scan /company/project`, telemetry records only the allowed command/event classification, never the supplied path.

## Started vs completed

A command invocation is not equivalent to successful use. Where useful, maintain separate aggregate counters for started/completed/failed-or-aborted.

Failure telemetry must not contain raw error strings or stack traces because they can contain paths or sensitive context.

## Network metadata caveat

An HTTPS endpoint can observe network metadata such as source IP at the transport/infrastructure layer even if IP is absent from the telemetry payload.

Therefore privacy claims must distinguish "not included in/stored by application telemetry" from "technically never visible to infrastructure." Configure logs and retention so raw request metadata is not retained beyond what is operationally/security necessary.

## Consent and transparency

For a security product, telemetry should be explicit and controllable. Preferred approach: transparent opt-in with equally easy decline.

The product should publish the exact telemetry schema and provide controls to inspect/enable/disable telemetry.

Conceptual first-run disclosure:

```text
Collected:
✓ command/feature used
✓ completion outcome
✓ SecretLoop version
✓ CLI / VS Code / MCP surface

Never collected:
✗ repository identity
✗ source code
✗ credentials
✗ findings
✗ file paths
✗ user identity
```

Exact CLI control syntax should be designed against the shipped command architecture rather than invented in documentation before implementation.

## What V1 can and cannot measure

Can answer:

- how many telemetry-enabled scan completions occurred;
- relative use of scan/history/mask/MCP/etc.;
- feature adoption by version/surface;
- completion/failure rates.

Cannot reliably answer without an identifier:

- unique users;
- unique installations;
- scans per user;
- 7-day user retention.

This limitation is intentional in V1. Revisit only if unique-user measurement becomes materially necessary and the privacy trade-off is justified.

## Website analytics

Website-side aggregate analytics may separately measure page/CTA behavior such as demo viewed, command copied or pilot CTA used. Do not silently join website identity with local SecretLoop security activity.

## Principle

> Measure SecretLoop usage, never what the user is scanning.
