# GPY Analytics / SecretLoop Website Research

**Status:** parked research and planning. This folder is intentionally separate from the active SecretLoop P0/P1/P2 execution roadmap.

The website should make SecretLoop understandable to non-specialists while preserving enough evidence and technical depth for developers, security engineers and enterprise evaluators.

## Core experience

The intended journey is:

**Curiosity → Understanding → Evidence → Trust → Try → Reproduce → Pilot**

The website should not merely describe SecretLoop. A visitor should be able to:

1. watch SecretLoop run in an interactive console;
2. understand each result in plain language;
3. copy the exact commands/configuration;
4. reproduce the workflow locally;
5. understand the security/privacy model;
6. evaluate MCP through an explicit Agent → MCP → SecretLoop → evidence flow;
7. request a design-partner / enterprise pilot.

## Current strategic constraint

Until hosted scanning is justified by demand and budget, prefer a near-zero-cost model:

- static website;
- interactive/synthetic console demonstrations;
- executable/follow-along documentation;
- public synthetic demo repository;
- locally executed SecretLoop scans on the visitor's machine;
- no signup required for local usage;
- no hosted repository processing required.

A hosted public-repository scanner remains a planned future layer, not a prerequisite for launch.

## Documents

- [`STRATEGY.md`](STRATEGY.md) — positioning, site map, visitor journeys, curiosity and conversion model.
- [`EXPERIENCE.md`](EXPERIENCE.md) — console, follow-along, public repo flow, MCP demonstration and reproducible commands.
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — static-first architecture, hosted scanner evolution and security boundaries.
- [`TELEMETRY-PRIVACY.md`](TELEMETRY-PRIVACY.md) — privacy-preserving aggregate command counters and data-minimization principles.
- [`ENTERPRISE.md`](ENTERPRISE.md) — future enterprise data architecture, deployment modes, privacy controls and customer agreements.
- [`COSTS-ROADMAP.md`](COSTS-ROADMAP.md) — cost model, phased delivery and promotion gates.

## Rules that remain in force

1. Website claims must match shipped SecretLoop behavior.
2. Future P0/P1/P2 capabilities must never be presented as already available.
3. Verification and credential-changing actions must remain authorization-sensitive.
4. Public web experiences must never execute repository code.
5. Source code, credential plaintext and security findings should stay local wherever possible.
6. Telemetry must measure product usage, not what the user is scanning.
7. Enterprise data collection must be feature-required, contractually defined and configurable — never "collect everything because the agreement allows it."
8. New website ideas are recorded here; they do not interrupt the committed SecretLoop engineering roadmap unless deliberately promoted after evaluation.
