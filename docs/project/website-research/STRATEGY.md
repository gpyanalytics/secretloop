# Website Strategy

## Objective

The GPY Analytics website should make a visitor curious enough to continue exploring while remaining simple enough that a non-technical visitor can understand the problem.

The communication rule is:

> Explain the problem simply first. Offer technical depth one click later.

The intended funnel is:

**Curiosity → Understanding → Evidence → Trust → Try → Reproduce → Pilot**

## Positioning

Avoid generic company language. Lead with the security problem.

Example concept:

> You deleted the leaked credential. But did you actually remove the exposure?

SecretLoop should then be explained through a simple sequence:

**Detect → Verify → Investigate → Remediate**

As exposure-intelligence capabilities ship, the story can evolve without claiming unshipped functionality.

## Proposed site map

```text
gpyanalytics.com
├── /
├── /secretloop
│   ├── /demo
│   ├── /docs
│   ├── /security
│   ├── /evidence
│   ├── /compare
│   ├── /changelog
│   └── /roadmap
├── /pilot
├── /research
├── /about
├── /contact
├── /privacy
├── /terms
└── /.well-known/security.txt
```

## Homepage journey

1. Problem hook.
2. Short visual flow: Detect → Verify → Investigate → Remediate.
3. Interactive SecretLoop console demonstration.
4. Plain-language explanation of LIVE / DEAD / UNKNOWN.
5. "Why finding isn't enough" explanation.
6. Actual product surfaces: CLI, VS Code, MCP.
7. Security principles: evidence over assumptions, local-first, unknown means unknown.
8. Optional technical architecture.
9. Security/evidence center.
10. Try SecretLoop locally.
11. Design-partner/pilot CTA.

## Three visitor modes

### WATCH

See SecretLoop execute against controlled synthetic examples.

### TRY

Initially: reproduce the workflow locally with exact commands and a synthetic demo repository.

Future: optionally scan a public GitHub repository through an isolated hosted scanner.

### REPRODUCE

Every demonstrated workflow should expose the exact currently shipped command/configuration and expected output so the visitor can reproduce it locally.

## Progressive disclosure

A manager should see:

> Finding a credential does not tell you whether it is still dangerous.

A security engineer can then open:

> How verification works.

The first layer must avoid unnecessary terms such as entropy, fingerprints, SARIF, regex internals and MCP protocol details. Those belong in deeper evidence/documentation layers.

## Trust center

The security page is a product/sales surface, not footer paperwork. It should answer plainly:

- Does source code leave the machine?
- What network activity occurs during verification?
- Are credentials stored?
- What does UNKNOWN mean?
- What does MCP expose?
- What consent exists for sensitive actions?
- What telemetry is collected?
- How is a vulnerability reported?

## Evidence center

Publish safe, reproducible evidence where appropriate:

- detection coverage;
- verifier coverage;
- benchmark methodology;
- known limitations;
- release verification;
- security model;
- architecture decisions.

Do not publish private benchmark material or information that creates new security exposure.

## Comparison philosophy

Do not use misleading feature-checkmark marketing. Explain honestly where SecretLoop differs and where another tool may be the better choice. Detector count alone is not the strategy.

## Pilot funnel

The pilot page should be oriented around an assessment, not generic "contact sales" language.

Concept:

- one engineering team;
- controlled scope;
- local-first execution;
- source stays in the customer's environment wherever possible;
- findings/verification/history/remediation workflow reviewed together;
- future exposure-intelligence capabilities included only after they ship.

## Public roadmap

Do not publish the full internal strategic roadmap. A public roadmap should remain broad, non-date-promissory and distinguish Now / Next / Exploring.
