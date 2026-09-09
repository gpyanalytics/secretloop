# Decision records

Design decisions that shape what SecretLoop detects, what it refuses to do, and
what it sends. Each record states the decision, the alternatives that were
measured or considered, the evidence it rests on, and the release each decision
shipped in. Evidence lives in a private benchmark workspace and is cited
by SHA-256 of the frozen record; public summaries are in
[benchmarks](../benchmarks.md) and the changelog.

| record | decision | status |
|---|---|---|
| [0001](0001-entropy-tier-opt-in.md) | The generic high-entropy tier is off by default | shipped in 0.4.0 |
| [0002](0002-one-layer-decoding.md) | Encoded spans are decoded once, strictly, and never re-decoded | shipped in 0.5.0 |
| [0003](0003-archive-depth-one.md) | Archives are opened in memory, one layer deep, under frozen limits | shipped in 0.5.0 |
| [0004](0004-verification-consent-gate.md) | An MCP verification needs a human approval in a terminal, bound to one value | shipped in 0.2.0; refusals for member and encoded findings shipped in 0.5.0 |
| [0005](0005-api-document-entropy-scope.md) | The entropy tier is not run over API description documents | shipped in 0.5.0 |
| [0006](0006-archive-coverage-accounting.md) | Archive containers, members, metadata and enumeration are accounted separately from files | shipped in 0.5.0 |

A record is amended, not rewritten, when a decision changes; the amendment says
what changed and why.
