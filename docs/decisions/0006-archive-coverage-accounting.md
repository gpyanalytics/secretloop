# 0006 — Archive containers, members, metadata and enumeration are accounted separately from files

**Status:** shipped in 0.5.0 (2026-09-09) (PR #47). **Surfaces:** CLI text, JSON, SARIF,
MCP, VS Code workspace summary.

## Decision

A scan that meets archives reports, beside the file counts and never folded
into them: containers opened and members scanned; members refused, by reason;
members excluded by configuration; metadata entries skipped; containers not
fully enumerated, with the count of declared entries not inspected (known for a
ZIP, unknown by construction for a stopped tar walk); and recognized containers
that would not open, by reason. The sentence carries counts only; the
structured object (`summary.archives`, SARIF invocation properties, MCP
`scope.archives`) carries the bounded reason codes.

A container whose magic is recognised but which the parser declines is
disclosed as *not opened* and then takes the ordinary text path, so a
named-rule value inside it is still reported at the file path and the file is
not double-counted as a binary skip.

## Why

Before this, a recognized archive that failed to open was indistinguishable from
an ordinary binary skip, refused members inflated counters labelled as files,
and a walk that stopped at a cap said nothing. A scan that cannot say what it
did not look at is the failure this project has spent most of its effort
avoiding.

## What did not change

Archive support, parsing decisions, traversal, limits and detection are exactly
as in decision 0003. Findings, fingerprints, encoded scanning, PKCS#12 and the
entropy scope are unchanged; the default exit status is unchanged and there is
no strict-coverage flag.

## Evidence

27 planted cases whose sentences and structured objects equal frozen
expectations; six-repository regression with finding multisets unchanged in all
18 repository-mode pairs and only the predeclared metadata differing; four
archive-free repositories byte-identical in every mode; comparison checker
rejects finding, accounting and unrelated-field mutations. Records
`archive-coverage-disclosure-*` in the benchmark workspace.
