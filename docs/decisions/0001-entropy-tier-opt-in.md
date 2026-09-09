# 0001 — The generic high-entropy tier is off by default

**Status:** shipped in 0.4.0 (2026-09-08). **Surfaces:** CLI, VS Code, MCP.

## Decision

`entropyPassEnabled` defaults to `false`. A default scan reports named-format
rules and file-level PKCS#12 detection only. The tier ships intact and is
restored per run with `--include-entropy` or persistently with
`"entropyPassEnabled": true`. `secretloop mask` masks generic strings only with
`--entropy`, which was already its behaviour.

## Why

On the frozen six-repository benchmark the tier produced 279 of SecretLoop's
299 false positives. Turning it off moved precision from 37.7% to 89.3% on the
same population and reproduced the prior reports byte for byte when turned
back on, so the previous behaviour remains available exactly.

## What it costs, stated

The default removes 14 validated true positives across 5 sites — all
`generic-high-entropy` on Kubernetes AES encryption-config test data, which no
named rule reached at the time — and coverage falls from 142/145 to 137/145 of
the validated files. The recall the tier uniquely contributes over rule-based
scanning was not measured by the N9 study or by this one, so the default is set
on the measured half of the trade and the tier is kept for the unmeasured half.

## Alternatives measured

- Suppressing the tier's dominant noise class by alphabetic density (N9): the
  frozen candidate discarded 49.8% of realistic credentials on an independent
  corpus. Rejected.
- Format-scoped suppression of the residual entropy false positives: rejected on
  its own evidence; not planned.
- Removing the tier: rejected, because its true positives were real.

## Evidence

Freeze record `entropy-default-freeze-fd01370.md` (benchmark workspace);
changelog 0.4.0; [benchmarks §2](../benchmarks.md#2-the-040-default-entropy-tier-off--same-corpus-same-labels).

## Since then

One of the five lost sites — the `transformation_test.go` AES key — is now
recovered in default mode on `main` by the named rule
`encryption-key-assignment` (PR #48), which claims the value before the entropy
tier sees it. The other Kubernetes encryption-config sites remain entropy-only.
