# 0005 — The entropy tier is not run over API description documents

**Status:** `main`, unreleased (PR #45). **Surfaces:** scan, staged, VS Code,
MCP. History and `mask` deliberately keep the pre-scope behaviour.

## Decision

When the generic entropy tier is enabled, a text recognised as an OpenAPI,
Swagger or AsyncAPI description is scanned by every named rule but not by the
entropy heuristic, and the scan discloses how many documents that affected
(`N API description document(s) scanned without generic entropy`). Recognition
needs both the extension (`.json`, `.yaml`, `.yml`, on the logical path — an
archive member's own path, never its container's) and a top-level marker: for
JSON, an `openapi`/`swagger` string with `paths`, `components` or
`definitions`, or an `asyncapi` string with `channels`; for YAML, a column-0
`openapi:`/`swagger:`/`asyncapi:` key with a digit-leading value within the
first 65,536 code units. Restore with `--include-api-document-entropy` or
`includeApiDocumentEntropy`.

## Why

On the six-repository benchmark, 101 of the entropy tier's 279 false positives
were `operationId` and `description` strings inside OpenAPI documents, and no
validated true positive sat in one.

## What it costs, stated

An unnamed generic secret written into such a document — an `example` value,
say — is not reported unless the switch is set. Four of 24 eligible planted
positives in the validation corpus were suppressed by design and all four were
recovered by the restore switch with identical fingerprints. This is a
documented contract, not a claim that API documents never contain secrets.

## Why whole-document, why named rules are unconditional

Suppressing per field would need a parser with opinions about which fields are
examples; whole-document is decidable, deterministic and disclosed. Named rules
never consult the classifier: a provider token in an OpenAPI example is still a
provider token.

## Evidence

Exactly the 101 predeclared historical false positives removed, zero added, every
surviving finding an identical object; restore mode byte-identical to the
pre-change reports; planted corpus and independent enumeration of the 81
documents in `kubernetes`. Records `entropy-scope-v1-*` in the benchmark
workspace.
