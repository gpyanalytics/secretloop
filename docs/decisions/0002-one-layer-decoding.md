# 0002 — Encoded spans are decoded once, strictly, and never re-decoded

**Status:** in 0.5.0, prepared and pending publication (PR #43). **Surfaces:** every scan surface.

## Decision

Standard base64, hexadecimal and URL percent-encoded runs found in scanned text
are decoded exactly once and the named rules run over the decoded text. Bounds:
a run of at most 4,096 characters; decoded output of 12 to 4,096 bytes; strict
UTF-8; no NUL. Decoded output is never offered to the decoder again, and the
decoded text is not retained: the finding's value is the encoded source span,
its fingerprint folds the transform into its identity, and the entropy tier is
not run over decoded text.

## Why

A credential that is base64-encoded in a config file or hex-encoded in a
fixture is a credential a text rule cannot see. The scanner's existing rules are
the right detector once the text is decoded; what was missing was the decode.

## Why one layer, and why strict

- **One layer, structurally.** Recursive decoding turns every scanned file into
  an unbounded search; the bound here is not a flag but the fact that the only
  caller of the decoder is the scanner's encoded pass, which runs rules over the
  output and nothing else.
- **Strict decoding.** Node's base64 decoder is permissive; re-encoding closes
  every hole at once (wrong length, non-canonical trailing bits, bad padding).
  One malformed percent escape rejects the whole candidate. Invalid UTF-8 or a
  NUL rejects it, because that is the same text/binary boundary the walker draws.
- **Never transmitted.** The encoded text is not the credential and the decoded
  form is deliberately not kept, so verification refuses these findings before
  dispatch with the reason `unsupported-transform`, on every surface, and the
  MCP consent flow never mints a record for one.

## Evidence

Planted corpus: 15 positives (5 base64, 5 hex, 5 percent) recovered under the
expected provider rule, 0 control findings, both modes; six-repository
regression: finding populations unchanged apart from the intended additions;
pre-implementation freeze `encoded-v1-preimplementation-freeze-v0.4.0.md` and
post-implementation record in the benchmark workspace (manifests 28/28 and
51/51). Changelog **Unreleased** will carry the shipped summary at release.
