# Contributing

Thank you for looking. This is a small project maintained outside a day job, so
the fastest way to get a change in is to make it easy to verify.

## Before you start

- **Security issues are not issues.** A weakness in a secret scanner goes
  through the private channel in [SECURITY.md](SECURITY.md), not a public issue
  or a pull request.
- **Never commit a real credential**, and prefer not to commit a
  credential-shaped one either: CI scans this repository with SecretLoop, and
  tests generate their fixtures at runtime from a fixed seed for exactly that
  reason. If a test needs a literal, build it by concatenation.
- **Read the roadmap first** for anything larger than a rule or a fix.
  [docs/project/roadmap.md](docs/project/roadmap.md) says what is out of scope
  and why; a pull request that argues with it should say so up front.

## Setting up

```bash
git clone https://github.com/gpyanalytics/secretloop
cd secretloop
npm ci
npm run compile && npm run bundle
npm test
```

Node 18 or newer. The build, layout and test harness are described in
[docs/development.md](docs/development.md).

## What a pull request needs

- **One change per pull request**, with a subject line that says what changed
  in behaviour, not which file was touched.
- **Tests that fail before and pass after.** For a detection change, say in the
  description which assertion failed against the unchanged code. A test that
  passes either way does not count.
- **A changelog entry** under **Unreleased** in [CHANGELOG.md](CHANGELOG.md)
  for anything a user could notice: a rule, a flag, a message, a count.
- **Documentation for the page that owns the topic.** Each topic has one
  authoritative page under `docs/`; update that page rather than adding a
  paragraph to the README.
- **No dependency additions.** The published package declares no runtime
  dependencies, and that is a property people rely on. A development dependency
  needs a reason in the description.
- **No version bumps, tags or packaging changes.** Releases follow
  [RELEASING.md](RELEASING.md) and are cut by the maintainer.

CI runs the test suite on Node 18 and 20, the packaging smoke tests, and a
self-scan. All of them must pass; a flaky run is rerun, not waived, and a
timing-dependent failure is worth a note in the description.

## Adding a detection rule

The mechanics — the rule shape, the fixture, the tests that will fail if you
miss a step — are in
[docs/development.md](docs/development.md#adding-a-rule). Two things the tests
cannot check for you:

- Bring the evidence. Where did you meet this credential shape, and what does a
  false positive look like? Real repositories, not a regex you expect to match.
- Keep the id stable. Rule ids are baseline identity; renaming one silently
  invalidates every accepted finding that mentions it.

## Changes to the security-critical surface

Anything under `src/mcp*.ts`, `src/consent.ts`, `src/verify*.ts` or
`src/workspace*.ts` is reviewed against the invariants listed in
[docs/decisions/0004-verification-consent-gate.md](docs/decisions/0004-verification-consent-gate.md)
before it merges. Expect questions about what an attacker who controls the
repository, the MCP client or a provider response could make the change do.

## Licence

By contributing you agree that your contribution is licensed under the
project's [LICENSE](LICENSE).
