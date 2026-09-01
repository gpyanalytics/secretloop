# Security policy

## Reporting a vulnerability

Use the **Report a vulnerability** button on this repository's Security tab,
not a public issue. A weakness in a secret scanner is worth more to an attacker
than to anyone else, so a report stays private until there is a fix to point at.

What helps: the command you ran, what happened, and what you expected. A
minimal reproduction beats a severity rating.

## What the tool does with your code and your credentials

Scanning is local. Reading files, matching rules and scoring entropy all happen
in this process, and none of that code opens a socket. There is no telemetry, no
analytics, no usage reporting and no account. There is no language model in here
either — detection is patterns and arithmetic, so the same input always produces
the same output. The published package declares no runtime dependencies.

Two features can reach the network, and neither runs on its own.

**Verification** asks a provider whether a detected credential still works,
which means sending that credential to that provider. It is off by default and
has a separate control on each surface: the `--verify` flag on the command line,
and the `secretloop.enableLiveVerification` setting in the editor. Turning the
setting on matters more than it looks — verification then runs as part of the
ordinary on-save scan rather than as a separate action you take each time, and
the extension may offer to enable it in a prompt. If your policy is that no
credential leaves the machine, refusing `--verify` is only half of it; pin the
setting off as well.

Eighteen of the rules have a verifier, covering fifteen providers. A credential
matched by any other rule is never transmitted, whatever the flag says. One of
those eighteen never transmits either: `sk_live_`/`sk_test_` is issued by more
than one company, so a key matching it cannot be attributed to an issuer and is
not sent to any of them — it reports as unknown with that reason. Seventeen
rules, then, can actually put a credential on the wire.

Every credential that does leave is logged to the extension's output channel,
naming the count and the providers. The log records what was sent, not what was
attempted, so it cannot overstate.

**Rotation** acts on one finding when you ask it to. For GitHub, Stripe and
Google it opens the provider's own console and transmits nothing. For Slack it
calls Slack's revocation API with the exposed token. For AWS it opens the IAM
console — unless you have stored admin credentials for rotation, in which case
it makes an authenticated IAM call to deactivate the leaked key.

Those AWS admin credentials are the one privileged secret this tool can hold.
They live in the operating system's credential store through the editor's secret
storage, never in a settings or configuration file, and the extension migrates
any that a previous version left in settings. If you do not use AWS rotation,
nothing of the kind is stored.

Baselines store fingerprints — path, rule id and a hash of the value — rather
than the values themselves.

## Supported versions

The latest published release, and only that one. SecretLoop is at 0.1.x with no
long-term support branches — fixes ship forward.

## What to expect

This is maintained by one person outside a day job, so there is no response-time
guarantee and printing one would be dishonest. Reports are acknowledged when
they are seen, realistically within a few days, and security reports get read
before anything else in the queue.
