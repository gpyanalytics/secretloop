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
has a separate control on each of three surfaces:

- the `--verify` flag on the command line;
- the `secretloop.enableLiveVerification` setting in the editor;
- the `secretloop approve` consent gate, for the `secretloop_verify` tool an
  MCP client can call.

Turning the editor setting on matters more than it looks — verification then
runs as part of the ordinary on-save scan rather than as a separate action you
take each time, and the extension may offer to enable it in a prompt.

The third surface is the one to check if an AI coding agent is connected. An
assistant can *ask* for a verification, but it cannot grant one: the first call
transmits nothing and returns `CONSENT_REQUIRED`, and the check runs only after
a person has run `secretloop approve <fingerprint>` in a terminal, which refuses
to run without one. Approval is opt-in, one-time, and bound to a single
credential.

If your policy is that no credential leaves the machine, all three have to be
closed: do not pass `--verify`, pin `secretloop.enableLiveVerification` off, and
either do not connect the MCP server or never approve a request.

The consent records behind that gate live in `.secretloop` under your home
directory and hold a hash of the credential, never the credential. **On macOS
and Linux, SecretLoop refuses to trust, write, approve or claim a consent
record when that directory or its `pending` directory fails its private-store
checks** — it must be a real directory (not a symbolic link) owned by your
account with mode `0700`; a directory you own that is too open is set to `0700`
and re-checked, and a directory owned by another account is refused rather than
changed. The refusal names the problem in fixed words and says what to do; it
never prints a path, a record or an OS error. This is the trust boundary the
tool has always documented, now enforced instead of assumed. It inspects the
store's own two directories by mode bits and ownership, not the path above
them; it does not see POSIX ACL entries, so an ACL grant to another account is
not detected; and it closes no window against a process already running as
you or against any account that can write your home directory. **On Windows the check is a different one**, because mode bits mean nothing
there. Before every consent operation SecretLoop reads the owner and the access
list of `.secretloop`, of its `pending` directory and of each record it is about
to use, and requires every entry to allow only your account, SYSTEM or
Administrators, the owner to be one of those three, and your account to hold
full access. Records are checked individually, not just the directories around
them: a record another account planted and a protected parent later caught looks
private, because its inherited access list is rewritten, while its owner stays
the account that planted it — and an owner can re-grant itself. SecretLoop also
walks every folder from the drive root down to the store's parent and refuses if
any account outside a small platform set (SYSTEM, Administrators, the service
identities that own stock system folders) can delete, rename or re-permission
one of them, because a private store inside a folder someone else can rename can
be replaced wholesale. New stores are created private and a failed creation
withdraws only what it made; an existing store is refused, never repaired. The
built-in `powershell.exe` and `icacls.exe` are used to read and set permissions;
if either cannot be run, consent is refused rather than assumed safe.

What that does not buy you: applying an access list does not revoke a handle
another process already holds, so these checks prevent the situation for a store
SecretLoop creates rather than revoking anything, and for a store that already
existed they describe the present only — not whether it was always private, nor
whether a handle was opened while it was not. Nothing here defends against an
administrator, against SYSTEM, against a compromised Windows service, or against
code already running as you. A store under a folder that grants other accounts is
now refused and will not be created, and a store on a network or UNC path is
refused because these checks have not been established for that kind of location.

Where this was exercised: local accounts on one hosted Windows Server 2025 image
with an NTFS volume, in English, with the checks driven by an ordinary account
against a second ordinary account. That is one environment, not a statement that
Windows is supported everywhere. Domain accounts and domain groups, profiles that
are roamed, redirected or otherwise managed, non-NTFS volumes, non-English hosts
and ARM64 have not been exercised, so nothing is claimed about them.

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

**Encoded and archived content** is handled in the same process: base64, hex
and percent-encoded spans are decoded once and scanned, and ZIP, tar and gzip
archives are opened in memory one layer deep with nothing extracted to disk and
no member name resolved against a filesystem. A credential found by decoding or inside an archive
member is never transmitted: verification refuses it before any provider
lookup, and the MCP consent flow never writes a record for it. Archive members
are quoted in MCP error messages through the same untrusted-data wrapper as
every other repository-authored fragment.

## Supported versions

The latest published release, and only that one. There are no long-term
support branches — fixes ship forward, so a fix lands in the next release
rather than as a patch to an older one. This document ships with **SecretLoop
0.6.0**; check what you are running with `secretloop --version`, or the version
on the extension's listing, and upgrade before reporting an issue against an
older one.

## What to expect

This is maintained by one person outside a day job, so there is no response-time
guarantee and printing one would be dishonest. Reports are acknowledged when
they are seen, realistically within a few days, and security reports get read
before anything else in the queue.
