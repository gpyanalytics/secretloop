# Triage rules for the precision baseline

One row per finding. `run_scans.sh` writes every row but the last two columns;
a human fills `verdict` and `reason`. Copy `triage_seed.csv` to `triage.csv`
and edit that — never edit the seed, so a re-scan can be diffed against it.

## verdict

| value | meaning |
|---|---|
| `TP` | a credential. Something that would grant access if it were live, whether or not it still is. |
| `FP` | not a credential. A digest, UUID, hash, public key, sample from documentation, type name, base64 asset, test vector. |
| `UNKNOWN` | you looked and could not decide. Not a parking space for rows you did not read. |

Liveness is **not** the test — verification is off for both tools, and a
rotated-but-real AWS key is still a true positive for a detector. The test is
whether the bytes are a credential.

## The judgment calls, fixed in advance

Written down before triage starts, because deciding these while looking at the
numbers is how a benchmark gets its thumb on the scale.

- **A committed test credential is a TP** if it is a real credential shape
  issued for a test account; **FP** if it is a literal placeholder
  (`sk_test_xxxxxxxx`, `AKIAIOSFODNN7EXAMPLE`, `your-token-here`).
- **A documentation example is FP.** Provider docs publish these deliberately.
- **A private key block is a TP** even if the key is a fixture. It is a
  credential; whether it guards anything is a different question.
- **A JWT is a TP** if it carries anything but public claims, **FP** if it is
  the canonical `eyJhbGci...` example. `bench/README.md` records that this
  particular call moves the number materially, so it is stated here rather
  than left to the triager's mood.
- **A `.env.example` value is FP** unless it is a real credential shape.
- **A high-entropy string with no credential meaning is FP** — lockfile
  integrity hashes, content-addressed asset names, git SHAs, base64 images.

## reason

Free text, but say the class, not the feeling: `docs example`, `sha256 digest`,
`uuid`, `test fixture key`, `lockfile integrity`, `type name`, `real key for
test account`. `compute_precision.py` groups by it, so consistent wording is
worth more than eloquent wording.

## What the triager must not do

- Do not verify a credential against a provider. This baseline is offline.
- Do not decode, read, or reuse a value.
- Do not paste a value into `triage.csv`, an issue, or a commit message. The
  seed carries masked values and a scrubbed snippet on purpose; the real line
  is in the pinned checkout, which is where it stays.
- If a finding looks like a **live third-party credential**, stop, mark it
  `TP`, write `withheld — disclosure` as the reason, and handle it the way
  `bench/MULTI-CORPUS.md` handled its four: reported as a count, never
  described.

## The committed record

`bench/precision/triage.csv` is the triaged run, minus the `snippet` column.
Snippets are a working aid that carry scrubbed source text; the record does not
need source text, because repo + commit + file + line reproduces any row exactly
from the pinned checkout. `compute_precision.py` reads either shape.
