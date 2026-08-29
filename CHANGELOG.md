# Changelog

## 0.1.1 — unreleased

Precision and honesty. No detection rule changed.

### Fewer findings, same detection
- **Generated files are skipped by default** — lockfiles (`*.lock`, including
  CocoaPods `Podfile.lock`), Gradle and Maven wrappers, Xcode project files and
  SARIF reports. Scan them anyway with `--include-generated`, which bypasses
  this group only: `node_modules`, `package-lock.json` and minified bundles are
  never scanned, as before. On a bugsnag-js benchmark this removed 408 of 855
  history findings.
- **URLs and file paths no longer look like secrets.** The entropy pass already
  skipped bare URLs and absolute paths; it now also skips protocol-relative
  URLs (`//cdn.example.com/…`) and relative paths
  (`../node_modules/react-native/…`). A further 148 history findings. Genuine
  high-entropy values are unaffected, including base64 containing slashes.
- **Repeated values are reported once.** One credential copied into forty files
  is one thing to rotate, so the text report groups occurrences of the same
  value into a single entry listing every location. Counts, JSON and SARIF are
  unchanged — one result per occurrence, every fingerprint intact — so existing
  baselines and dashboards are unaffected.

On bugsnag-js at `5da3ae1`: history 855 → 299 findings (82 grouped entries);
working tree 239 → 150 findings (30 grouped entries).

### Honesty about what was and was not looked at
- **Redaction hardened for short secrets.** Masking revealed the first and last
  four characters at every length above eight, which showed eight of a
  nine-character value — the length range where human-chosen passwords live.
  Values of 9–15 characters now show only a two-character prefix and never a
  suffix. Values of 8 or fewer are still fully masked; 16 and above are
  unchanged.
- **Scan scope is now disclosed in JSON and SARIF**, not only in the text
  report. JSON gains `summary.scope`, `summary.scannedCount` and
  `summary.scopeNoun`; SARIF gains a standard `invocations` entry carrying the
  same sentence. CI reads exactly these two formats, so this is where the
  guarantee that "nothing was scanned" never reads as "nothing was found"
  matters most. Existing keys are unchanged; the new ones are additive.
- **Inline suppressions are counted and disclosed.** A scan that dropped
  findings to `secretloop:allow` or `gitleaks:allow` now says so:
  `; 3 finding(s) suppressed by inline directives`. The directives themselves
  behave exactly as before.
- **Staged scans fail loudly when git cannot answer.** `secretloop staged`
  treated a failed `git diff --cached` as an empty index, so a locked index
  during a pre-commit hook exited 0 on a scan that never ran. It now exits 2 and
  says why.

### Corrections
- **A non-zero exit says what it means.** `--fail-on` prints to stderr when it
  fails a build: `exit 1: findings at or above the fail-on threshold (this is
  the CI gate, not an error)`. Report output on stdout is byte-identical.
- **A corrupt baseline now names the file** — `Could not parse
  .secretloop-baseline.json: …` instead of a bare parser error.
- **`.secretloop.example.json` claimed a fallback that never shipped.** It said
  a `.secretguard.json` from before the rebrand would still be read if no
  `.secretloop.json` existed. No release ever did this: `resolveConfigFile`
  has only ever looked for `.secretloop.json`. The comment is corrected, and no
  fallback was added. If you are carrying a `.secretguard.json`, rename it.
