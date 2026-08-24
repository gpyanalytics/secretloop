# SecretLoop — top-of-README demo GIF
#
#   vhs docs/demo.tape
#
# This file contains no credentials and is safe to commit. It types commands
# only; the tokens live in an untracked scratch directory that the tape enters
# off-camera. Nothing here needs editing when the token is rotated.
#
# ---------------------------------------------------------------------------
# One-time setup, outside this tape
# ---------------------------------------------------------------------------
#
#   # in the secretloop repo
#   npm pack
#
#   mkdir -p ~/sl-demo/src && cd ~/sl-demo
#   npm init -y && npm i ~/path/to/secretloop-0.1.0.tgz
#
# Do NOT git init ~/sl-demo. walk.ts falls back to a directory walk when
# `git ls-files` fails, so the scan works fine without a repo — and the live
# token then never touches git at all.
#
# Check this before recording:
#
#   git -C ~/sl-demo rev-parse --show-toplevel   # must print nothing
#
# A scan inside a git repo climbs to the repo root. If your home directory is
# itself a repo (dotfiles-in-home), ~/sl-demo inherits it and the scan
# enumerates your entire home directory — a broken take, and every finding in it
# on camera. Put the scratch directory somewhere outside any repo if so.
#
# ~/sl-demo/src/github-sync.ts:
#
#   import { Octokit } from "@octokit/rest";
#
#   // Rotated both of these back in March — leaving them here for reference.
#   const OLD_CI_TOKEN  = "ghp_<36 fabricated alphanumerics>";
#   const OLD_BOT_TOKEN = "ghp_<a real GitHub PAT with NO scopes ticked>";
#
#   export const client = new Octokit({ auth: process.env.GITHUB_TOKEN });
#
# The fabricated one 401s and reads CONFIRMED DEAD. The real scopeless one 200s
# and reads CONFIRMED LIVE — GET /user gates on authentication, not
# authorization, so no scope is required. Revoke it as soon as the take is good.
#
# ---------------------------------------------------------------------------

Output docs/demo.gif

# 1400px at 22pt is ~102 columns; the widest output line is 90. Recorded at
# roughly 2x the width a README renders at, so it stays sharp downscaled.
Set Shell        "bash"
Set FontSize     22
Set Width        1400
Set Height       620
Set Padding      24
Set TypingSpeed  80ms

# Off-camera: enter the scratch directory and flatten the prompt, so no
# username, path or git branch reaches the recording.
Hide
Type "cd ~/sl-demo"
Enter
Type "export PS1='> ' && clear"
Enter
Show

# Beat 1 — a held prompt. Lets the loop settle before anything moves.
#
# Deliberately no `cat src/github-sync.ts` here. The real token is unredacted on
# disk, and the scan output is the only place it appears masked. Putting the
# file on camera would publish a working credential to npm and GitHub in a
# secret-scanning tool's own README. The "rotated these in March" premise goes
# in the README prose beside the GIF instead, where it costs nothing.
Sleep 1s

# Beat 2 — the command, typed at a readable pace.
Type "npx secretloop scan --verify"

# Beat 3 — the pause before Enter. There is no spinner to watch (the whole
# scan-and-verify returns in about 0.7s), so this is where the tension lives.
Sleep 1200ms
Enter

# Beat 4 — the payoff. Two identical-looking tokens, opposite verdicts. Long
# hold on purpose: there are two verdicts to read and contrast, and it should
# feel a touch too long rather than a touch too short.
Sleep 8s

# Beat 5 — answers the second question every reader has: does this gate CI.
Type "echo $?"
Enter
Sleep 2500ms
