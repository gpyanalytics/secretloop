#!/bin/bash
# Evidence after the macOS full-suite step did not finish.
#
# WHY. On 2026-09-27 `test-macos (18)` (run 36296308215, job 108555694110) printed its last
# "ok" line at 05:09:10Z -- the plain FIFO case of tests/bounded-file-reads.test.ts -- and then
# nothing for 29 minutes until the 30-minute job timeout cancelled it. The job-end sweep killed one
# orphan `node`. Which process hung, and where, is unknown: the harness names a test only after it
# finishes, and a cancelled job runs no further steps. The suite step now has its own 15-minute
# bound and this script runs after it under `if: always()`, so a hang becomes a FAILED job within
# 15 minutes that says which test was running, which processes survived, where they were blocked
# and what they held open -- and then cleans up exactly what the suite created.
#
# WHAT IT READS. The suite step writes a small state directory ($RUNNER_TEMP/secretloop-suite):
#   suite.start    epoch seconds when the suite began
#   suite.pgid     the process group the suite pipeline ran in (set -m gives it its own group)
#   suite.tmpdir   the directory os.tmpdir() resolved to for the suite
#   tmp-before.txt the top-level entries of that directory before the suite ran
#   suite.log      the tee'd suite output
#   suite.ok       present only if the suite step finished successfully
#
# WHAT IT NEVER PRINTS. Environment, command-line arguments, file contents, credentials. Process
# rows carry pid, parent, group, state, elapsed time and the executable's base name. Sample and
# lsof output pass through a redaction of the home directory, the runner temp directory, the suite
# temp directory and the workspace, and are capped in lines. The last-completed-test lines are the
# harness's own fixed test names and headings.
#
# WHAT IT TOUCHES. Only processes in the recorded process group (never by name) and only
# directories that are new in the suite temp directory since the snapshot, were born after the
# suite started, are owned by this user, and carry a test lab prefix (secretloop- or sl-). Nothing
# else is killed or removed. The suite step's own failure is what fails the job; this script exits
# non-zero only when its cleanup could not finish.
#
# BOUNDS. Every external probe runs under a perl alarm (the alarm survives exec), the whole step
# has its own timeout-minutes in the workflow, and output per probe is capped.
set -u

STATE="${SECRETLOOP_SUITE_STATE:-${RUNNER_TEMP:-/tmp}/secretloop-suite}"
if [ -f "$STATE/suite.ok" ]; then
  echo "suite step succeeded; nothing to collect"
  exit 0
fi
if [ ! -d "$STATE" ] || [ ! -f "$STATE/suite.pgid" ]; then
  echo "no suite state recorded: the suite step did not reach its start (nothing to collect)"
  exit 0
fi

PG="$(tr -d '[:space:]' < "$STATE/suite.pgid")"
START="$(tr -d '[:space:]' < "$STATE/suite.start" 2>/dev/null || echo 0)"
SUITE_TMP="$(cat "$STATE/suite.tmpdir" 2>/dev/null || echo "${TMPDIR:-/tmp}")"
SUITE_TMP="${SUITE_TMP%/}"
LOG="$STATE/suite.log"
HOME_DIR="${HOME:-/nonexistent}"
RT="${RUNNER_TEMP:-/nonexistent}"
WS="${GITHUB_WORKSPACE:-/nonexistent}"

redact() {
  # Longest, most specific paths first. The suite temp directory usually sits under the user's
  # home-like /var/folders tree, the runner temp under the workspace parent.
  sed -e "s#${SUITE_TMP}#<tmp>#g" -e "s#${RT}#<runner-temp>#g" -e "s#${WS}#<workspace>#g" -e "s#${HOME_DIR}#~#g"
}
bounded() { # bounded SECONDS cmd args...  -- the alarm persists across exec, so a stuck probe dies
  local secs="$1"; shift
  perl -e 'alarm shift @ARGV; exec @ARGV or exit 127' "$secs" "$@"
}
members() { ps -axo pgid= | tr -d ' ' | grep -c "^${PG}\$" || true; }

echo "::group::suite did not finish — evidence (sanitized)"
echo "suite started at epoch ${START}; recorded process group ${PG}; now $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ---- 1. the last completed test, from the tee'd log
if [ -f "$LOG" ]; then
  TOTAL="$(wc -l < "$LOG" | tr -d ' ')"
  LASTNO="$(grep -n -E '^  (ok|skip|FAIL) - ' "$LOG" | tail -1 | cut -d: -f1)"
  if [ -n "${LASTNO:-}" ]; then
    HEADING="$(head -n "$LASTNO" "$LOG" | grep -v -E '^( |$|>|[0-9]+ passed)' | tail -1)"
    echo "last completed test (log line ${LASTNO} of ${TOTAL}):"
    echo "  suite   : ${HEADING}"
    echo "  test    : $(sed -n "${LASTNO}p" "$LOG")"
    AFTER=$((TOTAL - LASTNO))
    echo "  ${AFTER} line(s) followed it; the hung test is the next one in that file's order"
    if [ "$AFTER" -gt 0 ]; then
      echo "  lines after it (redacted, at most 5):"
      tail -n "$AFTER" "$LOG" | head -5 | redact | sed 's/^/    | /'
    fi
  else
    echo "suite log has ${TOTAL} line(s) and no completed test line"
  fi
else
  echo "no suite log was captured"
fi

# ---- 2. surviving processes in the suite's own process group (never selected by name)
echo "surviving processes in group ${PG}: $(members)"
SURVIVORS="$(ps -axo pid=,ppid=,pgid=,stat=,etime=,comm= | awk -v pg="$PG" '$3==pg')"
if [ -n "$SURVIVORS" ]; then
  echo "  pid ppid pgid stat elapsed comm"
  echo "$SURVIVORS" | awk '{ n=split($6,a,"/"); printf "  %s %s %s %s %s %s\n", $1, $2, $3, $4, $5, a[n] }'
fi

# ---- 3. where they are blocked and what they hold open (first three, each probe bounded)
COUNT=0
for PID in $(echo "$SURVIVORS" | awk '{print $1}'); do
  COUNT=$((COUNT + 1)); [ "$COUNT" -gt 3 ] && { echo "  (more survivors not sampled)"; break; }
  echo "--- pid ${PID}: stack sample (2 s, redacted, first 120 lines)"
  # `sample` writes its report to /tmp unless told otherwise; keep it inside the job's own state
  # directory, which the runner discards, and print it from there.
  SAMPLE="$STATE/sample-${PID}.txt"
  bounded 30 /usr/bin/sample "$PID" 2 -mayDie -file "$SAMPLE" >/dev/null 2>&1 || echo "  (sample did not complete)"
  # The report header names the binary's install path; only its base name is kept.
  # The trailing "Binary Images" table (library load addresses and install paths) carries nothing
  # about where the process is blocked, so the report stops there.
  [ -f "$SAMPLE" ] && redact < "$SAMPLE" | sed -E 's#^(Path: +).*/([^/]+)$#\1.../\2#' | sed '/^Binary Images:/q' | head -120 | sed 's/^/  /'
  echo "--- pid ${PID}: open descriptors (fd type location/basename, first 40)"
  # NAME is reduced to a directory class and the base name: <tmp>, <runner-temp>, <workspace>, ~
  # (home) or <other>. A FIFO the process is still blocked in open() on has no descriptor yet and
  # does not appear here; the stack sample is what shows that state.
  bounded 20 /usr/sbin/lsof -nP -p "$PID" 2>&1 | awk 'NR>1 { print $4, $5, $NF }' | redact \
    | awk '{ n=split($3,a,"/"); base=a[n]; cls="<other>"; if ($3 ~ /^<tmp>/) cls="<tmp>"; else if ($3 ~ /^<runner-temp>/) cls="<runner-temp>"; else if ($3 ~ /^<workspace>/) cls="<workspace>"; else if ($3 ~ /^~/) cls="~"; else if ($3 !~ /^\//) { cls=""; base=$3 } printf "%s %s %s%s%s\n", $1, $2, cls, (cls==""?"":"/.../"), base }' \
    | head -40 | sed 's/^/  /'
done

# ---- 4. end the suite's process group: TERM, wait up to 5 s, then KILL
CLEAN_OK=1
if [ "$(members)" -gt 0 ]; then
  kill -TERM -- "-${PG}" 2>/dev/null || true
  for _ in 1 2 3 4 5; do [ "$(members)" -eq 0 ] && break; sleep 1; done
  if [ "$(members)" -gt 0 ]; then
    kill -KILL -- "-${PG}" 2>/dev/null || true
    sleep 1
  fi
  LEFT="$(members)"
  echo "process group ${PG} after cleanup: ${LEFT} member(s)"
  [ "$LEFT" -eq 0 ] || CLEAN_OK=0
fi

# ---- 5. lab directories the suite created and could not remove
REMOVED=0; KEPT=0
if [ -d "$SUITE_TMP" ] && [ -f "$STATE/tmp-before.txt" ]; then
  ls -1A "$SUITE_TMP" > "$STATE/tmp-after.txt" 2>/dev/null || true
  while IFS= read -r NAME; do
    [ -n "$NAME" ] || continue
    case "$NAME" in secretloop-*|sl-*) ;; *) continue ;; esac
    P="$SUITE_TMP/$NAME"
    [ -d "$P" ] || continue
    BORN="$(stat -f %B "$P" 2>/dev/null || echo 0)"; OWNER="$(stat -f %u "$P" 2>/dev/null || echo -1)"
    if [ "$BORN" -ge "$START" ] && [ "$OWNER" = "$(id -u)" ]; then
      if rm -rf "$P" 2>/dev/null; then REMOVED=$((REMOVED + 1)); echo "  removed lab directory: $(echo "$NAME" | sed -E 's/-[A-Za-z0-9]{6,}$/-<random>/')"
      else KEPT=$((KEPT + 1)); CLEAN_OK=0; fi
    else
      KEPT=$((KEPT + 1))
    fi
  done < <(comm -13 <(sort "$STATE/tmp-before.txt") <(sort "$STATE/tmp-after.txt"))
fi
echo "lab directories: ${REMOVED} removed, ${KEPT} left in place (not new, not ours, not born after the suite started, or not removable)"
echo "::endgroup::"

if [ "$CLEAN_OK" -eq 1 ]; then
  echo "evidence collected and cleanup complete; the suite step's own result stands"
  exit 0
fi
echo "evidence collected but cleanup did NOT finish (see counts above)"
exit 1
