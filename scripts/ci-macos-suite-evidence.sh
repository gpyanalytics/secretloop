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
# WHAT IT TOUCHES. Only processes in the recorded process group that started after the suite began
# and are not this step or its ancestors (a group id is a reused pid; if it equals this step's own
# group the script stops without touching anything), killed by pid, never by name; and only
# directories that are new in the suite temp directory since the snapshot, were born after the
# suite started, are owned by this user, carry a test lab prefix (secretloop- or sl-) and are not
# symbolic links. Nothing
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
  sed -e "s#${SUITE_TMP}#<tmp>#g" -e "s#${RT}#<runner-temp>#g" -e "s#${WS}#<workspace>#g" -e "s#${HOME_DIR}#~#g" \
      -e "s#/private/tmp/#<systmp>/#g" -e "s#/private/var/folders/#<systmp>/#g" -e "s#/var/folders/#<systmp>/#g" -e "s#/tmp/#<systmp>/#g"
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
# A process-group id is the leader's pid, and pids are reused. Three guards against a stale or
# recycled id: the recorded group must not be this step's own group; no member may be this script
# or one of its ancestors; and every member must have started after the suite began (etime is the
# member's own age, so start = now - etime). Anything failing a guard is reported, never touched.
OWN_PG="$(ps -o pgid= -p $$ | tr -d ' ')"
if [ "$PG" = "$OWN_PG" ]; then
  echo "recorded group ${PG} is this step's own process group: the id has been reused; nothing is sampled, killed or removed"
  echo "::endgroup::"
  exit 0
fi
ANCESTORS=" "; A="$$"; while [ -n "$A" ] && [ "$A" != "0" ] && [ "$A" != "1" ]; do ANCESTORS="${ANCESTORS}${A} "; A="$(ps -o ppid= -p "$A" 2>/dev/null | tr -d ' ')"; done
NOW="$(date +%s)"
etime_secs() { # [[dd-]hh:]mm:ss -> seconds
  local t="$1" d=0; case "$t" in *-*) d="${t%%-*}"; t="${t#*-}";; esac
  local IFS=:; set -- $t
  case $# in 3) echo $((d*86400 + $1*3600 + $2*60 + $3));; 2) echo $((d*86400 + $1*60 + $2));; *) echo 0;; esac
}
RAW="$(ps -axo pid=,ppid=,pgid=,stat=,etime=,comm= | awk -v pg="$PG" '$3==pg')"
SURVIVORS=""; REJECTED=0
while IFS= read -r ROW; do
  [ -n "$ROW" ] || continue
  set -- $ROW; RPID="$1"; RET="$5"
  case "$ANCESTORS" in *" $RPID "*) REJECTED=$((REJECTED + 1)); continue;; esac
  STARTED=$((NOW - $(etime_secs "$RET")))
  if [ "$STARTED" -lt $((START - 5)) ]; then REJECTED=$((REJECTED + 1)); continue; fi
  SURVIVORS="${SURVIVORS}${ROW}
"
done <<< "$RAW"
SURVIVORS="$(printf '%s' "$SURVIVORS")"
# IDENTITY, re-checked at every use. A pid can be recycled between this listing and a later
# sample or signal. Each accepted pid is fingerprinted now -- group, start time (second
# resolution) and executable; NOT the parent pid, which the kernel rewrites to 1 when a parent
# exits first -- and the fingerprint must still match immediately before it is
# sampled and immediately before each signal; a pid whose fingerprint differs or cannot be read is
# skipped and the cleanup reported incomplete. The window between a check and the following
# kill(2) is not closed by this (nothing in user space can close it), so no claim of race-free
# cleanup is made; the window is reduced to microseconds and any mismatch is reported.
FP_FILE="$STATE/fingerprints.txt"; : > "$FP_FILE"
fingerprint() { ps -o pgid=,lstart=,comm= -p "$1" 2>/dev/null | tr -s ' ' | sed -e 's/^ //' -e 's/ $//'; }
for P in $(printf '%s\n' "$SURVIVORS" | awk 'NF {print $1}'); do printf '%s\t%s\n' "$P" "$(fingerprint "$P")" >> "$FP_FILE"; done
same_identity() { # 0 = same process as fingerprinted; 1 = gone (exited, or a zombie not yet reaped); 2 = different or unreadable
  local now st
  now="$(fingerprint "$1")"
  if [ -z "$now" ]; then
    kill -0 "$1" 2>/dev/null || return 1
    sleep 0.2; now="$(fingerprint "$1")"
    [ -z "$now" ] && { kill -0 "$1" 2>/dev/null || return 1; return 2; }
  fi
  # Read AFTER the fingerprint: a process that exited between the two reads is gone, not different.
  st="$(ps -o stat= -p "$1" 2>/dev/null | tr -d ' ')"
  case "$st" in ""|Z*) return 1;; esac
  [ "$now" = "$(grep "^$1	" "$FP_FILE" | cut -f2-)" ] && return 0 || return 2
}
echo "surviving processes in group ${PG}: $(printf '%s\n' "$SURVIVORS" | grep -c .) accepted, ${REJECTED} rejected (this step's ancestry, or started before the suite)"
if [ -n "$SURVIVORS" ]; then
  echo "  pid ppid pgid stat elapsed comm"
  echo "$SURVIVORS" | awk '{ n=split($6,a,"/"); printf "  %s %s %s %s %s %s\n", $1, $2, $3, $4, $5, a[n] }'
fi

# ---- 3. where they are blocked and what they hold open (leaves first, at most four, each probe bounded)
# The process that is actually stuck is normally the DEEPEST one -- npm -> sh -> ts-node -> the
# test's child -- while its ancestors merely wait on it. Survivors with no surviving child in the
# group are sampled first, then the rest, so the cap falls on the waiters, not the blocked leaf.
# (The first experiment run sampled npm, tee and sh by pid order and missed both node processes.)
# Order: leaves before waiters, deeper before shallower (depth = ancestors inside the group), so a
# childless helper such as `tee` does not take a slot ahead of the blocked leaf.
ORDERED="$(echo "$SURVIVORS" | awk '{ pid[NR]=$1; ppid[$1]=$2; isparent[$2]=1 }
  END { for (i=1;i<=NR;i++) { d=0; q=ppid[pid[i]]; while (q in ppid && d<64) { d++; q=ppid[q] }
        printf "%d %d %s\n", (pid[i] in isparent) ? 1 : 0, -d, pid[i] } }' | sort -n -k1,1 -k2,2 | awk '{print $3}')"
COUNT=0
IDENTITY_SKIPS=0
for PID in $ORDERED; do
  COUNT=$((COUNT + 1)); [ "$COUNT" -gt 4 ] && { echo "  (more survivors not sampled)"; break; }
  same_identity "$PID"; ID=$?
  if [ "$ID" -ne 0 ]; then
    echo "--- pid ${PID}: $([ "$ID" -eq 1 ] && echo 'exited before sampling' || echo 'identity changed or unreadable before sampling; skipped')"
    [ "$ID" -eq 2 ] && IDENTITY_SKIPS=$((IDENTITY_SKIPS + 1))
    continue
  fi
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
    | awk '{ v=$3; if (v !~ /\//) { printf "%s %s %s\n", $1, $2, v; next }
             n=split(v,a,"/"); base=a[n]; cls="<other>";
             if (v ~ /^</) { cls=substr(v, 1, index(v, ">")) } else if (v ~ /^~/) { cls="~" }
             printf "%s %s %s/.../%s\n", $1, $2, cls, base }' \
    | head -40 | sed 's/^/  /'
done

# ---- 4. end the accepted survivors: TERM, wait up to 5 s, then KILL -- by pid, identity re-checked
# immediately before each signal; never by name, never by group signal
CLEAN_OK=1
[ "$IDENTITY_SKIPS" -gt 0 ] && CLEAN_OK=0
# Signalled deepest-first (the order used for sampling), so a waiter is never signalled before the
# process it waits on.
ACCEPTED="$ORDERED"
MISMATCH=0
signal_same() { # signal_same SIG pid: signal only the fingerprinted process
  same_identity "$2"; local id=$?
  case "$id" in
    0) kill "-$1" "$2" 2>/dev/null || true ;;
    1) ;;
    *) MISMATCH=$((MISMATCH + 1)); echo "  pid $2: identity changed or unreadable before $1; NOT signalled" ;;
  esac
}
alive_same() { local n=0; for P in $ACCEPTED; do same_identity "$P" >/dev/null 2>&1; [ $? -eq 0 ] && n=$((n + 1)); done; echo "$n"; }
if [ -n "$ACCEPTED" ]; then
  for P in $ACCEPTED; do signal_same TERM "$P"; done
  for _ in 1 2 3 4 5; do [ "$(alive_same)" -eq 0 ] && break; sleep 1; done
  if [ "$(alive_same)" -gt 0 ]; then
    for P in $ACCEPTED; do signal_same KILL "$P"; done
    sleep 1
  fi
  LEFT="$(alive_same)"
  echo "accepted survivors after cleanup: ${LEFT} still alive with their recorded identity; ${MISMATCH} identity mismatch(es) left unsignalled; group ${PG} now has $(members) member(s)"
  [ "$LEFT" -eq 0 ] && [ "$MISMATCH" -eq 0 ] || CLEAN_OK=0
fi

# ---- 5. lab directories the suite created and could not remove
REMOVED=0; KEPT=0
if [ -d "$SUITE_TMP" ] && [ -f "$STATE/tmp-before.txt" ]; then
  ls -1A "$SUITE_TMP" > "$STATE/tmp-after.txt" 2>/dev/null || true
  while IFS= read -r NAME; do
    [ -n "$NAME" ] || continue
    case "$NAME" in secretloop-*|sl-*) ;; *) continue ;; esac
    P="$SUITE_TMP/$NAME"
    # A symbolic link is never followed or removed, whatever it points at.
    if [ -L "$P" ]; then KEPT=$((KEPT + 1)); echo "  left in place: symbolic link $(echo "$NAME" | sed -E 's/-[A-Za-z0-9]{6,}$/-<random>/')"; continue; fi
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
echo "lab directories: ${REMOVED} removed, ${KEPT} left in place (symbolic link, not ours, not born after the suite started, or not removable)"
echo "::endgroup::"

if [ "$CLEAN_OK" -eq 1 ]; then
  echo "evidence collected and cleanup complete; the suite step's own result stands"
  exit 0
fi
echo "evidence collected but cleanup did NOT finish or could not be confirmed (see counts above)"
exit 1
