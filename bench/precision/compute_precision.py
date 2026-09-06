#!/usr/bin/env python3
"""Score a triaged precision run.

    python3 compute_precision.py triage.csv

Precision is TP / (TP + FP). UNKNOWN rows are excluded from that ratio and
reported separately, with a bound either side: pessimistic counts every UNKNOWN
as a false positive, optimistic counts every one as a true positive. A point
estimate quoted without those bounds is only honest when UNKNOWN is zero, so
this prints them whenever it is not.

Recall is not measured here and cannot be inferred from this file: nothing was
planted in these repositories, so a secret neither tool found leaves no trace.
"""

import csv
import sys
from collections import Counter, defaultdict

VERDICTS = ("TP", "FP", "UNKNOWN")


def precision(tp, fp):
    return tp / (tp + fp) if (tp + fp) else None


def fmt(p):
    return "     --" if p is None else f"{p:7.3f}"


def main(path):
    rows = []
    with open(path, newline="") as fh:
        for i, row in enumerate(csv.DictReader(fh), start=2):
            v = (row.get("verdict") or "").strip().upper()
            if not v:
                sys.exit(f"{path}:{i}: blank verdict -- every row must be triaged")
            if v not in VERDICTS:
                sys.exit(f"{path}:{i}: verdict {v!r} not one of {'/'.join(VERDICTS)}")
            row["verdict"] = v
            rows.append(row)

    if not rows:
        sys.exit(f"{path}: no rows")

    tools = sorted({r["tool"] for r in rows})
    repos = sorted({r["repo"] for r in rows})

    def count(pred):
        c = Counter(r["verdict"] for r in rows if pred(r))
        return c["TP"], c["FP"], c["UNKNOWN"]

    # len(repos) counts repositories that produced at least one finding: a
    # repository both tools were clean on leaves no row here to count.
    print(f"\n{len(rows)} findings across {len(repos)} repositories with "
          f"findings, working tree only, verification off\n")

    print("## Precision by tool\n")
    print(f"{'tool':<12}{'found':>7}{'TP':>6}{'FP':>6}{'UNK':>6}"
          f"{'precision':>11}{'pess.':>9}{'opt.':>9}")
    for t in tools:
        tp, fp, unk = count(lambda r, t=t: r["tool"] == t)
        print(f"{t:<12}{tp+fp+unk:>7}{tp:>6}{fp:>6}{unk:>6}"
              f"{fmt(precision(tp, fp)):>11}"
              f"{fmt(precision(tp, fp + unk)):>9}"
              f"{fmt(precision(tp + unk, fp)):>9}")

    print("\n## Precision by repository\n")
    w = max(len(x) for x in repos) + 2
    print(f"{'repo':<{w}}" + "".join(f"{t:>30}" for t in tools))
    print(f"{'':<{w}}" + "".join(f"{'found  TP  FP UNK    prec':>30}" for t in tools))
    for repo in repos:
        line = f"{repo:<{w}}"
        for t in tools:
            tp, fp, unk = count(lambda r, t=t, repo=repo: r["tool"] == t and r["repo"] == repo)
            line += (f"{tp+fp+unk:>10}{tp:>4}{fp:>4}{unk:>4}"
                     f"{fmt(precision(tp, fp)):>8}")
        print(line)

    print("\n## False positives by rule\n")
    for t in tools:
        by_rule = Counter(r["rule_id"] for r in rows
                          if r["tool"] == t and r["verdict"] == "FP")
        if not by_rule:
            print(f"{t}: none\n")
            continue
        total = sum(by_rule.values())
        print(f"{t} -- {total} FP across {len(by_rule)} rule(s)")
        for rule, n in by_rule.most_common():
            print(f"    {n:>5}  {rule}  ({n/total:.0%})")
        print()

    print("## False positives by reason\n")
    for t in tools:
        by_reason = Counter((r.get("reason") or "unstated").strip().lower()
                            for r in rows if r["tool"] == t and r["verdict"] == "FP")
        if not by_reason:
            print(f"{t}: none\n")
            continue
        print(t)
        for reason, n in by_reason.most_common():
            print(f"    {n:>5}  {reason}")
        print()

    # A second policy, printed always rather than on request. Every credential
    # these repositories commit is a test fixture, and a reader who wants to
    # know "how much of what this tool reported would I have acted on" is asking
    # a different question from "how much of it is a credential". Both answers
    # come from the same triage; only the treatment of `(test fixture)` differs.
    fixture = sum(1 for r in rows
                  if r["verdict"] == "TP" and "(test fixture)" in r.get("reason", ""))
    if fixture:
        print("\n## Precision, discounting test fixtures\n")
        print(f"{'tool':<12}{'TP':>6}{'FP':>6}{'precision':>11}")
        for t in tools:
            tp, fp, _ = count(lambda r, t=t: r["tool"] == t)
            fx = sum(1 for r in rows if r["tool"] == t and r["verdict"] == "TP"
                     and "(test fixture)" in r.get("reason", ""))
            print(f"{t:<12}{tp-fx:>6}{fp+fx:>6}{fmt(precision(tp - fx, fp + fx)):>11}")
        print(f"\n    {fixture} of the true positives are committed test fixtures -- key\n"
              "    material and tokens that are real credentials by shape but guard\n"
              "    nothing. Treating them as noise is the harsher reading, and the\n"
              "    one that matches what a user triaging their own repository does.")

    tps = defaultdict(set)
    for r in rows:
        if r["verdict"] == "TP":
            tps[r["tool"]].add((r["repo"], r["file"], str(r["line"])))
    if len(tools) == 2 and any(tps.values()):
        a, b = tools
        print("\n## True positives, overlap\n")
        lab = max(len(a), len(b)) + 6
        print(f"    {a + ' only':<{lab}}{len(tps[a] - tps[b])}")
        print(f"    {b + ' only':<{lab}}{len(tps[b] - tps[a])}")
        print(f"    {'both':<{lab}}{len(tps[a] & tps[b])}")
        print("\n    Same file and line. A shared line found by different rules "
              "counts as agreement.")

    unk = sum(1 for r in rows if r["verdict"] == "UNKNOWN")
    if unk:
        print(f"\n{unk} UNKNOWN row(s): quote the pessimistic and optimistic "
              "columns, not the point estimate.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
