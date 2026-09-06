#!/usr/bin/env python3
"""
n9_gate.py -- the independent recall gate for the frozen N9 candidate.

Applies EXACTLY the frozen predicate, with the exact rounding semantics used
by characterize_ghe.py to produce it:

    round(alpha_count / length, 4) >= 0.83

to every row of n9_gate_features.tsv (emitted by the seeded generator in
bench/entropy-vetoes.ts; features only, no token values). No alternate
threshold. No second candidate. Reports per-bucket and per-family counts.

Gate population = the corpus's own REALISTIC set:
  realistic-documented, realistic-floor-length,
  realistic-untouched-branch, adversarial-low-tail
("the buckets that stand for credentials a user would be sorry to lose").
Diagnostic buckets are reported separately and NOT counted -- the same split
N7a/N7b were measured against.

Verdict is binary on the realistic population:
  rejected == 0  ->  N9 candidate survives this gate
  rejected  > 0  ->  N9 STOP  (the frozen candidate failed; this does NOT
                     prove no value-structure predicate can ever work)
"""
import csv, sys
from collections import defaultdict

THRESHOLD = 0.83
REALISTIC = {"realistic-documented", "realistic-floor-length",
             "realistic-untouched-branch", "adversarial-low-tail"}

def frozen_predicate(alpha_count: int, length: int) -> bool:
    # EXACT semantics of characterize_ghe.py: alpha_frac = round(alpha/n, 4)
    return round(alpha_count / length, 4) >= THRESHOLD

def main(path="n9_gate_features.tsv"):
    by_bucket = defaultdict(lambda: [0, 0])          # bucket -> [n, rejected]
    by_fam    = defaultdict(lambda: [0, 0])          # (bucket-realistic?, family) -> [n, rejected]
    with open(path, newline="", encoding="utf-8") as fh:
        rd = csv.DictReader(fh, delimiter="\t")
        need = {"bucket", "family", "length", "alpha_count"}
        if not need.issubset(rd.fieldnames or []):
            sys.exit(f"ERROR: {path} must have columns {sorted(need)}; got {rd.fieldnames}")
        for r in rd:
            n, a = int(r["length"]), int(r["alpha_count"])
            if n <= 0 or a < 0 or a > n:
                sys.exit(f"ERROR: bad row {r}")
            rej = frozen_predicate(a, n)
            by_bucket[r["bucket"]][0] += 1
            by_bucket[r["bucket"]][1] += rej
            if r["bucket"] in REALISTIC:
                by_fam[r["family"]][0] += 1
                by_fam[r["family"]][1] += rej

    pct = lambda p, w: f"{(p / w * 100):.4f}%" if w else "n/a"
    print(f"frozen predicate: round(alpha_count/length,4) >= {THRESHOLD}\n")
    print(f"{'bucket':28}{'n':>8}{'rejected':>10}{'loss':>12}")
    tot_n = tot_r = 0
    for b in sorted(by_bucket):
        n, rj = by_bucket[b]
        tag = "" if b in REALISTIC else "   (diagnostic, not counted)"
        print(f"{b:28}{n:>8}{rj:>10}{pct(rj, n):>12}{tag}")
        if b in REALISTIC:
            tot_n += n; tot_r += rj

    print(f"\nREALISTIC TOKENS  n={tot_n}")
    print(f"  N9 frozen candidate  rejected, loss   {tot_r}  {pct(tot_r, tot_n)}")

    print(f"\nper family (realistic buckets only):")
    print(f"{'family':28}{'n':>8}{'rejected':>10}{'loss':>12}")
    for f in sorted(by_fam, key=lambda k: -by_fam[k][1] / max(by_fam[k][0], 1)):
        n, rj = by_fam[f]
        print(f"{f:28}{n:>8}{rj:>10}{pct(rj, n):>12}")

    print()
    if tot_r == 0:
        print("VERDICT: rejected = 0  ->  the frozen N9 candidate SURVIVES this gate.")
    else:
        print(f"VERDICT: rejected = {tot_r} ({pct(tot_r, tot_n)})  ->  N9 STOP.")
        print("  The frozen candidate alpha_frac>=0.83 failed the independent recall gate.")
        print("  This does NOT prove that no value-structure predicate can work; it proves")
        print("  that THIS candidate is not shippable. No retuning against this corpus.")

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "n9_gate_features.tsv")
