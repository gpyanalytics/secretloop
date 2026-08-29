#!/usr/bin/env python3
"""Exact-line scoring for corpus A.

Exact match, not a +/-1 window. The corpus places decoys on lines adjacent to
secrets -- 21 of 50 secret labels have a decoy neighbour -- so a tolerance
window credits findings that landed on a decoy as true positives. Measured on
the first run of this benchmark: +3 spurious TPs for secretloop and +7 for
gitleaks. All three tools report exact lines for these formats, so the window
bought nothing and cost correctness.
"""
import json


def load_secretloop(path, corpus_root):
    d = json.load(open(path))
    return [(f["file"], f["line"], f["ruleId"]) for f in d["findings"]]


def score(rows, secrets, decoys):
    """recall over labels; precision over findings; exact line match."""
    det = {(p, l) for (p, l, _) in rows if (p, l) in secrets}
    tp = sum(1 for (p, l, _) in rows if (p, l) in secrets)
    fp_decoy = sum(1 for (p, l, _) in rows if (p, l) in decoys)
    fp_other = len(rows) - tp - fp_decoy
    n = len(secrets)
    rec = len(det) / n if n else 0.0
    pre = tp / len(rows) if rows else 0.0
    f1 = 2 * pre * rec / (pre + rec) if (pre + rec) else 0.0
    return {
        "found": len(rows), "tp": tp, "fp_decoy": fp_decoy, "fp_other": fp_other,
        "detected": len(det), "secrets": n,
        "precision": round(pre, 4), "recall": round(rec, 4), "f1": round(f1, 4),
        "missed": sorted({secrets[k]["kind"] for k in secrets if k not in det}),
        "missed_detail": [secrets[k] for k in secrets if k not in det],
        "fps": [(p, l, r) for (p, l, r) in rows if (p, l) not in secrets],
    }


def label_index(labels):
    tree_sec = {(l["path"], l["line"]): l for l in labels["tree"] if l["label"] == "secret"}
    tree_dec = {(l["path"], l["line"]): l for l in labels["tree"] if l["label"] == "decoy"}
    hist_sec = dict(tree_sec)
    hist_sec.update({(l["path"], l["line"]): l for l in labels["history_only"]})
    return tree_sec, tree_dec, hist_sec
