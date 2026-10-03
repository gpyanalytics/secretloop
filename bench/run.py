#!/usr/bin/env python3
"""Regenerate corpus A from seed, run the local SecretLoop build, score it.

Corpus A is regenerated rather than checked in: a committed corpus of
credential-shaped files is a liability, and a generator plus a pinned
labels.json proves the same thing. The regenerated labels are compared against
bench/labels.json on every run, so a change to the generator fails loudly
instead of silently rescoring against a corpus nobody looked at.
"""
import argparse, json, os, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import gen_corpus, gen_history, score as scoring  # noqa: E402

CLI = os.path.join(REPO, "out", "cli.js")


def build_corpus(dest, seed=None):
    root = os.path.join(dest, "corpusA")
    gen_corpus.build(root) if seed is None else gen_corpus.build(root, seed)
    labels = gen_history.build(root)
    return root, labels


def run_cli(args, out):
    subprocess.run(["node", CLI, *args, "--format", "json", "-o", out],
                   capture_output=True, text=True)
    return json.load(open(out))


def scan(root, dest, entropy_on):
    """One arm of corpus A. `entropy_on` passes `--include-entropy` to BOTH the tree and
    the history scan: the flag is raise-only in the CLI, so the tier runs whatever a
    project file says. The other arm switches the tier off through an explicit project
    file rather than relying on the default (which has been off since 0.4.0 -- when it
    flipped, an arm that merely omitted the flag silently became a second entropy-off
    arm, and the two labels measured one configuration). Each report's `configDigest`
    is returned so the caller can check that the two arms really differ."""
    cfg = os.path.join(root, ".secretloop.json")
    flags = ["--include-entropy"] if entropy_on else []
    wrote_cfg = not entropy_on
    if wrote_cfg:
        open(cfg, "w").write('{"entropyPassEnabled": false}\n')
    try:
        tree = run_cli(["scan", "--path", root, *flags], os.path.join(dest, "t.json"))
        hist = run_cli(["history", "--path", root, *flags], os.path.join(dest, "h.json"))
    finally:
        if wrote_cfg and os.path.exists(cfg):
            os.remove(cfg)
    rows = lambda d: [(f["file"], f["line"], f["ruleId"]) for f in d["findings"]]
    return rows(tree), rows(hist), tree.get("configDigest")


def corpus_b(path):
    with tempfile.TemporaryDirectory() as d:
        tree = run_cli(["scan", "--path", path], os.path.join(d, "t.json"))
        hist = run_cli(["history", "--path", path], os.path.join(d, "h.json"))
    loc = 0
    files = subprocess.run(["git", "ls-files"], cwd=path, capture_output=True, text=True).stdout.split()
    for f in files:
        p = os.path.join(path, f)
        try:
            b = open(p, "rb").read()
            if b[:8000].find(b"\0") != -1:
                continue
            loc += b.count(b"\n")
        except OSError:
            pass
    return {"tree_fp": tree["summary"]["total"], "history_fp": hist["summary"]["total"],
            "files": len(files), "loc": loc,
            "fp_per_kloc": round(tree["summary"]["total"] / (loc / 1000), 3) if loc else None,
            "tree_by_rule": _by_rule(tree), "history_by_rule": _by_rule(hist)}


def _by_rule(d):
    out = {}
    for f in d["findings"]:
        out[f["ruleId"]] = out.get(f["ruleId"], 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tool", default="secretloop", choices=["secretloop"])
    ap.add_argument("--corpus-b", help="path to a real-noise checkout (all findings are FPs)")
    ap.add_argument("--json", help="write the full result object here")
    ap.add_argument("--seed", type=int,
                    help="regenerate corpus A with a different seed -- a HOLDOUT run. "
                         "Skips the labels.json pin (a different seed means a different "
                         "corpus by definition) and measures generalisation rather than "
                         "the corpus the fixes were written against.")
    a = ap.parse_args()

    if not os.path.exists(CLI):
        sys.exit("bench: out/cli.js not found — run `npm run bundle` first.")

    # A benchmark that silently measures a stale bundle reports the previous
    # build's numbers as the current build's. That happened once during the
    # 0.1.1 detection work: a rule was edited, the benchmark run, and the
    # unchanged score read as "the fix did nothing".
    newest_src = max(os.path.getmtime(os.path.join(REPO, "src", f))
                     for f in os.listdir(os.path.join(REPO, "src")) if f.endswith(".ts"))
    if newest_src > os.path.getmtime(CLI):
        sys.exit("bench: out/cli.js is older than src/ — run `npm run bundle` first, "
                 "or you will measure the previous build.")

    dest = tempfile.mkdtemp(prefix="secretloop-bench-")
    try:
        root, labels = build_corpus(dest, a.seed)
        pinned = json.load(open(os.path.join(HERE, "labels.json")))
        if a.seed is not None:
            print(f"HOLDOUT RUN — seed {a.seed}, not the committed corpus. "
                  f"The labels.json pin is skipped by design.\n")
        elif labels != pinned:
            sys.exit("bench: regenerated corpus does not match bench/labels.json — "
                     "the generator changed. Reconcile before trusting any score.")
        tree_sec, tree_dec, hist_sec = scoring.label_index(labels)

        result = {"corpus_a": {}}
        digests = {}
        for tier, entropy_on in (("entropy-on", True), ("named-only", False)):
            t, h, digests[tier] = scan(root, dest, entropy_on)
            result["corpus_a"][tier] = {
                "tree": scoring.score(t, tree_sec, tree_dec),
                "history": scoring.score(h, hist_sec, tree_dec),
            }
        # Identical totals cannot show the flag took effect -- corpus A's decoys are
        # high-entropy by design and the tier reports none of them, so both arms score
        # the same either way. The configuration identity can: it must differ.
        if digests["entropy-on"] == digests["named-only"]:
            sys.exit("bench: the entropy-on and named-only arms resolved to the same "
                     "configuration identity -- the tier was not enabled; refusing to "
                     "report two arms that measured one configuration.")
        result["corpus_a"]["config_digests"] = digests
        if a.corpus_b:
            result["corpus_b"] = corpus_b(a.corpus_b)
    finally:
        shutil.rmtree(dest, ignore_errors=True)

    print(f"{'corpus A':22}{'found':>7}{'TP':>5}{'FPdec':>7}{'FPoth':>7}{'detected':>10}{'prec':>8}{'rec':>8}{'F1':>8}")
    for tier in ("entropy-on", "named-only"):
        for which in ("tree", "history"):
            r = result["corpus_a"][tier][which]
            print(f"{tier+' '+which:22}{r['found']:7}{r['tp']:5}{r['fp_decoy']:7}{r['fp_other']:7}"
                  f"{str(r['detected'])+'/'+str(r['secrets']):>10}{r['precision']:8.3f}{r['recall']:8.3f}{r['f1']:8.3f}")
    for tier in ("entropy-on", "named-only"):
        m = result["corpus_a"][tier]["tree"]["missed"]
        print(f"  {tier} tree misses by kind: {m or 'none'}")
    if a.corpus_b:
        b = result["corpus_b"]
        print(f"\ncorpus B ({b['files']} files, {b['loc']/1000:.1f} KLOC) — every finding is a false positive")
        print(f"  tree FPs {b['tree_fp']}  ({b['fp_per_kloc']} per KLOC)   history FPs {b['history_fp']}")
        print(f"  tree by rule: {b['tree_by_rule']}")
    if a.json:
        json.dump(result, open(a.json, "w"), indent=1)
        print(f"\nwrote {a.json}")


if __name__ == "__main__":
    main()
