#!/usr/bin/env python3
import json, os, subprocess, sys
import gen_corpus
def build(ROOT):
    """Adds the history-only half of corpus A and writes labels.json."""
    def git(*a): subprocess.run(["git", *a], cwd=ROOT, check=True, capture_output=True)

    plan = json.load(open(gen_corpus.scratch_path(ROOT, "_history_plan.json")))
    tree_labels = json.load(open(gen_corpus.scratch_path(ROOT, "_labels_tree.json")))["tree"]

    git("init", "-q", ".")
    git("config", "user.email", "bench@example.invalid")
    git("config", "user.name", "bench")
    git("add", "-A"); git("commit", "-qm", "initial import")

    hist = []
    for i, item in enumerate(plan):
        rel = f"legacy/old_config_{i:02d}.py"
        full = os.path.join(ROOT, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        body = ["import os", "", "# legacy configuration, later removed"]
        v = item["value"]
        # The same keyword-bearing names the tree plants use. Every history plant
        # used to be `CREDENTIAL = "..."`, which no keyword-gated rule can match,
        # so history recall measured the entropy tier and nothing else -- a named
        # rule scoring zero there said nothing about the rule.
        key = gen_corpus.KEYNAMES.get(item["kind"], "credential")
        if "\n" in v:
            first = len(body) + 2
            body.append(f'{key} = """'); body.extend(v.split("\n")); body.append('"""')
            line = first
        else:
            body.append(gen_corpus.emb_py(key, v))
            line = len(body)
        open(full, "w").write("\n".join(body) + "\n")
        git("add", rel); git("commit", "-qm", f"add legacy config {i}")
        hist.append({"path": rel, "line": line, "kind": item["kind"], "label": "secret", "where": "history-only"})

    # Remove them all, so nothing is in the working tree.
    for i in range(len(plan)):
        git("rm", "-q", f"legacy/old_config_{i:02d}.py")
    git("commit", "-qm", "remove legacy configs")

    for l in tree_labels: l["where"] = "tree"
    labels = {
      "corpus": "A-SEEDED",
      "generator_seed": 20260829,
      "tree": tree_labels,
      "history_only": hist,
      "counts": {
        "tree_secrets": sum(1 for l in tree_labels if l["label"] == "secret"),
        "tree_decoys":  sum(1 for l in tree_labels if l["label"] == "decoy"),
        "history_only_secrets": len(hist),
      },
    }
    json.dump(labels, open(os.path.join(ROOT, "..", "labels.json"), "w"), indent=1)
    # No git commands here any more. These live outside ROOT, so they were
    # never added, never committed, and there is nothing to remove from the
    # object store -- which was the whole reason the deletion commit existed.
    os.remove(gen_corpus.scratch_path(ROOT, "_history_plan.json"))
    os.remove(gen_corpus.scratch_path(ROOT, "_labels_tree.json"))
    return labels


if __name__ == "__main__":
    import sys
    print(json.dumps(build(sys.argv[1])["counts"], indent=1))
