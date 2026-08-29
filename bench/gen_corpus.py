#!/usr/bin/env python3
"""Deterministic seeded corpus. Every planted value is synthetic."""
import json, os, random, shutil, sys

ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
HEX = "0123456789abcdef"
B64 = ALNUM + "+/"

def g(n, a=ALNUM): return "".join(random.choice(a) for _ in range(n))
def hexs(n): return "".join(random.choice(HEX) for _ in range(n))
def uuid(): return f"{hexs(8)}-{hexs(4)}-{hexs(4)}-{hexs(4)}-{hexs(12)}"

# ---- secret generators: format-valid, synthetic ----------------------------
SECRETS = {
  "github-pat":       lambda: "ghp_" + g(36),
  "github-fine":      lambda: "github_pat_" + g(22) + "_" + g(59),
  "aws-access-key":   lambda: "AKIA" + g(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"),
  "aws-secret-key":   lambda: g(40, B64),
  "stripe-live":      lambda: "sk_live_" + g(24),
  "slack-bot":        lambda: "xoxb-" + g(12, "0123456789") + "-" + g(12, "0123456789") + "-" + g(24),
  "generic-password": lambda: g(random.randint(18, 26), ALNUM + "!@#$%"),
  "pem-key":          lambda: "-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(g(64, B64) for _ in range(6)) + "\n-----END RSA PRIVATE KEY-----",
}

# ---- decoys: high-entropy or credential-shaped, but NOT secrets -------------
DECOYS = {
  "git-sha1":          lambda: hexs(40),
  "sha256-digest":     lambda: hexs(64),
  "uuid":              lambda: uuid(),
  "jwt-public-claims": lambda: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
  "url":               lambda: f"https://cdn.{g(8,'abcdefghijklmnopqrstuvwxyz')}.example.com/v{random.randint(1,9)}/assets/{g(10,'abcdefghijklmnopqrstuvwxyz')}.js",
  "lockfile-integrity":lambda: "sha512-" + g(86, B64) + "==",
  "hashed-asset":      lambda: f"main.{hexs(20)}.chunk.js",
  "base64-image":      lambda: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk" + g(40, B64) + "=",
  "aws-doc-sample":    lambda: "AKIAIOSFODNN7EXAMPLE",
  "aws-doc-secret":    lambda: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYz9Qb7xTvKE",
  "version-string":    lambda: f"{random.randint(1,20)}.{random.randint(0,99)}.{random.randint(0,99)}",
  "hex-color-blob":    lambda: hexs(32),
}

# ---- host file templates: (extension, how a value is embedded) -------------
def emb_js(k, v):    return f'const {k} = "{v}";'
def emb_ts(k, v):    return f'export const {k}: string = "{v}";'
def emb_py(k, v):    return f'{k} = "{v}"'
def emb_go(k, v):    return f'\t{k} := "{v}"'
def emb_java(k, v):  return f'    private static final String {k.upper()} = "{v}";'
def emb_rb(k, v):    return f'{k} = "{v}"'
def emb_yaml(k, v):  return f'  {k}: "{v}"'
def emb_json(k, v):  return f'  "{k}": "{v}",'
def emb_env(k, v):   return f'{k.upper()}={v}'
def emb_tf(k, v):    return f'  {k} = "{v}"'
def emb_sh(k, v):    return f'export {k.upper()}="{v}"'
def emb_md(k, v):    return f'    {k}: {v}'

LANGS = [
  ("js", emb_js, 'const express = require("express");\nconst app = express();'),
  ("ts", emb_ts, 'import type { Request } from "express";'),
  ("py", emb_py, 'import os\nimport sys'),
  ("go", emb_go, 'package main\n\nimport "fmt"\n\nfunc main() {'),
  ("java", emb_java, 'package com.example;\n\npublic class Config {'),
  ("rb", emb_rb, "require 'json'"),
  ("yaml", emb_yaml, 'version: "3.8"\nservices:\n  app:\n    environment:'),
  ("json", emb_json, '{\n  "name": "sample",'),
  ("env", emb_env, '# environment'),
  ("tf", emb_tf, 'resource "aws_instance" "web" {'),
  ("sh", emb_sh, '#!/usr/bin/env bash\nset -euo pipefail'),
  ("md", emb_md, '# Notes\n\nExample configuration:\n'),
]

KEYNAMES = {
  "github-pat": "github_token", "github-fine": "gh_pat", "aws-access-key": "aws_access_key_id",
  "aws-secret-key": "aws_secret_access_key", "stripe-live": "stripe_secret_key",
  "slack-bot": "slack_bot_token", "generic-password": "password", "pem-key": "private_key",
  "git-sha1": "commit_sha", "sha256-digest": "checksum", "uuid": "request_id",
  "jwt-public-claims": "sample_jwt", "url": "cdn_url", "lockfile-integrity": "integrity",
  "hashed-asset": "bundle_name", "base64-image": "placeholder_png", "aws-doc-sample": "example_key",
  "aws-doc-secret": "example_secret", "version-string": "app_version", "hex-color-blob": "palette_hash",
}


# Path segments the product treats as fixture noise. Defined here so the corpus
# and the scanner cannot drift apart silently.
FIXTURE_SEGMENTS = {
    "test", "tests", "__test__", "__tests__", "__mocks__",
    "__snapshots__", "__fixtures__", "fixtures", "snapshots", "examples",
}


def is_fixture_dir(d):
    return any(seg in FIXTURE_SEGMENTS for seg in d.split("/"))


SEED = 20260829


def scratch_path(ROOT, name):
    """Where the generator keeps its own bookkeeping: beside the corpus, never in it.

    _history_plan.json holds the ten history-only credentials in plaintext, and
    it used to be written inside ROOT. gen_history's first commit is `git add
    -A`, so the file went into the object store before the later `git rm` took
    it out of the working tree -- leaving a clean tree and ten real credentials
    in git history, which the history scan then found. They were counted as
    false positives because the labels do not list them, and they capped corpus
    A's history precision at 0.857 by construction.

    A generator artifact is not a property of the code under test. Writing it
    beside the corpus rather than inside it means no git command can reach it
    and the measurement is of the scanner.
    """
    return os.path.join(os.path.dirname(os.path.abspath(ROOT)), name)


def build(ROOT, seed=SEED):
    """Generates the tree half of corpus A. Returns the label rows.

    Seeded inside the function, not at import: a module-level seed makes the
    second call in a process produce a different corpus than the first, which
    is exactly the kind of silent drift a pinned labels.json exists to catch.
    """
    random.seed(seed)
    shutil.rmtree(ROOT, ignore_errors=True)
    os.makedirs(ROOT)
    labels = []

    SECRET_PLAN, DECOY_PLAN = [], []
    skinds = list(SECRETS)
    for i in range(60):  SECRET_PLAN.append(skinds[i % len(skinds)])
    dkinds = list(DECOYS)
    for i in range(120): DECOY_PLAN.append(dkinds[i % len(dkinds)])
    random.shuffle(SECRET_PLAN); random.shuffle(DECOY_PLAN)

    # 10 secrets go to history only; 50 stay in the tree.
    history_only = SECRET_PLAN[:10]
    tree_secrets = SECRET_PLAN[10:]

    def write_file(relpath, ext, emb, header, items):
        """items: list of (kind, value, is_secret). Returns label rows."""
        lines = header.split("\n")
        rows = []
        for kind, value, is_secret in items:
            if "\n" in value:  # PEM block
                first = len(lines) + 1
                lines.append(f'{KEYNAMES[kind]} = """')
                for ln in value.split("\n"): lines.append(ln)
                lines.append('"""')
                rows.append((first + 1, kind, is_secret))
            else:
                lines.append(emb(KEYNAMES[kind], value))
                rows.append((len(lines), kind, is_secret))
        if ext == "go": lines.append("}")
        if ext == "java": lines.append("}")
        if ext == "json": lines.append('  "end": true\n}')
        full = os.path.join(ROOT, relpath)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        open(full, "w").write("\n".join(lines) + "\n")
        return [{"path": relpath, "line": ln, "kind": k, "label": "secret" if s else "decoy"} for ln, k, s in rows]

    DIRS = ["src", "src/api", "src/lib", "config", "services", "internal", "scripts", "deploy", "test", "docs"]
    # Secrets never land in a fixture path. A labelled secret sitting where the
    # product suppresses findings makes a miss unreadable: scanner failure, or
    # the corpus asking for something it also asked to be hidden? Decoys DO stay
    # in fixture paths on purpose -- they are the coverage for the suppression.
    NONFIXTURE_DIRS = [d for d in DIRS if not is_fixture_dir(d)]
    FILLER = 0
    si, di = 0, 0
    files_made = 0
    # 190 tree files; distribute secrets and decoys across them.
    for n in range(190):
        ext, emb, header = LANGS[n % len(LANGS)]
        carries_secret = si < len(tree_secrets) and n % 3 == 0
        d = NONFIXTURE_DIRS[n % len(NONFIXTURE_DIRS)] if carries_secret else DIRS[n % len(DIRS)]
        name = f"{d}/mod_{n:03d}.{ext}"
        items = []
        if carries_secret:
            k = tree_secrets[si]; si += 1
            items.append((k, SECRETS[k](), True))
        for _ in range(2 if n % 2 == 0 else 1):
            if di < len(DECOY_PLAN):
                k = DECOY_PLAN[di]; di += 1
                items.append((k, DECOYS[k](), False))
        if not items:
            FILLER += 1
            items = []
        labels.extend(write_file(name, ext, emb, header, items))
        files_made += 1

    # leftovers, if the modulo distribution did not place them all
    extra = 0
    while si < len(tree_secrets):
        k = tree_secrets[si]; si += 1
        labels.extend(write_file(f"src/extra_{extra:02d}.js", "js", emb_js, 'const x = 1;', [(k, SECRETS[k](), True)]))
        extra += 1; files_made += 1
    while di < len(DECOY_PLAN):
        k = DECOY_PLAN[di]; di += 1
        labels.extend(write_file(f"src/dextra_{extra:02d}.py", "py", emb_py, 'import os', [(k, DECOYS[k](), False)]))
        extra += 1; files_made += 1

    # A decoy in a fixture path is coverage for the fixture suppression, so what
    # should happen to it is recorded rather than inferred.
    for l in labels:
        if l["label"] == "decoy" and is_fixture_dir(os.path.dirname(l["path"])):
            l["expected"] = "suppressed"

    json.dump({"tree": labels, "history": []}, open(scratch_path(ROOT, "_labels_tree.json"), "w"), indent=1)
    # The history-only plants. Drawn from the same seeded stream and written
    # before returning, because gen_history reads this file -- generating them
    # lazily later would draw different values and silently change the corpus.
    json.dump([{"kind": k, "value": SECRETS[k]()} for k in history_only],
              open(scratch_path(ROOT, "_history_plan.json"), "w"), indent=1)
    return labels


def _cli():
    import sys
    labels = build(sys.argv[1])
    print(f"tree files: {sum(1 for _ in labels)} label rows  "
          f"secrets: {sum(1 for l in labels if l['label']=='secret')}  "
          f"decoys: {sum(1 for l in labels if l['label']=='decoy')}")


if __name__ == "__main__":
    _cli()
