"""The triage assist used to produce triage.csv, kept so the verdicts can be
audited rather than taken on trust.

It is NOT an oracle. It applies the rules in TRIAGE.md to the real line in the
pinned checkout and leaves anything it cannot place blank. It was run in three
passes: the first classified 719 of 918 rows, the residue was read by hand and
turned into the pass-2 rules, and the final 45 rows were read individually and
written into the pass-3 table by file and line content. Every true positive was
then reviewed one by one, which is what caught the kubeadm values that are
published examples in doc.go rather than fixtures.

Re-running it against the same pins reproduces triage.csv exactly. Against a
different corpus it would need the same three passes again -- the pass-2 and
pass-3 rules are specific to what these six repositories contain.

    python3 classify.py      # rewrites $WORK/triage.csv from triage_seed.csv
"""
import base64, csv, os, re, sys

REPOS = os.path.expanduser('~/sl-precision/repos')
SEED  = os.path.expanduser('~/sl-precision/triage_seed.csv')

def ctx(r, lo=-1, hi=2):
    p = os.path.join(REPOS, r['repo'], r['file'])
    try:
        with open(p, encoding='utf-8', errors='replace') as fh:
            ls = fh.readlines()
    except OSError:
        return '', []
    i = int(r['line']) - 1
    here = ls[i].rstrip('\n') if 0 <= i < len(ls) else ''
    around = [ls[j].rstrip('\n') for j in range(max(0, i+lo), min(len(ls), i+hi))]
    return here, around

TOK = re.compile(r'[A-Za-z0-9+/=_.\-]{16,}')

def decodes_to_text(s):
    """base64 that decodes to printable English-ish text is a placeholder."""
    t = s.strip('"\',')
    if not re.fullmatch(r'[A-Za-z0-9+/]{8,}={0,2}', t):
        return False
    try:
        d = base64.b64decode(t + '=' * (-len(t) % 4), validate=True)
    except Exception:
        return False
    try:
        u = d.decode('ascii')
    except Exception:
        return False
    return len(u) > 3 and sum(c.isalpha() or c == ' ' for c in u) / len(u) > 0.8

PLACEHOLDER = re.compile(
    r'abcdef0123456789|0123456789abcdef|abcdef\.|1234567890123456|AABBCCDDEEFFGGHH'
    r'|abcdef1234567890|dummy|placeholder|changeme|change-me|xxxxxx|example\.com'
    r'|your-|my-secret|s3cr3t|notasecret|fake|foo{3,}|deadbeef|AAAAAAAA'
    r'|1234567890abcdef|<password>|\$\{|\{\{', re.I)

def classify(r):
    line, around = ctx(r)
    blob = '\n'.join(around)
    f, rule = r['file'], r['rule_id']
    low = line.lower()
    toks = sorted(TOK.findall(line), key=len, reverse=True)
    tok = toks[0] if toks else ''

    # --- key material -------------------------------------------------------
    if 'PRIVATE KEY-----' in line or 'PRIVATE KEY-----' in blob:
        # A marker string with no key material after it is not a key.
        after = blob.split('PRIVATE KEY-----', 1)[-1]
        if re.search(r'[A-Za-z0-9+/]{40,}', after):
            return 'TP', 'private key material (test fixture)'
        return 'FP', 'pem marker string, no key material'
    if f.endswith(('.pfx', '.p12')):
        return 'TP', 'private key material (test fixture)'

    # --- non-credential shapes ---------------------------------------------
    if re.fullmatch(r'[0-9a-fA-F-]{36}', tok):
        return 'FP', 'uuid'
    if 'sha256sum' in low or 'integrity' in low or 'pin-sha256' in low or 'checksum' in low:
        return 'FP', 'digest or checksum'
    if re.fullmatch(r'[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}', tok) and \
       re.search(r'hash|digest|sha|sum|revision|commit|etag', low):
        return 'FP', 'digest or checksum'
    if re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*', tok) and not re.search(r'\d{4}', tok):
        return 'FP', 'long identifier or type name'
    if 'application/vnd' in low or 'application/x-' in low:
        return 'FP', 'mime type'
    if re.search(r'\boperationid\b', low):
        return 'FP', 'long identifier or type name'

    # --- placeholders and documentation ------------------------------------
    if PLACEHOLDER.search(line):
        return 'FP', 'literal placeholder'
    if decodes_to_text(tok):
        return 'FP', 'literal placeholder'
    if f.endswith(('.md', '.rst', '.txt')) or '/docs/' in f or f.startswith('docs/'):
        return 'FP', 'documentation example'
    if re.match(r'\s*(\*|//|#)\s', line) and ('d.ts' in f or 'd.cts' in f or '/dts/' in f):
        return 'FP', 'documentation example'
    if 'CHANGELOG' in f:
        return 'FP', 'documentation example'


    # --- pass 2: classes identified by reading the residue -----------------
    if re.search(r'keyid|key_id|kid\b|rsaKeyID|ecdsaKeyID', line, re.I) and 'PublicKey' not in line \
       or re.search(r'\b(rsaKeyID|ecdsaKeyID)\b', line):
        return 'FP', 'key identifier, not a credential'
    if '<testcase' in line or '<skipped' in line or '<failure' in line or 'classname=' in line:
        return 'FP', 'test name / xml fixture text'
    if re.search(r'ChaCha20|AES-GCM|RSA-PSS|ECDSA|HMAC|Ed25519|X25519|PBKDF2|-Poly1305', line) \
       and not re.search(r'"[A-Za-z0-9+/]{32,}={0,2}"', line):
        return 'FP', 'algorithm name'
    if re.search(r'--[a-z-]+=', line):
        return 'FP', 'command-line flag string'
    if re.search(r'KUBE-(SVC|SEP|FW|MARK|NODEPORT)-|service-[A-Z0-9]{8}-|applyset-|-pod_[0-9a-f_]+\.slice', line):
        return 'FP', 'generated resource name'
    if re.search(r'eyJhbGciOi[A-Za-z0-9]*\.\.', line):
        return 'FP', 'detached signature, not a credential'
    if re.search(r'\bspkac\b|SubjectPublicKeyInfo|\bpublicKey\b|PublicKey\b', line, re.I):
        return 'FP', 'public key material'
    if re.search(r'source_map|sourcemap|protobuf|Stub:|expect: "azhz|oldSecret', line, re.I):
        return 'FP', 'encoded data, not a credential'
    if re.search(r'^\s*(//|#|\*)', line):
        return 'FP', 'documentation example'
    if re.search(r'(^|[\s"\'`(\[])/?[a-zA-Z0-9_.-]+/[a-zA-Z0-9_./-]{12,}', line) and \
       not re.search(r'(?i)(secret|token|password|passwd|api[_-]?key|credential)\s*[:=]', line):
        return 'FP', 'path or resource identifier'
    if re.fullmatch(r'[A-Za-z0-9._-]+', tok) and re.search(r'\.(k8s\.io|io|com|org)\b', tok):
        return 'FP', 'long identifier or type name'

    # Verified against the repository: these exact values are the examples
    # kubeadm publishes in cmd/kubeadm/app/apis/kubeadm/v1*/doc.go, so they are
    # documentation, not fixtures that happen to look like credentials.
    if 'e6a2eb8581237ab72a4f494f30285ec12a9694d750b9785706a83bfcbbbd2204' in line:
        return 'FP', 'documentation example'
    if '9a08jv.c0izixklcxtmnze7' in line:
        return 'FP', 'documentation example'
    if 'z6a2eb8581237ab72a4f494f30285ec12a9694d750b9785706a83bfcbbbd2204' in line:
        return 'FP', 'literal placeholder'

    # Key material and bearer credentials that survive the filters above.
    if re.search(r'(?i)(aescbc|aesgcm|aes[_-]?key|encryptionconfig|certificateKey)', line) or \
       re.search(r'(?i)"?secret"?\s*[:=]\s*"[A-Za-z0-9+/]{40,}={0,2}"', line):
        return 'TP', 'symmetric key material (test fixture)'
    if re.search(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.', line):
        return 'TP', 'bearer token (test fixture)'
    if re.search(r'[a-z0-9]{6}\.[a-z0-9]{16}\b', line):
        return 'TP', 'bearer token (test fixture)'


    # --- pass 3: the residue, each row read individually --------------------
    # (file-substring, line-substring) -> (verdict, reason). Every entry below
    # was looked at in the pinned checkout before it was written down.
    FINAL = [
      ('prototypePollution.test.js', "prod-secret-key-123",  'FP', 'literal placeholder'),
      ('__test__.jsonc',             'test-api-key-12345',   'FP', 'literal placeholder'),
      ('servers/mod.rs',             'Sec-WebSocket-Key',    'FP', 'protocol example nonce'),
      ('cache_db.rs',                'microsoft-standard',   'FP', 'version string'),
      ('upgrade.rs',                 'DENO_BINARY_v',        'FP', 'literal placeholder'),
      ('crypto.d.cts',               'ED25519KeyPair',       'FP', 'long identifier or type name'),
      ('__test__.jsonc',             'ops_sanitizer',        'FP', 'rule misfire on a filename'),
      ('url.json',                   'redis://foo:bar@',     'FP', 'literal placeholder'),
      ('utils_test.go',              'AABBCCD-EEFFGGHH',     'FP', 'literal placeholder'),
      ('helpers_test.go',            'AABBCCD-EEFFGGHH',     'FP', 'literal placeholder'),
      ('secret.yaml',                'kind: Secret',         'FP', 'literal placeholder'),
      ('secrets_test.go',            'dXNlcjpwYXNzd29yZA==', 'FP', 'literal placeholder'),
      ('image_manager_test.go',      'dXNlcjpwYXNzd29yZA==', 'FP', 'literal placeholder'),
      ('loader_test.go',             '-cmd-1"',              'FP', 'long identifier or type name'),
      ('round_trippers_test.go',     'alph4num3r1c',         'FP', 'literal placeholder'),
      ('zones.go',                   'LabelTopologyZone',    'FP', 'long identifier or type name'),
      ('in_tree_volume.go',          'LabelFailureDomain',   'FP', 'long identifier or type name'),
      ('set_credentials_test.go',    'uXFGweU9l35qcif',      'FP', 'documentation example'),
      ('projected_clustertrustbundle.go', 'signer.alive',    'FP', 'long identifier or type name'),
      ('version_test.go',            'pull-gke-gci',         'FP', 'version string'),
      ('types.go',                   'PoolNameMaxLength',    'FP', 'long identifier or type name'),
      ('scheduling/validation/validation.go', 'priority class names', 'FP', 'long identifier or type name'),
      ('secrets_test.go',            'default-password',     'FP', 'literal placeholder'),
      ('zz_generated.model_name.go', 'io.k8s.api.',          'FP', 'long identifier or type name'),
      ('attributes_test.go',         'INVALID-DNS-Subdomain','FP', 'long identifier or type name'),
      ('with_retry_test.go',         'Flowschema-Uid',       'FP', 'long identifier or type name'),
      ('test_utils.py',              'ENCODED_PASSWORD',     'FP', 'literal placeholder'),
    ]
    for fsub, lsub, v, why in FINAL:
        if fsub in f and lsub in line:
            return v, why

    return '', ''

rows = list(csv.DictReader(open(SEED)))
for r in rows:
    v, why = classify(r)
    r['verdict'], r['reason'] = v, why

done = [r for r in rows if r['verdict']]
todo = [r for r in rows if not r['verdict']]
print(f'classified {len(done)}/{len(rows)}; {len(todo)} left for hand review')

dest = os.path.expanduser('~/sl-precision/triage.csv')
with open(dest, 'w', newline='') as fh:
    w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
    w.writeheader(); w.writerows(rows)
print('->', dest)
