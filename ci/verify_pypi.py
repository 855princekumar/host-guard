#!/usr/bin/env python3
"""After publishing: prove PyPI serves exactly what CI tested.  python3 ci/verify_pypi.py VERSION DIST OUT

  1. waits until PyPI lists VERSION (up to 15 minutes)
  2. PyPI's files are exactly the wheel and the sdist in DIST (the ones the package audit, the
     red team, the cloud emulators and the lifecycle tests ran on): same names, same SHA-256
  3. each file downloaded from PyPI's file host has that same SHA-256 (not just what the index says)
  4. each file has a provenance attestation from Trusted Publishing, made by this repository's
     release.yml (PyPI's integrity API)
  5. writes the downloaded files to OUT, for the install tests that follow
Any difference exits 1: then yank the release on pypi.org and find out why.
"""
import hashlib
import json
import os
import sys
import time
import urllib.request

REPO = '855princekumar/host-guard'
version, dist, out = sys.argv[1], sys.argv[2], sys.argv[3]
problems = []


def get(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'host-guard-release-check', 'Accept': 'application/json'})
    with urllib.request.urlopen(req, timeout=60) as r:  # nosec B310 (fixed https URLs)
        return r.read()


local = {f: hashlib.sha256(open(os.path.join(dist, f), 'rb').read()).hexdigest()
         for f in sorted(os.listdir(dist)) if f.endswith(('.whl', '.tar.gz'))}
meta = None
for _ in range(90):
    try:
        meta = json.loads(get(f'https://pypi.org/pypi/host-guard/{version}/json'))
        break
    except Exception:
        time.sleep(10)
if not meta:
    sys.exit(f'PyPI does not list host-guard {version} after 15 minutes')
remote = {u['filename']: u for u in meta.get('urls', [])}
if sorted(remote) != sorted(local):
    problems.append(f'PyPI has {sorted(remote)}, CI tested {sorted(local)}')
os.makedirs(out, exist_ok=True)
for name, want in local.items():
    u = remote.get(name)
    if not u:
        continue
    if u['digests']['sha256'] != want:
        problems.append(f'{name}: PyPI lists sha256 {u["digests"]["sha256"]}, CI tested {want}')
    body = get(u['url'])
    got = hashlib.sha256(body).hexdigest()
    if got != want:
        problems.append(f'{name}: the file PyPI serves has sha256 {got}, CI tested {want}')
        continue                                            # never handed to the install tests
    with open(os.path.join(out, name), 'wb') as f:
        f.write(body)
    attested = False
    try:
        prov = json.loads(get(f'https://pypi.org/integrity/host-guard/{version}/{name}/provenance'))
        pubs = [b.get('publisher', {}) for b in prov.get('attestation_bundles', [])]
        ok = any(p.get('kind') == 'GitHub' and p.get('repository') == REPO and p.get('workflow') == 'release.yml' for p in pubs)
        if not ok:
            problems.append(f'{name}: provenance publisher is {pubs}, expected GitHub {REPO} release.yml')
        attested = ok
    except Exception as e:
        problems.append(f'{name}: no provenance attestation ({e})')
    print(f'{name}: sha256 {want} on PyPI and in the downloaded file'
          + (f'; attested by {REPO} release.yml' if attested else '; NOT attested'))
for p in problems:
    print('FAIL', p)
sys.exit(1 if problems else 0)
