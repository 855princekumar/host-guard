#!/usr/bin/env python3
"""Build the pip package: copy what runs on a server into src/host_guard/payload, then build
the sdist and the wheel into dist/ and check that both carry it.

    python3 ci/build_dist.py            (needs: pip install build)
    python3 ci/build_dist.py --payload-only
"""
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAYLOAD = os.path.join(ROOT, 'src', 'host_guard', 'payload')
PARTS = ('VERSION', 'LICENSE', 'guard', 'panel', 'examples')     # manager.RELEASE_FILES
MUST = ('payload/VERSION', 'payload/guard/install.sh', 'payload/guard/hostguard.py',
        'payload/guard/conf/base-hardening.sh', 'payload/panel/hgpanel.py', 'payload/examples/profiles/plain-vps.conf')


def payload():
    shutil.rmtree(PAYLOAD, ignore_errors=True)
    os.makedirs(PAYLOAD)
    skip = shutil.ignore_patterns('__pycache__', '*.pyc', 'tests')
    for part in PARTS:
        src = os.path.join(ROOT, part)
        if os.path.isdir(src):
            shutil.copytree(src, os.path.join(PAYLOAD, part), ignore=skip)
        else:
            shutil.copyfile(src, os.path.join(PAYLOAD, part))


def check(dist):
    version = open(os.path.join(ROOT, 'VERSION'), encoding='utf-8').read().strip()
    wheel = os.path.join(dist, f'host_guard-{version}-py3-none-any.whl')
    sdist = os.path.join(dist, f'host_guard-{version}.tar.gz')
    names = zipfile.ZipFile(wheel).namelist()
    for m in MUST:
        if 'host_guard/' + m not in names:
            sys.exit(f'{wheel} lacks {m}')
    if any('/tests/' in n or n.endswith('.pyc') for n in names):
        sys.exit(f'{wheel} carries tests or bytecode')
    snames = tarfile.open(sdist).getnames()
    for m in MUST:
        if f'host_guard-{version}/src/host_guard/' + m not in snames:
            sys.exit(f'{sdist} lacks {m}')
    print(f'ok: {os.path.basename(wheel)} ({len(names)} files), {os.path.basename(sdist)}')


if __name__ == '__main__':
    payload()
    if '--payload-only' not in sys.argv:
        dist = os.path.join(ROOT, 'dist')
        shutil.rmtree(dist, ignore_errors=True)
        subprocess.run([sys.executable, '-m', 'build', '--outdir', dist, ROOT], check=True)
        check(dist)
