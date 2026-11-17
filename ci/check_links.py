"""Every relative link and image in the Markdown files points at a file that exists.
Run from the repository root: python3 ci/check_links.py"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
LINK = re.compile(r'(?:\]\(|src="|href=")([^)"#\s]+)')
bad = []
for md in ROOT.rglob('*.md'):
    if any(part.startswith('.') and part != '.github' for part in md.relative_to(ROOT).parts):
        continue
    for target in LINK.findall(md.read_text(encoding='utf-8')):
        if re.match(r'^[a-z]+:', target) or target.startswith('/'):
            continue
        if not (md.parent / target).exists():
            bad.append(f'{md.relative_to(ROOT)}: {target}')
print('\n'.join(bad) or 'all local links resolve')
sys.exit(1 if bad else 0)
