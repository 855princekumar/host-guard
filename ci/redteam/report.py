#!/usr/bin/env python3
"""The red-team report (Markdown) from results.jsonl: python3 report.py OUT_DIR SECONDS COMMIT"""
import json
import os
import sys
import time

out, seconds, commit = sys.argv[1], int(sys.argv[2]), sys.argv[3]
rows = [json.loads(line) for line in open(os.path.join(out, 'results.jsonl'), encoding='utf-8') if line.strip()]
PHASES = [('SSH', 'SSH: initial access'), ('WEB', 'Web: probing and flooding'),
          ('HOST', 'Host: persistence, privilege, miners'), ('NET', 'Network: egress and scanning'),
          ('BAK', 'Backups: confidentiality and integrity'), ('SEC', 'Secrets'), ('PANEL', 'Panel: web attacks')]
ICON = {'PASS': 'stopped', 'GAP': 'gap', 'FAIL': '**FAILED**'}
n = {k: sum(r['result'] == k for r in rows) for k in ('PASS', 'GAP', 'FAIL')}


def cell(text):
    return str(text).replace('|', '\\|').replace('\n', ' ')


def technique(t):
    path = t.replace('.', '/')
    return f'[{t}](https://attack.mitre.org/techniques/{path}/)'


print('# host-guard red-team report\n')
print(f'Run {time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())}, commit `{commit}`, {seconds // 60} min {seconds % 60} s. '
      'Target: Ubuntu 24.04 with host-guard installed by its version manager (plain VPS profile, panel, '
      'off-site copies to an emulated S3), attacked from separate containers on an isolated network.\n')
print('| Result | Count |\n|---|---|')
print(f'| Stopped or detected as designed | {n["PASS"]} |')
print(f'| Known gaps (reported, planned) | {n["GAP"]} |')
print(f'| Failed defenses | {n["FAIL"]} |\n')
for key, title in PHASES:
    part = [r for r in rows if r['id'].startswith(key + '-')]
    if not part:
        continue
    print(f'## {title}\n')
    print('| ID | ATT&CK | Attack | Expected defense | Result | Evidence |\n|---|---|---|---|---|---|')
    for r in part:
        print(f'| {r["id"]} | {technique(r["tech"])} | {cell(r["attack"])} | {cell(r["expected"])} | '
              f'{ICON.get(r["result"], r["result"])} | {cell(r["evidence"])} |')
    print()
gaps = [r for r in rows if r['result'] == 'GAP']
if gaps:
    print('## Known gaps\n')
    for r in gaps:
        print(f'- **{r["id"]}** {r["attack"]}: {r["evidence"]}')
    print()
subjects = os.path.join(out, 'mail-subjects.txt')
if os.path.exists(subjects):
    print('## Mails the admins received during the run\n')
    for s in open(subjects, encoding='utf-8').read().splitlines():
        print(f'- {s}')
    print()
print('How it runs: [ci/redteam/run.sh](../ci/redteam/run.sh). Container-only adaptations: systemctl is a stub, '
      'services are started by hand, the sshd jail reads rsyslog\'s file instead of the journal.')
