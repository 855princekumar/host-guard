#!/usr/bin/env python3
"""Attacks on approvals by reply, against a real IMAP server (Dovecot over TLS, on the target):
forged senders, a stamp the attacker wrote, another mail server's verdict, a non-admin, a
command instead of an action line, a code only in the quoted mail, a replayed code, a reboot
approved by one admin, and a taken-over panel feeding the root side approvals. The receiving
mail server's own Authentication-Results line (Gmail's mx.google.com in real life) is played
here by the top header of each delivered message, the way such a server prepends it.

Runs on the target as root. Prints one JSON object per check, like panel_attack.py."""
import imaplib
import importlib.machinery
import importlib.util
import json
import os
import re
import ssl
import subprocess
import sys
import time

AUTHSERV = 'mx.redteam.test'
ADMIN, ADMIN2, OUTSIDER = 'security@example.com', 'admin2@example.com', 'outsider@example.org'
USER, PASS = 'guardmail', 'Rt-Imap-Pass-4821'
CA = '/etc/dovecot/rt.pem'
MAILBOX = '/var/mail/hg-captured'
OUTBOX = '/var/lib/host-guard-panel/outbox'
FID = 'deadbeef'
out = []


def check(id_, technique, attack, expected, ok, evidence, gap=False):
    out.append({'id': id_, 'technique': technique, 'attack': attack, 'expected': expected,
                'result': 'PASS' if ok else ('GAP' if gap else 'FAIL'), 'evidence': str(evidence)[:400]})


def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)   # nosec B602 (fixed test commands)


# ---------------------------------------------------------------- a real IMAP server, and replies on
setup = r'''
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq dovecot-imapd openssl >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=localhost -addext subjectAltName=DNS:localhost \
  -keyout /etc/dovecot/rt.key -out /etc/dovecot/rt.pem 2>/dev/null
cat > /etc/dovecot/conf.d/99-redteam.conf <<'EOF'
protocols = imap
ssl = required
ssl_cert = </etc/dovecot/rt.pem
ssl_key = </etc/dovecot/rt.key
mail_location = maildir:~/Maildir
EOF
id guardmail >/dev/null 2>&1 || useradd -m guardmail
echo 'guardmail:Rt-Imap-Pass-4821' | chpasswd
dovecot </dev/null >/dev/null 2>&1
'''
r = run(setup)
cfg = (f'REPLY_ACTIONS=on\nIMAP_HOST=localhost\nIMAP_PORT=993\nIMAP_USER={USER}\nIMAP_CA={CA}\n'
       f'REPLY_AUTHSERV={AUTHSERV}\n')
with open('/etc/host-guard/guard.conf', 'a') as f:
    f.write(cfg)
with open('/etc/host-guard/.env', 'a') as f:
    f.write(f'IMAP_PASSWORD={PASS}\n')
for _ in range(30):
    try:
        imaplib.IMAP4_SSL('localhost', 993, ssl_context=ssl.create_default_context(cafile=CA), timeout=5).logout()
        break
    except OSError:
        time.sleep(1)

loader = importlib.machinery.SourceFileLoader('hostguard', '/usr/local/sbin/hostguard')
spec = importlib.util.spec_from_loader('hostguard', loader)
hg = importlib.util.module_from_spec(spec)
sys.modules['hostguard'] = hg
sys.argv = ['hostguard']
loader.exec_module(hg)
ap = hg.approvals_module()

st = hg.load('shield.json')
st.setdefault('known', {})[FID] = {'tier': 'Critical', 'status': 'open', 'name': 'openssl 3.0.2', 'where': 'host',
                                   'vuln': 'CVE-2026-1111', 'plan': {'kind': 'apt', 'packages': ['openssl']},
                                   'text': 'x', 'first': time.time()}
hg.save(st, 'shield.json')


def code(action, target=FID):
    text = ap.offer_text(hg, [(action, target, 'openssl 3.0.2: CVE-2026-1111')])
    return next(w for w in text.split() if w.startswith('hg-'))


def imap():
    im = imaplib.IMAP4_SSL('localhost', 993, ssl_context=ssl.create_default_context(cafile=CA), timeout=20)
    im.login(USER, PASS)
    im.select('INBOX')
    return im


def deliver(frm, first, ars=(), quoted='', subject='Re: [P1 Critical] Advisory | redteam-target'):
    head = ''.join(f'Authentication-Results: {a}\r\n' for a in ars)
    raw = (f'{head}From: <{frm}>\r\nTo: {USER}@localhost\r\nSubject: {subject}\r\n'
           f'Message-ID: <{os.urandom(8).hex()}@redteam.test>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n'
           f'{first}\r\n\r\nOn Mon, 23 Nov 2026 at 10:00, host-guard wrote:\r\n{quoted}\r\n').encode()
    im = imap()
    im.append('INBOX', None, None, raw)
    im.logout()
    return run('hostguard replies').stdout


def stamp(dom='example.com', dmarc='pass', serv=AUTHSERV):
    return f'{serv}; dkim={dmarc} header.d={dom}; spf={dmarc} smtp.mailfrom={dom}; dmarc={dmarc} header.from={dom}'


def status():
    return hg.load('shield.json')['known'][FID]['status']


def log_tail(n=1):
    return hg.load('approvals.json').get('log', [])[-n:]


def mailbox():
    try:
        return open(MAILBOX, encoding='utf-8', errors='replace').read()
    except FileNotFoundError:
        return ''


def as_panel(items):
    """Write outbox files exactly as the panel's own user can (what a taken-over panel could do)."""
    t = time.time()
    script = ' ; '.join(f"printf '%s' '{json.dumps(dict(x, at=t))}' > {OUTBOX}/{int(t * 1000) + i}-{os.urandom(8).hex()}.json"
                        for i, x in enumerate(items))
    subprocess.run(['runuser', '-u', 'hgpanel', '--', 'sh', '-c', script], capture_output=True)


def wait(pred, n=60):
    for _ in range(n):
        if pred():
            return True
        time.sleep(1)
    return pred()


def mailed_code(to, before):
    """The change code root mailed to `to` after mailbox offset `before` (what the admin reads)."""
    for part in reversed(mailbox()[before:].split('=== MAIL to ')[1:]):
        head, _, body = part.partition('\n')
        m = re.search(r'Code: ([0-9]{6})', body)
        if to in head and 'confirm a dashboard change' in body and m:
            return m.group(1)
    return ''


def dashboard(email, change):
    """The real two-step dashboard flow: ask root for a code, read it from the mailbox, confirm."""
    cid, before = os.urandom(16).hex(), len(mailbox())
    as_panel([{'kind': 'change-request', 'email': email, 'cid': cid, 'change': change}])
    wait(lambda: mailed_code(email, before), 30)
    c = mailed_code(email, before)
    if c:
        as_panel([{'kind': 'confirm', 'email': email, 'cid': cid, 'code': c}])
    return cid, c


# The panel stage just before signed in as admin2 again and again and used up its 5 mailed codes in
# 15 minutes (that limit is tested there). This stage starts a fresh quarter-hour, as if later.
pm = hg.load('panel-mail.json')
pm['sent'] = []
hg.save(pm, 'panel-mail.json')

check('MAIL-0', 'T1078', 'The reply reader logs in to a real IMAP server over TLS (its own certificate, IMAP_CA)',
      'it reads the inbox', 'replies: 0 read' in run('hostguard replies').stdout,
      (r.stderr or 'dovecot up')[-200:])

# 1: a forged sender, no stamp from the mail server, but a real code (someone saw a mail)
hold = code('hold')
before = len(mailbox())
res = deliver(ADMIN, f'HOLD {hold}')
new = mailbox()[before:]
check('MAIL-1', 'T1656', 'A forged reply from an admin address carrying a real HOLD code (no verdict from the mail server)',
      'nothing done; the code is void; every admin warned',
      status() == 'open' and 'Forged approval refused' in new and deliver(ADMIN, f'HOLD {hold}', [stamp()]) and status() == 'open',
      f'{res.strip()[:120]}; finding {status()}; warning mailed: {"Forged approval refused" in new}')

# 2: the attacker writes a passing stamp below the server's failing one
hold = code('hold')
deliver(ADMIN, f'HOLD {hold}', [stamp(dmarc='fail'), stamp()])
check('MAIL-2', 'T1656', 'A forged reply with its own "dmarc=pass" Authentication-Results below the mail server\'s "fail"',
      'only the top line, from our mail server, counts: refused', status() == 'open', f'finding {status()}; log: {log_tail()}')

# 3: a passing stamp from another server's name
hold = code('hold')
deliver(ADMIN, f'HOLD {hold}', [stamp(serv='mx.attacker.example')])
check('MAIL-3', 'T1656', 'A reply whose top verdict claims pass but names another mail server',
      'refused', status() == 'open', f'finding {status()}; log: {log_tail()}')

# 4: a real sender who is not an admin
hold = code('hold')
before = len(mailbox())
deliver(OUTSIDER, f'HOLD {hold}', [stamp('example.org')])
check('MAIL-4', 'T1078', 'A genuine (DMARC pass) reply from an address that is not an admin', 'refused, and not answered',
      status() == 'open' and OUTSIDER not in mailbox()[before:], f'finding {status()}; log: {log_tail()}')

# 5: commands instead of an action line
before = len(mailbox())
for line in ('touch /tmp/mail-pwned', f'HOLD {hold}; touch /tmp/mail-pwned', '$(touch /tmp/mail-pwned)',
             'sudo hostguard fix deadbeef'):
    deliver(ADMIN, line, [stamp()])
check('MAIL-5', 'T1059', 'Genuine admin replies with shell commands instead of an action line', 'nothing is ever run',
      not os.path.exists('/tmp/mail-pwned') and status() == 'open', f'/tmp/mail-pwned exists: {os.path.exists("/tmp/mail-pwned")}; '
      f'finding {status()}')

# 6: the code only in the quoted part
deliver(ADMIN, 'Thanks, I will look later', [stamp()], quoted=f'> HOLD {hold}')
check('MAIL-6', 'T1204', 'A genuine reply that only quotes host-guard\'s mail (the code is below the quote line)',
      'nothing done: only the reply\'s own first lines count', status() == 'open', f'finding {status()}')

# 7: the genuine reply, then the same code again from the other admin
deliver(ADMIN, f'HOLD {hold}', [stamp()])
ok7 = status() == 'held' and log_tail()[0]['channel'] == 'email' and log_tail()[0]['by'] == ADMIN
deliver(ADMIN2, f'HOLD {hold}', [stamp()])
check('MAIL-7', 'T1550', 'A genuine admin reply holds the fix; then the same code is replayed by another admin',
      'the first works and is logged (who, email); the replay does nothing',
      ok7 and 'refused' in log_tail()[0]['result'], f'after the first: held={ok7}; replay: {log_tail()[0]["result"]}')

# 8: a reboot approved by one admin only, then the second admin on the dashboard
hg_state = hg.load()
hg_state.pop('planned_reboot', None)
hg.save(hg_state)
reboot = code('reboot', 'now')
before = len(mailbox())
deliver(ADMIN, f'REBOOT {reboot}', [stamp()])
one = 'planned_reboot' not in hg.load() and 'Approval 1 of 2: reboot now' in mailbox()[before:]
_, code8 = dashboard(ADMIN2, {'action': 'approve', 'verb': 'reboot', 'target': 'now'})
wait(lambda: hg.load().get('planned_reboot'))
pr = hg.load().get('planned_reboot') or {}
check('MAIL-8', 'T1529', 'A reboot approved by one admin by mail', 'nothing until a second admin approves (here on the '
      'dashboard, with the code root mailed); then a backup and the reboot, naming both and how',
      one and ADMIN in pr.get('by', '') and ADMIN2 in pr.get('by', '') and 'dashboard' in pr.get('by', ''),
      f'after one: not rebooted={one}; code mailed: {bool(code8)}; after two: {pr.get("by", "not rebooted")}')

# 9: a taken-over panel: the old direct kinds, a change it confirms with guessed codes, and an
#    inside source an admin really confirms (the root side still refuses the address)
st = hg.load('shield.json')
st['known'][FID]['status'] = 'open'
hg.save(st, 'shield.json')
before = len(mailbox())
as_panel([{'kind': 'approve', 'email': ADMIN, 'verb': 'hold', 'target': FID},
          {'kind': 'approve', 'email': OUTSIDER, 'verb': 'hold', 'target': FID},
          {'kind': 'approve', 'email': ADMIN, 'verb': 'shell', 'target': FID},
          {'kind': 'approve', 'email': ADMIN, 'verb': 'fix', 'target': '../../etc'},
          {'kind': 'source-add', 'email': ADMIN, 'name': 'Inside', 'url': 'https://floci:4566/', 'fmt': 'page'}])
time.sleep(6)
direct = status() == 'open'
cid = os.urandom(16).hex()
as_panel([{'kind': 'change-request', 'email': ADMIN, 'cid': cid, 'change': {'action': 'approve', 'verb': 'hold', 'target': FID}}])
time.sleep(4)
as_panel([{'kind': 'confirm', 'email': ADMIN, 'cid': cid, 'code': g} for g in ('000000', '123456', '999999', '111111', '424242')])
time.sleep(6)
guessed = status() == 'open'
_, code23 = dashboard(ADMIN, {'action': 'add', 'name': 'Inside', 'url': 'https://floci:4566/', 'fmt': 'page'})
wait(lambda: 'not a public address' in mailbox()[before:], 60)
new = mailbox()[before:]
extra = [s['url'] for s in hg.load('shield.json').get('extra_sources', [])]
check('PANEL-23', 'T1068', "The panel's own user (if the panel were taken over) writes root approvals and source changes "
      'directly, confirms a hold with guessed codes, and an admin confirms an advisory source inside the network (SSRF)',
      'direct writes and guesses do nothing; the inside source is refused by root and the admin told',
      direct and guessed and status() == 'open' and 'https://floci:4566/' not in extra and 'not a public address' in new,
      f'direct refused: {direct}; guesses refused: {guessed}; real code mailed: {bool(code23)}; '
      f'finding {status()}; sources added: {extra or "none"}')

# 10: other mail in the inbox is left alone
deliver('friend@example.net', 'Lunch on Friday?', [stamp('example.net')], subject='Lunch')
im = imap()
typ, data = im.search(None, 'UNSEEN')
im.logout()
check('MAIL-9', 'T1114', 'Mail in the account that is not a reply to host-guard', 'left unread and untouched',
      len((data[0] or b'').split()) >= 1, f'unread left: {len((data[0] or b"").split())}')

for x in out:
    print(json.dumps(x))
