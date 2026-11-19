#!/usr/bin/env python3
"""Attacks on the panel from someone who can reach 127.0.0.1:8650 (an SSH tunnel) but should
not get in, from someone holding a stolen session cookie, and from the panel's own user if it
were taken over (abusing the root mailer). Runs on the target as root; reads sign-in codes from
the captured mailbox the way an admin reads them from an inbox. Prints one JSON object per
check: {"id", "technique", "attack", "expected", "result": PASS|FAIL|GAP, "evidence"}."""
import http.client
import json
import os
import re
import subprocess
import time
import urllib.parse

HOST, PORT = '127.0.0.1', 8650
ADMIN = 'admin2@example.com'            # the browser stage signs in as security@example.com
OUTSIDER = 'outsider@example.org'
MAILBOX = '/var/mail/hg-captured'
OUTBOX = '/var/lib/host-guard-panel/outbox'


def req(method, path, body=None, headers=None, host=None):
    c = http.client.HTTPConnection(HOST, PORT, timeout=10)
    h = {'Host': host or f'{HOST}:{PORT}', **(headers or {})}
    if body is not None:
        body = urllib.parse.urlencode(body)
        h['Content-Type'] = 'application/x-www-form-urlencoded'
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    data = r.read().decode('utf-8', 'replace')
    return r.status, r.getheaders(), data


def cookies_of(headers):
    jar, raw = {}, []
    for k, v in headers:
        if k.lower() == 'set-cookie':
            raw.append(v)
            name, val = v.split(';', 1)[0].split('=', 1)
            jar[name] = val
    return jar, raw


def form_token(path='/login', jar=None):
    st, hdr, body = req('GET', path, headers={'Cookie': '; '.join(f'{k}={v}' for k, v in (jar or {}).items())})
    pre = cookies_of(hdr)[0].get('hg_pre', '')
    m = re.search(r'name="csrf" value="([^"]+)"', body)
    return pre, m.group(1) if m else ''


def mailbox():
    try:
        return open(MAILBOX, encoding='utf-8', errors='replace').read()
    except OSError:
        return ''


def mails_to(addr, text=None):
    """The mails in the mailbox addressed to addr (the capture writes '=== MAIL to ADDR')."""
    parts = (text if text is not None else mailbox()).split('=== MAIL to ')
    return [p for p in parts[1:] if p.split('\n', 1)[0].strip() == addr]


def ask_code(email, csrf_override=None):
    """POST the address; returns (status, page, pre cookie, form token for the code form)."""
    pre, csrf = form_token()
    st, hdr, body = req('POST', '/login', {'email': email, 'csrf': csrf if csrf_override is None else csrf_override},
                        {'Cookie': f'hg_pre={pre}'})
    jar = cookies_of(hdr)[0]
    m = re.search(r'name="csrf" value="([^"]+)"', body)
    return st, body, jar.get('hg_pre', ''), (m.group(1) if m else '')


def wait_code(email, before, timeout=25):
    """The newest code mailed to email after the mailbox had `before` characters."""
    end = time.time() + timeout
    while time.time() < end:
        new = mailbox()[before:]
        codes = [m for p in mails_to(email, new) for m in re.findall(r'Code: (\d{6})', p)]
        if codes:
            return codes[-1]
        time.sleep(0.5)
    return ''


def send_code(email, code, pre, csrf):
    st, hdr, body = req('POST', '/login/code', {'email': email, 'code': code, 'csrf': csrf}, {'Cookie': f'hg_pre={pre}'})
    jar, raw = cookies_of(hdr)
    return st, jar.get('hg_s'), raw, body


def sign_in(email=ADMIN):
    before = len(mailbox())
    st, body, pre, csrf = ask_code(email)
    code = wait_code(email, before)
    st2, tok, raw, body2 = send_code(email, code, pre, csrf)
    return code, st2, tok, raw, body2


out = []


def check(id_, technique, attack, expected, ok, evidence, gap=False):
    out.append({'id': id_, 'technique': technique, 'attack': attack, 'expected': expected,
                'result': 'PASS' if ok else ('GAP' if gap else 'FAIL'), 'evidence': evidence})


st, hdr, _ = req('GET', '/', host='evil.example')
check('PANEL-1', 'T1557', 'DNS rebinding: a page on evil.example reaches the panel through the browser',
      'request refused (Host header checked)', st == 400, f'HTTP {st} for Host: evil.example')

st, hdr, _ = req('GET', '/login')
h = {k.lower(): v for k, v in hdr}
need = {'content-security-policy': "default-src 'none'", 'x-frame-options': 'DENY',
        'x-content-type-options': 'nosniff', 'cache-control': 'no-store'}
missing = [k for k, v in need.items() if v not in h.get(k, '')]
check('PANEL-2', 'T1185', 'Clickjacking, script injection, cached pages',
      'CSP without script, no framing, nosniff, no-store', not missing,
      'all present' if not missing else 'missing: ' + ', '.join(missing))

before = len(mailbox())
st, body, _, _ = ask_code(ADMIN, csrf_override='forged')
time.sleep(3)
check('PANEL-3', 'T1185', 'Cross-site code request (forged form token)', 'refused, no code mailed',
      st == 403 and not mails_to(ADMIN, mailbox()[before:]), f'HTTP {st}; codes mailed: {len(mails_to(ADMIN, mailbox()[before:]))}')

st, body, pre, csrf = ask_code("admin' OR '1'='1' --@example.com")
st2, tok, _, body2 = send_code(ADMIN, "1' OR '1'='1", pre, csrf)
check('PANEL-4', 'T1190', 'SQL injection in the address and the code', 'refused as not an address / not a code; no error, no session',
      st == 400 and st2 in (401, 403) and not tok and 'Traceback' not in body + body2, f'address: HTTP {st}; code: HTTP {st2}')

# address enumeration: an admin's address and anyone else's get the same answer, and only the admin gets mail
before = len(mailbox())
sa, ba, _, _ = ask_code(ADMIN)
so, bo, _, _ = ask_code(OUTSIDER)
time.sleep(4)
strip = lambda t, e: re.sub(r'value="[^"]+"', '', t).replace(e, 'X')        # noqa: E731
same = sa == so and strip(ba, ADMIN) == strip(bo, OUTSIDER)
to_outsider = len(mails_to(OUTSIDER, mailbox()[before:]))
check('PANEL-18', 'T1589.002', 'Find out which addresses are admins (ask for a code for an admin and for anyone else)',
      'the same answer for both; a code only ever goes to an admin', same and to_outsider == 0,
      f'same page and status: {same}; mails to the outsider: {to_outsider}')

code, st, tok, raw, body = sign_in()
flags = next((r for r in raw if r.startswith('hg_s=')), '')
good = st == 303 and tok and all(f in flags for f in ('HttpOnly', 'SameSite=Strict', 'Secure'))
check('PANEL-5', 'T1539', 'Session cookie theft by script or cross-site request', 'HttpOnly, SameSite=Strict, Secure',
      good, f'code from the mailbox: {bool(code)}; HTTP {st}; cookie flags: {"; ".join(p.strip() for p in flags.split(";")[1:])}')
time.sleep(3)
notice = [p for p in mailbox().split('=== MAIL to ')[1:] if f'Dashboard sign-in: {ADMIN}' in p]
check('PANEL-21', 'T1078', 'A sign-in by someone who got hold of an admin\'s mailbox', 'every admin is mailed about every sign-in',
      bool(notice), f'sign-in notices mailed: {len(notice)}')

st2, hdr2, body2 = req('GET', '/', headers={'Cookie': f'hg_s={tok}', 'User-Agent': 'curl/8.5.0 (another machine)'})
check('PANEL-6', 'T1550.004', 'Stolen session cookie replayed from another browser',
      'detected or refused (session bound to the browser, anomaly mailed)', st2 != 200,
      f'HTTP {st2}: the stolen cookie works from another client; no binding or anomaly alert yet '
      '(planned: session binding and hijack alerts)', gap=True)

m = re.search(r'name="csrf" value="([^"]+)"', body2)
st3, _, _ = req('POST', '/logout', {'csrf': 'wrong'}, {'Cookie': f'hg_s={tok}'})
check('PANEL-7', 'T1185', 'Cross-site request with a valid cookie but no form token', 'refused', st3 == 403, f'HTTP {st3}')
if m:
    req('POST', '/logout', {'csrf': m.group(1)}, {'Cookie': f'hg_s={tok}'})
st4b, _, body4 = req('GET', '/', headers={'Cookie': f'hg_s={tok}'})
signin = 'name="email"' in body4
check('PANEL-8', 'T1550.004', 'Reuse of a session cookie after sign-out', 'session gone (sign-in page)',
      signin, f'HTTP {st4b}, sign-in page shown: {signin}')

pre, csrf = form_token()
st, tok, _, _ = send_code(ADMIN, code, pre, csrf)
check('PANEL-9', 'T1111', 'Replay of a sign-in code already used', 'refused (single use)', not tok and st == 401, f'HTTP {st}')

codes, cors = {}, []
for m_ in ('PUT', 'DELETE', 'PATCH', 'TRACE', 'OPTIONS'):
    st, hdr, _ = req(m_, '/', headers={'Origin': 'https://evil.example', 'Access-Control-Request-Method': 'POST'})
    codes[m_] = st
    cors += [k for k, _ in hdr if k.lower().startswith('access-control-')]
check('PANEL-16', 'T1190', 'Unusual methods and a CORS preflight from another origin (PUT, DELETE, PATCH, TRACE, OPTIONS)',
      'none succeeds; no CORS header ever sent', all(c >= 400 for c in codes.values()) and not cors,
      f'answers: {codes}; CORS headers: {cors or "none"}')
leaked = []
for path in ('/../../etc/passwd', '/%2e%2e/%2e%2e/etc/passwd', '/style.css/../../../etc/shadow', '//etc/passwd',
             '/static/..%2f..%2fetc%2fpasswd'):
    st, _, body = req('GET', path)
    if 'root:' in body:
        leaked.append(path)
check('PANEL-17', 'T1083', 'Path traversal to /etc/passwd and /etc/shadow (5 encodings)', 'no file served',
      not leaked, f'files served: {leaked or "none"}')

before = len(mailbox())
st, body, pre, csrf = ask_code(ADMIN)
right = wait_code(ADMIN, before)
answers = []
for i in range(5):
    wrong = str((int(right or '0') + 1 + i) % 10 ** 6).zfill(6)
    st, tok, _, body = send_code(ADMIN, wrong, pre, csrf)
    answers.append(st)
    pre, csrf = form_token()
st, tok, _, _ = send_code(ADMIN, right, pre, csrf)
check('PANEL-10', 'T1110.001', 'Guess the 6-digit code (5 wrong), then the right one',
      'the code is burned after 5 wrong tries: even the right one is refused', bool(right) and not tok,
      f'guesses answered {sorted(set(answers))}; then the right code: HTTP {st}, session: {bool(tok)}')

before = len(mailbox())
for _ in range(10):
    ask_code(ADMIN)
time.sleep(5)
n = len(mails_to(ADMIN, mailbox()[before:]))
check('PANEL-19', 'T1499', 'Flood an admin with sign-in codes (10 requests at once)', 'a few codes at most (3 per address in 10 minutes)',
      n <= 1, f'codes mailed for 10 requests: {n} (this address had 2 already in the last 10 minutes)')

# the panel's own user, taken over, abuses the root mailer
before = len(mailbox())
shadow = subprocess.run(['sha256sum', '/etc/shadow'], capture_output=True, text=True).stdout
t = int(time.time() * 1000)
script = f'''
cd {OUTBOX}
printf '{{"kind": "code", "email": "{OUTSIDER}", "code": "123456", "at": {time.time()}}}' > {t}-aaaaaaaaaaaaaaaa.json
printf '{{"kind": "signed-in", "email": "{OUTSIDER}", "at": {time.time()}}}' > {t + 1}-bbbbbbbbbbbbbbbb.json
ln -s /etc/shadow {t + 2}-cccccccccccccccc.json
head -c 100000 /dev/zero > {t + 3}-dddddddddddddddd.json
printf '{{"kind": "code", "email": "{ADMIN}", "code": "not a code", "at": {time.time()}}}' > {t + 4}-eeeeeeeeeeeeeeee.json
mkdir junk-dir; printf x > notes.txt
'''
subprocess.run(['runuser', '-u', 'hgpanel', '--', 'sh', '-c', script], capture_output=True)
time.sleep(6)
left = sorted(os.listdir(OUTBOX))
new = mailbox()[before:]
leak = 'root:' in new or '$y$' in new or '$6$' in new
check('PANEL-20', 'T1068', 'The panel\'s own user (if the panel were taken over) feeds the root mailer: a code for an '
      'outsider, a link to /etc/shadow, a 100 KB file, a bad code, a folder',
      'nothing mailed to anyone but admins, no link followed, every entry removed',
      not mails_to(OUTSIDER, new) and not leak and not left and
      subprocess.run(['sha256sum', '/etc/shadow'], capture_output=True, text=True).stdout == shadow,
      f'mails to the outsider: {len(mails_to(OUTSIDER, new))}; shadow content mailed: {leak}; left in the outbox: {left or "nothing"}')

for r in out:
    print(json.dumps(r))
