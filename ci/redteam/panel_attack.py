#!/usr/bin/env python3
"""Attacks on the panel from someone who can reach 127.0.0.1:8650 (an SSH tunnel) but should
not get in, and from someone holding a stolen session cookie. Prints one JSON object per check:
{"id", "technique", "attack", "expected", "result": PASS|FAIL|GAP, "evidence"}."""
import base64
import hashlib
import hmac
import http.client
import json
import re
import struct
import time
import urllib.parse

HOST, PORT = '127.0.0.1', 8650
USER, PASSWORD, SECRET = 'admin', 'Panel-Pass-2026!', 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'


def totp(step):
    key = base64.b32decode(SECRET)
    mac = hmac.new(key, struct.pack('>Q', step), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    return str((struct.unpack('>I', mac[off:off + 4])[0] & 0x7FFFFFFF) % 10 ** 6).zfill(6)


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


def login_form():
    st, hdr, body = req('GET', '/login')
    jar, _ = cookies_of(hdr)
    m = re.search(r'name="csrf" value="([^"]+)"', body)
    return jar.get('hg_pre', ''), m.group(1) if m else ''


def login(password=PASSWORD, code=None, user=USER, csrf_override=None):
    pre, csrf = login_form()
    code = code or totp(int(time.time() // 30))
    st, hdr, body = req('POST', '/login', {'username': user, 'password': password, 'code': code,
                                           'csrf': csrf if csrf_override is None else csrf_override},
                        {'Cookie': f'hg_pre={pre}'})
    jar, raw = cookies_of(hdr)
    return st, jar.get('hg_s'), raw, body


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

st, tok, raw, body = login(csrf_override='forged')
check('PANEL-3', 'T1185', 'Cross-site login (forged form token)', 'refused', st == 403 and not tok, f'HTTP {st}')

st, tok, raw, body = login(user="admin' OR '1'='1' --", password="x' OR '1'='1")
check('PANEL-4', 'T1190', 'SQL injection in the sign-in form', 'generic refusal, no error, no session',
      st == 401 and not tok and 'Traceback' not in body, f'HTTP {st}, generic message: {"Sign-in failed" in body}')

st, tok, raw, body = login()
flags = next((r for r in raw if r.startswith('hg_s=')), '')
good = st == 303 and tok and all(f in flags for f in ('HttpOnly', 'SameSite=Strict', 'Secure'))
check('PANEL-5', 'T1539', 'Session cookie theft by script or cross-site request', 'HttpOnly, SameSite=Strict, Secure',
      good, f'HTTP {st}; cookie flags: {"; ".join(p.strip() for p in flags.split(";")[1:])}')
used_code = totp(int(time.time() // 30))

st2, hdr2, body2 = req('GET', '/', headers={'Cookie': f'hg_s={tok}', 'User-Agent': 'curl/8.5.0 (another machine)'})
check('PANEL-6', 'T1550.004', 'Stolen session cookie replayed from another browser',
      'detected or refused (session bound to the browser, anomaly mailed)', st2 != 200,
      f'HTTP {st2}: the stolen cookie works from another client; no binding or anomaly alert yet '
      '(planned: session binding and hijack alerts in the panel release)', gap=True)

m = re.search(r'name="csrf" value="([^"]+)"', body2)
st3, _, _ = req('POST', '/logout', {'csrf': 'wrong'}, {'Cookie': f'hg_s={tok}'})
check('PANEL-7', 'T1185', 'Cross-site request with a valid cookie but no form token', 'refused', st3 == 403, f'HTTP {st3}')
if m:
    req('POST', '/logout', {'csrf': m.group(1)}, {'Cookie': f'hg_s={tok}'})
st4b, _, body4 = req('GET', '/', headers={'Cookie': f'hg_s={tok}'})
signin = 'name="password"' in body4
check('PANEL-8', 'T1550.004', 'Reuse of a session cookie after sign-out', 'session gone (sign-in page)',
      signin, f'HTTP {st4b}, sign-in page shown: {signin}')

st, tok, raw, body = login(code=used_code)
check('PANEL-9', 'T1111', 'Replay of an authenticator code already used', 'refused', not tok, f'HTTP {st}')

codes, cors = {}, []
for m in ('PUT', 'DELETE', 'PATCH', 'TRACE', 'OPTIONS'):
    st, hdr, _ = req(m, '/', headers={'Origin': 'https://evil.example', 'Access-Control-Request-Method': 'POST'})
    codes[m] = st
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

results = [login(password=f'guess-{i}')[0] for i in range(5)]
time.sleep(1)
st, tok, raw, body = login(code=totp(int(time.time() // 30) + 1))
check('PANEL-10', 'T1110.001', 'Password guessing (5 wrong), then the right password and code',
      'account locked: even the right credentials are refused', not tok,
      f'guesses answered {sorted(set(results))}; then right credentials: HTTP {st}, session: {bool(tok)}')

for r in out:
    print(json.dumps(r))
