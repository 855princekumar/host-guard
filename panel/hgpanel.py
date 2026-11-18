#!/usr/bin/env python3
"""host-guard panel: one page for one admin, read-only in this version.
Python 3 standard library and one SQLite file, nothing else.

    hgpanel init-admin NAME [--reset]   set the one admin: password (asked twice, not shown)
                                        and a new authenticator (TOTP) secret, confirmed by a code
    hgpanel serve                       run the panel (systemd runs it as the user hgpanel)
    hgpanel audit [N]                   the last N audit lines (sign-ins, failures, lockouts)

Security model
  * Listens on 127.0.0.1 only (reach it through an SSH tunnel or Tailscale); another
    address needs ALLOW_REMOTE=1 and a matching ALLOWED_HOSTS entry.
  * Runs as an unprivileged user. It never reads host-guard's state or .env: it reads
    STATUS_FILE, which `hostguard export` writes without secrets.
  * One admin (the table cannot hold two). Password hashed with scrypt, second factor
    TOTP (RFC 6238) with replay protection; 5 failures lock the account for 15 minutes,
    10 failures from one address in 15 minutes block that address.
  * Sessions: random 256-bit token, only its SHA-256 is stored; HttpOnly, SameSite=Strict,
    Secure; 15 minutes idle, 8 hours at most; a new token at every sign-in.
  * Every form carries a CSRF token; every query is parameterized; every value shown is
    HTML-escaped; strict Content-Security-Policy with no script at all; Host header checked.

Settings: /etc/host-guard-panel/panel.conf (KEY=VALUE), environment HGP_<KEY> wins.
"""
import base64
import getpass
import hashlib
import hmac
import html
import http.server
import ipaddress
import json
import os
import secrets
import sqlite3
import struct
import sys
import threading
import time
import urllib.parse

CONF = os.environ.get('HGP_CONF', '/etc/host-guard-panel/panel.conf')
DEFAULTS = {
    'BIND': '127.0.0.1', 'PORT': '8650', 'ALLOW_REMOTE': '0', 'ALLOWED_HOSTS': '',
    'DB': '/var/lib/host-guard-panel/panel.db', 'STATUS_FILE': '/var/lib/host-guard-export/status.json',
    'COOKIE_SECURE': '1', 'IDLE_MIN': '15', 'MAX_HOURS': '8',
    'LOCK_AFTER': '5', 'LOCK_MIN': '15', 'IP_LIMIT': '10', 'ISSUER': 'host-guard',
}
MAX_BODY = 8192
SCRYPT = {'n': 2 ** 15, 'r': 8, 'p': 1}


def read_kv(file):
    out = {}
    try:
        for line in open(file, encoding='utf-8'):
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                k, v = line.split('=', 1)
                out[k.strip()] = v.strip().strip('"').strip("'")
    except (FileNotFoundError, PermissionError):
        pass
    return out


def conf():
    c = dict(DEFAULTS)
    c.update({k: v for k, v in read_kv(CONF).items() if k in DEFAULTS})
    for k in DEFAULTS:
        if os.environ.get('HGP_' + k):
            c[k] = os.environ['HGP_' + k]
    return c


C = conf()


# ---------------------------------------------------------------- database
SCHEMA = '''
CREATE TABLE IF NOT EXISTS admin (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  username TEXT NOT NULL, pw_hash TEXT NOT NULL, totp_secret TEXT NOT NULL,
  totp_last_step INTEGER NOT NULL DEFAULT 0, failed INTEGER NOT NULL DEFAULT 0,
  locked_until REAL NOT NULL DEFAULT 0, created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY, csrf TEXT NOT NULL, created REAL NOT NULL, seen REAL NOT NULL, ip TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS failures (ip TEXT NOT NULL, at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS audit (at REAL NOT NULL, ip TEXT NOT NULL, event TEXT NOT NULL, detail TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS failures_ip ON failures (ip, at);
'''
_lock = threading.Lock()


def db():
    path = C['DB']
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    con = sqlite3.connect(path, timeout=10, isolation_level=None)
    con.execute('PRAGMA journal_mode=WAL')
    con.execute('PRAGMA foreign_keys=ON')
    con.executescript(SCHEMA)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return con


def audit(con, ip, event, detail=''):
    con.execute('INSERT INTO audit (at, ip, event, detail) VALUES (?, ?, ?, ?)', (time.time(), ip, event, detail[:200]))


# ---------------------------------------------------------------- passwords and TOTP
def hash_password(pw):
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, maxmem=64 * 1024 * 1024, dklen=32, **SCRYPT)
    return 'scrypt${n}${r}${p}$'.format(**SCRYPT) + base64.b64encode(salt).decode() + '$' + base64.b64encode(h).decode()


def check_password(pw, stored):
    try:
        alg, n, r, p, salt, h = stored.split('$')
        if alg != 'scrypt':
            return False
        got = hashlib.scrypt(pw.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                             maxmem=64 * 1024 * 1024, dklen=32)
        return hmac.compare_digest(got, base64.b64decode(h))
    except (ValueError, TypeError):
        return False


DUMMY_HASH = hash_password(secrets.token_urlsafe(16))      # same work for an unknown user


def totp(secret_b32, step, digits=6):
    key = base64.b32decode(secret_b32 + '=' * (-len(secret_b32) % 8), casefold=True)
    mac = hmac.new(key, struct.pack('>Q', step), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack('>I', mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp_step_ok(secret_b32, code, last_step, at=None):
    """The step a valid code belongs to (now, or 30 s either side), or None. A step at or
    before last_step was used already (replay)."""
    if not (isinstance(code, str) and len(code) == 6 and code.isdigit()):
        return None
    now_step = int((at or time.time()) // 30)
    for step in (now_step - 1, now_step, now_step + 1):
        if step > last_step and hmac.compare_digest(totp(secret_b32, step), code):
            return step
    return None


# ---------------------------------------------------------------- sessions
def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def new_session(con, ip):
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    t = time.time()
    con.execute('INSERT INTO sessions (token_hash, csrf, created, seen, ip) VALUES (?, ?, ?, ?, ?)',
                (sha(token), csrf, t, t, ip))
    return token


def get_session(con, token):
    if not token or len(token) > 100:
        return None
    row = con.execute('SELECT token_hash, csrf, created, seen FROM sessions WHERE token_hash = ?',
                      (sha(token),)).fetchone()
    if not row:
        return None
    t = time.time()
    if t - row[3] > float(C['IDLE_MIN']) * 60 or t - row[2] > float(C['MAX_HOURS']) * 3600:
        con.execute('DELETE FROM sessions WHERE token_hash = ?', (row[0],))
        return None
    con.execute('UPDATE sessions SET seen = ? WHERE token_hash = ?', (t, row[0]))
    return {'hash': row[0], 'csrf': row[1]}


# ---------------------------------------------------------------- sign-in
def ip_blocked(con, ip):
    since = time.time() - float(C['LOCK_MIN']) * 60
    con.execute('DELETE FROM failures WHERE at < ?', (since,))
    n = con.execute('SELECT COUNT(*) FROM failures WHERE ip = ? AND at >= ?', (ip, since)).fetchone()[0]
    return n >= int(C['IP_LIMIT'])


def sign_in(con, ip, username, password, code):
    """Returns (session token or None, message). The message never says which part was wrong."""
    generic = 'Sign-in failed. Check the name, password and code.'
    with _lock:
        if ip_blocked(con, ip):
            audit(con, ip, 'blocked', 'too many failures from this address')
            return None, 'Too many failed sign-ins from this address. Try again later.'
        row = con.execute('SELECT username, pw_hash, totp_secret, totp_last_step, failed, locked_until '
                          'FROM admin WHERE id = 1').fetchone()
        name_ok = bool(row) and hmac.compare_digest((username or '').encode(), row[0].encode())
        pw_ok = check_password(password or '', row[1] if name_ok else DUMMY_HASH) and name_ok
        if row and row[5] > time.time():
            audit(con, ip, 'locked', 'sign-in while the account is locked')
            return None, generic
        step = totp_step_ok(row[2], code or '', row[3]) if pw_ok else None
        if not step:
            con.execute('INSERT INTO failures (ip, at) VALUES (?, ?)', (ip, time.time()))
            if row and name_ok:
                failed = row[4] + 1
                locked = time.time() + float(C['LOCK_MIN']) * 60 if failed >= int(C['LOCK_AFTER']) else 0
                con.execute('UPDATE admin SET failed = ?, locked_until = ? WHERE id = 1',
                            (0 if locked else failed, locked))
                if locked:
                    audit(con, ip, 'lockout', f'{failed} failed sign-ins')
            audit(con, ip, 'sign-in failed', 'name' if not name_ok else 'password' if not pw_ok else 'code')
            return None, generic
        con.execute('UPDATE admin SET failed = 0, locked_until = 0, totp_last_step = ? WHERE id = 1', (step,))
        audit(con, ip, 'sign-in', '')
        return new_session(con, ip), ''


# ---------------------------------------------------------------- pages
CSS = b'''*{box-sizing:border-box}body{margin:0;font:15px/1.5 system-ui,sans-serif;background:#f6f7f9;color:#1c2330}
@media (prefers-color-scheme:dark){body{background:#12161d;color:#e3e7ee}.card{background:#1b212b!important;border-color:#2a3240!important}
th{color:#9aa6b8!important}input{background:#12161d;color:#e3e7ee;border-color:#2a3240}}
header{display:flex;justify-content:space-between;align-items:center;padding:12px 16px;border-bottom:1px solid #8883}
main{max-width:1100px;margin:0 auto;padding:16px}h1{font-size:18px;margin:0}h2{font-size:15px;margin:0 0 8px}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fill,minmax(320px,1fr))}
.card{background:#fff;border:1px solid #dde1e7;border-radius:8px;padding:12px;overflow:auto}
table{border-collapse:collapse;width:100%}td,th{padding:3px 6px;text-align:left;vertical-align:top;border-bottom:1px solid #8882}
th{color:#5b6576;font-weight:500;white-space:nowrap}.bad{color:#c62828;font-weight:600}.ok{color:#2e7d32;font-weight:600}
form.login{max-width:340px;margin:10vh auto}label{display:block;margin:10px 0 4px}
input{width:100%;padding:8px;border:1px solid #c5cbd5;border-radius:6px;font:inherit}
button{margin-top:14px;padding:8px 14px;border:0;border-radius:6px;background:#2f5bd3;color:#fff;font:inherit;cursor:pointer}
.err{color:#c62828}.muted{color:#8a94a6;font-size:13px}pre{white-space:pre-wrap;margin:0;font-size:13px}
'''
SECTIONS = [('health', 'Health'), ('watch', 'Intrusion watch'), ('bans', 'Bans'), ('backup', 'Backup'),
            ('restore_test', 'Restore test'), ('scan', 'Scan'), ('feeds', 'Early warning'), ('lockdown', 'Lockdown')]


def esc(v):
    return html.escape(str(v), quote=True)


def when(t):
    try:
        return time.strftime('%Y-%m-%d %H:%M', time.localtime(float(t)))
    except (TypeError, ValueError):
        return esc(t)


def render_value(v, depth=0):
    if isinstance(v, dict):
        if not v:
            return '<span class="muted">none</span>'
        rows = ''.join(f'<tr><th>{esc(k)}</th><td>{when(x) if k in ("at", "last", "since") else render_value(x, depth + 1)}'
                       f'</td></tr>' for k, x in list(v.items())[:50])
        return f'<table>{rows}</table>'
    if isinstance(v, list):
        if not v:
            return '<span class="muted">none</span>'
        if depth > 1:
            return f'<pre>{esc(json.dumps(v, indent=1)[:2000])}</pre>'
        return ''.join(f'<div>{render_value(x, depth + 1)}</div>' for x in v[:30])
    if v is None:
        return '<span class="muted">not run yet</span>'
    return esc(v)


def page(title, body, csrf=None):
    out = f'<form method="post" action="/logout"><input type="hidden" name="csrf" value="{esc(csrf)}">' \
          f'<button>Sign out</button></form>' if csrf else ''
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" '
            f'content="width=device-width,initial-scale=1"><title>{esc(title)}</title>'
            f'<link rel="stylesheet" href="/style.css"></head><body><header><h1>{esc(title)}</h1>{out}</header>'
            f'<main>{body}</main></body></html>').encode()


def dashboard(csrf):
    try:
        with open(C['STATUS_FILE'], encoding='utf-8') as f:
            s = json.load(f)
    except (FileNotFoundError, PermissionError, ValueError) as e:
        return page('host-guard', f'<p class="err">No status yet ({esc(type(e).__name__)}). Is the '
                                  f'host-guard-export timer running?</p>', csrf)
    age = time.time() - float(s.get('generated') or 0)
    stale = f' <span class="bad">({int(age // 60)} min old)</span>' if age > 600 else ''
    problems = s.get('open_problems') or []
    head = (f'<p>{esc(s.get("site", ""))}: status of {when(s.get("generated"))}{stale}. '
            + (f'<span class="bad">{len(problems)} open problem(s)</span>' if problems else '<span class="ok">No open problems</span>')
            + '</p>')
    cards = ['<div class="card"><h2>Open problems</h2>' + (
        '<table>' + ''.join(f'<tr><td>{when(p.get("at"))}</td><td>{esc(p.get("subject") or p.get("key"))}</td></tr>'
                            for p in problems) + '</table>' if problems else '<span class="muted">none</span>') + '</div>']
    cards += [f'<div class="card"><h2>{esc(label)}</h2>{render_value(s.get(key))}</div>' for key, label in SECTIONS]
    mails = list(reversed(s.get('mails') or []))[:15]
    cards.append('<div class="card"><h2>Recent mails</h2><table>' + ''.join(
        f'<tr><td>{when(m.get("at"))}</td><td>{esc(m.get("subject", ""))}</td></tr>' for m in mails) + '</table></div>')
    return page('host-guard', head + '<div class="grid">' + ''.join(cards) + '</div>'
                + '<p class="muted"><a href="/audit">Audit log</a>. Read-only: changes are made on the server.</p>', csrf)


def login_page(pre, msg=''):
    err = f'<p class="err">{esc(msg)}</p>' if msg else ''
    return page('host-guard sign-in', f'<form class="login" method="post" action="/login">{err}'
                f'<input type="hidden" name="csrf" value="{esc(pre)}">'
                '<label for="u">Name</label><input id="u" name="username" autocomplete="username" required maxlength="64">'
                '<label for="p">Password</label><input id="p" name="password" type="password" '
                'autocomplete="current-password" required maxlength="256">'
                '<label for="c">Authenticator code</label><input id="c" name="code" inputmode="numeric" '
                'autocomplete="one-time-code" pattern="[0-9]{6}" required maxlength="6">'
                '<button>Sign in</button></form>')


# ---------------------------------------------------------------- HTTP
HEADERS = {
    'Content-Security-Policy': "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; "
                               "base-uri 'none'",
    'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer',
    'Cache-Control': 'no-store', 'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin', 'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
}


def allowed_hosts():
    port = C['PORT']
    hosts = {f'127.0.0.1:{port}', f'localhost:{port}', '127.0.0.1', 'localhost', f'[::1]:{port}'}
    hosts |= {h.strip().lower() for h in C['ALLOWED_HOSTS'].split(',') if h.strip()}
    return hosts


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'host-guard'
    sys_version = ''

    def log_message(self, fmt, *args):                    # no query strings or cookies in logs
        sys.stderr.write(f'{self.client_address[0]} {self.command} {urllib.parse.urlsplit(self.path).path}\n')

    def ip(self):
        return self.client_address[0]

    def cookies(self):
        out = {}
        for part in (self.headers.get('Cookie') or '').split(';'):
            if '=' in part:
                k, v = part.strip().split('=', 1)
                out[k] = v
        return out

    def send(self, code, body=b'', ctype='text/html; charset=utf-8', cookies=(), location=None):
        self.send_response(code)
        for k, v in HEADERS.items():
            self.send_header(k, v)
        if C['COOKIE_SECURE'] == '1':
            self.send_header('Strict-Transport-Security', 'max-age=31536000')
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        for c in cookies:
            self.send_header('Set-Cookie', c)
        if location:
            self.send_header('Location', location)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def cookie(self, name, value, max_age=None):
        parts = [f'{name}={value}', 'Path=/', 'HttpOnly', 'SameSite=Strict']
        if C['COOKIE_SECURE'] == '1':
            parts.append('Secure')
        if max_age is not None:
            parts.append(f'Max-Age={max_age}')
        return '; '.join(parts)

    def host_ok(self):
        return (self.headers.get('Host') or '').lower() in allowed_hosts()

    def form(self):
        try:
            n = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            return None
        if n > MAX_BODY or (self.headers.get('Content-Type') or '').split(';')[0] != 'application/x-www-form-urlencoded':
            return None
        data = urllib.parse.parse_qs(self.rfile.read(n).decode('utf-8', 'replace'), max_num_fields=10)
        return {k: v[0] for k, v in data.items()}

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        if not self.host_ok():
            return self.send(400, b'bad host', 'text/plain')
        route = urllib.parse.urlsplit(self.path).path
        if route == '/style.css':
            return self.send(200, CSS, 'text/css; charset=utf-8')
        con = db()
        try:
            sess = get_session(con, self.cookies().get('hg_s'))
            if route == '/login' or not sess:
                pre = secrets.token_urlsafe(24)
                return self.send(200, login_page(pre), cookies=[self.cookie('hg_pre', pre, 900)])
            if route == '/':
                return self.send(200, dashboard(sess['csrf']))
            if route == '/audit':
                rows = con.execute('SELECT at, ip, event, detail FROM audit ORDER BY at DESC LIMIT 200').fetchall()
                body = '<div class="card"><table><tr><th>When</th><th>From</th><th>Event</th><th>Detail</th></tr>' + ''.join(
                    f'<tr><td>{when(a)}</td><td>{esc(i)}</td><td>{esc(e)}</td><td>{esc(d)}</td></tr>' for a, i, e, d in rows
                ) + '</table></div><p><a href="/">Back</a></p>'
                return self.send(200, page('host-guard audit log', body, sess['csrf']))
            return self.send(404, page('Not found', '<p>Not found. <a href="/">Back</a></p>', sess['csrf']))
        finally:
            con.close()

    def do_POST(self):
        if not self.host_ok():
            return self.send(400, b'bad host', 'text/plain')
        route = urllib.parse.urlsplit(self.path).path
        f = self.form()
        if f is None:
            return self.send(400, b'bad request', 'text/plain')
        con = db()
        try:
            cookies = self.cookies()
            if route == '/login':
                pre = cookies.get('hg_pre', '')
                if not pre or not hmac.compare_digest(pre.encode(), (f.get('csrf') or '').encode()):
                    audit(con, self.ip(), 'csrf', '/login')
                    return self.send(403, b'form expired, reload the page', 'text/plain')
                token, msg = sign_in(con, self.ip(), f.get('username', ''), f.get('password', ''),
                                     (f.get('code') or '').strip())
                if not token:
                    new_pre = secrets.token_urlsafe(24)
                    return self.send(401, login_page(new_pre, msg), cookies=[self.cookie('hg_pre', new_pre, 900)])
                old = get_session(con, cookies.get('hg_s'))
                if old:
                    con.execute('DELETE FROM sessions WHERE token_hash = ?', (old['hash'],))
                return self.send(303, cookies=[self.cookie('hg_s', token), self.cookie('hg_pre', '', 0)], location='/')
            sess = get_session(con, cookies.get('hg_s'))
            if not sess or not hmac.compare_digest(sess['csrf'].encode(), (f.get('csrf') or '').encode()):
                audit(con, self.ip(), 'csrf', route)
                return self.send(403, b'forbidden', 'text/plain')
            if route == '/logout':
                con.execute('DELETE FROM sessions WHERE token_hash = ?', (sess['hash'],))
                audit(con, self.ip(), 'sign-out', '')
                return self.send(303, cookies=[self.cookie('hg_s', '', 0)], location='/login')
            return self.send(404, b'not found', 'text/plain')
        finally:
            con.close()


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32


def make_server():
    bind = C['BIND']
    if not ipaddress.ip_address(bind).is_loopback and C['ALLOW_REMOTE'] != '1':
        raise SystemExit(f'BIND={bind} is not a loopback address; set ALLOW_REMOTE=1 (and ALLOWED_HOSTS) to allow it')
    if ':' in bind:
        Server.address_family = __import__('socket').AF_INET6
    return Server((bind, int(C['PORT'])), Handler)


# ---------------------------------------------------------------- command line
def init_admin(name, reset=False):
    if not name or len(name) > 64 or not name.replace('.', '').replace('-', '').replace('_', '').isalnum():
        raise SystemExit('the name is letters, digits, dot, dash or underscore (64 at most)')
    con = db()
    if con.execute('SELECT 1 FROM admin WHERE id = 1').fetchone() and not reset:
        raise SystemExit('an admin exists already; --reset replaces it (and signs everyone out)')
    pw = getpass.getpass('Password (12 characters at least): ')
    if len(pw) < 12 or pw != getpass.getpass('Again: '):
        raise SystemExit('too short, or the two did not match')
    secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip('=')
    uri = (f'otpauth://totp/{urllib.parse.quote(C["ISSUER"])}:{urllib.parse.quote(name)}?secret={secret}'
           f'&issuer={urllib.parse.quote(C["ISSUER"])}&algorithm=SHA1&digits=6&period=30')
    print('\nAdd this to your authenticator app (it is shown once, here only):')
    print(f'  key: {secret}\n  or the link: {uri}\n')
    if not totp_step_ok(secret, input('Code from the app, to confirm: ').strip(), 0):
        raise SystemExit('that code did not match; nothing was changed, run this again')
    con.execute('DELETE FROM admin')
    con.execute('DELETE FROM sessions')
    con.execute('INSERT INTO admin (id, username, pw_hash, totp_secret, created) VALUES (1, ?, ?, ?, ?)',
                (name, hash_password(pw), secret, time.time()))
    audit(con, 'local', 'admin set', name)
    print(f'admin {name} set. Open the panel through a tunnel: ssh -L {C["PORT"]}:127.0.0.1:{C["PORT"]} <server>')


def main(argv):
    if len(argv) >= 2 and argv[0] == 'init-admin':
        return init_admin(argv[1], '--reset' in argv[2:])
    if argv == ['serve']:
        srv = make_server()
        print(f'host-guard panel on http://{C["BIND"]}:{C["PORT"]}', flush=True)
        srv.serve_forever()
    elif argv and argv[0] == 'audit':
        n = int(argv[1]) if len(argv) > 1 and argv[1].isdigit() else 50
        for a, i, e, d in db().execute('SELECT at, ip, event, detail FROM audit ORDER BY at DESC LIMIT ?', (n,)):
            print(when(a), i, e, d)
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == '__main__':
    main(sys.argv[1:])
