#!/usr/bin/env python3
"""host-guard panel: one page for the admins, read-only in this version.
Python 3 standard library and one SQLite file, nothing else.

    hgpanel serve                       run the panel (systemd runs it as the user hgpanel)
    hgpanel audit [N]                   the last N audit lines (code requests, sign-ins, failures)

Sign-in: no password. An admin enters their email address; a 6-digit code goes to that
address, and only that address. It works once, for 10 minutes. The admins are the
addresses host-guard mails (MAIL_TO in /etc/host-guard/guard.conf, set at install with
--mail-to), or PANEL_ADMINS there when set.

Security model
  * Listens on 127.0.0.1 only (reach it through an SSH tunnel or Tailscale): only someone
    who can open the tunnel sees the sign-in page at all. Another address needs
    ALLOW_REMOTE=1 and a matching ALLOWED_HOSTS entry.
  * Runs as an unprivileged user that cannot read host-guard's state, .env or the mail
    password. It writes a code request into its outbox; a root service (`hostguard
    panel-outbox`, started by host-guard-panel-mail.path) checks the address against the
    admin list, limits how often it mails, and sends it. The panel never learns who the
    admins are, so its answer is the same for every address.
  * Codes: random, only a salted SHA-256 is stored; single use; 10 minutes; 5 wrong tries
    burn the code; 3 requests per address in 10 minutes. 10 failures in 15 minutes block
    further guesses (a right code still gets in).
  * Every sign-in is mailed to all admins (a session someone else opened is noticed).
  * Sessions: random 256-bit token, only its SHA-256 is stored; HttpOnly, SameSite=Strict,
    Secure; 15 minutes idle, 8 hours at most; a new token at every sign-in.
  * Every form carries a CSRF token; posts from another origin are refused; every query is
    parameterized; every value shown is HTML-escaped; strict Content-Security-Policy with no
    script at all; Host header checked.

Settings: /etc/host-guard-panel/panel.conf (KEY=VALUE), environment HGP_<KEY> wins.
"""
import hashlib
import hmac
import html
import http.server
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
import urllib.parse

CONF = os.environ.get('HGP_CONF', '/etc/host-guard-panel/panel.conf')
DEFAULTS = {
    'BIND': '127.0.0.1', 'PORT': '8650', 'ALLOW_REMOTE': '0', 'ALLOWED_HOSTS': '',
    'DB': '/var/lib/host-guard-panel/panel.db', 'STATUS_FILE': '/var/lib/host-guard-export/status.json',
    'OUTBOX': '/var/lib/host-guard-panel/outbox',
    'COOKIE_SECURE': '1', 'IDLE_MIN': '15', 'MAX_HOURS': '8',
    'CODE_MIN': '10', 'CODE_TRIES': '5', 'CODE_REQUESTS': '3', 'LOCK_MIN': '15', 'IP_LIMIT': '10',
}
MAX_BODY = 8192
EMAIL = re.compile(r'^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$')


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
CREATE TABLE IF NOT EXISTS codes (
  email TEXT PRIMARY KEY, salt TEXT NOT NULL, code_hash TEXT NOT NULL, created REAL NOT NULL,
  tries INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS requests (email TEXT NOT NULL, at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY, csrf TEXT NOT NULL, created REAL NOT NULL, seen REAL NOT NULL, ip TEXT NOT NULL,
  email TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS failures (ip TEXT NOT NULL, at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS audit (at REAL NOT NULL, ip TEXT NOT NULL, event TEXT NOT NULL, detail TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS failures_ip ON failures (ip, at);
CREATE INDEX IF NOT EXISTS requests_email ON requests (email, at);
'''
_lock = threading.Lock()


def db():
    path = C['DB']
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    con = sqlite3.connect(path, timeout=10, isolation_level=None)
    con.execute('PRAGMA journal_mode=WAL')
    con.executescript(SCHEMA)
    cols = [r[1] for r in con.execute('PRAGMA table_info(sessions)')]
    if 'email' not in cols:                                     # a panel database from before 0.4
        con.execute("ALTER TABLE sessions ADD COLUMN email TEXT NOT NULL DEFAULT ''")
    con.execute('DROP TABLE IF EXISTS admin')                   # the password and authenticator of 0.3
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return con


def audit(con, ip, event, detail=''):
    con.execute('INSERT INTO audit (at, ip, event, detail) VALUES (?, ?, ?, ?)', (time.time(), ip, event, detail[:200]))
    con.execute('DELETE FROM audit WHERE at < ?', (time.time() - 180 * 86400,))      # 180 days kept


# ---------------------------------------------------------------- the outbox (read by the root mailer)
def outbox(kind, email, **extra):
    """Leave a request for `hostguard panel-outbox` (root): kind 'code' (mail this code to
    this address, if it is an admin) or 'signed-in' (tell every admin). One small JSON file,
    created new (never through a link), readable only by this user and root."""
    os.makedirs(C['OUTBOX'], mode=0o700, exist_ok=True)
    name = os.path.join(C['OUTBOX'], f'{int(time.time() * 1000)}-{secrets.token_hex(8)}.json')
    data = json.dumps({'kind': kind, 'email': email, 'at': time.time(), **extra}).encode()
    fd = os.open(name + '.tmp', os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
    os.replace(name + '.tmp', name)                            # the mailer sees only whole files


# ---------------------------------------------------------------- codes
def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def norm(email):
    e = (email or '').strip().lower()
    return e if EMAIL.match(e) else ''


def request_code(con, ip, email):
    """Make a code for this address and hand it to the mailer. Returns the message shown,
    the same for every address (the panel does not know who the admins are)."""
    msg = 'If this address belongs to an admin of this server, a code is on its way. It works once, for 10 minutes.'
    e = norm(email)
    if not e:
        return False, 'Enter an email address.'
    with _lock:
        t = time.time()
        con.execute('DELETE FROM requests WHERE at < ?', (t - 600,))
        n = con.execute('SELECT COUNT(*) FROM requests WHERE email = ?', (e,)).fetchone()[0]
        if n >= int(C['CODE_REQUESTS']):
            audit(con, ip, 'code throttled', e)
            return True, msg                                     # same answer; no new code
        code = str(secrets.randbelow(10 ** 6)).zfill(6)
        salt = secrets.token_hex(16)
        con.execute('INSERT OR REPLACE INTO codes (email, salt, code_hash, created, tries) VALUES (?, ?, ?, ?, 0)',
                    (e, salt, sha(salt + code), t))
        con.execute('INSERT INTO requests (email, at) VALUES (?, ?)', (e, t))
        audit(con, ip, 'code requested', e)
    outbox('code', e, code=code, ip=ip)
    return True, msg


def ip_blocked(con, ip):
    since = time.time() - float(C['LOCK_MIN']) * 60
    con.execute('DELETE FROM failures WHERE at < ?', (since,))
    n = con.execute('SELECT COUNT(*) FROM failures WHERE ip = ? AND at >= ?', (ip, since)).fetchone()[0]
    return n >= int(C['IP_LIMIT'])


def sign_in(con, ip, email, code):
    """Returns (session token or None, message). The code is single use: it is deleted on
    success, and burned after CODE_TRIES wrong tries or CODE_MIN minutes."""
    generic = 'That code is not valid. Ask for a new one.'
    e = norm(email)
    code = (code or '').strip()
    with _lock:
        blocked = ip_blocked(con, ip)
        row = con.execute('SELECT salt, code_hash, created, tries FROM codes WHERE email = ?', (e,)).fetchone() if e else None
        fresh = bool(row) and time.time() - row[2] <= float(C['CODE_MIN']) * 60 and row[3] < int(C['CODE_TRIES'])
        good = fresh and len(code) == 6 and code.isdigit() and hmac.compare_digest(sha(row[0] + code), row[1])
        if blocked and not good:
            # Every visitor arrives as 127.0.0.1 through the tunnel, so this counter is shared:
            # it slows guessing, but the right code always gets in.
            audit(con, ip, 'blocked', 'too many failures from this address')
            return None, 'Too many failed sign-ins. Try again later.'
        if not good:
            con.execute('INSERT INTO failures (ip, at) VALUES (?, ?)', (ip, time.time()))
            if row:
                if fresh and row[3] + 1 < int(C['CODE_TRIES']):
                    con.execute('UPDATE codes SET tries = tries + 1 WHERE email = ?', (e,))
                else:
                    con.execute('DELETE FROM codes WHERE email = ?', (e,))          # burned
                    audit(con, ip, 'code burned', e)
            audit(con, ip, 'sign-in failed', e or '(no address)')
            return None, generic
        con.execute('DELETE FROM codes WHERE email = ?', (e,))                        # single use
        audit(con, ip, 'sign-in', e)
        token = new_session(con, ip, e)
    outbox('signed-in', e, ip=ip)
    return token, ''


# ---------------------------------------------------------------- sessions
def new_session(con, ip, email):
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    t = time.time()
    con.execute('INSERT INTO sessions (token_hash, csrf, created, seen, ip, email) VALUES (?, ?, ?, ?, ?, ?)',
                (sha(token), csrf, t, t, ip, email))
    return token


def get_session(con, token):
    if not token or len(token) > 100:
        return None
    row = con.execute('SELECT token_hash, csrf, created, seen, email FROM sessions WHERE token_hash = ?',
                      (sha(token),)).fetchone()
    if not row or not row[4]:
        return None
    t = time.time()
    if t - row[3] > float(C['IDLE_MIN']) * 60 or t - row[2] > float(C['MAX_HOURS']) * 3600:
        con.execute('DELETE FROM sessions WHERE token_hash = ?', (row[0],))
        return None
    con.execute('UPDATE sessions SET seen = ? WHERE token_hash = ?', (t, row[0]))
    return {'hash': row[0], 'csrf': row[1], 'email': row[4]}


# ---------------------------------------------------------------- pages
CSS = b'''*{box-sizing:border-box}body{margin:0;font:15px/1.5 system-ui,sans-serif;background:#f6f7f9;color:#1c2330}
@media (prefers-color-scheme:dark){body{background:#12161d;color:#e3e7ee}.card{background:#1b212b!important;border-color:#2a3240!important}
th{color:#9aa6b8!important}input{background:#12161d;color:#e3e7ee;border-color:#2a3240}}
header{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:12px 16px;border-bottom:1px solid #8883}
main{max-width:1100px;margin:0 auto;padding:16px}h1{font-size:18px;margin:0}h2{font-size:15px;margin:0 0 8px}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fill,minmax(320px,1fr))}
.card{background:#fff;border:1px solid #dde1e7;border-radius:8px;padding:12px;overflow:auto}
table{border-collapse:collapse;width:100%}td,th{padding:3px 6px;text-align:left;vertical-align:top;border-bottom:1px solid #8882}
th{color:#5b6576;font-weight:500;white-space:nowrap}.bad{color:#c62828;font-weight:600}.ok{color:#2e7d32;font-weight:600}
form.login{max-width:360px;margin:10vh auto}label{display:block;margin:10px 0 4px}
input{width:100%;padding:8px;border:1px solid #c5cbd5;border-radius:6px;font:inherit}
button{margin-top:14px;padding:8px 14px;border:0;border-radius:6px;background:#2f5bd3;color:#fff;font:inherit;cursor:pointer}
.err{color:#c62828}.note{color:#067647}.muted{color:#8a94a6;font-size:13px}pre{white-space:pre-wrap;margin:0;font-size:13px}
.who{margin-left:auto;font-size:13px;color:#8a94a6}
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


def page(title, body, csrf=None, who=''):
    out = (f'<span class="who">{esc(who)}</span><form method="post" action="/logout"><input type="hidden" name="csrf" '
           f'value="{esc(csrf)}"><button>Sign out</button></form>') if csrf else ''
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" '
            f'content="width=device-width,initial-scale=1"><title>{esc(title)}</title>'
            f'<link rel="stylesheet" href="/style.css"></head><body><header><h1>{esc(title)}</h1>{out}</header>'
            f'<main>{body}</main></body></html>').encode()


def dashboard(sess):
    csrf, who = sess['csrf'], sess['email']
    try:
        with open(C['STATUS_FILE'], encoding='utf-8') as f:
            s = json.load(f)
    except (FileNotFoundError, PermissionError, ValueError) as e:
        return page('host-guard', f'<p class="err">No status yet ({esc(type(e).__name__)}). Is the '
                                  f'host-guard-export timer running?</p>', csrf, who)
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
                + '<p class="muted"><a href="/audit">Audit log</a>. Read-only: changes are made on the server.</p>', csrf, who)


def email_page(pre, msg=''):
    err = f'<p class="err">{esc(msg)}</p>' if msg else ''
    return page('host-guard sign-in', f'<form class="login" method="post" action="/login">{err}'
                f'<input type="hidden" name="csrf" value="{esc(pre)}">'
                '<label for="e">Admin email address</label><input id="e" name="email" type="email" '
                'autocomplete="email" required maxlength="254">'
                '<button>Send me a sign-in code</button>'
                '<p class="muted">A code goes to that address if it is one of this server\'s admins. No password.</p></form>')


def code_page(pre, email, msg='', err=''):
    note = f'<p class="note">{esc(msg)}</p>' if msg else ''
    bad = f'<p class="err">{esc(err)}</p>' if err else ''
    return page('host-guard sign-in', f'<form class="login" method="post" action="/login/code">{note}{bad}'
                f'<input type="hidden" name="csrf" value="{esc(pre)}">'
                f'<input type="hidden" name="email" value="{esc(email)}">'
                f'<p>Code for <b>{esc(email)}</b></p>'
                '<label for="c">6-digit code from the mail</label><input id="c" name="code" inputmode="numeric" '
                'autocomplete="one-time-code" pattern="[0-9]{6}" required maxlength="6">'
                '<button>Sign in</button><p class="muted"><a href="/login">Use another address or ask for a new code</a></p>'
                '</form>')


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
    timeout = 20                                          # a slow or stalled client is dropped

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
        raw = (self.headers.get('Content-Length') or '0').strip()
        if not raw.isdigit() or int(raw) > MAX_BODY:     # no negative, signed or huge length
            return None
        n = int(raw)
        if (self.headers.get('Content-Type') or '').split(';')[0] != 'application/x-www-form-urlencoded':
            return None
        data = urllib.parse.parse_qs(self.rfile.read(n).decode('utf-8', 'replace'), max_num_fields=10)
        return {k: v[0] for k, v in data.items()}

    def do_HEAD(self):
        self.do_GET()

    def fresh_pre(self):
        pre = secrets.token_urlsafe(24)
        return pre, [self.cookie('hg_pre', pre, 900)]

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
                pre, ck = self.fresh_pre()
                return self.send(200, email_page(pre), cookies=ck)
            if route == '/':
                return self.send(200, dashboard(sess))
            if route == '/audit':
                rows = con.execute('SELECT at, ip, event, detail FROM audit ORDER BY at DESC LIMIT 200').fetchall()
                body = '<div class="card"><table><tr><th>When</th><th>From</th><th>Event</th><th>Detail</th></tr>' + ''.join(
                    f'<tr><td>{when(a)}</td><td>{esc(i)}</td><td>{esc(e)}</td><td>{esc(d)}</td></tr>' for a, i, e, d in rows
                ) + '</table></div><p><a href="/">Back</a></p>'
                return self.send(200, page('host-guard audit log', body, sess['csrf'], sess['email']))
            return self.send(404, page('Not found', '<p>Not found. <a href="/">Back</a></p>', sess['csrf'], sess['email']))
        finally:
            con.close()

    def same_origin(self):
        """A form post must come from the panel's own page: a browser names the page's origin
        (Origin) and whether it is another site (Sec-Fetch-Site). Either one pointing elsewhere is
        refused, on top of the form token and the SameSite=Strict cookie."""
        site = self.headers.get('Sec-Fetch-Site')
        if site and site not in ('same-origin', 'none'):
            return False
        origin = self.headers.get('Origin')
        if origin is None:
            return True                                    # not sent by every client; the form token still is
        if origin == 'null':                               # what browsers send under Referrer-Policy: no-referrer;
            return site == 'same-origin'                   # then the browser's own Sec-Fetch-Site decides
        return urllib.parse.urlsplit(origin).netloc.lower() in allowed_hosts()

    def do_POST(self):
        if not self.host_ok():
            return self.send(400, b'bad host', 'text/plain')
        if not self.same_origin():
            con = db()
            try:
                audit(con, self.ip(), 'cross-site post', (self.headers.get('Origin') or '')[:80])
            finally:
                con.close()
            return self.send(403, b'cross-site request refused', 'text/plain')
        route = urllib.parse.urlsplit(self.path).path
        f = self.form()
        if f is None:
            return self.send(400, b'bad request', 'text/plain')
        con = db()
        try:
            cookies = self.cookies()
            if route in ('/login', '/login/code'):
                pre = cookies.get('hg_pre', '')
                if not pre or not hmac.compare_digest(pre.encode(), (f.get('csrf') or '').encode()):
                    audit(con, self.ip(), 'csrf', route)
                    return self.send(403, b'form expired, reload the page', 'text/plain')
                new_pre, ck = self.fresh_pre()
                email = norm(f.get('email'))
                if route == '/login':
                    ok, msg = request_code(con, self.ip(), f.get('email', ''))
                    if not ok:
                        return self.send(400, email_page(new_pre, msg), cookies=ck)
                    return self.send(200, code_page(new_pre, email, msg), cookies=ck)
                token, msg = sign_in(con, self.ip(), email, f.get('code', ''))
                if not token:
                    return self.send(401, code_page(new_pre, email, err=msg), cookies=ck)
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
                audit(con, self.ip(), 'sign-out', sess['email'])
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
def main(argv):
    if argv == ['serve']:
        srv = make_server()
        print(f'host-guard panel on http://{C["BIND"]}:{C["PORT"]}', flush=True)
        srv.serve_forever()
    elif argv and argv[0] == 'audit':
        n = int(argv[1]) if len(argv) > 1 and argv[1].isdigit() else 50
        for a, i, e, d in db().execute('SELECT at, ip, event, detail FROM audit ORDER BY at DESC LIMIT ?', (n,)):
            print(*(''.join(ch if ch.isprintable() else '?' for ch in str(x)) for x in (when(a), i, e, d)))   # no terminal escapes
    elif argv and argv[0] == 'init-admin':
        print('There is no panel password any more: the admins sign in with their email address and a code mailed '
              'to it. The admins are MAIL_TO (or PANEL_ADMINS) in /etc/host-guard/guard.conf.')
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == '__main__':
    main(sys.argv[1:])
