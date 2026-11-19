"""The panel's security promises, tested against a real server on 127.0.0.1: sign-in by
email and a mailed code (single use, expiry, burned after wrong tries, request limits, the
same answer for every address), the outbox the root mailer reads, CSRF, cross-site posts,
SQL injection, escaping, Host check, headers, session expiry, and the read-only status."""
import http.client
import importlib.util
import json
import os
import re
import threading
import time
import urllib.parse

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ADMIN = 'ops@example.com'


@pytest.fixture
def hp(tmp_path, monkeypatch):
    monkeypatch.setenv('HGP_CONF', str(tmp_path / 'none.conf'))
    spec = importlib.util.spec_from_file_location('hgpanel', os.path.join(HERE, 'hgpanel.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.C.update({'DB': str(tmp_path / 'panel.db'), 'STATUS_FILE': str(tmp_path / 'status.json'),
                  'OUTBOX': str(tmp_path / 'outbox'), 'PORT': '0', 'COOKIE_SECURE': '0'})
    srv = mod.make_server()
    mod.C['PORT'] = str(srv.server_address[1])
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield mod
    srv.shutdown()


def outbox(hp):
    """What the panel left for the root mailer, oldest first (and emptied, as the mailer does)."""
    d = hp.C['OUTBOX']
    items = []
    for n in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        items.append(json.load(open(os.path.join(d, n), encoding='utf-8')))
        os.remove(os.path.join(d, n))
    return items


class Client:
    def __init__(self, mod, host=None):
        self.mod, self.jar = mod, {}
        self.host = host or f'127.0.0.1:{mod.C["PORT"]}'
        self.form_csrf = ''

    def req(self, method, path, form=None, headers=None):
        c = http.client.HTTPConnection('127.0.0.1', int(self.mod.C['PORT']), timeout=10)
        h = {'Host': self.host, 'Cookie': '; '.join(f'{k}={v}' for k, v in self.jar.items())}
        body = None
        if form is not None:
            body = urllib.parse.urlencode(form)
            h['Content-Type'] = 'application/x-www-form-urlencoded'
        h.update(headers or {})
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        text = r.read().decode('utf-8', 'replace')
        for sc in r.headers.get_all('Set-Cookie') or []:
            k, v = sc.split(';')[0].split('=', 1)
            if 'Max-Age=0' in sc:
                self.jar.pop(k, None)
            else:
                self.jar[k] = v
        r.text = text
        m = re.search(r'name="csrf" value="([^"]+)"', text)
        self.form_csrf = m.group(1) if m else self.form_csrf
        return r

    def ask(self, email=ADMIN):
        self.req('GET', '/login')
        return self.req('POST', '/login', {'csrf': self.form_csrf, 'email': email})

    def code(self, code, email=ADMIN):
        return self.req('POST', '/login/code', {'csrf': self.form_csrf, 'email': email, 'code': code})

    def login(self, email=ADMIN):
        self.ask(email)
        codes = [x['code'] for x in outbox(self.mod) if x['kind'] == 'code' and x['email'] == email]
        return self.code(codes[-1], email)


def test_the_sign_in_page_asks_only_for_an_address(hp):
    r = Client(hp).req('GET', '/')
    assert r.status == 200 and 'name="email"' in r.text and 'type="password"' not in r.text
    assert 'Open problems' not in r.text


def test_an_address_gets_a_code_in_the_outbox_and_the_code_signs_in_once(hp):
    c = Client(hp)
    r = c.ask()
    assert r.status == 200 and 'a code is on its way' in r.text and 'name="code"' in r.text
    items = outbox(hp)
    assert [x['kind'] for x in items] == ['code'] and re.fullmatch(r'\d{6}', items[0]['code'])
    assert c.code(items[0]['code']).status == 303 and 'hg_s' in c.jar
    assert [x['kind'] for x in outbox(hp)] == ['signed-in']                  # every admin is told
    page = c.req('GET', '/').text
    assert 'Sign out' in page and ADMIN in page
    again = Client(hp)
    again.req('GET', '/login')
    assert again.code(items[0]['code']).status == 401                        # single use


def test_the_outbox_files_are_private_and_whole(hp):
    Client(hp).ask()
    d = hp.C['OUTBOX']
    names = os.listdir(d)
    assert len(names) == 1 and re.fullmatch(r'\d{10,16}-[0-9a-f]{16}\.json', names[0])
    if os.name != 'nt':
        assert os.stat(os.path.join(d, names[0])).st_mode & 0o077 == 0


def test_only_a_hash_of_the_code_is_stored(hp):
    Client(hp).ask()
    code = outbox(hp)[0]['code']
    row = hp.db().execute('SELECT salt, code_hash FROM codes').fetchone()
    assert code not in row and row[1] == hp.sha(row[0] + code)


def test_every_address_gets_the_same_answer(hp):
    a, b = Client(hp).ask(ADMIN), Client(hp).ask('nobody@example.org')
    strip = lambda r, e: re.sub(r'value="[^"]+"', '', r.text).replace(e, 'X')      # noqa: E731
    assert a.status == b.status == 200 and strip(a, ADMIN) == strip(b, 'nobody@example.org')


def test_a_code_expires(hp):
    c = Client(hp)
    c.ask()
    code = outbox(hp)[0]['code']
    hp.db().execute('UPDATE codes SET created = created - 601')
    assert c.code(code).status == 401


def test_five_wrong_codes_burn_it(hp):
    c = Client(hp)
    c.ask()
    code = outbox(hp)[0]['code']
    for i in range(5):
        assert c.code(str((int(code) + 1 + i) % 10 ** 6).zfill(6)).status == 401
    assert c.code(code).status == 401                                         # the right one, burned
    assert 'code burned' in [r[0] for r in hp.db().execute('SELECT event FROM audit')]


def test_three_requests_per_address_in_ten_minutes(hp):
    for _ in range(5):
        assert Client(hp).ask().status == 200                                 # same answer every time
    assert len([x for x in outbox(hp) if x['kind'] == 'code']) == 3


def test_after_ten_failures_no_more_guesses_but_the_right_code_still_gets_in(hp):
    # every visitor comes through the tunnel as 127.0.0.1: the block must slow guessing
    # without letting anyone lock the real admin out
    for i in range(10):
        Client(hp).ask(f'guess{i}@example.org')
        outbox(hp)
        c = Client(hp)
        c.req('GET', '/login')
        c.code('000000', f'guess{i}@example.org')
    c = Client(hp)
    c.ask()
    code = outbox(hp)[0]['code']
    assert 'Too many failed sign-ins' in c.code('111111' if code != '111111' else '222222').text
    c.req('GET', '/login')
    c.ask()
    code = [x['code'] for x in outbox(hp) if x['kind'] == 'code'][-1]
    assert c.code(code).status == 303


def test_not_an_address_and_sql_injection(hp):
    for e in ("' OR 1=1 --", "admin'--@x", 'a@b', '<script>@x.com'):
        r = Client(hp).ask(e)
        assert r.status == 400 and 'Enter an email address' in r.text
    assert outbox(hp) == []
    c = Client(hp)
    c.ask()
    outbox(hp)
    assert c.code("1' OR '1'='1").status == 401 and 'hg_s' not in c.jar


def test_sign_in_shows_the_status_and_escapes_it(hp):
    json.dump({'site': '<script>alert(1)</script>', 'generated': time.time(), 'health': {'at': time.time(), 'problems': 0},
               'open_problems': [{'key': 'disk', 'subject': 'Disk <b>91%</b>', 'at': time.time()}],
               'mails': [{'at': time.time(), 'subject': 'Daily report', 'level': 'info'}]},
              open(hp.C['STATUS_FILE'], 'w'))
    c = Client(hp)
    assert c.login().status == 303
    page = c.req('GET', '/').text
    assert '&lt;script&gt;alert(1)&lt;/script&gt;' in page and '<script>' not in page
    assert 'Disk &lt;b&gt;91%&lt;/b&gt;' in page and '1 open problem' in page and 'Daily report' in page


def test_forms_need_their_csrf_token(hp):
    c = Client(hp)
    c.req('GET', '/login')
    assert c.req('POST', '/login', {'csrf': 'forged', 'email': ADMIN}).status == 403
    assert outbox(hp) == []
    c = Client(hp)
    assert c.login().status == 303
    assert c.req('POST', '/logout', {'csrf': 'forged'}).status == 403
    token = re.search(r'name="csrf" value="([^"]+)"', c.req('GET', '/').text).group(1)
    assert c.req('POST', '/logout', {'csrf': token}).status == 303
    assert 'name="email"' in c.req('GET', '/').text                   # signed out


def test_foreign_host_header_is_refused(hp):
    assert Client(hp, host='evil.example:80').req('GET', '/').status == 400


def test_security_headers_and_cookie_flags(hp):
    c = Client(hp)
    r = c.req('GET', '/login')
    csp = r.headers['Content-Security-Policy']
    assert "default-src 'none'" in csp and 'script' not in csp and "frame-ancestors 'none'" in csp
    assert r.headers['X-Frame-Options'] == 'DENY' and r.headers['Cache-Control'] == 'no-store'
    r = c.login()
    sc = ' '.join(r.headers.get_all('Set-Cookie'))
    assert 'HttpOnly' in sc and 'SameSite=Strict' in sc


def test_idle_sessions_expire(hp):
    c = Client(hp)
    c.login()
    hp.db().execute('UPDATE sessions SET seen = seen - 3600')
    assert 'name="email"' in c.req('GET', '/').text


def test_only_the_token_hash_is_stored(hp):
    c = Client(hp)
    c.login()
    stored = [r[0] for r in hp.db().execute('SELECT token_hash FROM sessions')]
    assert c.jar['hg_s'] not in stored and hp.sha(c.jar['hg_s']) in stored


def test_a_session_from_before_email_sign_in_is_not_accepted(hp):
    con = hp.db()
    con.execute("INSERT INTO sessions (token_hash, csrf, created, seen, ip, email) VALUES (?, 'x', ?, ?, '127.0.0.1', '')",
                (hp.sha('old-token'), time.time(), time.time()))
    c = Client(hp)
    c.jar['hg_s'] = 'old-token'
    assert 'name="email"' in c.req('GET', '/').text


def test_large_bodies_are_refused(hp):
    r = Client(hp).req('POST', '/login', headers={'Content-Type': 'application/x-www-form-urlencoded'},
                       form={'x': 'y' * 10000})
    assert r.status == 400


def test_a_remote_bind_needs_allow_remote(hp):
    hp.C.update({'BIND': '0.0.0.0', 'ALLOW_REMOTE': '0'})
    with pytest.raises(SystemExit):
        hp.make_server()


def test_a_form_post_from_another_site_is_refused(hp):
    c = Client(hp)
    assert c.login().status == 303
    token = re.search(r'name="csrf" value="([^"]+)"', c.req('GET', '/').text).group(1)
    assert c.req('POST', '/logout', {'csrf': token}, {'Origin': 'https://evil.example'}).status == 403
    assert c.req('POST', '/logout', {'csrf': token}, {'Sec-Fetch-Site': 'cross-site'}).status == 403
    assert 'Sign out' in c.req('GET', '/').text                                  # still signed in
    con = hp.db()
    assert con.execute("SELECT COUNT(*) FROM audit WHERE event = 'cross-site post'").fetchone()[0] == 2
    assert c.req('POST', '/logout', {'csrf': token}, {'Origin': f'http://127.0.0.1:{hp.C["PORT"]}',
                                                      'Sec-Fetch-Site': 'same-origin'}).status == 303


def test_a_browser_sending_origin_null_is_judged_by_sec_fetch_site(hp):
    """Chrome sends Origin: null on a same-origin form post under Referrer-Policy: no-referrer
    (found by the red team's browser stage: the admin could not sign in)."""
    c = Client(hp)
    assert c.login().status == 303
    token = re.search(r'name="csrf" value="([^"]+)"', c.req('GET', '/').text).group(1)
    assert c.req('POST', '/logout', {'csrf': token}, {'Origin': 'null'}).status == 403            # no proof
    assert c.req('POST', '/logout', {'csrf': token}, {'Origin': 'null', 'Sec-Fetch-Site': 'same-site'}).status == 403
    assert c.req('POST', '/logout', {'csrf': token}, {'Origin': 'null', 'Sec-Fetch-Site': 'same-origin'}).status == 303


def test_a_negative_or_signed_length_is_refused_before_any_body_is_read(hp):
    """Audit 0.3.0: Content-Length: -1 passed the size check and the whole stream was read."""
    import socket
    for length in ('-1', '+5', ' 99999999', '1e9'):
        s = socket.create_connection(('127.0.0.1', int(hp.C['PORT'])), timeout=10)
        s.sendall(f'POST /login HTTP/1.1\r\nHost: 127.0.0.1:{hp.C["PORT"]}\r\n'
                  f'Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {length}\r\n\r\n'.encode())
        assert s.recv(64).split(b' ')[1] in (b'400', b'403'), length
        s.close()


def test_the_audit_listing_prints_no_terminal_control_characters(hp, capsys):
    con = hp.db()
    hp.audit(con, '127.0.0.1', 'cross-site post', 'https://evil.example\x1b]0;owned\x07\x1b[2J')
    con.close()
    hp.main(['audit'])
    out = capsys.readouterr().out
    assert 'evil.example' in out
    assert '\x1b' not in out and '\x07' not in out
