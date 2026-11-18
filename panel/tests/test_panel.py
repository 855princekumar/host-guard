"""The panel's security promises, tested against a real server on 127.0.0.1:
one admin, scrypt + TOTP, lockout, replay, CSRF, SQL injection, escaping, Host check,
headers, session expiry, and that it shows the exported status read-only."""
import http.client
import importlib.util
import json
import os
import re
import sqlite3
import threading
import time
import urllib.parse

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'          # base32 of RFC 6238's "12345678901234567890" gitleaks:allow


@pytest.fixture
def hp(tmp_path, monkeypatch):
    monkeypatch.setenv('HGP_CONF', str(tmp_path / 'none.conf'))
    spec = importlib.util.spec_from_file_location('hgpanel', os.path.join(HERE, 'hgpanel.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.C.update({'DB': str(tmp_path / 'panel.db'), 'STATUS_FILE': str(tmp_path / 'status.json'),
                  'PORT': '0', 'COOKIE_SECURE': '0'})
    con = mod.db()
    con.execute('INSERT INTO admin (id, username, pw_hash, totp_secret, created) VALUES (1, ?, ?, ?, ?)',
                ('admin', mod.hash_password('correct horse battery'), SECRET, time.time()))
    con.close()
    srv = mod.make_server()
    mod.C['PORT'] = str(srv.server_address[1])
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield mod
    srv.shutdown()


class Client:
    def __init__(self, mod, host=None):
        self.mod, self.jar = mod, {}
        self.host = host or f'127.0.0.1:{mod.C["PORT"]}'

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
        return r

    def csrf(self, path='/login'):
        return re.search(r'name="csrf" value="([^"]+)"', self.req('GET', path).text).group(1)

    def login(self, user='admin', pw='correct horse battery', code=None, step=None):
        code = code or self.mod.totp(SECRET, step if step is not None else int(time.time() // 30))
        return self.req('POST', '/login', {'csrf': self.csrf(), 'username': user, 'password': pw, 'code': code})


def test_totp_matches_rfc_6238(hp):
    assert hp.totp(SECRET, 59 // 30, digits=8) == '94287082'
    assert hp.totp(SECRET, 1111111109 // 30, digits=8) == '07081804'


def test_password_hash_is_scrypt_and_salted(hp):
    a, b = hp.hash_password('x' * 12), hp.hash_password('x' * 12)
    assert a.startswith('scrypt$') and a != b and hp.check_password('x' * 12, a) and not hp.check_password('y' * 12, a)
    assert not hp.check_password('x', 'garbage')


def test_only_one_admin_row_is_possible(hp):
    con = hp.db()
    with pytest.raises(sqlite3.IntegrityError):
        con.execute("INSERT INTO admin (id, username, pw_hash, totp_secret, created) VALUES (2, 'b', 'x', 'y', 0)")


def test_sign_in_shows_the_status_and_escapes_it(hp):
    json.dump({'site': '<script>alert(1)</script>', 'generated': time.time(), 'health': {'at': time.time(), 'problems': 0},
               'open_problems': [{'key': 'disk', 'subject': 'Disk <b>91%</b>', 'at': time.time()}],
               'mails': [{'at': time.time(), 'subject': 'Daily report', 'level': 'info'}]},
              open(hp.C['STATUS_FILE'], 'w'))
    c = Client(hp)
    r = c.login()
    assert r.status == 303 and 'hg_s' in c.jar
    page = c.req('GET', '/').text
    assert '&lt;script&gt;alert(1)&lt;/script&gt;' in page and '<script>' not in page
    assert 'Disk &lt;b&gt;91%&lt;/b&gt;' in page and '1 open problem' in page and 'Daily report' in page


def test_no_session_means_the_sign_in_page(hp):
    r = Client(hp).req('GET', '/')
    assert r.status == 200 and 'Authenticator code' in r.text and 'Open problems' not in r.text


def test_wrong_parts_get_one_message(hp):
    msgs = {Client(hp).login(pw='wrong password!').text.count('Sign-in failed'),
            Client(hp).login(code='000000').text.count('Sign-in failed'),
            Client(hp).login(user='root').text.count('Sign-in failed')}
    assert msgs == {1}


def test_sql_injection_does_not_sign_in(hp):
    for user in ("' OR 1=1 --", "admin'--", 'admin" OR "1"="1'):
        r = Client(hp).login(user=user, pw="' OR '1'='1")
        assert r.status == 401
    assert hp.db().execute('SELECT COUNT(*) FROM admin').fetchone()[0] == 1


def test_a_code_works_once(hp):
    step = int(time.time() // 30)
    assert Client(hp).login(step=step).status == 303
    assert Client(hp).login(step=step).status == 401             # replay


def test_five_failures_lock_the_account(hp):
    for _ in range(5):
        assert Client(hp).login(pw='wrong password!').status == 401
    assert Client(hp).login().status == 401                       # right password, still locked
    events = [r[0] for r in hp.db().execute('SELECT event FROM audit')]
    assert 'lockout' in events and 'locked' in events


def test_one_address_is_blocked_after_ten_failures(hp):
    hp.C['LOCK_AFTER'] = '100'
    for _ in range(10):
        Client(hp).login(user='nobody')
    assert 'Too many failed sign-ins' in Client(hp).login().text


def test_forms_need_their_csrf_token(hp):
    c = Client(hp)
    c.req('GET', '/login')
    r = c.req('POST', '/login', {'csrf': 'forged', 'username': 'admin', 'password': 'correct horse battery',
                                 'code': hp.totp(SECRET, int(time.time() // 30))})
    assert r.status == 403
    c = Client(hp)
    assert c.login().status == 303
    assert c.req('POST', '/logout', {'csrf': 'forged'}).status == 403
    token = re.search(r'name="csrf" value="([^"]+)"', c.req('GET', '/').text).group(1)
    assert c.req('POST', '/logout', {'csrf': token}).status == 303
    assert 'Authenticator code' in c.req('GET', '/').text           # signed out


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
    assert 'Authenticator code' in c.req('GET', '/').text


def test_only_the_token_hash_is_stored(hp):
    c = Client(hp)
    c.login()
    stored = [r[0] for r in hp.db().execute('SELECT token_hash FROM sessions')]
    assert c.jar['hg_s'] not in stored and hp.sha(c.jar['hg_s']) in stored


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
