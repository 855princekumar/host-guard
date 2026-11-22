"""Advisory sources without root or the network: the admins' own sources are https on public
hosts only (checked when added, again before each read, and on the connection actually made),
they are context and never decide anything, every change is mailed, and root applies the
dashboard's changes only for admins and only a few an hour."""
import importlib.util
import json
import os
import socket
import sys
import threading
import time
import urllib.error

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PUBLIC = '93.184.215.14'                                  # any global address; nothing connects to it here


@pytest.fixture
def hg(tmp_path, monkeypatch):
    sent = tmp_path / 'sent.txt'
    monkeypatch.setenv('HOSTGUARD_CONF', str(tmp_path / 'none.conf'))
    monkeypatch.setenv('HG_STATE_DIR', str(tmp_path / 'state'))
    monkeypatch.setenv('HG_MAIL_TO', 'ops@example.com, sec@example.com')
    catcher = tmp_path / 'catch.py'
    catcher.write_text('import sys\n'
                       f"open({str(sent)!r}, 'a', encoding='utf-8').write(sys.stdin.read())\n")
    monkeypatch.setenv('HG_NOTIFY_CMD', f'"{sys.executable}" "{catcher}"')
    monkeypatch.setenv('HG_SITE', 'test-host')
    monkeypatch.setenv('HG_CLOUD', 'other')
    monkeypatch.setenv('HG_EXPORT_FILE', str(tmp_path / 'export' / 'status.json'))
    spec = importlib.util.spec_from_file_location('hostguard', os.path.join(HERE, 'hostguard.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.SENT = sent
    return mod


@pytest.fixture
def sh(hg):
    return hg.shield_module()


def resolves_to(monkeypatch, table):
    """Make getaddrinfo answer from {host: address} (anything else does not resolve)."""
    def fake(host, port, *a, **kw):
        if host not in table:
            raise socket.gaierror('no such host')
        return [(socket.AF_INET6 if ':' in table[host] else socket.AF_INET, socket.SOCK_STREAM, 6, '', (table[host], port))]
    monkeypatch.setattr(socket, 'getaddrinfo', fake)


def mails(hg):
    return hg.SENT.read_text(encoding='utf-8') if hg.SENT.exists() else ''


@pytest.mark.parametrize('url,why', [
    ('http://news.example/feed', 'only https'),
    ('https://user:pw@news.example/feed', 'only https'),
    ('https://news.example/a b', 'spaces'),
    ('https://nowhere.example/', 'does not resolve'),
    ('https://localhost/', 'not a public address'),
    ('https://metadata.example/latest/', 'not a public address'),     # 169.254.169.254: cloud credentials
    ('https://inside.example/', 'not a public address'),               # 10.0.0.5
    ('https://v6.example/', 'not a public address'),                   # ::1
    ('https://cgnat.example/', 'not a public address'),                # 100.64.0.1: Tailscale's range
])
def test_an_admin_source_must_be_https_on_a_public_host(sh, monkeypatch, url, why):
    resolves_to(monkeypatch, {'localhost': '127.0.0.1', 'metadata.example': '169.254.169.254',
                              'inside.example': '10.0.0.5', 'v6.example': '::1', 'cgnat.example': '100.64.0.1',
                              'news.example': PUBLIC})
    assert why in sh.public_https(url)
    assert sh.public_https('https://news.example/feed') == ''


def test_sources_are_added_capped_unique_and_every_change_is_mailed(hg, sh, monkeypatch):
    resolves_to(monkeypatch, {'news.example': PUBLIC, 'blog.example': PUBLIC})
    hg.C['SOURCES_MAX'] = '2'
    st = {}
    ok, msg = sh.add_source(hg, st, 'Example News', 'https://news.example/feed', 'feed', by='ops@example.com')
    assert ok and 'never starts a fix' in msg
    assert not sh.add_source(hg, st, 'Again', 'https://news.example/feed')[0]                     # same address
    assert sh.add_source(hg, st, 'Example News', 'https://blog.example/', 'page')[0]               # same name: new id
    assert 'at most 2' in sh.add_source(hg, st, 'Third', 'https://blog.example/x')[1]
    assert not sh.add_source(hg, st, 'Bad', 'https://news.example/y', 'script')[0]
    ids = [s['id'] for s in st['extra_sources']]
    assert len(set(ids)) == 2 and ids[0] == 'example-news'
    text = mails(hg)
    assert text.count('Advisory source added: Example News') == 2 and 'ops@example.com added a context source' in text
    assert 'never starts a fix' in text
    added = [s for s in sh.all_sources(st) if s.get('added')]
    assert all(s['kind'] == 'context' for s in added)                  # an admin's source never becomes official
    assert sh.remove_source(hg, st, ids[0])[0] and 'Advisory source removed' in mails(hg)
    assert not sh.remove_source(hg, st, 'cisa-kev')[0]                 # built-in sources stay


def test_a_page_is_read_as_markdown_links_and_lines(sh):
    md = ('# Security news\n\n'
          '* [Critical nginx flaw CVE-2026-123007 lets attackers run code](https://news.example/nginx-rce)\n'
          '* [Weekly roundup](https://news.example/weekly)\n\n'
          'A remote code execution in OpenSSH was reported by researchers today.\n')
    items = sh.page_items(md, 'https://news.example/')
    assert ('Critical nginx flaw CVE-2026-123007 lets attackers run code', 'https://news.example/nginx-rce') in items
    assert ('A remote code execution in OpenSSH was reported by researchers today.', 'https://news.example/') in items


def test_context_reads_an_added_page_through_the_reader_and_rechecks_its_address(hg, sh, monkeypatch):
    resolves_to(monkeypatch, {'news.example': PUBLIC})
    st = {}
    sh.add_source(hg, st, 'Example News', 'https://news.example/', 'page')
    calls = []

    def read_page(url, public_only=False):
        calls.append((url, public_only))
        return '[Critical nginx flaw CVE-2026-123007 found](https://news.example/a)\n'
    monkeypatch.setattr(hg, 'read_page', read_page)
    monkeypatch.setattr(hg, 'get_text', lambda *a, **k: '')            # the built-in feeds: nothing
    inv = {'components': [{'name': 'nginx', 'kind': 'product', 'where': 'host'}], 'os': {}}
    found = sh.context(hg, inv, st)
    assert calls == [('https://news.example/', True)]
    assert [f['cves'] for f in found] == [['CVE-2026-123007']] and found[0]['source'] == 'Example News'
    resolves_to(monkeypatch, {'news.example': '10.1.2.3'})             # the name moved inside the network
    st['context_seen'] = {}
    calls.clear()
    assert sh.context(hg, inv, st) == [] and calls == []
    assert 'not a public address' in st['sources']['example-news']['error']


def test_the_connection_itself_must_reach_a_public_address(hg):
    srv = socket.socket()
    srv.bind(('127.0.0.1', 0))
    srv.listen(1)
    threading.Thread(target=lambda: srv.accept(), daemon=True).start()
    port = srv.getsockname()[1]
    with pytest.raises(urllib.error.URLError, match='not a public address'):
        hg.fetch(f'https://127.0.0.1:{port}/', public_only=True)
    with pytest.raises(ValueError, match='not an allowed'):
        hg.fetch(f'http://127.0.0.1:{port}/', public_only=True)
    redirect = hg._PublicRedirect()
    with pytest.raises(urllib.error.URLError, match='https only'):
        redirect.redirect_request(None, None, 302, 'Found', {}, 'http://169.254.169.254/latest/meta-data/')
    srv.close()


def test_the_reader_is_used_for_pages_and_falls_back_to_a_direct_read(hg, monkeypatch):
    got = []

    def get_text(url, timeout=60, headers=None, public_only=False):
        got.append((url, headers, public_only))
        if url.startswith('https://r.jina.ai/'):
            raise urllib.error.URLError('429 too many requests')
        return '<html><script>x()</script><h1>Title</h1><p>OpenSSH flaw &amp; fix</p></html>'
    monkeypatch.setattr(hg, 'get_text', get_text)
    hg.C.update(READER='https://r.jina.ai/', READER_KEY='jina_test_key')
    text = hg.read_page('https://news.example/', public_only=True)
    assert got[0] == ('https://r.jina.ai/https://news.example/', {'Authorization': 'Bearer jina_test_key'}, True)
    assert got[1][0] == 'https://news.example/' and got[1][2] is True
    assert 'OpenSSH flaw & fix' in text and 'x()' not in text


NGINX_PAGE = '''<html><body><h4>Security advisories</h4><ul>
<li><p>Buffer overflow in the HTTP/2 module<br>Severity: major<br>
<a href="https://mailman.nginx.org/x">Advisory</a><br><a href="https://www.cve.org/x">CVE-2026-123007</a><br>
Not vulnerable: 1.31.9+, 1.30.7+<br>Vulnerable: 1.9.5-1.31.8</p></li>
<li><p>Memory disclosure in the mp4 module<br>Severity: medium<br>
<a href="https://mailman.nginx.org/y">Advisory</a><br><a href="https://www.cve.org/y">CVE-2026-1200</a><br>
Not vulnerable: 1.31.2+, 1.30.3+<br>Vulnerable: 1.1.3-1.31.1</p></li>
</ul></body></html>'''


def test_the_vendor_page_names_the_fix_before_nvd_does(sh):
    adv = sh.parse_nginx_advisories(NGINX_PAGE)
    assert [a['cve'] for a in adv] == ['CVE-2026-123007', 'CVE-2026-1200']
    h2 = adv[0]
    assert h2['safe'] == ['1.31.9', '1.30.7'] and h2['severity'] == 'major'
    assert sh.vendor_affected('1.30.5', h2) and sh.vendor_fix('1.30.5', h2) == '1.30.7'
    assert not sh.vendor_affected('1.30.7', h2) and not sh.vendor_affected('1.32.0', h2)
    assert not sh.vendor_affected('1.30.5', adv[1])                     # 1.30.3+ fixed that one


# ---------------------------------------------------------------- dashboard changes, applied by root
def drop(hg, tmp_path, data):
    import pwd
    box = tmp_path / 'outbox'
    box.mkdir(mode=0o700, exist_ok=True)
    os.chmod(box, 0o700)
    t = time.time()
    name = f'{int(t * 1000)}-{os.urandom(8).hex()}.json'
    (box / name).write_text(json.dumps(dict(data, at=t)))
    hg.C.update(PANEL_OUTBOX=str(box), PANEL_USER=pwd.getpwuid(os.getuid()).pw_name)


def test_root_adds_a_dashboard_source_only_for_an_admin_and_exports_it(hg, tmp_path, monkeypatch):
    resolves_to(monkeypatch, {'news.example': PUBLIC})
    drop(hg, tmp_path, {'kind': 'source-add', 'email': 'evil@example.org', 'name': 'Evil', 'url': 'https://news.example/'})
    hg.panel_outbox()
    assert not hg.load('shield.json').get('extra_sources')
    drop(hg, tmp_path, {'kind': 'source-add', 'email': 'sec@example.com', 'name': 'Example News',
                        'url': 'https://news.example/', 'fmt': 'page'})
    hg.panel_outbox()
    extra = hg.load('shield.json')['extra_sources']
    assert [(s['name'], s['fmt'], s['by']) for s in extra] == [('Example News', 'page', 'sec@example.com (on the dashboard)')]
    exported = json.load(open(hg.C['EXPORT_FILE']))['sources']
    assert any(s['added'] and s['name'] == 'Example News' for s in exported)
    assert any(s['id'] == 'cisa-kev' and s['kind'] == 'official' for s in exported)


def test_root_refuses_a_dashboard_source_inside_the_network_and_says_why(hg, tmp_path, monkeypatch):
    resolves_to(monkeypatch, {'metadata.example': '169.254.169.254'})
    drop(hg, tmp_path, {'kind': 'source-add', 'email': 'sec@example.com', 'name': 'Creds',
                        'url': 'https://metadata.example/latest/meta-data/'})
    hg.panel_outbox()
    assert not hg.load('shield.json').get('extra_sources')
    text = mails(hg)
    assert 'Dashboard change not made' in text and 'not a public address' in text


def test_dashboard_source_changes_are_limited_to_ten_an_hour(hg, tmp_path, monkeypatch):
    resolves_to(monkeypatch, {f'n{i}.example': PUBLIC for i in range(14)})
    hg.C['SOURCES_MAX'] = '50'
    for i in range(14):
        drop(hg, tmp_path, {'kind': 'source-add', 'email': 'sec@example.com', 'name': f'N{i}', 'url': f'https://n{i}.example/'})
    hg.panel_outbox()
    assert len(hg.load('shield.json')['extra_sources']) == 10


def test_a_confirm_code_mail_names_the_change(hg, tmp_path):
    drop(hg, tmp_path, {'kind': 'code', 'email': 'sec@example.com', 'code': '123456', 'purpose': 'confirm',
                        'summary': 'add the feed "Example News" at https://news.example/ as an advisory source\nBcc: x@evil'})
    hg.panel_outbox()
    text = mails(hg)
    assert 'Your code to confirm a dashboard change' in text and 'Code: 123456' in text
    assert 'add the feed "Example News" at https://news.example/' in text and '\nBcc:' not in text


# ---------------------------------------------------------------- tiers
def test_an_ubuntu_record_is_matched_to_cisa_kev_through_its_upstream_cve(sh):
    d = sh._osv_summary({'id': 'UBUNTU-CVE-2026-4242', 'upstream': ['CVE-2026-4242'], 'aliases': [],
                         'severity': [{'type': 'Ubuntu', 'score': 'medium'}]})
    assert 'CVE-2026-4242' in d['aliases']
    assert sh.cve_of('UBUNTU-CVE-2026-4242') == 'CVE-2026-4242' and sh.cve_of('GHSA-xxxx') == ''


def test_without_a_fix_a_finding_is_low_unless_it_is_exploited(sh):
    assert sh.tier(9.8, False, 0.9, True, 'host', fixable=False) == 'Low'           # nothing to install yet
    assert sh.tier(None, True, None, True, 'host', fixable=False) == 'Critical'     # exploited: act anyway
    assert sh.tier(9.8, False, None, True, 'host', fixable=True) == 'Critical'
    assert sh.tier(9.8, False, None, False, 'host', fixable=True) == 'Moderate'     # installed, not running
    assert sh.tier(5.5, False, 0.2, True, 'host', fixable=True) == 'Moderate'
    assert sh.tier(5.5, False, 0.01, True, 'host', fixable=True) == 'Low'
