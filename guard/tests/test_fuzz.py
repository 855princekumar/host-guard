"""Fuzzing with random input (standard library only): every parser that reads something from
outside (replies by mail, feeds, web pages, vendor pages, the admins' source addresses) must
never raise and never approve or accept anything it should not. FUZZ_N sets the cases per
parser (CI: a few hundred on every push, many thousands every night); FUZZ_SEED repeats a run.
"""
import importlib.util
import os
import random
import sys
import time

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
N = int(os.environ.get('FUZZ_N', '300'))
SEED = int(os.environ.get('FUZZ_SEED', str(int(time.time()))))
PIECES = ['HOLD ', 'FIX ', 'REBOOT ', 'hg-', 'abcdefghijklmnopqrstuvwxyz234567', '\r\n', '\n', '> ', 'On x wrote:',
          'From: ', 'Authentication-Results: ', 'mx.google.com; ', 'dmarc=pass ', 'header.from=example.com',
          '<', '>', '"', ';', '=?utf-8?b?', '?=', '\x00', '‮', 'Content-Type: text/html', 'multipart/mixed; boundary=b',
          '--b', '<blockquote>', '<br>', '&lt;', '[x](https://a.example/)', '<item><title>', '</title><link>', '</link></item>',
          'CVE-2026-1234', '<entry>', 'https://', '127.0.0.1', '169.254.169.254', '%00', '@', ' ', 'é', '\ud800']


def rnd(r, n=40):
    return ''.join(r.choice(PIECES) if r.random() < 0.7 else chr(r.randrange(0, 0x3000)) for _ in range(r.randrange(n)))


@pytest.fixture
def hg(tmp_path, monkeypatch):
    monkeypatch.setenv('HOSTGUARD_CONF', str(tmp_path / 'none.conf'))
    monkeypatch.setenv('HG_STATE_DIR', str(tmp_path / 'state'))
    monkeypatch.setenv('HG_MAIL_TO', 'ops@example.com, sec@example.com')
    monkeypatch.setenv('HG_NOTIFY_CMD', f'"{sys.executable}" -c "import sys; sys.stdin.read()"')
    monkeypatch.setenv('HG_CLOUD', 'other')
    spec = importlib.util.spec_from_file_location('hostguard', os.path.join(HERE, 'hostguard.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.C['REPLY_ACTIONS'] = 'on'
    mod.save({'known': {'deadbeef': {'tier': 'Critical', 'status': 'open', 'name': 'openssl 3', 'where': 'host',
                                     'vuln': 'CVE-2026-1', 'plan': {'kind': 'apt'}, 'text': 'x'}}}, 'shield.json')
    return mod


def test_random_replies_never_raise_and_never_approve(hg):
    ap = hg.approvals_module()
    ap.offer_text(hg, [('hold', 'deadbeef', 'x')])
    mailed = []
    hg.mail = lambda *a, **k: mailed.append(k.get('subject', a[0] if a else '')) or True
    r = random.Random(SEED)
    for _ in range(N):
        raw = (rnd(r, 12) + '\r\n\r\n' + rnd(r, 60)).encode('utf-8', 'surrogatepass')
        verdict, _ = ap.handle(hg, raw)
        assert verdict in ('refused', 'skipped'), (SEED, raw[:200])
    assert hg.load('shield.json')['known']['deadbeef']['status'] == 'open', SEED


def test_random_feeds_pages_and_vendor_pages_never_raise(hg):
    sh = hg.shield_module()
    r = random.Random(SEED + 1)
    for _ in range(N):
        text = rnd(r, 80)
        for items in (sh.rss_items(text), sh.page_items(text, 'https://news.example/')):
            assert isinstance(items, list), SEED
        assert isinstance(sh.parse_nginx_advisories(text), list), SEED


def test_random_source_addresses_are_refused_unless_https_on_a_public_host(hg, monkeypatch):
    import socket
    sh = hg.shield_module()
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.1', 443))])
    r = random.Random(SEED + 2)
    for _ in range(N):
        url = r.choice(['https://', 'http://', '', 'https://u:p@']) + rnd(r, 8)
        assert sh.public_https(url) != '', (SEED, url)    # everything resolves inside the network here
