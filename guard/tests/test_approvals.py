"""Approvals without root, mail or the network: a reply acts only when it comes from an admin
address that the receiving mail server vouches for (DMARC pass in the topmost
Authentication-Results), names one known action with the live single-use code host-guard
mailed, and puts that line first (not in the quoted mail). A reboot needs two admins. Every
approval and refusal is logged with who and the channel (email, dashboard, console)."""
import importlib.util
import json
import os
import sys
import time

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GOOD_AR = ('mx.google.com; dkim=pass header.i=@example.com header.s=s1 header.b=abc; '
           'spf=pass smtp.mailfrom=sec@example.com; dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=example.com')


@pytest.fixture
def hg(tmp_path, monkeypatch):
    sent = tmp_path / 'sent.txt'
    monkeypatch.setenv('HOSTGUARD_CONF', str(tmp_path / 'none.conf'))
    monkeypatch.setenv('HG_STATE_DIR', str(tmp_path / 'state'))
    monkeypatch.setenv('HG_MAIL_TO', 'ops@example.com, sec@example.com')
    catcher = tmp_path / 'catch.py'
    catcher.write_text('import sys\n'
                       f"open({str(sent)!r}, 'a', encoding='utf-8').write(sys.stdin.read() + '\\n=====\\n')\n")
    monkeypatch.setenv('HG_NOTIFY_CMD', f'"{sys.executable}" "{catcher}"')
    monkeypatch.setenv('HG_SITE', 'test-host')
    monkeypatch.setenv('HG_CLOUD', 'other')
    monkeypatch.setenv('HG_EXPORT_FILE', str(tmp_path / 'export' / 'status.json'))
    spec = importlib.util.spec_from_file_location('hostguard', os.path.join(HERE, 'hostguard.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.SENT = sent
    mod.C['REPLY_ACTIONS'] = 'on'
    mod.save({'known': {'deadbeef': {'tier': 'Critical', 'status': 'open', 'name': 'openssl 3.0.2', 'where': 'host',
                                     'vuln': 'CVE-2026-1111', 'plan': {'kind': 'apt'}, 'text': 'x', 'first': time.time()}}},
             'shield.json')
    return mod


@pytest.fixture
def ap(hg):
    return hg.approvals_module()


def mails(hg):
    return hg.SENT.read_text(encoding='utf-8') if hg.SENT.exists() else ''


def reply(frm, first, ar=GOOD_AR, mid=None, quoted='', extra_ar=None):
    head = ''
    if ar is not None:
        head += f'Authentication-Results: {ar}\r\n'
    for x in extra_ar or []:
        head += f'Authentication-Results: {x}\r\n'
    return (f'{head}From: Someone <{frm}>\r\nTo: guard@example.com\r\nSubject: Re: [P1 Critical] Advisory\r\n'
            f'Message-ID: <{mid or os.urandom(6).hex()}@example.com>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n'
            f'{first}\r\n\r\nOn Mon, 23 Nov 2026 at 10:00, host-guard wrote:\r\n{quoted}\r\n').encode()


def codes(hg, ap, action='fix', target='deadbeef'):
    text = ap.offer_text(hg, [(action, target, 'openssl 3.0.2: CVE-2026-1111')])
    return next(w for w in text.split() if w.startswith('hg-'))


def log(hg):
    return hg.load('approvals.json').get('log', [])


# ---------------------------------------------------------------- offering codes
def test_no_reply_lines_when_replies_are_off(hg, ap):
    hg.C['REPLY_ACTIONS'] = 'off'
    assert ap.offer_text(hg, [('fix', 'deadbeef', 'x')]) == ''


def test_a_code_is_made_once_per_action_and_kept_until_used(hg, ap):
    a, b = codes(hg, ap), codes(hg, ap)
    assert a == b and len(a) == 29
    assert codes(hg, ap, 'hold') != a                                        # one code per action
    raw = json.dumps(hg.load('approvals.json'))
    assert a not in raw                                                      # codes are derived, never stored
    assert oct(os.stat(hg.path('approvals.key')).st_mode & 0o777) in ('0o600', '0o666')   # 0o666: Windows ignores modes


# ---------------------------------------------------------------- a genuine reply
def test_an_admin_reply_holds_the_fix_and_the_log_says_who_and_how(hg, ap):
    tok = codes(hg, ap, 'hold')
    verdict, _ = ap.handle(hg, reply('sec@example.com', f'HOLD {tok}'))
    assert verdict == 'approved'
    v = hg.load('shield.json')['known']['deadbeef']
    assert v['status'] == 'held' and 'sec@example.com (email)' in v['held_by']
    last = log(hg)[-1]
    assert (last['channel'], last['by'], last['action'], last['target']) == ('email', 'sec@example.com', 'hold', 'deadbeef')
    assert last['result'].startswith('done')
    assert 'Approved by mail: hold deadbeef (sec@example.com)' in mails(hg)


def test_a_used_code_does_not_work_again(hg, ap):
    tok = codes(hg, ap, 'hold')
    assert ap.handle(hg, reply('sec@example.com', f'HOLD {tok}'))[0] == 'approved'
    assert ap.handle(hg, reply('ops@example.com', f'HOLD {tok}'))[0] == 'refused'


def test_the_same_mail_is_read_once(hg, ap):
    tok = codes(hg, ap, 'hold')
    raw = reply('sec@example.com', f'HOLD {tok}', mid='same')
    assert ap.handle(hg, raw)[0] == 'approved'
    assert ap.handle(hg, raw) == ('skipped', 'already read')


# ---------------------------------------------------------------- forged and wrong replies
def test_a_reply_the_mail_server_did_not_vouch_for_is_refused_and_its_code_voided(hg, ap):
    tok = codes(hg, ap, 'hold')
    verdict, why = ap.handle(hg, reply('sec@example.com', f'HOLD {tok}', ar=None))
    assert verdict == 'refused' and 'Authentication-Results' in why
    assert hg.load('shield.json')['known']['deadbeef']['status'] == 'open'
    assert 'Forged approval refused' in mails(hg)
    assert ap.handle(hg, reply('sec@example.com', f'HOLD {tok}'))[0] == 'refused'     # void now, even genuine


@pytest.mark.parametrize('ar,extra', [
    ('mx.google.com; dkim=fail; spf=fail; dmarc=fail (p=NONE) header.from=example.com', None),
    ('mx.google.com; dmarc=pass header.from=evil.example', None),                        # another domain passed
    ('attacker.example; dmarc=pass header.from=example.com', None),                       # not our mail server
    ('mx.google.com; dmarc=none header.from=example.com', [GOOD_AR]),                    # a lower header lies
])
def test_only_the_top_result_of_our_mail_server_with_dmarc_pass_counts(hg, ap, ar, extra):
    tok = codes(hg, ap, 'hold')
    assert ap.handle(hg, reply('sec@example.com', f'HOLD {tok}', ar=ar, extra_ar=extra))[0] == 'refused'
    assert hg.load('shield.json')['known']['deadbeef']['status'] == 'open'


def test_a_non_admin_is_refused_and_not_answered(hg, ap):
    tok = codes(hg, ap, 'hold')
    ar = GOOD_AR.replace('example.com', 'other.example')
    assert ap.handle(hg, reply('boss@other.example', f'HOLD {tok}', ar=ar)) == ('refused', 'not an admin')
    assert 'boss@other.example' not in mails(hg)
    assert log(hg)[-1]['result'] == 'refused: not an admin address'


def test_a_code_only_in_the_quoted_mail_does_nothing(hg, ap):
    tok = codes(hg, ap, 'hold')
    verdict, _ = ap.handle(hg, reply('sec@example.com', 'Thanks, looking at it', quoted=f'> HOLD {tok}'))
    assert verdict == 'refused'
    assert hg.load('shield.json')['known']['deadbeef']['status'] == 'open'


def test_a_code_works_only_for_its_own_action(hg, ap):
    tok = codes(hg, ap, 'hold')
    assert ap.handle(hg, reply('sec@example.com', f'FIX {tok}'))[0] == 'refused'
    assert hg.load('shield.json')['known']['deadbeef']['status'] == 'open'


def test_an_expired_code_does_nothing(hg, ap):
    tok = codes(hg, ap, 'hold')
    st = hg.load('approvals.json')
    st['requests']['hold:deadbeef']['expires'] = time.time() - 1
    hg.save(st, 'approvals.json')
    assert ap.handle(hg, reply('sec@example.com', f'HOLD {tok}'))[0] == 'refused'


@pytest.mark.parametrize('line', ['rm -rf / HOLD', 'HOLD; reboot', 'REBOOT now', 'run sudo hostguard fix deadbeef'])
def test_nothing_else_in_a_reply_is_ever_run(hg, ap, line):
    codes(hg, ap, 'hold')
    assert ap.handle(hg, reply('sec@example.com', line))[0] == 'refused'


# ---------------------------------------------------------------- two admins for a reboot
def test_a_reboot_needs_two_different_admins_on_any_channel(hg, ap, monkeypatch):
    done = []
    monkeypatch.setattr(hg, 'approved_reboot', lambda by: (done.append(by), (True, 'rebooting'))[1])
    tok = codes(hg, ap, 'reboot', 'now')
    ok, msg = ap.handle(hg, reply('sec@example.com', f'REBOOT {tok}'))
    assert ok == 'approved' and 'another admin' in msg and not done
    assert 'Approval 1 of 2: reboot now' in mails(hg)
    assert ap.approve(hg, 'reboot', 'now', 'sec@example.com', 'dashboard')[0] is False      # not the same admin twice
    ok, msg = ap.approve(hg, 'reboot', 'now', 'ops@example.com', 'dashboard')
    assert ok and done == ['sec@example.com (email) and ops@example.com (dashboard)']
    assert [x['channel'] for x in log(hg)][-3:] == ['email', 'dashboard', 'dashboard']


def test_with_one_admin_a_reboot_needs_one(hg, ap):
    hg.C['MAIL_TO'] = 'sec@example.com'
    assert ap.need(hg, 'reboot') == 1 and ap.need(hg, 'hold') == 1


@pytest.mark.parametrize('action,target', [('reboot', 'deadbeef'), ('fix', 'now'), ('shell', 'deadbeef'), ('fix', '../x')])
def test_only_known_actions_and_targets(hg, ap, action, target):
    assert ap.approve(hg, action, target, 'sec@example.com', 'dashboard') == (False, 'not an action host-guard knows')


# ---------------------------------------------------------------- the dashboard and the console
def test_the_dashboard_approval_goes_through_root_only_for_admins(hg, ap, tmp_path):
    pwd = pytest.importorskip('pwd')
    box = tmp_path / 'outbox'
    box.mkdir(mode=0o700)
    os.chmod(box, 0o700)
    hg.C.update(PANEL_OUTBOX=str(box), PANEL_USER=pwd.getpwuid(os.getuid()).pw_name)
    for who in ('evil@example.org', 'sec@example.com'):
        t = time.time()
        (box / f'{int(t * 1000)}-{os.urandom(8).hex()}.json').write_text(json.dumps(
            {'kind': 'approve', 'email': who, 'verb': 'hold', 'target': 'deadbeef', 'at': t}))
        hg.panel_outbox()
        if who.startswith('evil'):
            assert hg.load('shield.json')['known']['deadbeef']['status'] == 'open'
    assert hg.load('shield.json')['known']['deadbeef']['status'] == 'held'
    assert log(hg)[-1]['channel'] == 'dashboard' and log(hg)[-1]['by'] == 'sec@example.com'
    exported = json.load(open(hg.C['EXPORT_FILE']))
    assert exported['approvals']['log'][-1]['channel'] == 'dashboard'
    assert all('nonce' not in w for w in exported['approvals']['waiting'])


def test_the_console_is_logged_too(hg, ap, monkeypatch):
    monkeypatch.setenv('SUDO_USER', 'ubuntu')
    assert hg.shield_module().cli(hg, ['hold', 'deadbeef']) == 0
    last = log(hg)[-1]
    assert (last['channel'], last['by']) == ('console', 'ubuntu on the server')
    assert 'ubuntu on the server (console) held the automatic fix' in mails(hg)


# ---------------------------------------------------------------- reading the inbox
class FakeImap:
    def __init__(self, msgs):
        self.msgs, self.seen, self.logged = msgs, set(), None

    def login(self, u, p):
        self.logged = (u, p)

    def select(self, box):
        return 'OK', [b'1']

    def uid(self, cmd, *args):
        if cmd == 'SEARCH':
            return 'OK', [b' '.join(k for k in self.msgs if k not in self.seen)]
        if cmd == 'FETCH' and args[1] == '(RFC822.SIZE)':
            return 'OK', [b'1 (UID %s RFC822.SIZE %d)' % (args[0], len(self.msgs[args[0]]))]
        if cmd == 'FETCH':
            return 'OK', [(b'1 (UID %s BODY[] {%d}' % (args[0], len(self.msgs[args[0]])), self.msgs[args[0]]), b')']
        if cmd == 'STORE':
            self.seen.add(args[0])
            return 'OK', []

    def logout(self):
        pass


def test_poll_acts_on_host_guard_replies_and_leaves_other_mail_alone(hg, ap):
    hg.C['SMTP_PASSWORD'] = 'app-password-x'
    hg.C['MAIL_FROM'] = 'guard@example.com'
    tok = codes(hg, ap, 'hold')
    im = FakeImap({b'1': b'From: a@b.example\r\nSubject: lunch\r\n\r\nhello\r\n',
                   b'2': reply('sec@example.com', f'HOLD {tok}'),
                   b'3': reply('sec@example.com', f'HOLD {tok}') + b'x' * (ap.MSG_MAX + 1)})
    assert ap.poll(hg, imap=im) == 0
    assert im.seen == {b'2'} and im.logged == ('guard@example.com', 'app-password-x')
    assert hg.load('shield.json')['known']['deadbeef']['status'] == 'held'


def test_poll_does_nothing_when_replies_are_off(hg, ap):
    hg.C['REPLY_ACTIONS'] = 'off'
    assert ap.poll(hg, imap=FakeImap({})) == 0


def test_a_mail_the_parser_cannot_read_is_refused_and_the_rest_go_on(hg, ap):
    # found by the fuzzer: the standard library's address parser raised IndexError on this
    raw = b'From: (.\r\nMessage-ID: <x@y>\r\n\r\nHOLD hg-aaaaaaaaaaaaaaaaaaaaaaaaaa\r\n'
    verdict, _ = ap.handle(hg, raw)
    assert verdict == 'refused'
    tok = codes(hg, ap, 'hold')
    assert ap.handle(hg, reply('sec@example.com', f'HOLD {tok}'))[0] == 'approved'
