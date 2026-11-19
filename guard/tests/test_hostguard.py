"""host-guard logic without root, Docker or the network: sign-in guessing is
counted per address and only on sign-in paths, a problem mails once and then
"resolved", early warning matches only what runs here and stays quiet on the
first run, replication is read right, and the daily report has every part."""
import importlib.util
import json
import os
import sys
import time

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


PROFILE = {'STACK_DIR': '/srv/app', 'DB_ENGINE': 'mariadb', 'DB_SERVICE': 'mariadb', 'DB_REPLICA': 'mariadb-lake',
           'CONTAINERS_PYTHON': 'edgeshell sensehive', 'APP_NAME': 'EdgeShell', 'HEALTH_PATH': '/healthz'}


@pytest.fixture
def hg(tmp_path, monkeypatch, request):
    sent = tmp_path / 'sent.txt'
    monkeypatch.setenv('HOSTGUARD_CONF', str(tmp_path / 'none.conf'))
    monkeypatch.setenv('HG_STATE_DIR', str(tmp_path / 'state'))
    monkeypatch.setenv('HG_MAIL_TO', 'ops@example.com')
    catcher = tmp_path / 'catch.py'
    catcher.write_text('import sys\n'
                       f"open({str(sent)!r}, 'a', encoding='utf-8').write(sys.stdin.read())\n")
    monkeypatch.setenv('HG_NOTIFY_CMD', f'"{sys.executable}" "{catcher}"')
    monkeypatch.setenv('HG_SITE', 'test-host')
    monkeypatch.setenv('HG_CLOUD', 'other')                # never ask a real metadata service
    # most tests run as the EdgeShell profile (examples/profiles/edgeshell.conf): a Compose app with
    # a MariaDB primary and replica; the test_a_plain_server_* tests run with nothing set
    if request.node.name.startswith('test_a_plain_server'):
        for k in PROFILE:
            monkeypatch.delenv('HG_' + k, raising=False)
    else:
        for k, v in PROFILE.items():
            monkeypatch.setenv('HG_' + k, v)
    spec = importlib.util.spec_from_file_location('hostguard', os.path.join(HERE, 'hostguard.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.SENT = sent
    return mod


def mails(hg):
    return hg.SENT.read_text().count('Subject: ') if hg.SENT.exists() else 0


def line(ip, path, status, t=None, method='POST'):
    t = time.strftime('%d/%b/%Y:%H:%M:%S +0000', time.gmtime(t or time.time()))
    return f'{ip} - - [{t}] "{method} {path} HTTP/1.1" {status} 512 "-" "curl/8"'


def test_a_problem_mails_once_then_resolved(hg):
    assert hg.mail('Disk 91% full', 'details', key='disk', level='alert')
    assert not hg.mail('Disk 92% full', 'details', key='disk', level='alert')      # cooldown
    hg.resolved('disk', 'Disk back under the limit')
    hg.resolved('disk', 'Disk back under the limit')                              # only once
    text = hg.SENT.read_text()
    assert mails(hg) == 2 and '[P2 Attention] Health | test-host | Disk 91% full' in text
    assert '[Resolved] Health | test-host | Disk back' in text
    log = json.load(open(os.path.join(hg.C['STATE_DIR'], 'mail-log.json')))
    assert [m['level'] for m in log['sent']] == ['alert', 'resolved']


def test_replication_is_read_from_the_replica(hg, monkeypatch):
    ok_text = 'Slave_IO_Running: Yes\n Slave_SQL_Running: Yes\n Seconds_Behind_Master: 3\n Last_Error: \n'
    monkeypatch.setattr(hg, 'compose', lambda args, timeout=120: (0, ok_text))
    assert hg.replication() == (True, 'IO Yes, SQL Yes, 3 s behind')
    bad = 'Replica_IO_Running: Yes\nReplica_SQL_Running: No\nSeconds_Behind_Source: NULL\nLast_Error: Duplicate entry\n'
    monkeypatch.setattr(hg, 'compose', lambda args, timeout=120: (0, bad))
    ok, detail = hg.replication()
    assert ok is False and 'SQL No' in detail and 'Duplicate entry' in detail
    monkeypatch.setattr(hg, 'compose', lambda args, timeout=120: (0, ''))
    assert hg.replication() == (None, 'no replication configured')


def feed_server(monkeypatch, hg, kev, usn, osv, details):
    def get_json(url, data=None, timeout=60):
        if url == hg.C['KEV_URL']:
            return kev
        if url == hg.C['USN_URL']:
            return usn
        if url == hg.C['OSV_URL']:
            return osv
        return details.get(url.rsplit('/', 1)[-1], {})
    monkeypatch.setattr(hg, 'get_json', get_json)
    monkeypatch.setattr(hg, 'installed_packages', lambda: {'openssh-server': '1:9.6p1', 'nginx': '1.24'})
    monkeypatch.setattr(hg, 'python_packages', lambda svc: {'werkzeug': '3.1.0'} if svc == 'edgeshell' else {})


def test_early_warning_baselines_then_mails_only_what_runs_here(hg, monkeypatch):
    kev = {'vulnerabilities': [{'cveID': 'CVE-2020-0001', 'vendorProject': 'OpenBSD', 'product': 'OpenSSH'}]}
    usn = {'notices': []}
    osv = {'results': [{'vulns': []}]}
    feed_server(monkeypatch, hg, kev, usn, osv, {})
    hg.feeds()
    assert 'Early warning switched on' in hg.SENT.read_text() and mails(hg) == 1   # baseline: nothing urgent
    kev['vulnerabilities'] += [
        {'cveID': 'CVE-2026-1111', 'vendorProject': 'OpenBSD', 'product': 'OpenSSH', 'shortDescription': 'auth bypass',
         'requiredAction': 'Apply updates'},
        {'cveID': 'CVE-2026-2222', 'vendorProject': 'Acme', 'product': 'Printer firmware'}]       # not on this server
    usn['notices'] = [{'id': 'USN-7000-1', 'title': 'OpenSSH vulnerabilities',
                       'release_packages': {'noble': [{'name': 'openssh-server'}]}},
                      {'id': 'USN-7001-1', 'title': 'Something else', 'release_packages': {'noble': [{'name': 'gimp'}]}}]
    osv['results'] = [{'vulns': [{'id': 'GHSA-xxxx-yyyy-zzzz'}]}]
    feed_server(monkeypatch, hg, kev, usn, osv, {'GHSA-xxxx-yyyy-zzzz': {
        'summary': 'Werkzeug debugger RCE', 'aliases': ['CVE-2026-3333'],
        'affected': [{'ranges': [{'events': [{'introduced': '0'}, {'fixed': '3.1.4'}]}]}]}})
    hg.feeds()
    text = hg.SENT.read_text().split('Subject: ')[-1]
    assert text.startswith('[P1 Critical] Advisory | test-host | 2 security warning(s)')
    assert 'CVE-2026-1111' in text and 'CVE-2026-2222' not in text
    assert 'USN-7000-1' in text and 'USN-7001-1' not in text
    assert 'werkzeug 3.1.0 has GHSA-xxxx-yyyy-zzzz (CVE-2026-3333)' in text and 'fixed in: 3.1.4' in text
    hg.feeds()
    assert mails(hg) == 2                                   # nothing new: no mail


def test_the_daily_report_has_every_part(hg, monkeypatch):
    monkeypatch.setattr(hg, 'containers', lambda: [{'service': 'edgeshell', 'status': 'Up 3 days (healthy)',
                                                    'state': 'running', 'health': 'healthy', 'image': 'x'}])
    monkeypatch.setattr(hg, 'replication', lambda: (True, 'IO Yes, SQL Yes, 0 s behind'))
    monkeypatch.setattr(hg, 'api', lambda p: {'/status': {'version': '1.19.0', 'nodes': {'online': 5, 'total': 6}},
                                              '/fleet/summary': {'fleet': {}, 'categories': [
                                                  {'name': 'Pi Nodes', 'online': 5, 'total': 6, 'availability_percent': 83.3}]},
                                              '/alerts': {'summary': {'critical': 1, 'warning': 2, 'nodes': 2}}}[p])
    monkeypatch.setattr(hg, 'sh', lambda cmd, timeout=120, input=None: (0, '0'))
    s = hg.load()
    s['backup'] = {'at': time.time() - 1800, 'name': 'edgeshell-db-x.sql.gz.gpg', 'bytes': 2048000, 's3': True}
    s['findings'] = [{'at': time.time(), 'text': 'New account that can log in: "eve"'}]
    hg.save(s)
    text = hg.report_text()
    for part in ('== Memory', '== Containers', 'edgeshell       Up 3 days (healthy)', 'Version 1.19.0, nodes online 5 of 6',
                 'Pi Nodes', 'Open alerts: 1 critical, 2 warning on 2 node(s)', '== Database replica', 'IO Yes',
                 'edgeshell-db-x.sql.gz.gpg (30 min ago, 2000 KB, off-site copy: s3)', 'Host watch: 1 finding(s)', 'eve',
                 '== Early warning', '== Updates', '== Last weekly scan', '== At a glance'):
        assert part in text, part
    glance = text.split('== At a glance')[1].split('\n\n')[0]
    assert 'Containers' in glance and 'EdgeShell' in glance and 'ATTENTION' in glance   # 1 critical node alert
    assert 'Intrusion watch' in glance and '1 finding(s)' in glance


def test_s3_requests_are_signed_like_aws(hg, monkeypatch):
    """SigV4 against the documented AWS example key (no network)."""
    seen = {}

    class R:
        status = 200
        headers = {}

        def read(self):
            return b''

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    monkeypatch.setattr(hg.urllib.request, 'urlopen', lambda req, timeout=0, **kw: (seen.update(req=req), R())[1])
    hg.C.update(S3_BUCKET='backups', S3_ENDPOINT='http://127.0.0.1:4566', AWS_REGION='us-east-1',
                AWS_ACCESS_KEY_ID='AKIDEXAMPLE', AWS_SECRET_ACCESS_KEY='wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY')
    st, _, _ = hg.s3('PUT', 'edgeshell-db/x.gpg', b'hello', {'x-amz-checksum-sha256': 'abc'})
    req = seen['req']
    auth = req.get_header('Authorization')
    assert st == 200 and req.full_url == 'http://127.0.0.1:4566/backups/edgeshell-db/x.gpg'
    assert auth.startswith('AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/') and '/us-east-1/s3/aws4_request' in auth
    assert 'SignedHeaders=host;x-amz-checksum-sha256;x-amz-content-sha256;x-amz-date' in auth
    assert len(auth.rsplit('Signature=', 1)[1]) == 64


def test_fail2ban_bans_are_read_and_new_ones_mailed_once(hg, monkeypatch):
    status = {'sshd': 'Status for the jail: sshd\n|- Filter\n|  |- Currently failed:\t0\n`- Actions\n'
                      '   |- Currently banned:\t1\n   |- Total banned:\t7\n   `- Banned IP list:\t203.0.113.9\n',
              'nginx-limit-req': 'Status\n   |- Currently banned:\t0\n   |- Total banned:\t2\n   `- Banned IP list:\t\n'}
    real = hg.sh

    def sh(cmd, timeout=120, input=None):
        if not cmd.startswith('fail2ban-client'):
            return real(cmd, timeout, input)                   # the mail command
        jail = cmd.split()[-1]
        return (0, status[jail]) if jail in status else (255, 'no such jail')
    monkeypatch.setattr(hg, 'sh', sh)
    jails = hg.fail2ban()
    assert jails == {'sshd': {'now': 1, 'total': 7, 'ips': ['203.0.113.9']},
                     'nginx-limit-req': {'now': 0, 'total': 2, 'ips': []}}
    assert hg.new_bans() == {} and mails(hg) == 0                      # first check: the baseline
    status['nginx-limit-req'] = status['nginx-limit-req'].replace('Banned IP list:\t', 'Banned IP list:\t198.51.100.4 ')
    assert hg.new_bans() == {'nginx-limit-req': ['198.51.100.4']}
    assert hg.new_bans() == {}                                       # the same ban: no second mail
    text = hg.SENT.read_text()
    assert mails(hg) == 1 and '198.51.100.4: flooding the sign-in pages (nginx-limit-req)' in text


def test_early_warning_words_match_whole_words(hg):
    assert hg.KEV_WORDS.search('openbsd openssh') and hg.KEV_WORDS.search('Linux Kernel')
    assert not hg.KEV_WORDS.search('digital signage player') and not hg.KEV_WORDS.search('Gitea')


PRICES = {
    'ec2': {'manifest': {'hawkFilePublicationDate': '2026-11-10T17:38:52Z'}, 'regions': {'Asia Pacific (Mumbai)': {
        'a': {'Instance Type': 't3.medium', 'price': '0.0448', 'vCPU': '2', 'Memory': '4 GiB'},
        'b': {'Instance Type': 't3.small', 'price': '0.0224', 'vCPU': '2', 'Memory': '2 GiB'},
        'c': {'Instance Type': 't4g.medium', 'price': '0.0224', 'vCPU': '2', 'Memory': '4 GiB'}}}},
    'ebs': {'regions': {'Asia Pacific (Mumbai)': {'Storage General Purpose gp3 GB Mo': {'price': '0.0912'}}}},
    'transfer': {'regions': {'Asia Pacific (Mumbai)': {'DataTransfer External Outbound Next 10 TB': {'price': '0.1093'}}}},
    'vpc': {'regions': {'Asia Pacific (Mumbai)': {'Hourly charge for In use Public IPv4 Addresses per Hrs': {'price': '0.005'}}}},
    's3': {'regions': {'Asia Pacific (Mumbai)': {'Standard Storage First 50 TB per GB Mo': {'price': '0.025'}}}},
    'lightsail': {'regions': {'Asia Pacific (Mumbai)': {
        'Lightsail Instance Bundle 4GB Linux 80GB Storage 2 vCPU 4GB Memory 2TB Quota': {'price': '0.03225'},
        'Lightsail Instance Bundle 4GB IPv6 Linux 80GB Storage 2 vCPU 4GB Memory 2TB Quota': {'price': '0.0268'}}}},
}


def test_running_cost_from_published_prices_and_measured_usage(hg, monkeypatch):
    def get_json(url, data=None, timeout=60):
        for k, rel in (('ec2', 'ec2-ondemand'), ('ebs', 'ebs.json'), ('transfer', 'datatransfer'), ('vpc', 'vpc.json'),
                       ('s3', 's3.json'), ('lightsail', 'lightsail.json')):
            if rel in url:
                return PRICES[k]
        raise AssertionError(url)
    monkeypatch.setattr(hg, 'get_json', get_json)
    monkeypatch.setattr(hg, 'imds', lambda p: None)
    hg.C.update(INSTANCE_TYPE='t3.medium', AWS_REGION='ap-south-1', EBS_GB='30', PUBLIC_IPV4='yes', USD_INR='88',
                S3_BUCKET='b', S3_RETENTION_DAYS='30')
    s = hg.load()
    s['backup'] = {'bytes': 200_000_000}                       # 0.2 GB a day, 30 kept: 6 GB in S3
    hg.save(s)
    t0 = time.time() - 12 * 3600
    u = {'mem_total_mb': 4000, 'samples': [
        {'t': t0, 'cpu': 10.0, 'mem': 30.0, 'rx': 0, 'tx': 0, 'disk_gb': 12.0,
         'svc': {'edgeshell': [6.0, 600.0], 'mariadb': [2.0, 400.0], 'nginx': [0.0, 0.0]}},
        {'t': t0 + 6 * 3600, 'cpu': 30.0, 'mem': 35.0, 'rx': 0, 'tx': 500_000_000, 'disk_gb': 12.0,
         'svc': {'edgeshell': [6.0, 600.0], 'mariadb': [2.0, 400.0], 'nginx': [0.0, 0.0]}},
        {'t': t0 + 12 * 3600, 'cpu': 20.0, 'mem': 32.0, 'rx': 0, 'tx': 1_000_000_000, 'disk_gb': 12.0,
         'svc': {'edgeshell': [6.0, 600.0], 'mariadb': [2.0, 400.0], 'nginx': [0.0, 0.0]}}]}
    hg.save(u, 'usage.json')
    e = hg.cost_estimate()
    assert e['live_prices'] and e['spec'] == {'price': 0.0448, 'vcpu': 2, 'mem_gb': 4.0}
    assert e['lines'] == {'instance': 32.7, 'disk (EBS gp3)': 2.74, 'public IPv4': 3.65,
                          'internet egress': round(2.0 * 30.4 * 0.1093, 2), 'backups (S3)': 0.15}   # 1 GB in 12 h: 2 GB a day
    assert e['month'] == round(sum(e['lines'].values()), 2) and e['use']['cpu_peak'] == 30.0
    assert [k for k, _ in e['per_service']] == ['edgeshell', 'mariadb', 'nginx']
    assert abs(sum(v for _, v in e['per_service']) - (32.7 + 2.74)) < 0.05
    ideas = ' '.join(e['ideas'])
    assert 'Graviton t4g.medium' in ideas and '$16.35' in ideas and 'Lightsail 4 GB plan' in ideas and '$23.54' in ideas
    assert 'Smaller' not in ideas                              # peak memory 1.4 GB of 4: not under half... 35% of 4 GB
    text, _ = hg.cost_text(nodes=50)
    assert 'AWS list prices published 2026-11-10' in text and 'Per managed node: $' in text and '(Rs ' in text


def test_secrets_come_only_from_the_env_file(hg, tmp_path, monkeypatch, capsys):
    conf, env = tmp_path / 'guard.conf', tmp_path / '.env'
    conf.write_text('MAIL_TO=ops@example.com\nBACKUP_PASSPHRASE=in-the-wrong-file\nDISK_WARN=70\n')
    env.write_text('BACKUP_PASSPHRASE=from-env\nEDGESHELL_KEY=esk_x\n')
    monkeypatch.setattr(hg, 'CONF', str(conf))
    monkeypatch.delenv('HG_MAIL_TO', raising=False)
    monkeypatch.setenv('HG_ENV_FILE', str(env))
    c = hg.conf()
    assert c['BACKUP_PASSPHRASE'] == 'from-env' and c['EDGESHELL_KEY'] == 'esk_x' and c['DISK_WARN'] == '70'
    assert 'belongs in the .env file' in capsys.readouterr().err


def test_mail_goes_to_every_admin_and_nothing_reaches_the_shell(hg, tmp_path, monkeypatch):
    args = tmp_path / 'args.txt'
    catcher = tmp_path / 'catch_args.py'
    catcher.write_text('import sys, json\n'
                       f"open({str(args)!r}, 'w').write(json.dumps(sys.argv[1:]))\n"
                       f"open({str(hg.SENT)!r}, 'a', encoding='utf-8').write(sys.stdin.read())\n")
    monkeypatch.setitem(hg.C, 'NOTIFY_CMD', f'"{sys.executable}" "{catcher}"')
    monkeypatch.setitem(hg.C, 'MAIL_TO', 'ops@example.com, Admin2@example.org ops@example.com;rm -rf x,$(id)@a.b')
    assert hg.recipients() == ['ops@example.com', 'Admin2@example.org']
    assert hg.mail('Report', 'body')
    assert json.loads(args.read_text()) == ['ops@example.com', 'Admin2@example.org']
    text = hg.SENT.read_text()
    assert 'To: ops@example.com, Admin2@example.org\n' in text and '<ops@example.com>' in text


def test_no_valid_recipient_sends_nothing(hg, monkeypatch):
    monkeypatch.setitem(hg.C, 'MAIL_TO', 'not-an-address, ;touch /tmp/x')
    assert hg.recipients() == [] and not hg.mail('Report', 'body') and mails(hg) == 0


def test_replication_with_empty_fields_as_mariadb_prints_them(hg, monkeypatch):
    # Production output: an empty Last_Error is followed by Skip_Counter, and an
    # empty Master_SSL_Key by Seconds_Behind_Master. Empty must stay empty.
    text = ('*************************** 1. row ***************************\n'
            '                Slave_IO_State: Waiting for master to send event\n'
            '              Slave_IO_Running: Yes\n'
            '             Slave_SQL_Running: Yes\n'
            '                    Last_Error: \n'
            '                  Skip_Counter: 0\n'
            '                Master_SSL_Key: \n'
            '         Seconds_Behind_Master: 0\n'
            '                Last_SQL_Error: \n')
    monkeypatch.setattr(hg, 'compose', lambda args, timeout=120: (0, text))
    assert hg.replication() == (True, 'IO Yes, SQL Yes, 0 s behind')


def test_two_runs_saving_together_keep_both_results(hg):
    # health and watch start at the same moment: both read, then each saves its own key
    health_view, watch_view = hg.load(), None
    watch_view = hg.load()
    health_view['health'] = {'at': 1, 'problems': 0}
    hg._LOADED['state.json'] = {}
    hg.save(health_view)
    hg._LOADED['state.json'] = {}
    watch_view['watch'] = {'at': 2, 'alerts': 0}
    hg.save(watch_view)
    s = hg.load()
    assert s['health'] == {'at': 1, 'problems': 0} and s['watch'] == {'at': 2, 'alerts': 0}
    s.pop('watch')
    hg.save(s)                                   # a key this run removed is removed
    assert 'watch' not in hg.load() and 'health' in hg.load()


def test_mails_are_html_with_a_text_fallback_and_escape_everything(hg):
    import base64 as b64
    body = ('Server: test-host\n\n== At a glance\n'
            '  Backups           OK         last 1 h ago\n'
            '  Intrusion watch   ATTENTION  1 finding(s)\n\n'
            '== Findings\n  <script>alert(1)</script> in /tmp/x\n'
            'Root disk used: 20%')
    assert hg.mail('Daily report\nBcc: evil@example.com', body)          # a newline cannot add a header
    raw = hg.SENT.read_text()
    headers = raw.split('\n\n')[0]
    assert raw.count('Subject: ') == 1 and '\nBcc:' not in headers
    assert 'multipart/alternative' in raw and 'Content-Type: text/plain' in raw and 'Content-Type: text/html' in raw
    assert 'Intrusion watch   ATTENTION' in raw                            # the plain text is there as it was
    page = b64.b64decode(raw.split('Content-Transfer-Encoding: base64\n\n')[1].split('\n--')[0]).decode()
    assert '<script>' not in page and '&lt;script&gt;alert(1)&lt;/script&gt;' in page
    assert '<h3' in page and 'At a glance' in page and '<li' in page and '>Root disk used<' in page
    assert 'ATTENTION</span>' in page and 'OK</span>' in page and 'For information' in page


def test_export_has_the_status_and_no_secret(hg, tmp_path, monkeypatch):
    target = tmp_path / 'panel' / 'status.json'
    monkeypatch.setitem(hg.C, 'EXPORT_FILE', str(target))
    monkeypatch.setitem(hg.C, 'EXPORT_GROUP', '')
    monkeypatch.setitem(hg.C, 'SMTP_PASSWORD', 'abcdefghijklmnop')
    hg.save({'health': {'at': 1, 'problems': 0}, 'backup': {'note': 'used abcdefghijklmnop', 'api_token': 'x'}})
    hg.mail('Disk 91% full', 'details', key='disk', level='alert')
    hg.export()
    data = json.loads(target.read_text())
    assert data['health'] == {'at': 1, 'problems': 0} and data['site'] == 'test-host'
    assert data['open_problems'][0]['key'] == 'disk' and data['mails'][-1]['level'] == 'alert'
    text = target.read_text()
    assert 'abcdefghijklmnop' not in text and 'api_token' not in text and '[hidden]' in text


def test_a_plain_server_has_no_app_checks_and_no_false_alarms(hg, monkeypatch):
    # a VPS with no Docker app, no domain and no database: only host checks run
    monkeypatch.setattr(hg, 'sh', lambda cmd, timeout=120, input=None: (0, ''))
    monkeypatch.setattr(hg, 'mem_free_pct', lambda: 60)
    monkeypatch.setattr(hg, 'disk_pct', lambda p='/': 30)
    keys = [c[0] for c in hg.checks()]
    assert 'containers' not in keys and 'https' not in keys and 'replication' not in keys and 'backup' not in keys
    assert not any(bad for _, bad, _, _ in hg.checks())
    assert hg.replication() == (None, 'not configured') and hg.dump_command() == (None, None)
    monkeypatch.setattr(hg, 'fail2ban', lambda: {})
    text = hg.report_text()
    assert '== Containers' not in text and '== EdgeShell' not in text and '== Database replica' not in text


def test_a_plain_server_backs_up_and_restore_tests_any_command(hg, tmp_path, monkeypatch):
    import shutil as sh_
    if not sh_.which('gpg') or not sh_.which('gzip') or not sh_.which('sh') or os.name == 'nt':
        pytest.skip('needs gpg, gzip and a POSIX shell')
    monkeypatch.setitem(hg.C, 'BACKUP_CMD', "printf 'hello from the app'")
    monkeypatch.setitem(hg.C, 'BACKUP_MIN_BYTES', '1')
    monkeypatch.setitem(hg.C, 'BACKUP_PASSPHRASE', 'test-passphrase-123')
    monkeypatch.setitem(hg.C, 'BACKUP_DIR', str(tmp_path / 'b'))
    monkeypatch.setenv('GNUPGHOME', str(tmp_path / 'gnupg'))
    os.makedirs(tmp_path / 'gnupg', mode=0o700)
    hg.backup()
    s = hg.load()
    assert s['backup']['name'].startswith('backup-') and s['backup']['name'].endswith('.gz.gpg')
    hg.restore_test()
    s = hg.load()
    assert s['restore_test']['ok'] and 'KB after unpacking' in s['restore_test']['tables'][0]
    assert 'Restore test passed' in hg.SENT.read_text()


def test_a_plain_server_dump_commands_for_each_database(hg, monkeypatch):
    monkeypatch.setitem(hg.C, 'DB_ENGINE', 'postgres')
    assert hg.dump_command() == ('sudo -u postgres pg_dumpall', 'sql.gz')
    monkeypatch.setitem(hg.C, 'STACK_DIR', '/srv/my app')
    monkeypatch.setitem(hg.C, 'DB_SERVICE', 'db')
    cmd, _ = hg.dump_command()
    assert cmd.startswith("docker compose --project-directory '/srv/my app' exec -T db pg_dumpall")
    monkeypatch.setitem(hg.C, 'DB_ENGINE', 'mariadb')
    assert 'mariadb-dump' in hg.dump_command()[0]
    monkeypatch.setitem(hg.C, 'BACKUP_CMD', 'tar -cf - /srv/data')
    assert hg.dump_command() == ('tar -cf - /srv/data', 'gz')


def test_every_profile_uses_only_known_settings(hg):
    import glob as g
    profiles = g.glob(os.path.join(HERE, '..', 'examples', 'profiles', '*.conf'))
    assert len(profiles) >= 4
    for p in profiles:
        for k in hg.read_kv(p):
            assert k in hg.DEFAULTS and k not in hg.SECRETS, f'{os.path.basename(p)}: {k}'


def fake_proc(tmp_path, procs):
    proc = tmp_path / 'proc'
    for pid, cmdline in procs.items():
        (proc / str(pid)).mkdir(parents=True)
        (proc / str(pid) / 'cmdline').write_bytes(cmdline.replace(' ', '\0').encode() + b'\0')
        (proc / str(pid) / 'comm').write_text(cmdline.split()[0].split('/')[-1][:15])
    return proc


def test_a_second_root_account_is_locked_without_killing_root_processes(hg, tmp_path, monkeypatch):
    """Red-team HOST-1: pkill -u NAME on a UID 0 account kills every root process (sshd, Docker,
    the web server, host-guard itself). Only that account's own SSH logins may end."""
    passwd = tmp_path / 'passwd'
    passwd.write_text('root:x:0:0:root:/root:/bin/bash\nops:x:1000:1000::/home/ops:/bin/bash\n'
                      'sysbackup:x:0:0::/root:/bin/bash\n')
    proc = fake_proc(tmp_path, {1: '/sbin/init', 101: '/usr/sbin/sshd -D', 102: 'sshd: ops@pts/0',
                                103: 'sshd-session: sysbackup [priv]', 104: 'sshd: sysbackup@pts/1',
                                105: '/usr/bin/dockerd -H fd://', 106: 'sshd: sysbackup2@pts/2'})
    monkeypatch.setattr(hg, 'PASSWD', str(passwd))
    monkeypatch.setattr(hg, 'PROC', str(proc))
    real, cmds = hg.sh, []

    def sh(cmd, timeout=120, input=None):
        cmds.append(cmd)
        return real(cmd, timeout, input) if 'catch.py' in cmd else (0, '')
    monkeypatch.setattr(hg, 'sh', sh)
    hg.watch()
    assert 'usermod -L -e 1 sysbackup' in cmds
    assert not any('pkill' in c for c in cmds)
    assert sorted(c for c in cmds if c.startswith('kill')) == ['kill -9 103', 'kill -9 104']
    text = hg.SENT.read_text()
    assert '[P1 Critical] Intrusion | test-host |' in text
    assert 'Extra root (UID 0) account "sysbackup": locked; 2 of its SSH login' in text


def test_web_probe_filter_matches_after_fail2ban_cuts_the_date():
    """Red-team WEB-1: fail2ban removes the time stamp before matching, leaving [] in the line."""
    import re
    text = open(os.path.join(HERE, 'conf', 'base-hardening.sh'), encoding='utf-8').read()
    rx = re.search(r'^failregex = (.*)$', text, re.M).group(1).replace('<HOST>', r'(?P<host>\S+)')
    cut = '172.18.0.5 - - [] "GET /.env HTTP/1.1" 404 162 "-" "curl/8.5.0"'
    assert re.match(rx, cut).group('host') == '172.18.0.5'
    assert not re.match(rx, '172.18.0.5 - - [] "GET /index.html HTTP/1.1" 200 162 "-" "curl/8.5.0"')


def test_only_real_root_logins_count(hg):
    """Red-team HOST-8: with /etc/ld.so.preload set, loader warnings mention "from
    /etc/ld.so.preload"; that is not a login (it was mailed as one)."""
    journal = ("ERROR: ld.so: object '/usr/lib/x.so' from /etc/ld.so.preload cannot be preloaded: ignored.\n"
               'Accepted publickey for root from 8.8.4.4 port 50122 ssh2: ED25519 SHA256:abc\n'
               'Accepted publickey for root from 10.0.0.5 port 50123 ssh2\n'
               'Accepted publickey for root from 100.101.102.103 port 50124 ssh2\n'
               'Accepted password for root from 2606:4700:4700::1111 port 50125 ssh2\n'
               'Accepted publickey for ops from 198.51.100.7 port 50126 ssh2\n')
    assert hg.root_logins_from_internet(journal) == ['8.8.4.4', '2606:4700:4700::1111']


def test_an_upload_is_confirmed_by_every_size_and_checksum_the_store_reports(hg):
    import base64
    import hashlib
    data = b'x' * 1000
    md5 = base64.b64encode(hashlib.md5(data).digest()).decode()
    assert hg.remote_confirms({'Content-Length': '1000'}, data)                         # S3, Azure
    assert hg.remote_confirms({'x-goog-stored-content-length': '1000', 'x-goog-hash': f'crc32c=x,md5={md5}'}, data)
    assert hg.remote_confirms({'content-md5': md5}, data)                               # OCI
    assert not hg.remote_confirms({'Content-Length': '999'}, data)
    assert not hg.remote_confirms({'Content-Length': '1000', 'content-md5': 'AAAA'}, data)   # one disagrees
    assert not hg.remote_confirms({'Content-Type': 'application/octet-stream'}, data)        # nothing to check


def test_remote_urls_carry_the_object_name_before_the_signature(hg, monkeypatch):
    seen = []

    class Resp:
        status, headers = 201, {}

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b''

    def fake(req, timeout=0):
        seen.append((req.get_method(), req.full_url, dict(req.header_items())))
        return Resp()
    monkeypatch.setattr(hg.urllib.request, 'urlopen', fake)
    hg.C.update({'BACKUP_REMOTE': 'azure', 'S3_PREFIX': 'host-guard/',
                 'BACKUP_REMOTE_URL': 'https://acct.blob.core.windows.net/backups?sv=2021-08-06&sp=rcwl&sig=abc%3D'})
    hg.remote('PUT', 'db-1.sql.gz.gpg', b'data')
    method, url, headers = seen[-1]
    assert url == 'https://acct.blob.core.windows.net/backups/host-guard/db-1.sql.gz.gpg?sv=2021-08-06&sp=rcwl&sig=abc%3D'
    assert headers.get('X-ms-blob-type') == 'BlockBlob'
    hg.C.update({'BACKUP_REMOTE': 'oci-par',
                 'BACKUP_REMOTE_URL': 'https://objectstorage.ap-mumbai-1.oraclecloud.com/p/TOKEN/n/ns/b/backups/o/'})
    hg.remote('GET', 'db-1.sql.gz.gpg')
    assert seen[-1][1] == 'https://objectstorage.ap-mumbai-1.oraclecloud.com/p/TOKEN/n/ns/b/backups/o/host-guard/db-1.sql.gz.gpg'
    hg.C.update({'BACKUP_REMOTE_URL': 'file:///etc/shadow'})
    assert hg.remote('GET', 'x')[0] == 0                      # only http(s)


def test_the_cloud_is_read_from_its_own_metadata_service(hg, monkeypatch):

    answers = {
        'gcp': {'/computeMetadata/v1/instance/machine-type': ('projects/1/machineTypes/e2-medium', {'Metadata-Flavor': 'Google'}),
                '/computeMetadata/v1/instance/zone': ('projects/1/zones/asia-south1-a', {'Metadata-Flavor': 'Google'})},
        'azure': {'/metadata/instance/compute': ('{"vmSize": "Standard_B2s", "location": "centralindia"}', {})},
        'oci': {'/opc/v2/instance/': ('{"shape": "VM.Standard.E4.Flex", "canonicalRegionName": "ap-mumbai-1"}', {})},
    }
    for cloud, table in answers.items():
        def md(url, headers, timeout=1.0, table=table):
            path_ = url.split('169.254.169.254', 1)[1].split('?')[0]
            if path_ not in table:
                raise OSError('no route')
            return table[path_]
        monkeypatch.setattr(hg, '_md', md)
        monkeypatch.setattr(hg, 'imds', lambda p: None)
        hg._CLOUD.clear()
        hg.C['CLOUD'] = ''
        info = hg.cloud_info()
        assert info['cloud'] == cloud, info
    assert hg.cloud_info()['type'] == 'VM.Standard.E4.Flex' and 'Oracle Cloud' in hg.cloud_text()
    hg._CLOUD.clear()
    monkeypatch.setattr(hg, '_md', lambda *a, **k: (_ for _ in ()).throw(OSError('no metadata service')))
    assert hg.cloud_info()['cloud'] == 'other'                # bare metal or a plain VPS
    hg._CLOUD.clear()
    hg.C['CLOUD'] = 'gcp'
    assert hg.cloud_info()['cloud'] == 'gcp'                  # set by hand: no guessing, never fails


def test_off_aws_the_cost_section_says_why_instead_of_guessing(hg, monkeypatch):
    hg._CLOUD.clear()
    hg._CLOUD.update({'cloud': 'azure', 'type': 'Standard_B2s', 'region': 'centralindia'})
    monkeypatch.setattr(hg, 'price_files', lambda region: (_ for _ in ()).throw(AssertionError('AWS prices fetched')))
    text, e = hg.cost_text()
    assert 'Azure (Standard_B2s, centralindia)' in text and 'PRICE_HOUR' in text and not e['priced']


def test_every_mail_says_severity_category_and_server_and_carries_filter_headers(hg):
    hg.mail('Intrusion signs on the server', 'x', level='critical', category='Intrusion')
    hg.mail('Blocked 3 address(es)', 'x', key='ban-1', level='alert', category='Attack')
    hg.mail('Daily report: all good', 'x', level='daily', category='Daily report')
    raw = hg.SENT.read_text()
    assert 'Subject: [P1 Critical] Intrusion | test-host | Intrusion signs on the server' in raw
    assert 'Subject: [P2 Attention] Attack | test-host | Blocked 3 address(es)' in raw
    assert 'Subject: [Daily] Daily report | test-host | Daily report: all good' in raw
    assert 'List-Id: host-guard Intrusion <intrusion.test-host.host-guard>' in raw
    assert 'X-Host-Guard-Severity: P1' in raw and 'X-Host-Guard-Category: Attack' in raw
    first = raw.split('Subject: ')[1]
    assert 'X-Priority: 1' in first and 'Importance: high' in first          # only the critical one
    assert raw.count('X-Priority: 1') == 1


def test_a_flood_of_similar_mails_is_held_and_named_in_the_next_one(hg, monkeypatch):
    """An attack that trips a ban every few minutes must not bury the inbox: P2 mails of one
    category are capped an hour; a P1 mail always goes out."""
    hg.C['MAIL_MAX_PER_HOUR'] = '2'
    for i in range(5):
        hg.mail(f'Blocked address 198.51.100.{i}', 'x', key=f'ban-{i}', level='alert', category='Attack')
    assert mails(hg) == 2
    log = hg.load('mail-log.json')
    assert [h['subject'] for h in log['held']] == [f'Blocked address 198.51.100.{i}' for i in (2, 3, 4)]
    assert hg.mail('Intrusion signs on the server', 'x', level='critical', category='Attack')   # never held
    assert mails(hg) == 3
    text = hg.SENT.read_text().split('Subject: ')[-1]
    assert 'Held back in the last hour (3 similar mail(s), flood protection)' in text
    assert 'Blocked address 198.51.100.4' in text
    assert hg.load('mail-log.json')['held'] == []                         # named once, then cleared
    hg.mail('Disk 91% full', 'x', key='disk', level='alert', category='Health')
    assert mails(hg) == 4                                                 # another category: its own budget
    assert len(hg.load('mail-log.json')['held_log']) == 3                # still counted for the daily report


def test_signs_of_someone_on_the_server_are_never_held(hg):
    """Red-team HOST-9: four noisy changes must not hide the fifth (a new login account)."""
    hg.C['MAIL_MAX_PER_HOUR'] = '2'
    for i in range(4):
        assert hg.mail(f'Security files changed {i}', 'x', key=f'host-{i}', level='alert', category='Host change')
    assert hg.mail('New login account: support', 'x', key='host-9', level='alert', category='Host change')
    assert mails(hg) == 5 and not hg.load('mail-log.json').get('held')


def test_the_watch_subject_says_what_was_found(hg):
    assert hg.watch_subject(['New account that can log in: "support". If it is not yours: sudo usermod -L support',
                             'SSH key(s) added for ops (not removed: ...)\nssh-ed25519 AAAA',
                             'Security-relevant files changed (normal after updates ...):\n  /etc/crontab']) == \
        'New login account: support; SSH key added; Security files changed'


# ---------------------------------------------------------------- security audit of 0.3.0
def test_a_quarantine_copy_is_capped_and_never_follows_a_link(hg, tmp_path):
    big = tmp_path / 'xmrig'
    with open(big, 'wb') as f:
        f.truncate(5 * 1024 * 1024)                     # sparse: costs nothing to make, all of it to copy
    kept = hg.quarantine_copy(str(big), str(tmp_path / 'q1'), limit=1024 * 1024)
    assert kept.endswith('(first 1 MiB only)') and os.path.getsize(tmp_path / 'q1') == 1024 * 1024
    if hasattr(os, 'symlink') and os.name != 'nt':
        os.symlink(tmp_path / 'victim', tmp_path / 'q2')
        assert hg.quarantine_copy(str(big), str(tmp_path / 'q2')).startswith('not kept')
        assert not (tmp_path / 'victim').exists()


def test_a_user_name_cannot_forge_a_root_login(hg):
    journal = ('Invalid user Accepted x for root from 8.8.4.4 port 1 ssh2\n'
               'Connection closed by invalid user Accepted publickey for root from 8.8.8.8 port 1 ssh2 [preauth]\n'
               'Accepted publickey for root from 1.1.1.1 port 50122 ssh2: ED25519 SHA256:abc\n')
    assert hg.root_logins_from_internet(journal) == ['1.1.1.1']


def test_text_that_is_not_valid_unicode_still_mails(hg):
    assert hg.mail('Advisory \ud800 for nginx', 'a feed line with \udcff in it', category='Advisory')
    assert 'Advisory ? for nginx' in hg.SENT.read_text(encoding='utf-8', errors='replace')
    rc, text = hg.sh(f'"{sys.executable}" -c "import sys; sys.stdout.buffer.write(bytes([0xff, 0x41]))"')
    assert rc == 0 and text.endswith('A')


def test_a_held_mail_does_not_start_the_cooldown(hg):
    hg.C['MAIL_MAX_PER_HOUR'] = '1'
    assert hg.mail('Low memory: 5% free', 'x', key='memory-a', level='alert', category='Health')
    assert not hg.mail('Disk 95% full', 'x', key='disk', level='alert', category='Health')        # held
    hg.C['MAIL_MAX_PER_HOUR'] = '5'
    assert hg.mail('Disk 96% full', 'x', key='disk', level='alert', category='Health')            # not cooling down


def test_a_feed_answer_cannot_expand_without_limit(hg, monkeypatch):
    import gzip as gz
    import io as io_

    class Answer(io_.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    bomb = gz.compress(b'0' * (3 * 1024 * 1024))
    monkeypatch.setattr(hg, 'FEED_MAX', 1024 * 1024)
    monkeypatch.setattr(hg.urllib.request, 'urlopen', lambda req, timeout=60: Answer(bomb))
    with pytest.raises(ValueError, match='larger than'):
        hg.get_json('https://feed.example/kev.json')


def test_a_broken_certificate_date_or_lag_never_stops_the_health_run(hg, monkeypatch):
    hg.C['DOMAIN'] = 'example.com'
    monkeypatch.setattr(hg, 'sh', lambda cmd, timeout=120, input=None: (0, 'notAfter=Smarch 13 25:61:00 2026 GMT'))
    assert hg.cert_days() is None
    monkeypatch.setattr(hg, 'compose', lambda args, timeout=120: (0, 'Slave_IO_Running: Yes\n Slave_SQL_Running: Yes\n'
                                                                    ' Seconds_Behind_Master: soon\n'))
    assert hg.replication()[0] is False
    monkeypatch.setattr(hg, '_checks', lambda: 1 / 0)
    assert hg.checks()[0][:3] == ('health-check', True, 'A health check failed to run')


# ---------------------------------------------------------------- the panel's sign-in mails
def me():
    import pwd
    return pwd.getpwuid(os.getuid()).pw_name


def drop(box, name, data):
    os.makedirs(box, mode=0o700, exist_ok=True)
    os.chmod(box, 0o700)
    p = os.path.join(box, name)
    with open(p, 'w', encoding='utf-8') as f:
        f.write(data if isinstance(data, str) else json.dumps(data))
    return p


def sent_to(hg):
    """[(recipients line, mail text)] of what the catcher got."""
    text = hg.SENT.read_text(encoding='utf-8') if hg.SENT.exists() else ''
    return [(m.split('\n', 1)[0], m) for m in text.split('To: ')[1:]]


def test_a_sign_in_code_goes_only_to_that_admin_and_only_to_admins(hg, tmp_path):
    box = str(tmp_path / 'outbox')
    hg.C.update({'PANEL_OUTBOX': box, 'PANEL_USER': me(), 'MAIL_TO': 'a@example.com, b@example.com'})
    t = time.time()
    drop(box, f'{int(t * 1000)}-{"1" * 16}.json', {'kind': 'code', 'email': 'B@example.com', 'code': '123456', 'at': t})
    drop(box, f'{int(t * 1000) + 1}-{"2" * 16}.json', {'kind': 'code', 'email': 'evil@example.org', 'code': '654321', 'at': t})
    drop(box, f'{int(t * 1000) + 2}-{"3" * 16}.json', {'kind': 'code', 'email': 'a@example.com', 'code': '12345x', 'at': t})
    drop(box, f'{int(t * 1000) + 3}-{"4" * 16}.json', {'kind': 'code', 'email': 'a@example.com', 'code': '111111', 'at': t - 3600})
    hg.panel_outbox()
    mails = sent_to(hg)
    assert len(mails) == 1 and mails[0][0] == 'b@example.com'
    assert 'Code: 123456' in mails[0][1] and '[P3 Info] Sign-in | test-host | Your dashboard sign-in code' in mails[0][1]
    assert '654321' not in hg.SENT.read_text() and os.listdir(box) == []
    log = json.load(open(os.path.join(hg.C['STATE_DIR'], 'mail-log.json')))
    assert not any('123456' in m['subject'] for m in log['sent'])          # the code is never in a subject or a log


def test_the_outbox_follows_no_link_and_removes_everything(hg, tmp_path):
    box = str(tmp_path / 'outbox')
    secret = tmp_path / 'shadow'
    secret.write_text('root:$6$hash')
    hg.C.update({'PANEL_OUTBOX': box, 'PANEL_USER': me(), 'MAIL_TO': 'a@example.com'})
    t = int(time.time() * 1000)
    os.makedirs(box, mode=0o700)
    if os.name != 'nt':
        os.symlink(secret, os.path.join(box, f'{t}-{"a" * 16}.json'))
    drop(box, f'{t + 1}-{"b" * 16}.json', 'x' * 5000)
    drop(box, 'notes.txt', 'hello')
    os.makedirs(os.path.join(box, 'junk-dir'))
    hg.panel_outbox()
    assert os.listdir(box) == [] and not sent_to(hg) and secret.read_text() == 'root:$6$hash'


def test_codes_are_limited_even_if_the_panel_floods_the_outbox(hg, tmp_path):
    box = str(tmp_path / 'outbox')
    hg.C.update({'PANEL_OUTBOX': box, 'PANEL_USER': me(), 'MAIL_TO': 'a@example.com', 'MAIL_MAX_PER_HOUR': '1'})
    t = time.time()
    for i in range(8):
        drop(box, f'{int(t * 1000) + i}-{str(i) * 16}.json', {'kind': 'code', 'email': 'a@example.com', 'code': f'{i}' * 6, 'at': t})
    hg.panel_outbox()
    assert len(sent_to(hg)) == 5                     # 5 per address in 15 minutes; flood protection never holds them


def test_a_sign_in_is_announced_to_every_admin(hg, tmp_path):
    box = str(tmp_path / 'outbox')
    hg.C.update({'PANEL_OUTBOX': box, 'PANEL_USER': me(), 'MAIL_TO': 'a@example.com b@example.com'})
    drop(box, f'{int(time.time() * 1000)}-{"c" * 16}.json', {'kind': 'signed-in', 'email': 'b@example.com', 'at': time.time()})
    hg.panel_outbox()
    mails = sent_to(hg)
    assert len(mails) == 1 and mails[0][0] == 'a@example.com, b@example.com'
    assert 'Dashboard sign-in: b@example.com' in mails[0][1]


def test_an_outbox_swapped_for_a_link_reaches_nothing(hg, tmp_path):
    # a taken-over panel owns the outbox's parent: it can replace the outbox with a link to
    # any folder; root must neither read nor empty that folder
    victim = tmp_path / 'etc'
    (victim / 'sub').mkdir(parents=True)
    (victim / 'passwd').write_text('root:x:0:0')
    (victim / 'sub' / 'keep').write_text('1')
    os.chmod(victim, 0o700)
    box = str(tmp_path / 'outbox')
    os.symlink(victim, box)
    hg.C.update({'PANEL_OUTBOX': box, 'PANEL_USER': me(), 'MAIL_TO': 'a@example.com'})
    hg.panel_outbox()
    assert sorted(os.listdir(victim)) == ['passwd', 'sub'] and (victim / 'sub' / 'keep').exists()


def test_an_outbox_others_can_open_or_of_another_user_is_not_read(hg, tmp_path):
    box = str(tmp_path / 'outbox')
    t = time.time()
    drop(box, f'{int(t * 1000)}-{"d" * 16}.json', {'kind': 'code', 'email': 'a@example.com', 'code': '123456', 'at': t})
    os.chmod(box, 0o710)                                     # any group or other bit refuses it
    hg.C.update({'PANEL_OUTBOX': box, 'PANEL_USER': me(), 'MAIL_TO': 'a@example.com'})
    hg.panel_outbox()
    assert not sent_to(hg) and len(os.listdir(box)) == 1
    os.chmod(box, 0o700)
    hg.C['PANEL_USER'] = 'no-such-user'
    hg.panel_outbox()
    assert not sent_to(hg) and len(os.listdir(box)) == 1


def test_a_hard_link_in_the_outbox_is_not_read(hg, tmp_path):
    box = str(tmp_path / 'outbox')
    other = tmp_path / 'other.json'
    t = time.time()
    other.write_text(json.dumps({'kind': 'code', 'email': 'a@example.com', 'code': '123456', 'at': t}))
    os.makedirs(box, mode=0o700)
    os.link(other, os.path.join(box, f'{int(t * 1000)}-{"e" * 16}.json'))
    hg.C.update({'PANEL_OUTBOX': box, 'PANEL_USER': me(), 'MAIL_TO': 'a@example.com'})
    hg.panel_outbox()
    assert not sent_to(hg) and os.listdir(box) == [] and other.exists()


def test_sign_in_notices_are_limited_even_if_the_panel_floods_the_outbox(hg, tmp_path):
    box = str(tmp_path / 'outbox')
    hg.C.update({'PANEL_OUTBOX': box, 'PANEL_USER': me(), 'MAIL_TO': 'a@example.com b@example.com'})
    t = time.time()
    for i in range(12):
        drop(box, f'{int(t * 1000) + i}-{str(i % 10) * 15}{i % 10}.json',
             {'kind': 'signed-in', 'email': 'a@example.com', 'at': t})
    hg.panel_outbox()
    assert len(sent_to(hg)) == 5 and os.listdir(box) == []
