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
    assert mails(hg) == 2 and '[ALERT] [test-host] Disk 91% full' in text and '[RESOLVED] [test-host] Disk back' in text
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
    assert text.startswith('[CRITICAL] [test-host] 2 security warning(s)')
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
                 'edgeshell-db-x.sql.gz.gpg (30 min ago, 2000 KB, S3: yes)', 'Host watch: 1 finding(s)', 'eve',
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
    monkeypatch.setattr(hg.urllib.request, 'urlopen', lambda req, timeout=0: (seen.update(req=req), R())[1])
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
