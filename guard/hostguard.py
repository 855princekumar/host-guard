#!/usr/bin/env python3
"""host-guard: security, health and early warning for the server that runs the
EdgeShell stack (an EC2 with Docker). Python 3 standard library only.

    hostguard health         every 5 min: disk, memory, containers, HTTPS, certificate,
                             data lake replication, backups, pending reboot, new fail2ban
                             bans -> alert, then "resolved"
    hostguard watch          every 5 min: intrusion signs (extra root accounts, rootkit
                             preload, miners, programs in memory-only folders, root SSH from
                             the internet, changed auth and persistence files, new SSH keys)
    hostguard feeds          every 6 h: trusted sources (CISA KEV, Ubuntu notices, OSV for the
                             Python packages inside the running containers) -> early warning
    hostguard scan           weekly: Trivy on every running image, Lynis on the host
    hostguard backup         nightly: both databases dumped, encrypted (gpg AES-256), kept
                             locally and uploaded to S3 with a SHA-256 checksum
    hostguard restore-test   weekly: the newest backup from S3, decrypted and loaded into a
                             throwaway MariaDB; table and row counts reported
    hostguard patch-window   in the maintenance window: reboot for security updates only
                             after a fresh backup and with replication healthy
    hostguard cost           what the server costs to run, from AWS's published prices and
                             the measured usage: per day and month, per service, per managed
                             node, and where it could be cheaper (Graviton, smaller, Lightsail)
    hostguard report         daily: one mail with everything above and EdgeShell's fleet
    hostguard boot           after every boot: a mail, with the health check
    hostguard export         every minute (with the panel): a status file without secrets
                             for the web panel, which runs unprivileged
    hostguard test-mail | status | unlock

Bans (SSH, repeat offenders, sign-in floods, probes) are fail2ban's, set up by
EdgeShell's docker/host-hardening.sh, which install.sh runs first; host-guard
reports them. Unban: sudo fail2ban-client set <jail> unbanip <address>.

Settings: /etc/host-guard/guard.conf (KEY=VALUE, no secrets). Secrets live
only in /etc/host-guard/.env (root only): SMTP_PASSWORD (the Gmail app
password; msmtp reads it from there), BACKUP_PASSPHRASE, EDGESHELL_KEY and,
without an instance role, AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY. Nothing
here prints or mails a secret.
"""
import base64
import datetime as dt
import glob
import gzip
import hashlib
import hmac
import json
import os
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request

CONF = os.environ.get('HOSTGUARD_CONF', '/etc/host-guard/guard.conf')
DEFAULTS = {
    'MAIL_TO': '', 'MAIL_FROM': '', 'SITE': socket.gethostname(), 'DOMAIN': '',
    'EDGESHELL_DIR': '/home/ubuntu/edgeshell', 'EDGESHELL_URL': '', 'EDGESHELL_KEY': '',
    'STATE_DIR': '/var/lib/host-guard', 'NOTIFY_CMD': 'msmtp -a default',
    'EXPORT_FILE': '/var/lib/host-guard-export/status.json', 'EXPORT_GROUP': 'hgpanel',
    'DISK_WARN': '85', 'MEM_FREE_MIN': '10', 'CERT_DAYS': '14', 'LAG_WARN': '300', 'COOLDOWN_H': '6',
    'BACKUP_DIR': '/var/backups/host-guard', 'BACKUP_KEEP': '3', 'BACKUP_PASSPHRASE': '',
    'ENV_FILE': '/etc/host-guard/.env',
    'BACKUP_MAX_AGE_H': '26', 'S3_BUCKET': '', 'S3_PREFIX': 'edgeshell-db/', 'S3_ENDPOINT': '', 'AWS_REGION': 'ap-south-1',
    'AWS_ACCESS_KEY_ID': '', 'AWS_SECRET_ACCESS_KEY': '',
    'JAILS': 'sshd recidive nginx-limit-req edgeshell-probe',
    'LOCKDOWN': 'alert',            # alert | web (stop nginx on a critical intrusion sign)
    'LOGIN_USER': 'ubuntu', 'LYNIS_MIN': '65',
    'KEV_URL': 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    'USN_URL': 'https://ubuntu.com/security/notices.json?limit=30',
    'OSV_URL': 'https://api.osv.dev/v1/querybatch', 'OSV_VULN_URL': 'https://api.osv.dev/v1/vulns/',
    'CONTAINERS_PYTHON': 'edgeshell sensehive',
    # running cost: AWS's public price files (no credentials); the PRICE_* values are used
    # when they cannot be read. Mumbai list prices of 2026-11-10.
    'PRICES_URL': 'https://b0.p.awsstatic.com/pricing/2.0/meteredUnitMaps',
    'INSTANCE_TYPE': '', 'PUBLIC_IPV4': 'auto', 'EBS_GB': '', 'S3_RETENTION_DAYS': '30', 'USD_INR': '',
    'PRICE_HOUR': '', 'PRICE_EBS_GB_MONTH': '0.0912', 'PRICE_EGRESS_GB': '0.1093', 'PRICE_IPV4_HOUR': '0.005',
    'PRICE_S3_GB_MONTH': '0.025',
}
SECRETS = ('SMTP_PASSWORD', 'BACKUP_PASSPHRASE', 'EDGESHELL_KEY', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY')
REGIONS = {'ap-south-1': 'Asia Pacific (Mumbai)', 'ap-south-2': 'Asia Pacific (Hyderabad)',
           'ap-southeast-1': 'Asia Pacific (Singapore)', 'us-east-1': 'US East (N. Virginia)',
           'us-west-2': 'US West (Oregon)', 'eu-west-1': 'EU (Ireland)', 'eu-central-1': 'EU (Frankfurt)'}
KEV_WORDS = re.compile(r'\b(docker|containerd|runc|openssh|linux kernel|ubuntu|canonical|nginx|mariadb|mysql|python|'
                       r'flask|werkzeug|jinja2?|paramiko|openssl|glibc|sudo|polkit|systemd|privacyidea|mosquitto|'
                       r'tailscale|certbot|curl|git|xz)\b', re.I)
MINER = re.compile(r'(xmrig|kinsing|kdevtmpfsi|minerd|cpuminer|xmr-stak|nbminer|t-rex|lolminer|phoenixminer|kthreaddk|'
                   r'dbused)', re.I)
WATCHED = ['/etc/passwd', '/etc/shadow', '/etc/group', '/etc/sudoers', '/etc/sudoers.d/*', '/etc/ssh/sshd_config',
           '/etc/ssh/sshd_config.d/*', '/root/.ssh/authorized_keys', '/etc/crontab', '/etc/cron.d/*',
           '/var/spool/cron/crontabs/*', '/etc/systemd/system/*.service', '/etc/systemd/system/*.timer',
           '/etc/rc.local', '/etc/ld.so.preload']


# ---------------------------------------------------------------- settings and state
def read_kv(file):
    out_ = {}
    try:
        for line in open(file, encoding='utf-8'):
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                k, v = line.split('=', 1)
                out_[k.strip()] = v.strip().strip('"').strip("'")
    except (FileNotFoundError, PermissionError):
        pass
    return out_


def conf():
    """Settings from guard.conf, secrets from .env only (a secret in guard.conf is ignored)."""
    c = dict(DEFAULTS, **{k: '' for k in SECRETS})
    plain = read_kv(CONF)
    for k, v in plain.items():
        if k in SECRETS:
            print(f'{CONF}: {k} is a secret and belongs in the .env file; ignored here', file=sys.stderr)
        else:
            c[k] = v
    for k in list(DEFAULTS) + list(SECRETS):          # the environment wins (tests, one-off runs)
        if os.environ.get('HG_' + k):
            c[k] = os.environ['HG_' + k]
    secrets = read_kv(c['ENV_FILE'])
    for k in SECRETS:
        if secrets.get(k) and not os.environ.get('HG_' + k):
            c[k] = secrets[k]
    if not c['EDGESHELL_URL'] and c['DOMAIN']:
        c['EDGESHELL_URL'] = 'https://' + c['DOMAIN']
    return c


C = conf()


def path(name):
    os.makedirs(C['STATE_DIR'], exist_ok=True)
    return os.path.join(C['STATE_DIR'], name)


def load(name='state.json'):
    try:
        with open(path(name), encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return {}


def save(data, name='state.json'):
    tmp = path(name) + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=1, sort_keys=True)
    os.replace(tmp, path(name))


def sh(cmd, timeout=120, input=None):
    """Run a shell command; returns (exit code, stdout+stderr text). Never raises."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout, input=input)
        return r.returncode, (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return 124, f'timed out after {timeout}s: {cmd[:80]}'


def out(cmd, timeout=120):
    return sh(cmd, timeout)[1]


def now():
    return time.time()


def stamp(t=None):
    return dt.datetime.fromtimestamp(t or now()).strftime('%Y-%m-%d %H:%M:%S')


# ---------------------------------------------------------------- mail
EMAIL = re.compile(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')


def recipients():
    """MAIL_TO holds one address or several, separated by commas or spaces. Anything
    that is not a plain address is left out (and reported), so it never reaches a shell."""
    good = []
    for a in re.split(r'[,\s]+', C['MAIL_TO'].strip()):
        if not a:
            continue
        if not EMAIL.match(a):
            print(f'MAIL_TO: skipping {a!r}, not an email address', file=sys.stderr)
        elif a.lower() not in [g.lower() for g in good]:
            good.append(a)
    return good


def mail(subject, body, key=None, level='info'):
    """Send one mail. With a key, the same problem mails at most once per COOLDOWN_H
    hours; resolved() clears it. Returns True when a mail went out."""
    alerts = load('alerts.json')
    if key:
        last = alerts.get(key, {}).get('at', 0)
        if now() - last < float(C['COOLDOWN_H']) * 3600:
            return False
        alerts[key] = {'at': now(), 'subject': subject}
        save(alerts, 'alerts.json')
    tag = {'critical': '[CRITICAL] ', 'alert': '[ALERT] ', 'resolved': '[RESOLVED] '}.get(level, '')
    rcpts = recipients()
    to = ', '.join(rcpts)
    frm = C['MAIL_FROM'] or (rcpts[0] if rcpts else '')
    msg = (f'To: {to}\nFrom: host-guard {C["SITE"]} <{frm}>\nSubject: {tag}[{C["SITE"]}] {subject}\n'
           f'Date: {dt.datetime.now(dt.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")}\n'
           f'Content-Type: text/plain; charset=UTF-8\n\n{body}\n\n-- \nhost-guard on {C["SITE"]}'
           f'{" | " + C["EDGESHELL_URL"] if C["EDGESHELL_URL"] else ""} | {stamp()}\n')
    log = load('mail-log.json')
    log.setdefault('sent', []).append({'at': now(), 'subject': f'{tag}{subject}', 'level': level})
    log['sent'] = log['sent'][-200:]
    save(log, 'mail-log.json')
    if not rcpts:
        print(f'(no MAIL_TO) {tag}{subject}\n{body}')
        return False
    rc, text = sh(f'{C["NOTIFY_CMD"]} ' + ' '.join(shlex.quote(a) for a in rcpts), input=msg, timeout=60)
    if rc != 0:
        print(f'mail failed ({rc}): {text[:300]}', file=sys.stderr)
    return rc == 0


def resolved(key, subject, body=''):
    alerts = load('alerts.json')
    if key in alerts:
        alerts.pop(key)
        save(alerts, 'alerts.json')
        mail(subject, body or 'Back to normal.', level='resolved')


# ---------------------------------------------------------------- Docker and the EdgeShell stack
def compose(args, timeout=120):
    return sh(f'docker compose --project-directory {C["EDGESHELL_DIR"]} {args}', timeout)


def containers():
    """[{name, service, state, health, status}] of the EdgeShell stack."""
    rc, text = compose('ps -a --format json')
    rows = []
    if rc != 0:
        return rows
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith('{'):
            continue
        try:
            d = json.loads(line)
        except ValueError:
            continue
        rows.append({'name': d.get('Name'), 'service': d.get('Service'), 'state': d.get('State'),
                     'health': d.get('Health') or '', 'status': d.get('Status'), 'image': d.get('Image')})
    return rows


ONE_SHOT = {'init-data', 'lake-init', 'mfa-db-init'}


def api(path_):
    """GET from EdgeShell's API with the read-only key (daily report). None when not set up."""
    if not (C['EDGESHELL_KEY'] and C['EDGESHELL_URL']):
        return None
    ctx = ssl.create_default_context()
    if os.environ.get('HG_INSECURE_TLS'):           # the test bed's self-signed certificate
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    req = urllib.request.Request(C['EDGESHELL_URL'].rstrip('/') + '/api/v1' + path_,
                                 headers={'Authorization': 'Bearer ' + C['EDGESHELL_KEY'], 'User-Agent': 'host-guard'})
    try:
        with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
            return json.load(r)
    except Exception as e:
        return {'error': str(e)[:120]}


def replication():
    """The data lake replica's state: (ok, text)."""
    rc, text = compose("exec -T mariadb-lake sh -c 'mariadb -uroot -p\"$MARIADB_ROOT_PASSWORD\" -e \"SHOW REPLICA STATUS\\G\"'",
                       timeout=30)
    if rc != 0:
        return None, 'replica not reachable: ' + text.splitlines()[-1][:120] if text else 'replica not reachable'
    f = dict(re.findall(r'^\s*(\w+):\s*(.*)$', text, re.M))
    if not f:
        return None, 'no replication configured'
    io_ok, sql_ok = f.get('Slave_IO_Running', f.get('Replica_IO_Running')), f.get('Slave_SQL_Running', f.get('Replica_SQL_Running'))
    lag = f.get('Seconds_Behind_Master', f.get('Seconds_Behind_Source'))
    ok = io_ok == 'Yes' and sql_ok == 'Yes' and lag not in (None, 'NULL') and int(lag) <= int(C['LAG_WARN'])
    detail = f'IO {io_ok}, SQL {sql_ok}, {lag} s behind'
    if f.get('Last_Error'):
        detail += ', last error: ' + f['Last_Error'][:160]
    return ok, detail


# ---------------------------------------------------------------- health (every 5 min)
def mem_free_pct():
    m = {}
    for line in open('/proc/meminfo'):
        k, v = line.split(':', 1)
        m[k] = int(v.split()[0])
    return int(m.get('MemAvailable', 0) * 100 / max(1, m.get('MemTotal', 1)))


def disk_pct(p='/'):
    s = shutil.disk_usage(p)
    return int(s.used * 100 / s.total)


def cert_days():
    if not C['DOMAIN']:
        return None
    rc, text = sh(f'echo | timeout 15 openssl s_client -connect 127.0.0.1:443 -servername {C["DOMAIN"]} 2>/dev/null '
                  f'| openssl x509 -noout -enddate', 30)
    m = re.search(r'notAfter=(.*)', text)
    if not m:
        return None
    end = dt.datetime.strptime(m.group(1).strip().replace('  ', ' '), '%b %d %H:%M:%S %Y %Z')
    return (end - dt.datetime.utcnow()).days


def https_code():
    target = C['DOMAIN'] or 'localhost'
    rc, text = sh(f'curl -sk -o /dev/null -w "%{{http_code}}" --max-time 20 --resolve {target}:443:127.0.0.1 '
                  f'https://{target}/healthz', 30)
    return text.strip()[-3:] if rc == 0 else '000'


def checks():
    """Each check: (key, problem or None, subject, details)."""
    res = []
    free = mem_free_pct()
    res.append(('memory', free < int(C['MEM_FREE_MIN']), f'Low memory: {free}% free',
                out('free -h') + '\n\nTop memory users:\n' + out('ps -eo pid,comm,%mem,rss --sort=-rss | head -8')))
    d = disk_pct()
    res.append(('disk', d >= int(C['DISK_WARN']), f'Disk {d}% full',
                out('df -h /') + '\n\nDocker:\n' + out('docker system df') +
                '\n\nFree space: sudo docker image prune -af (old images); check data/ and backups.'))
    rows = containers()
    bad = [r for r in rows if r['service'] not in ONE_SHOT and (r['state'] != 'running' or r['health'] == 'unhealthy')]
    if rows:
        res.append(('containers', bool(bad), 'Container down: ' + ', '.join(r['service'] for r in bad),
                    '\n'.join(f'{r["service"]:<14} {r["status"]}' for r in rows)))
    else:
        res.append(('containers', True, 'The EdgeShell stack is not running', compose('ps -a')[1][:2000]))
    code = https_code()
    res.append(('https', code != '200', f'EdgeShell not answering (HTTP {code})',
                f'https://{C["DOMAIN"] or "localhost"}/healthz answered {code} from the server itself.'))
    days = cert_days()
    if days is not None:
        res.append(('cert', days < int(C['CERT_DAYS']), f'TLS certificate expires in {days} days',
                    'certbot renews it about 30 days before expiry; check: docker compose logs certbot'))
    ok, detail = replication()
    if ok is not None:
        res.append(('replication', not ok, 'Data lake replication: ' + detail,
                    'The lake keeps every metric; while it is behind, hot retention purges wait.'))
    if C['S3_BUCKET']:
        last = load().get('backup', {}).get('at', 0)
        age = (now() - last) / 3600 if last else None
        res.append(('backup', age is None or age > float(C['BACKUP_MAX_AGE_H']),
                    'No recent backup' + (f' ({age:.0f} h old)' if age else ''),
                    'Run: sudo hostguard backup, and check: journalctl -u host-guard-backup'))
    if os.path.exists('/var/run/reboot-required'):
        pk = open('/var/run/reboot-required.pkgs').read().split() if os.path.exists('/var/run/reboot-required.pkgs') else []
        res.append(('reboot', True, 'Reboot needed after security updates',
                    'Packages: ' + ' '.join(pk[:20]) + '\nIt happens in the maintenance window after a backup.'))
    else:
        res.append(('reboot', False, '', ''))
    return res


def health():
    problems = 0
    for key, bad, subject, body in checks():
        if bad:
            problems += 1
            mail(subject, body, key=key, level='alert')
        else:
            resolved(key, {'memory': 'Memory back to normal', 'disk': 'Disk back under the limit',
                           'containers': 'Every container running again', 'https': 'EdgeShell answering again',
                           'cert': 'TLS certificate renewed', 'replication': 'Data lake replication healthy again',
                           'backup': 'Backups fresh again', 'reboot': 'Rebooted, no restart pending'}.get(key, key + ' ok'))
    fresh = new_bans()
    try:
        sample_usage()
    except Exception as e:                       # cost figures must never stop the health check
        print(f'usage sample failed: {e}', file=sys.stderr)
    s = load()
    s['health'] = {'at': now(), 'problems': problems}
    save(s)
    print(f'health: {problems} problem(s), {sum(len(v) for v in fresh.values())} new ban(s)')
    return problems


# ---------------------------------------------------------------- fail2ban (the bans are fail2ban's)
def fail2ban():
    """{jail: {'now': n, 'total': n, 'ips': [...]}} for the jails that exist."""
    jails = {}
    for jail in C['JAILS'].split():
        rc, text = sh(f'fail2ban-client status {jail}', 15)
        if rc != 0:
            continue
        def num(label):
            m = re.search(label + r':\s*(\d+)', text)
            return int(m.group(1)) if m else 0
        m = re.search(r'Banned IP list:\s*(.*)', text)
        jails[jail] = {'now': num('Currently banned'), 'total': num('Total banned'),
                       'ips': m.group(1).split() if m else []}
    return jails


WHY = {'sshd': 'guessing SSH logins', 'recidive': 'banned again and again (every port, 1 week)',
       'nginx-limit-req': 'flooding the sign-in pages', 'edgeshell-probe': 'probing for .env, .git or admin pages'}


def new_bans(jails=None):
    """Addresses banned since the last check, by jail; mailed once per set."""
    jails = fail2ban() if jails is None else jails
    s = load()
    if 'banned' not in s:                       # the first check is the baseline: nothing mailed
        s['banned'] = {j: v['ips'] for j, v in jails.items()}
        save(s)
        return {}
    before = {j: set(v) for j, v in s.get('banned', {}).items()}
    fresh = {j: sorted(set(v['ips']) - before.get(j, set())) for j, v in jails.items()}
    fresh = {j: ips for j, ips in fresh.items() if ips}
    s['banned'] = {j: v['ips'] for j, v in jails.items()}
    hist = s.setdefault('ban_log', [])
    hist.extend({'at': now(), 'jail': j, 'ip': ip} for j, ips in fresh.items() for ip in ips)
    s['ban_log'] = hist[-500:]
    save(s)
    if fresh:
        lines = [f'{ip}: {WHY.get(j, j)} ({j})' for j, ips in fresh.items() for ip in ips]
        mail(f'Blocked {len(lines)} address(es)', '\n'.join(lines[:50]) +
             '\n\nUnban one: sudo fail2ban-client set <jail> unbanip <address>',
             key='ban-' + hashlib.sha1(''.join(lines).encode()).hexdigest()[:8], level='alert')
    return fresh


# ---------------------------------------------------------------- watch (every 5 min)
def sha(p):
    try:
        with open(p, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


def snapshot():
    return {f: sha(f) for f in sorted({f for pat in WATCHED for f in glob.glob(pat)})}


def lockdown(reason):
    s = load()
    if C['LOCKDOWN'] == 'web':
        compose('stop nginx')
        s['lockdown'] = {'at': now(), 'reason': reason}
        save(s)
        return 'nginx stopped: EdgeShell is unreachable from the internet until you run: sudo hostguard unlock'
    return 'LOCKDOWN is "alert": nothing stopped. Investigate now.'


def watch():
    s = load()
    critical, alerts = [], []
    if s.get('lockdown') and C['LOCKDOWN'] == 'web':
        compose('stop nginx')                                 # keep it stopped across restarts
    passwd = [line.split(':') for line in open('/etc/passwd').read().splitlines() if line.count(':') >= 6]
    for p in passwd:
        if p[2] == '0' and p[0] != 'root':
            sh(f'usermod -L -e 1 {p[0]}; pkill -KILL -u {p[0]}')
            critical.append(f'Extra root (UID 0) account "{p[0]}": locked and its processes killed')
    logins = sorted(p[0] for p in passwd if not p[6].endswith(('nologin', 'false', 'sync')) and p[0] != 'root')
    known = s.setdefault('logins', logins)
    for u in sorted(set(logins) - set(known)):
        alerts.append(f'New account that can log in: "{u}". If it is not yours: sudo usermod -L {u}')
    s['logins'] = logins
    if os.path.exists('/etc/ld.so.preload') and open('/etc/ld.so.preload').read().strip():
        critical.append('/etc/ld.so.preload is set (a classic rootkit technique):\n' + open('/etc/ld.so.preload').read()[:300])
    qdir = path('quarantine')
    os.makedirs(qdir, exist_ok=True)
    for pid in filter(str.isdigit, os.listdir('/proc')):
        try:
            exe = os.readlink(f'/proc/{pid}/exe')
            comm = open(f'/proc/{pid}/comm').read().strip()
            cmd = open(f'/proc/{pid}/cmdline', 'rb').read().replace(b'\0', b' ').decode(errors='replace')[:200]
        except OSError:
            continue
        if MINER.search(comm) or MINER.search(os.path.basename(exe)) or exe.startswith(('/dev/shm/', '/run/shm/')):
            q = os.path.join(qdir, f'{pid}-{os.path.basename(exe).replace(" (deleted)", "")}')
            try:
                shutil.copy(f'/proc/{pid}/exe', q)
                os.chmod(q, 0)
            except OSError:
                pass                                          # gone already; killed below anyway
            sh(f'kill -9 {pid}')
            critical.append(f'Suspicious process killed: pid {pid} {comm} ({exe})\n  command: {cmd}\n  copy kept: {q}')
        elif re.match(r'^/(tmp|var/tmp)/', exe):
            alerts.append(f'A program runs from a temporary folder: {exe} ({comm}, pid {pid})')
    keyfile = f'/home/{C["LOGIN_USER"]}/.ssh/authorized_keys'
    keys = open(keyfile).read() if os.path.exists(keyfile) else ''
    if 'keys' in s and keys != s['keys']:
        added = [k[:100] for k in keys.splitlines() if k.strip() and k not in s['keys'].splitlines()]
        if added:
            alerts.append(f'SSH key(s) added for {C["LOGIN_USER"]} (not removed: if they are not yours, delete them '
                          f'from {keyfile} now):\n' + '\n'.join(added))
    s['keys'] = keys
    rc, journal = sh("journalctl -u ssh -u sshd --since -6min -o cat 2>/dev/null | grep 'Accepted .* for root from'")
    for line in journal.splitlines():
        ip = line.split(' from ')[1].split()[0] if ' from ' in line else '?'
        if not re.match(r'^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|::1)', ip):
            critical.append(f'Root logged in over SSH from the internet: {ip}')
    snap = snapshot()
    if 'files' in s:
        changed = [f for f in snap if s['files'].get(f) != snap[f]] + [f for f in s['files'] if f not in snap]
        if changed:
            alerts.append('Security-relevant files changed (normal after updates or your own edits; check if '
                          'not):\n' + '\n'.join('  ' + f for f in changed))
    s['files'] = snap
    s['watch'] = {'at': now(), 'critical': len(critical), 'alerts': len(alerts)}
    findings = s.setdefault('findings', [])
    findings.extend({'at': now(), 'text': t.splitlines()[0]} for t in critical + alerts)
    s['findings'] = findings[-100:]
    save(s)
    if critical:
        action = lockdown('; '.join(c.splitlines()[0] for c in critical))
        mail('Intrusion signs on the server', '\n\n'.join(critical + alerts) + '\n\n' + action, level='critical')
    elif alerts:
        mail('Host security alert', '\n\n'.join(alerts), key='host-' + hashlib.sha1(''.join(alerts).encode()).hexdigest()[:10],
             level='alert')
    print(f'watch: {len(critical)} critical, {len(alerts)} alert(s)')


def unlock():
    s = load()
    s.pop('lockdown', None)
    save(s)
    compose('start nginx')
    print('nginx started')


# ---------------------------------------------------------------- feeds (every 6 h)
def get_json(url, data=None, timeout=60):
    req = urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None,
                                 headers={'User-Agent': 'host-guard', 'Accept': 'application/json',
                                          'Accept-Encoding': 'gzip',
                                          **({'Content-Type': 'application/json'} if data is not None else {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read()
    if body[:2] == b'\x1f\x8b':                 # AWS's price files come gzip-compressed, asked for or not
        body = gzip.decompress(body)
    return json.loads(body.decode('utf-8'))


def installed_packages():
    rc, text = sh("dpkg-query -W -f='${Package} ${Version}\\n'", 60)
    return dict(line.split(' ', 1) for line in text.splitlines() if ' ' in line) if rc == 0 else {}


def python_packages(service):
    rc, text = compose(f'exec -T {service} sh -c "pip list --format=freeze 2>/dev/null || pip freeze"', 60)
    pkgs = {}
    for line in text.splitlines():
        if '==' in line:
            n, v = line.split('==', 1)
            pkgs[n.strip().lower()] = v.strip()
    return pkgs


def feeds():
    s = load()
    seen = set(s.get('seen', []))
    first = 'seen' not in s
    news, urgent = [], []
    try:
        kev = get_json(C['KEV_URL'])
        for v in kev.get('vulnerabilities', []):
            kid = 'kev:' + v['cveID']
            if kid in seen:
                continue
            seen.add(kid)
            text = f"{v.get('vendorProject', '')} {v.get('product', '')}".lower()
            if not first and KEV_WORDS.search(text):
                urgent.append(f"ACTIVELY EXPLOITED (CISA KEV) {v['cveID']}: {v.get('vendorProject')} {v.get('product')}\n"
                              f"  {v.get('shortDescription', '')[:300]}\n  Required action: {v.get('requiredAction', '')[:200]}")
    except Exception as e:
        news.append(f'(CISA KEV not reachable: {str(e)[:80]})')
    try:
        pk = installed_packages()
        usn = get_json(C['USN_URL'])
        for n in usn.get('notices', []):
            nid = 'usn:' + n.get('id', '')
            if nid in seen:
                continue
            seen.add(nid)
            names = {p.get('name') for r in (n.get('release_packages') or {}).values() for p in r} if isinstance(
                n.get('release_packages'), dict) else set()
            hit = sorted(names & set(pk))
            if hit and not first:
                news.append(f"Ubuntu {n['id']}: {n.get('title', '')[:120]} (installed here: {', '.join(hit[:8])})\n"
                            '  Applied by unattended-upgrades within a day; a reboot follows in the window if needed.')
    except Exception as e:
        news.append(f'(Ubuntu notices not reachable: {str(e)[:80]})')
    for svc in C['CONTAINERS_PYTHON'].split():
        pkgs = python_packages(svc)
        if not pkgs:
            continue
        try:
            res = get_json(C['OSV_URL'], {'queries': [{'package': {'name': n, 'ecosystem': 'PyPI'}, 'version': v}
                                                      for n, v in sorted(pkgs.items())]})
        except Exception as e:
            news.append(f'(OSV not reachable for {svc}: {str(e)[:80]})')
            continue
        for (n, v), r in zip(sorted(pkgs.items()), res.get('results', [])):
            for vul in r.get('vulns', []) or []:
                vid = f"osv:{svc}:{n}:{vul['id']}"
                if vid in seen:
                    continue
                seen.add(vid)
                try:
                    det = get_json(C['OSV_VULN_URL'] + urllib.parse.quote(vul['id']))
                except Exception:
                    det = {}
                fixed = sorted({e.get('fixed') for a in det.get('affected', []) for rg in a.get('ranges', [])
                                for e in rg.get('events', []) if e.get('fixed')})
                line = (f"{svc}: {n} {v} has {vul['id']}{' (' + ', '.join(det.get('aliases', [])[:2]) + ')' if det.get('aliases') else ''}"
                        f"\n  {det.get('summary', '')[:200]}\n  fixed in: {', '.join(fixed) or 'no fix released yet'}"
                        f"\n  Ship it through a release (Dependabot, CI); the server never patches the app by itself.")
                (news if first else urgent).append(line)
    s['seen'] = sorted(seen)
    s['feeds'] = {'at': now(), 'urgent': len(urgent), 'news': len([n for n in news if not n.startswith('(')])}
    hist = s.setdefault('feed_items', [])
    hist.extend({'at': now(), 'text': t.splitlines()[0]} for t in urgent + news if not t.startswith('('))
    s['feed_items'] = hist[-200:]
    save(s)
    if first:
        mail('Early warning switched on', f'Baseline recorded: {len(seen)} known advisories. From now on only new '
             'ones that touch this server are mailed.\n\n' + '\n\n'.join(news[:30]))
    elif urgent:
        mail(f'{len(urgent)} security warning(s) for this server', '\n\n'.join(urgent + news), level='critical')
    elif [n for n in news if not n.startswith('(')]:
        mail(f'{len(news)} new security notice(s)', '\n\n'.join(news))
    down = [n for n in news if n.startswith('(')]
    print(f'feeds: {len(urgent)} urgent, {len(news) - len(down)} notices, {len(seen)} known'
          + (f'; {len(down)} source(s) not reachable: ' + ' '.join(down) if down else ''))


# ---------------------------------------------------------------- scan (weekly)
def scan():
    report, worst = [], []
    images = sorted({r['image'] for r in containers() if r.get('image')})
    if shutil.which('trivy'):
        for img in images:
            rc, text = sh(f'trivy image --quiet --scanners vuln --severity HIGH,CRITICAL --format json {img}', 900)
            try:
                data = json.loads(text[text.index('{'):])
            except ValueError:
                report.append(f'{img}: scan failed')
                continue
            vulns = [v for r in data.get('Results', []) for v in (r.get('Vulnerabilities') or [])]
            crit = [v for v in vulns if v.get('Severity') == 'CRITICAL']
            fixable = [v for v in crit if v.get('FixedVersion')]
            report.append(f'{img}: {len(crit)} critical, {len(vulns) - len(crit)} high ({len(fixable)} critical with a fix)')
            worst += [f"{img}: {v['VulnerabilityID']} {v.get('PkgName')} {v.get('InstalledVersion')} -> {v.get('FixedVersion')}"
                      for v in fixable[:10]]
    else:
        report.append('Trivy is not installed (sudo bash install.sh --with-trivy)')
    score = None
    if shutil.which('lynis'):
        sh('lynis audit system --quiet --no-colors --report-file ' + path('lynis-report.dat'), 1200)
        m = re.search(r'hardening_index=(\d+)', open(path('lynis-report.dat')).read()) if os.path.exists(
            path('lynis-report.dat')) else None
        score = int(m.group(1)) if m else None
        report.append(f'Lynis hardening index: {score}')
    s = load()
    s['scan'] = {'at': now(), 'lines': report, 'fixable_critical': worst, 'lynis': score}
    save(s)
    low = score is not None and score < int(C['LYNIS_MIN'])
    mail('Weekly security scan' + (' (action needed)' if worst or low else ''),
         '\n'.join(report) + ('\n\nCritical with a fix available:\n' + '\n'.join(worst) if worst else '') +
         (f'\n\nLynis below {C["LYNIS_MIN"]}: see {path("lynis-report.dat")}' if low else ''),
         level='alert' if worst or low else 'info')
    print('\n'.join(report))


# ---------------------------------------------------------------- S3 (SigV4, stdlib)
def aws_creds():
    if C['AWS_ACCESS_KEY_ID'] and C['AWS_SECRET_ACCESS_KEY']:
        return C['AWS_ACCESS_KEY_ID'], C['AWS_SECRET_ACCESS_KEY'], None
    try:                                                     # the instance role, through IMDSv2
        tok = urllib.request.urlopen(urllib.request.Request(
            'http://169.254.169.254/latest/api/token', method='PUT',
            headers={'X-aws-ec2-metadata-token-ttl-seconds': '300'}), timeout=3).read().decode()
        h = {'X-aws-ec2-metadata-token': tok}
        base = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
        role = urllib.request.urlopen(urllib.request.Request(base, headers=h), timeout=3).read().decode().split()[0]
        c = json.load(urllib.request.urlopen(urllib.request.Request(base + role, headers=h), timeout=3))
        return c['AccessKeyId'], c['SecretAccessKey'], c['Token']
    except Exception:
        raise RuntimeError('no AWS credentials: give the instance a role, or set AWS_ACCESS_KEY_ID and '
                           'AWS_SECRET_ACCESS_KEY in guard.conf')


def s3(method, key, body=b'', extra=None):
    """One S3 request (path style, SigV4). Returns (status, headers, body)."""
    region = C['AWS_REGION']
    endpoint = (C['S3_ENDPOINT'] or f'https://s3.{region}.amazonaws.com').rstrip('/')
    host = urllib.parse.urlparse(endpoint).netloc
    access, secret, token = aws_creds()
    t = dt.datetime.now(dt.timezone.utc)
    amz, day = t.strftime('%Y%m%dT%H%M%SZ'), t.strftime('%Y%m%d')
    payload = hashlib.sha256(body).hexdigest()
    uri = '/' + urllib.parse.quote(C['S3_BUCKET']) + ('/' + urllib.parse.quote(key) if key else '')
    query = ''
    if '?' in uri:
        uri, query = uri.split('?', 1)
    headers = {'host': host, 'x-amz-content-sha256': payload, 'x-amz-date': amz, **(extra or {})}
    if token:
        headers['x-amz-security-token'] = token
    signed = ';'.join(sorted(headers))
    canon = '\n'.join([method, uri, query, ''.join(f'{k}:{headers[k]}\n' for k in sorted(headers)), signed, payload])
    scope = f'{day}/{region}/s3/aws4_request'
    sts = '\n'.join(['AWS4-HMAC-SHA256', amz, scope, hashlib.sha256(canon.encode()).hexdigest()])
    k = ('AWS4' + secret).encode()
    for part in (day, region, 's3', 'aws4_request'):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    headers['Authorization'] = f'AWS4-HMAC-SHA256 Credential={access}/{scope}, SignedHeaders={signed}, Signature={sig}'
    req = urllib.request.Request(endpoint + uri + ('?' + query if query else ''), data=body if method in ('PUT', 'POST') else None,
                                 method=method, headers={k2: v for k2, v in headers.items() if k2 != 'host'})
    try:
        with urllib.request.urlopen(req, timeout=300) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


# ---------------------------------------------------------------- backup (nightly) and restore test (weekly)
DUMP = ("exec -T {svc} sh -c 'mariadb-dump -uroot -p\"$MARIADB_ROOT_PASSWORD\" --all-databases --single-transaction "
        "--routines --events --triggers --hex-blob'")


def backup():
    os.makedirs(C['BACKUP_DIR'], mode=0o700, exist_ok=True)
    if not C['BACKUP_PASSPHRASE']:
        raise SystemExit(f'no BACKUP_PASSPHRASE in {C["ENV_FILE"]} (install.sh creates it; keep a copy offline)')
    t = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    name = f'edgeshell-db-{t}.sql.gz.gpg'
    target = os.path.join(C['BACKUP_DIR'], name)
    raw = target[:-4]
    rc, text = sh(f'docker compose --project-directory {C["EDGESHELL_DIR"]} {DUMP.format(svc="mariadb")} | gzip -9 > {raw}', 1800)
    size = os.path.getsize(raw) if os.path.exists(raw) else 0
    if rc != 0 or size < 1024:
        mail('Backup FAILED', f'The database dump did not complete (exit {rc}, {size} bytes):\n{text[-800:]}',
             key='backup-failed', level='alert')
        raise SystemExit(1)
    rc, text = sh(f'gpg --batch --yes --pinentry-mode loopback --passphrase-fd 0 '
                  f'--symmetric --cipher-algo AES256 -o {target} {raw}', 600, input=C['BACKUP_PASSPHRASE'] + '\n')
    os.remove(raw)
    if rc != 0:
        mail('Backup FAILED', 'Encryption failed:\n' + text[-500:], key='backup-failed', level='alert')
        raise SystemExit(1)
    os.chmod(target, 0o600)
    digest = hashlib.sha256(open(target, 'rb').read()).hexdigest()
    uploaded = None
    if C['S3_BUCKET']:
        data = open(target, 'rb').read()
        st, hdr, body = s3('PUT', C['S3_PREFIX'] + name, data,
                           {'x-amz-checksum-sha256': base64.b64encode(bytes.fromhex(digest)).decode(),
                            'x-amz-server-side-encryption': 'AES256', 'content-type': 'application/octet-stream'})
        if st != 200:
            mail('Backup upload FAILED', f'S3 answered {st}: {body[:400]!r}', key='backup-upload', level='alert')
            raise SystemExit(1)
        st2, hdr2, _ = s3('HEAD', C['S3_PREFIX'] + name)
        uploaded = st2 == 200 and int(hdr2.get('Content-Length', hdr2.get('content-length', -1))) == len(data)
        if not uploaded:
            mail('Backup upload not confirmed', f'HEAD answered {st2}', key='backup-upload', level='alert')
            raise SystemExit(1)
        resolved('backup-upload', 'Backup uploads working again')
    for old in sorted(glob.glob(os.path.join(C['BACKUP_DIR'], 'edgeshell-db-*.gpg')))[:-int(C['BACKUP_KEEP'])]:
        os.remove(old)
    s = load()
    s['backup'] = {'at': now(), 'name': name, 'bytes': os.path.getsize(target), 'sha256': digest, 's3': uploaded}
    save(s)
    resolved('backup-failed', 'Backups working again')
    print(f'backup: {name}, {os.path.getsize(target)} bytes, s3={uploaded}')


def restore_test():
    """The newest backup, from S3 when configured (else local), decrypted and loaded
    into a throwaway MariaDB; table and row counts reported."""
    s = load()
    name = s.get('backup', {}).get('name')
    if not name:
        raise SystemExit('no backup yet')
    work = path('restore-test')
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work, mode=0o700)
    enc = os.path.join(work, name)
    if C['S3_BUCKET']:
        st, hdr, body = s3('GET', C['S3_PREFIX'] + name)
        if st != 200:
            mail('Restore test FAILED', f'Could not download {name}: S3 {st}', level='alert')
            raise SystemExit(1)
        open(enc, 'wb').write(body)
    else:
        shutil.copy(os.path.join(C['BACKUP_DIR'], name), enc)
    ok_sum = hashlib.sha256(open(enc, 'rb').read()).hexdigest() == s['backup']['sha256']
    rc, text = sh(f'gpg --batch --yes --pinentry-mode loopback --passphrase-fd 0 -d {enc} '
                  f'| gunzip > {work}/dump.sql', 900, input=C['BACKUP_PASSPHRASE'] + '\n')
    lines = []
    if rc == 0 and ok_sum:
        pw = base64.b16encode(os.urandom(12)).decode()
        cname = 'host-guard-restore-test'
        sh(f'docker rm -f {cname}', 30)
        sh(f'docker run -d --name {cname} -e MARIADB_ROOT_PASSWORD={pw} -v {work}:/restore:ro mariadb:11.4', 300)
        for _ in range(60):
            if sh(f'docker exec {cname} healthcheck.sh --connect', 20)[0] == 0:
                break
            time.sleep(2)
        rc, text = sh(f"docker exec {cname} sh -c 'mariadb -uroot -p{pw} < /restore/dump.sql'", 1800)
        if rc == 0:
            q = ("SELECT table_name, table_rows FROM information_schema.tables WHERE table_schema='edgeshell' "
                 "ORDER BY table_rows DESC LIMIT 12")
            rc2, rows = sh(f"docker exec {cname} mariadb -uroot -p{pw} -N -e \"{q}\"", 120)
            lines = rows.splitlines()
        sh(f'docker rm -f {cname}', 60)
    shutil.rmtree(work, ignore_errors=True)
    good = rc == 0 and ok_sum and len(lines) > 0
    s = load()
    s['restore_test'] = {'at': now(), 'ok': good, 'backup': name, 'tables': lines[:12]}
    save(s)
    mail('Restore test ' + ('passed' if good else 'FAILED'),
         f'Backup {name}: checksum {"matches" if ok_sum else "DOES NOT MATCH"}, restored '
         f'{"into a throwaway MariaDB" if good else "with errors: " + text[-400:]}.\n\nLargest tables (rows):\n' +
         '\n'.join(lines), level='info' if good else 'alert')
    print('restore-test:', 'ok' if good else 'FAILED')
    if not good:
        raise SystemExit(1)


# ---------------------------------------------------------------- patch window
def patch_window():
    if not os.path.exists('/var/run/reboot-required'):
        print('no reboot needed')
        return
    ok, detail = replication()
    if ok is False:
        mail('Reboot postponed', 'Security updates need a reboot, but data lake replication is not healthy '
             f'({detail}). It is tried again in the next window.', key='reboot-postponed', level='alert')
        return
    backup()
    pkgs = open('/var/run/reboot-required.pkgs').read().split() if os.path.exists('/var/run/reboot-required.pkgs') else []
    s = load()
    s['planned_reboot'] = {'at': now(), 'packages': pkgs}
    save(s)
    mail('Rebooting for security updates', 'Packages: ' + ' '.join(pkgs[:30]) + '\nA fresh backup was taken first. '
         'You get a mail when the server is back, with its health.')
    sh('systemctl reboot', 30)


def boot():
    time.sleep(int(os.environ.get('HG_BOOT_WAIT', '90')))
    s = load()
    planned = s.pop('planned_reboot', None)
    save(s)
    problems = [f'{subj}' for key, bad, subj, _ in checks() if bad and key != 'reboot']
    mail('Server started' + (' after the planned patch reboot' if planned else ' (not planned by host-guard)'),
         out('uptime') + '\n\nHealth: ' + ('all good' if not problems else '\n  ' + '\n  '.join(problems)),
         level='info' if planned and not problems else 'alert')



# ---------------------------------------------------------------- running cost (daily report, `hostguard cost`)
def cpu_times():
    f = [int(x) for x in open('/proc/stat').readline().split()[1:]]
    return sum(f), f[3] + (f[4] if len(f) > 4 else 0)        # total, idle + iowait


def net_bytes():
    rx = tx = 0
    for line in open('/proc/net/dev').readlines()[2:]:
        name, data = line.split(':', 1)
        name = name.strip()
        if name == 'lo' or name.startswith(('docker', 'br-', 'veth')):
            continue                                       # only what leaves the machine
        v = data.split()
        rx, tx = rx + int(v[0]), tx + int(v[8])
    return rx, tx


def size_mb(text):
    m = re.match(r'([\d.]+)\s*([KMGT]?i?B)', text.strip())
    if not m:
        return 0.0
    mult = {'B': 1 / 1048576, 'KB': 1 / 1024, 'KiB': 1 / 1024, 'MB': 1, 'MiB': 1, 'GB': 1024, 'GiB': 1024,
            'TB': 1048576, 'TiB': 1048576}.get(m.group(2), 1)
    return float(m.group(1)) * mult


def container_usage():
    """{service: (cpu %, memory MB)} for the stack's running containers."""
    names = {r['name']: r['service'] for r in containers()}
    rc, text = sh("docker stats --no-stream --format '{{json .}}'", 60)
    use = {}
    for line in text.splitlines():
        try:
            d = json.loads(line)
        except ValueError:
            continue
        svc = names.get(d.get('Name'))
        if svc:
            use[svc] = (float(d.get('CPUPerc', '0%').rstrip('%') or 0), size_mb(d.get('MemUsage', '0B').split('/')[0]))
    return use


def sample_usage():
    """One usage sample (every health run, 5 min); about 9 days are kept."""
    u = load('usage.json')
    total, idle = cpu_times()
    last = u.get('cpu_last')
    cpu = round(100.0 * (1 - (idle - last[1]) / max(1, total - last[0])), 1) if last else None
    m = {}
    for line in open('/proc/meminfo'):
        k, v = line.split(':', 1)
        m[k] = int(v.split()[0])
    mem = round(100.0 * (1 - m.get('MemAvailable', 0) / max(1, m.get('MemTotal', 1))), 1)
    rx, tx = net_bytes()
    st = shutil.disk_usage('/')
    sample = {'t': now(), 'cpu': cpu, 'mem': mem, 'rx': rx, 'tx': tx, 'disk_gb': round(st.used / 1e9, 2),
              'svc': {k: [round(c, 2), round(mb, 1)] for k, (c, mb) in container_usage().items()}}
    u['cpu_last'] = [total, idle]
    u['mem_total_mb'] = round(m.get('MemTotal', 0) / 1024)
    u['samples'] = (u.get('samples', []) + [sample])[-2600:]
    save(u, 'usage.json')
    return sample


def imds(path_):
    """Instance metadata through IMDSv2; None off EC2."""
    try:
        tok = urllib.request.urlopen(urllib.request.Request(
            'http://169.254.169.254/latest/api/token', method='PUT',
            headers={'X-aws-ec2-metadata-token-ttl-seconds': '60'}), timeout=2).read().decode()
        return urllib.request.urlopen(urllib.request.Request(
            'http://169.254.169.254/latest/meta-data/' + path_, headers={'X-aws-ec2-metadata-token': tok}),
            timeout=2).read().decode().strip()
    except Exception:
        return None


def price_files(region):
    """AWS's public price files for the region (cached a day): EC2 on-demand Linux, EBS, data
    transfer, VPC (public IPv4), S3, Lightsail. {} entries when not reachable."""
    cache = load('prices.json')
    if cache.get('region') == region and now() - cache.get('at', 0) < 86400:
        return cache
    name = REGIONS.get(region, region)
    q = urllib.parse.quote(name)
    files = {'ec2': f'ec2/USD/current/ec2-ondemand-without-sec-sel/{q}/Linux/index.json',
             'ebs': 'ec2/USD/current/ebs.json', 'transfer': 'datatransfer/USD/current/datatransfer.json',
             'vpc': 'vpc/USD/current/vpc.json', 's3': 's3/USD/current/s3.json',
             'lightsail': 'lightsail/USD/current/lightsail.json'}
    out_ = {'region': region, 'at': now(), 'published': None}
    for key, rel in files.items():
        try:
            d = get_json(C['PRICES_URL'].rstrip('/') + '/' + rel, timeout=60)
            out_[key] = d.get('regions', {}).get(name, {})
            out_['published'] = out_['published'] or d.get('manifest', {}).get('hawkFilePublicationDate')
        except Exception:
            out_[key] = {}
    out_['ec2'] = {v['Instance Type']: {'price': float(v['price']), 'vcpu': int(v.get('vCPU', 0) or 0),
                                        'mem_gb': float(str(v.get('Memory', '0')).split()[0] or 0)}
                   for v in out_['ec2'].values() if v.get('Instance Type') and v.get('price')}
    if any(out_[k] for k in files):
        save(out_, 'prices.json')
    return out_


def rate(table, *words, default=None):
    """The first price in a price-file region whose name has every word."""
    for k, v in (table or {}).items():
        if all(w.lower() in k.lower() for w in words):
            try:
                return float(v['price'])
            except (KeyError, ValueError):
                pass
    return default


def lightsail_bundles(table):
    out_ = []
    for k, v in (table or {}).items():
        m = re.match(r'Lightsail Instance Bundle ([\d.]+)GB Linux (\d+)GB Storage (\d+) vCPU ([\d.]+)GB Memory ([\d ]+)TB Quota', k)
        if m and 'IPv6' not in k:
            out_.append({'name': f'{m.group(1)} GB', 'vcpu': int(m.group(3)), 'mem_gb': float(m.group(4)),
                         'disk_gb': int(m.group(2)), 'transfer_tb': float(m.group(5).replace(' ', '.')),
                         'month': round(float(v['price']) * 730, 2)})
    return sorted(out_, key=lambda b: b['month'])


def usage_stats(hours=24):
    u = load('usage.json')
    ss = [x for x in u.get('samples', []) if x['t'] > now() - hours * 3600]
    if not ss:
        return None
    cpus = [x['cpu'] for x in ss if x.get('cpu') is not None]
    tx = 0
    for a, b in zip(ss, ss[1:]):
        tx += b['tx'] - a['tx'] if b['tx'] >= a['tx'] else b['tx']        # a counter reset: a reboot
    span_h = max(1e-6, (ss[-1]['t'] - ss[0]['t']) / 3600) if len(ss) > 1 else 0
    svc = {}
    for x in ss:
        for k, (c, mb) in x.get('svc', {}).items():
            a = svc.setdefault(k, [0.0, 0.0, 0])
            a[0], a[1], a[2] = a[0] + c, a[1] + mb, a[2] + 1
    return {'samples': len(ss), 'span_h': span_h,
            'cpu_avg': round(sum(cpus) / len(cpus), 1) if cpus else None, 'cpu_peak': max(cpus) if cpus else None,
            'mem_avg': round(sum(x['mem'] for x in ss) / len(ss), 1), 'mem_peak': max(x['mem'] for x in ss),
            'mem_total_mb': u.get('mem_total_mb'), 'disk_gb': ss[-1]['disk_gb'],
            'egress_gb_day': round(tx / 1e9 * (24 / span_h), 3) if span_h else 0.0,
            'svc': {k: (round(a[0] / a[2], 2), round(a[1] / a[2], 1)) for k, a in svc.items()}}


def ebs_gb():
    if C['EBS_GB']:
        return float(C['EBS_GB'])
    rc, text = sh('lsblk -b -dn -o SIZE,TYPE', 10)
    total = sum(int(a) for a, b in (line.split() for line in text.splitlines() if len(line.split()) == 2) if b == 'disk')
    return round(total / 1024 ** 3, 1) if total else round(shutil.disk_usage('/').total / 1024 ** 3, 1)


def cost_estimate():
    """What the server costs, from the published prices and the measured usage."""
    itype = C['INSTANCE_TYPE'] or imds('instance-type') or ''
    region = C['AWS_REGION'] or 'ap-south-1'
    pf = price_files(region)
    spec = pf.get('ec2', {}).get(itype, {})
    hour = float(C['PRICE_HOUR']) if C['PRICE_HOUR'] else spec.get('price')
    live = bool(spec) and not C['PRICE_HOUR']
    ebs_p = rate(pf.get('ebs'), 'Storage General Purpose gp3 GB Mo', default=float(C['PRICE_EBS_GB_MONTH']))
    egress_p = rate(pf.get('transfer'), 'DataTransfer External Outbound Next 10 TB', default=float(C['PRICE_EGRESS_GB']))
    ipv4_p = rate(pf.get('vpc'), 'In use Public IPv4', default=float(C['PRICE_IPV4_HOUR']))
    s3_p = rate(pf.get('s3'), 'Standard Storage First 50 TB', default=float(C['PRICE_S3_GB_MONTH']))
    public = C['PUBLIC_IPV4'] == 'yes' or (C['PUBLIC_IPV4'] == 'auto' and bool(imds('public-ipv4')))
    use = usage_stats() or {}
    disk = ebs_gb()
    b = load().get('backup', {})
    s3_gb = (b.get('bytes', 0) / 1e9) * int(C['S3_RETENTION_DAYS']) if C['S3_BUCKET'] else 0.0
    month_h = 730.0
    lines = {
        'instance': (hour or 0) * month_h,
        'disk (EBS gp3)': disk * ebs_p,
        'public IPv4': ipv4_p * month_h if public else 0.0,
        'internet egress': max(0.0, use.get('egress_gb_day', 0.0) * 30.4) * egress_p,
        'backups (S3)': s3_gb * s3_p,
    }
    month = sum(lines.values())
    svc = use.get('svc') or {}
    cpu_sum = sum(c for c, _ in svc.values()) or 1
    mem_sum = sum(m for _, m in svc.values()) or 1
    share = {k: 0.5 * c / cpu_sum + 0.5 * m / mem_sum for k, (c, m) in svc.items()}
    machine = lines['instance'] + lines['disk (EBS gp3)']
    per_service = sorted(((k, round(machine * v, 2)) for k, v in share.items()), key=lambda x: -x[1])
    ideas = []
    if spec:
        same = [(t, v) for t, v in pf['ec2'].items() if t.startswith('t4g.') and v['vcpu'] == spec['vcpu']
                and v['mem_gb'] == spec['mem_gb']]
        if same and not itype.startswith('t4g.') and same[0][1]['price'] < hour:
            t, v = same[0]
            ideas.append(f'Graviton {t} (same {v["vcpu"]} vCPU, {v["mem_gb"]:g} GB): ${v["price"] * month_h:.2f} a month for the '
                         f'instance instead of ${hour * month_h:.2f}; first check that every image in the stack has '
                         'an arm64 build (EdgeShell\'s has)')
        peak_mem_gb = (use.get('mem_peak') or 0) / 100 * (use.get('mem_total_mb') or 0) / 1024
        if use.get('cpu_peak') is not None and use['cpu_peak'] < 40 and peak_mem_gb and peak_mem_gb < spec['mem_gb'] / 2:
            smaller = sorted(((t, v) for t, v in pf['ec2'].items() if t.split('.')[0] == itype.split('.')[0]
                              and v['mem_gb'] >= peak_mem_gb * 1.5 and v['price'] < hour), key=lambda x: x[1]['price'])
            if smaller:
                t, v = smaller[0]
                ideas.append(f'Smaller: peak CPU {use["cpu_peak"]}%, peak memory {peak_mem_gb:.1f} GB of {spec["mem_gb"]:g}; '
                             f'{t} ({v["mem_gb"]:g} GB) is ${v["price"] * month_h:.2f} a month')
        fits = [x for x in lightsail_bundles(pf.get('lightsail')) if x['vcpu'] >= spec['vcpu'] and x['mem_gb'] >= spec['mem_gb']]
        if fits:
            x = fits[0]
            ideas.append(f'Lightsail {x["name"]} plan ({x["vcpu"]} vCPU, {x["mem_gb"]:g} GB, {x["disk_gb"]} GB disk, '
                         f'{x["transfer_tb"]:g} TB transfer and a public IPv4 included): ${x["month"]:.2f} a month, '
                         f'against ${month:.2f} here')
    ideas.append('Savings Plans or reserved instances lower the instance price for a 1 or 3 year commitment '
                 '(AWS Pricing Calculator)')
    return {'instance_type': itype or 'unknown', 'region': region, 'spec': spec, 'live_prices': live,
            'published': pf.get('published'), 'month': round(month, 2), 'day': round(month / 30.4, 2),
            'lines': {k: round(v, 2) for k, v in lines.items()}, 'per_service': per_service, 'use': use,
            'disk_gb': disk, 'public_ipv4': public, 'ideas': ideas,
            'rates': {'hour': hour, 'ebs_gb_month': ebs_p, 'egress_gb': egress_p, 'ipv4_hour': ipv4_p,
                      's3_gb_month': s3_p}}


def money(usd):
    inr = f' (Rs {usd * float(C["USD_INR"]):,.0f})' if C['USD_INR'] else ''
    return f'${usd:,.2f}{inr}'


def cost_text(nodes=None):
    e = cost_estimate()
    u = e['use']
    src = (f'AWS list prices published {e["published"][:10]}' if e['published'] else 'configured prices (AWS price files not reachable)')
    spec = e['spec']
    parts = [f'== Running cost (estimate, {src}, {e["region"]})',
             f'Instance {e["instance_type"]}' + (f' ({spec["vcpu"]} vCPU, {spec["mem_gb"]:g} GB)' if spec else '') +
             f' at ${e["rates"]["hour"] or 0:.4f}/h, disk {e["disk_gb"]:g} GB, public IPv4 {"yes" if e["public_ipv4"] else "no"}',
             f'Per day {money(e["day"])}, per month {money(e["month"])}']
    parts += [f'  {k:<16} {money(v)} a month' for k, v in e['lines'].items()]
    if nodes:
        parts.append(f'Per managed node: {money(e["month"] / nodes)} a month ({nodes} nodes)')
    if u:
        parts.append(f'Usage (24 h): CPU avg {u["cpu_avg"]}% peak {u["cpu_peak"]}%, memory avg {u["mem_avg"]}% '
                     f'peak {u["mem_peak"]}%, disk used {u["disk_gb"]} GB, internet egress {u["egress_gb_day"]} GB/day')
    if e['per_service']:
        parts.append('Instance and disk by service (half CPU, half memory share):')
        parts += [f'  {k:<14} {money(v)} a month   (CPU {u["svc"][k][0]}%, memory {u["svc"][k][1]:.0f} MB)'
                  for k, v in e['per_service']]
    parts += ['Where it could cost less:'] + ['  ' + i for i in e['ideas']]
    return '\n'.join(parts), e


def cost():
    text, e = cost_text()
    s = load()
    s['cost'] = {'at': now(), 'month': e['month'], 'day': e['day'], 'instance_type': e['instance_type']}
    save(s)
    print(text)


# ---------------------------------------------------------------- daily report
def ago(t):
    if not t:
        return 'never'
    h = (now() - t) / 3600
    return f'{h * 60:.0f} min ago' if h < 1 else f'{h:.0f} h ago' if h < 48 else f'{h / 24:.0f} days ago'


def report_text():
    s, day = load(), now() - 86400
    parts = [f'== {C["SITE"]}  {stamp()}', out('uptime')]
    parts += ['', '== Memory', out('free -h'), '', '== Disk', out('df -h / | tail -1'),
              f'Backups folder: {out("du -sh " + C["BACKUP_DIR"] + " 2>/dev/null")}']
    parts += ['', '== Containers'] + [f'{r["service"]:<14} {r["status"]}' for r in containers()]
    st, fleet, alerts = api('/status'), api('/fleet/summary'), api('/alerts')
    parts += ['', '== EdgeShell']
    if st and 'error' not in st:
        parts.append(f'Version {st.get("version")}, nodes online {st["nodes"]["online"]} of {st["nodes"]["total"]}')
        if fleet and 'fleet' in fleet:
            parts += [f'  {c["name"]:<20} {c["online"]}/{c["total"]} online, availability {c.get("availability_percent")}%'
                      for c in fleet.get('categories', [])]
        if alerts and 'summary' in alerts:
            a = alerts['summary']
            parts.append(f'Open alerts: {a.get("critical", 0)} critical, {a.get("warning", 0)} warning on {a.get("nodes", 0)} node(s)')
    else:
        parts.append('(set EDGESHELL_KEY to a read-only service key for fleet numbers)' if not st else f'API: {st.get("error")}')
    ok, detail = replication()
    parts += ['', '== Data lake', detail if ok is not None else 'not configured']
    b = s.get('backup', {})
    parts += ['', '== Backups', f'Last: {b.get("name", "none")} ({ago(b.get("at"))}, {b.get("bytes", 0) // 1024} KB, '
              f'S3: {"yes" if b.get("s3") else "no"})',
              f'Restore test: {"passed" if s.get("restore_test", {}).get("ok") else "not passed yet"} '
              f'({ago(s.get("restore_test", {}).get("at"))})']
    rc, ssh_fail = sh("journalctl -u ssh -u sshd --since -24h -o cat 2>/dev/null | grep -cE 'Invalid user|authentication failure|"
                      "Failed password|Connection closed by authenticating'")
    parts += ['', '== Security (24 h)', f'SSH: {ssh_fail.strip() or 0} failed attempts']
    jails = fail2ban()
    day_bans = [b for b in s.get('ban_log', []) if b['at'] > day]
    parts.append('Bans in 24 h: ' + str(len(day_bans)) + '; banned now / since fail2ban started: ' +
                 (', '.join(f'{j} {v["now"]}/{v["total"]}' for j, v in jails.items())
                  or "fail2ban not running (run EdgeShell's host-hardening.sh)"))
    find = [f['text'] for f in s.get('findings', []) if f['at'] > day]
    parts += [f'Host watch: {len(find)} finding(s)'] + ['  ' + f for f in find[:10]]
    if s.get('lockdown'):
        parts.append(f'LOCKDOWN since {stamp(s["lockdown"]["at"])}: {s["lockdown"]["reason"]}')
    items = [f['text'] for f in s.get('feed_items', []) if f['at'] > day]
    parts += ['', '== Early warning (24 h)', f'{len(items)} new item(s), last check {ago(s.get("feeds", {}).get("at"))}']
    parts += ['  ' + i for i in items[:15]]
    upg = out("grep -h 'Packages that will be upgraded' /var/log/unattended-upgrades/unattended-upgrades.log 2>/dev/null | tail -3")
    pend = out("apt list --upgradable 2>/dev/null | grep -c upgradable")
    parts += ['', '== Updates', f'Pending: {pend}', 'Recently applied: ' + (upg or 'none logged'),
              'REBOOT NEEDED (in the window)' if os.path.exists('/var/run/reboot-required') else 'No reboot needed']
    sc = s.get('scan', {})
    parts += ['', '== Last weekly scan', f'{ago(sc.get("at"))}'] + ['  ' + x for x in sc.get('lines', [])]
    try:
        nodes = st['nodes']['total'] if st and 'error' not in st else None
        ctext, e = cost_text(nodes)
        parts += [''] + ctext.splitlines()
        s2 = load()
        s2['cost'] = {'at': now(), 'month': e['month'], 'day': e['day'], 'instance_type': e['instance_type']}
        save(s2)
    except Exception as ex:
        parts += ['', f'== Running cost: not available ({str(ex)[:120]})']
    sent = [m for m in load('mail-log.json').get('sent', []) if m['at'] > day]
    parts += ['', f'== Mails in 24 h: {len(sent)}'] + [f'  {stamp(m["at"])[11:16]} {m["subject"]}' for m in sent[-15:]]
    return '\n'.join(str(p) for p in parts)


def report():
    text = report_text()
    open_problems = len(load('alerts.json'))
    mail('Daily report' + (f': {open_problems} open problem(s)' if open_problems else ': all good'), text)
    print(text)


def status():
    s = load()
    print(json.dumps({k: s.get(k) for k in ('health', 'bans', 'watch', 'feeds', 'scan', 'backup', 'restore_test',
                                            'lockdown')}, indent=1, default=str))
    print('open problems:', list(load('alerts.json')))


STATUS_KEYS = ('health', 'bans', 'watch', 'feeds', 'scan', 'backup', 'restore_test', 'lockdown')


def scrub(value, secret_values):
    """A copy of value with every secret value replaced and every secret-named key dropped."""
    if isinstance(value, dict):
        return {k: scrub(v, secret_values) for k, v in value.items()
                if not any(s.lower() in str(k).lower() for s in ('password', 'passphrase', 'secret', 'token', '_key'))}
    if isinstance(value, list):
        return [scrub(v, secret_values) for v in value]
    if isinstance(value, str):
        for s in secret_values:
            value = value.replace(s, '[hidden]')
    return value


def export():
    """Write what the panel shows (no secrets) to EXPORT_FILE, readable by the panel's group.
    The panel runs unprivileged and never reads host-guard's own state or .env."""
    target = C['EXPORT_FILE']
    s = load()
    data = {'site': C['SITE'], 'generated': now(),
            **{k: s.get(k) for k in STATUS_KEYS},
            'open_problems': [{'key': k, 'subject': v.get('subject', ''), 'at': v.get('at')}
                              for k, v in sorted(load('alerts.json').items())],
            'mails': load('mail-log.json').get('sent', [])[-30:]}
    data = scrub(json.loads(json.dumps(data, default=str)), [C[k] for k in SECRETS if len(C[k]) >= 6])
    os.makedirs(os.path.dirname(target), exist_ok=True)
    tmp = target + '.tmp'
    with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0), 0o640), 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=1, sort_keys=True)
    group = C['EXPORT_GROUP']
    if group and hasattr(os, 'chown'):
        try:
            import grp
            os.chown(tmp, 0, grp.getgrnam(group).gr_gid)
        except (KeyError, PermissionError, ImportError):
            pass
    os.replace(tmp, target)
    print(f'exported to {target}')


def test_mail():
    ok = mail('Test mail', 'If you can read this, host-guard can reach you.')
    print('sent' if ok else 'NOT sent: check /etc/msmtprc and the MAIL_TO setting')
    sys.exit(0 if ok else 1)


COMMANDS = {'health': health, 'cost': cost, 'watch': watch, 'feeds': feeds, 'scan': scan, 'backup': backup,
            'restore-test': restore_test, 'patch-window': patch_window, 'boot': boot, 'report': report,
            'status': status, 'test-mail': test_mail, 'unlock': unlock, 'export': export}

if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] in COMMANDS:
        COMMANDS[sys.argv[1]]()
    else:
        print(__doc__)
        sys.exit(2)
