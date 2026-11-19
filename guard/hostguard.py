#!/usr/bin/env python3
"""host-guard: security, health and early warning for one Linux server (a cloud
instance, a VPS or bare metal), with or without a Docker Compose app on it.
Python 3 standard library only. Every app-specific part is a setting that is off
when empty (docs/CONFIGURATION.md); examples/profiles/ has ready combinations.

    hostguard health         every 5 min: disk, memory, containers, HTTPS, certificate,
                             data lake replication, backups, pending reboot, new fail2ban
                             bans -> alert, then "resolved"
    hostguard watch          every 5 min: intrusion signs (extra root accounts, rootkit
                             preload, miners, programs in memory-only folders, root SSH from
                             the internet, changed auth and persistence files, new SSH keys)
    hostguard feeds          every 6 h: trusted sources (CISA KEV, Ubuntu notices, OSV for the
                             Python packages inside the running containers) -> early warning
    hostguard scan           weekly: Trivy on every running image, Lynis on the host
    hostguard backup         nightly: the database (MariaDB or PostgreSQL) or BACKUP_CMD's
                             output, encrypted (gpg AES-256), kept locally and optionally
                             uploaded to S3 with a SHA-256 checksum
    hostguard restore-test   weekly: the newest backup decrypted and loaded into a throwaway
                             database (or, for BACKUP_CMD output, decrypted and unpacked)
    hostguard patch-window   in the maintenance window: reboot for security updates only
                             after a fresh backup and with replication healthy
    hostguard cost           what the server costs to run, from AWS's published prices and
                             the measured usage: per day and month, per service, per managed
                             node, and where it could be cheaper (Graviton, smaller, Lightsail)
    hostguard report         daily: one mail with everything above (and EdgeShell's fleet, if used)
    hostguard boot           after every boot: a mail, with the health check
    hostguard export         every minute (with the panel): a status file without secrets
                             for the web panel, which runs unprivileged
    hostguard test-mail | status | unlock

Bans (SSH, repeat offenders, and with web logs sign-in floods and probes) are
fail2ban's, set up by conf/base-hardening.sh, which install.sh runs first;
host-guard reports them. Unban: sudo fail2ban-client set <jail> unbanip <address>.

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
import io
import ipaddress
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
    # the app on this server: all optional, off when empty (docs/CONFIGURATION.md)
    'APP_NAME': 'the website', 'STACK_DIR': '', 'HEALTH_PATH': '/', 'WEB_SERVICE': 'nginx',
    'DB_ENGINE': 'none', 'DB_SERVICE': '', 'DB_REPLICA': '', 'BACKUP_CMD': '', 'BACKUP_PREFIX': 'backup',
    'MARIADB_IMAGE': 'mariadb:11.4', 'PG_IMAGE': 'postgres:17', 'PG_USER': 'postgres', 'BACKUP_MIN_BYTES': '1024',
    'EDGESHELL_DIR': '', 'EDGESHELL_URL': '', 'EDGESHELL_KEY': '',
    'STATE_DIR': '/var/lib/host-guard', 'NOTIFY_CMD': 'msmtp -a default',
    'EXPORT_FILE': '/var/lib/host-guard-export/status.json', 'EXPORT_GROUP': 'hgpanel',
    'DISK_WARN': '85', 'MEM_FREE_MIN': '10', 'CERT_DAYS': '14', 'LAG_WARN': '300', 'COOLDOWN_H': '6',
    'BACKUP_DIR': '/var/backups/host-guard', 'BACKUP_KEEP': '3', 'BACKUP_PASSPHRASE': '',
    'ENV_FILE': '/etc/host-guard/.env',
    'BACKUP_MAX_AGE_H': '26', 'S3_BUCKET': '', 'S3_PREFIX': 'host-guard/', 'S3_ENDPOINT': '', 'AWS_REGION': 'ap-south-1',
    # off-site copies: s3 (AWS, Google Cloud Storage with HMAC keys, OCI's S3 compatibility API, R2, B2,
    # Wasabi, MinIO), azure (a container SAS URL) or oci-par (a bucket pre-authenticated request URL);
    # empty: s3 when S3_BUCKET is set. The URL of azure and oci-par is a secret: BACKUP_REMOTE_URL in .env.
    'BACKUP_REMOTE': '',
    'MAIL_MAX_PER_HOUR': '4',       # P2 and P3 mails of one category an hour; more are held (P1 never is)
    'S3_CA_BUNDLE': '',             # a CA file for an S3 store with a private certificate (self-hosted MinIO, ...)
    'CLOUD': '',                    # aws | gcp | azure | oci | other; empty: asked from the metadata service
    'AWS_ACCESS_KEY_ID': '', 'AWS_SECRET_ACCESS_KEY': '',
    'JAILS': 'sshd recidive nginx-limit-req web-probe edgeshell-probe',
    'LOCKDOWN': 'alert',            # alert | web (stop nginx on a critical intrusion sign)
    'LOGIN_USER': 'ubuntu', 'LYNIS_MIN': '65',
    'KEV_URL': 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    'USN_URL': 'https://ubuntu.com/security/notices.json?limit=30',
    'OSV_URL': 'https://api.osv.dev/v1/querybatch', 'OSV_VULN_URL': 'https://api.osv.dev/v1/vulns/',
    'CONTAINERS_PYTHON': '',
    # the panel's sign-in: who may get a code (empty: every MAIL_TO address), where the panel
    # leaves its requests, and the panel's own user (only its files are read)
    'PANEL_ADMINS': '', 'PANEL_OUTBOX': '/var/lib/host-guard-panel/outbox', 'PANEL_USER': 'hgpanel',
    # running cost: AWS's public price files (no credentials); the PRICE_* values are used
    # when they cannot be read. Mumbai list prices of 2026-11-10.
    'PRICES_URL': 'https://b0.p.awsstatic.com/pricing/2.0/meteredUnitMaps',
    'INSTANCE_TYPE': '', 'PUBLIC_IPV4': 'auto', 'EBS_GB': '', 'S3_RETENTION_DAYS': '30', 'USD_INR': '',
    'PRICE_HOUR': '', 'PRICE_EBS_GB_MONTH': '0.0912', 'PRICE_EGRESS_GB': '0.1093', 'PRICE_IPV4_HOUR': '0.005',
    'PRICE_S3_GB_MONTH': '0.025',
}
SECRETS = ('SMTP_PASSWORD', 'BACKUP_PASSPHRASE', 'EDGESHELL_KEY', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY',
           'BACKUP_REMOTE_URL')
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
    if not c['STACK_DIR'] and c['EDGESHELL_DIR']:          # the setting's name before 0.2
        c['STACK_DIR'] = c['EDGESHELL_DIR']
    if not c['EDGESHELL_URL'] and c['DOMAIN'] and c['EDGESHELL_KEY']:
        c['EDGESHELL_URL'] = 'https://' + c['DOMAIN']
    c['SITE_URL'] = 'https://' + c['DOMAIN'] if c['DOMAIN'] else ''
    return c


C = conf()


def path(name):
    os.makedirs(C['STATE_DIR'], exist_ok=True)
    return os.path.join(C['STATE_DIR'], name)


_LOADED = {}          # file name -> its content when this run read it


def _read(name):
    try:
        with open(path(name), encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return {}


def _copy(data):
    return json.loads(json.dumps(data, default=str))


def load(name='state.json'):
    data = _read(name)
    _LOADED[name] = _copy(data)
    return data


def save(data, name='state.json'):
    """Write back only the keys this run changed, onto the file as it is now, under a lock:
    health and watch start together every 5 minutes, and a whole-file write by one
    would undo the other's result."""
    try:
        import fcntl
    except ImportError:                  # not Linux (tests elsewhere): no lock
        fcntl = None
    with open(path(name) + '.lock', 'w') as lock:
        if fcntl:
            fcntl.flock(lock, fcntl.LOCK_EX)
        base, new, cur = _LOADED.get(name, {}), _copy(data), _read(name)
        for k in set(base) | set(new):
            if k not in new:
                cur.pop(k, None)
            elif base.get(k) != new[k]:
                cur[k] = new[k]
        tmp = path(name) + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(cur, f, indent=1, sort_keys=True)
        os.replace(tmp, path(name))
        _LOADED[name] = _copy(cur)


def sh(cmd, timeout=120, input=None):
    """Run a shell command; returns (exit code, stdout+stderr text). Never raises."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='replace',  # nosec B602
                           timeout=timeout, input=input)
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


LEVELS = {'critical': ('#b42318', 'Critical: act now'), 'alert': ('#b54708', 'Attention needed'),
          'resolved': ('#067647', 'Resolved'), 'info': ('#1d4ed8', 'For information')}
BADGES = {'OK': '#067647', 'PASSED': '#067647', 'YES': '#067647', 'ATTENTION': '#b54708', 'WARNING': '#b54708',
          'CRITICAL': '#b42318', 'FAILED': '#b42318', 'NO': '#b54708'}
KV = re.compile(r'^([A-Z][\w /()%.,+-]{0,38}): (\S.*)$')


def _cell(text, first=False):
    import html as h
    t = text.strip()
    color = BADGES.get(t.upper()) if not first else None
    if color:
        return (f'<span style="background:{color};color:#fff;border-radius:10px;padding:1px 9px;font-size:12px;'
                f'font-weight:600">{h.escape(t)}</span>')
    return h.escape(t)


def mail_html(subject, body, level, footer):
    """The mail as HTML, built from the plain text (which stays in the mail as the
    fallback): '== X' a heading, 'Key: value' a table row, indented lines with column
    gaps a table, other indented lines bullets. Everything is escaped: log lines can
    carry an attacker's text."""
    import html as h
    color, label = LEVELS.get(level, LEVELS['info'])
    td = 'padding:5px 10px;border-bottom:1px solid #eaecf0;vertical-align:top;font-size:14px'
    out, group, kind = [], [], None

    def flush():
        nonlocal group, kind
        if kind == 'kv':
            out.append('<table cellpadding="0" cellspacing="0" style="border-collapse:collapse;width:100%;margin:4px 0 10px">'
                       + ''.join(f'<tr><td style="{td};color:#475467;width:36%;white-space:nowrap">{h.escape(k)}</td>'
                                 f'<td style="{td}">{_cell(v)}</td></tr>' for k, v in group) + '</table>')
        elif kind == 'table':
            n = max(len(r) for r in group)
            out.append('<table cellpadding="0" cellspacing="0" style="border-collapse:collapse;width:100%;margin:4px 0 10px">'
                       + ''.join('<tr>' + ''.join(f'<td style="{td}{";font-weight:600" if i == 0 else ""}">'
                                                  f'{_cell(c, i == 0)}</td>' for i, c in enumerate(r + [''] * (n - len(r))))
                                 + '</tr>' for r in group) + '</table>')
        elif kind == 'ul':
            out.append('<ul style="margin:4px 0 10px;padding-left:20px">' + ''.join(
                f'<li style="margin:3px 0;font-size:14px">{h.escape(x)}</li>' for x in group) + '</ul>')
        elif kind == 'p':
            out.append(''.join(f'<p style="margin:6px 0;font-size:14px">{h.escape(x)}</p>' for x in group))
        group, kind = [], None

    def add(k, item):
        nonlocal kind
        if kind != k:
            flush()
            kind = k
        group.append(item)

    for line in body.splitlines():
        if not line.strip():
            flush()
        elif line.startswith('== '):
            flush()
            out.append(f'<h3 style="margin:18px 0 6px;padding:6px 10px;background:#f2f4f7;border-left:4px solid {color};'
                       f'font-size:15px;color:#101828">{h.escape(line[3:].strip())}</h3>')
        elif line.startswith('  '):
            cells = re.split(r'\s{2,}', line.strip())
            if len(cells) > 1:
                add('table', cells)
            else:
                add('ul', line.strip().lstrip('-* '))
        elif KV.match(line):
            add('kv', KV.match(line).groups())
        else:
            add('p', line)
    flush()
    return ('<!doctype html><html><body style="margin:0;padding:16px;background:#f9fafb;'
            'font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#101828">'
            '<div style="max-width:720px;margin:0 auto;background:#fff;border:1px solid #eaecf0;border-radius:8px;overflow:hidden">'
            f'<div style="background:{color};color:#fff;padding:14px 18px">'
            f'<div style="font-size:12px;text-transform:uppercase;letter-spacing:.06em;opacity:.9">{h.escape(label)}'
            f' &middot; {h.escape(C["SITE"])}</div>'
            f'<div style="font-size:18px;font-weight:600;margin-top:4px">{h.escape(subject)}</div></div>'
            f'<div style="padding:8px 18px 14px">{"".join(out)}</div>'
            f'<div style="padding:10px 18px;border-top:1px solid #eaecf0;color:#667085;font-size:12px">{h.escape(footer)}'
            '</div></div></body></html>')


SEVERITY = {'critical': ('P1', 'Critical'), 'alert': ('P2', 'Attention'), 'info': ('P3', 'Info'),
            'resolved': ('', 'Resolved'), 'daily': ('', 'Daily')}
CATEGORIES = ('Intrusion', 'Attack', 'Host change', 'Advisory', 'Backup', 'Health', 'Updates', 'Scan', 'Daily report',
              'Test', 'Sign-in')
# Never held by flood protection: signs of someone on the server. Holding them would let an
# intruder bury the alert that matters under a few noisy ones (red-team HOST-9).
NEVER_HELD = ('Intrusion', 'Host change', 'Daily report', 'Test', 'Sign-in')   # a held sign-in code is useless
KEY_CATEGORY = {'memory': 'Health', 'disk': 'Health', 'containers': 'Health', 'https': 'Health', 'cert': 'Health',
                'replication': 'Health', 'backup': 'Backup', 'backup-upload': 'Backup', 'backup-failed': 'Backup',
                'reboot': 'Updates'}


def mail_subject(subject, level, category):
    """[P1 Critical] Intrusion | web-01 | what happened. The same three parts in every mail, so an
    inbox can sort and filter by severity, then category, then server."""
    code, word = SEVERITY.get(level, SEVERITY['info'])
    return f'[{code + " " if code else ""}{word}] {category} | {C["SITE"]} | {subject}'


def _held(log, category):
    hour = now() - 3600
    return [h for h in log.get('held', []) if h['category'] == category and h['at'] > hour]


MAIL_BODY_MAX = 200_000


def mail(subject, body, key=None, level='info', category=None, to=None):
    """Send one mail. With a key, the same problem mails at most once per COOLDOWN_H
    hours; resolved() clears it. P2 and P3 mails of one category are limited to
    MAIL_MAX_PER_HOUR an hour: the rest are held, named in the next mail of that category
    and in the daily report. P1 (critical), resolved and daily mails always go out.
    Returns True when a mail went out."""
    category = category or KEY_CATEGORY.get((key or '').split(':')[0]) or 'Health'
    subject, body = (str(x).encode('utf-8', 'replace').decode('utf-8') for x in (subject, body))   # no lone surrogates
    if len(body) > MAIL_BODY_MAX:             # thousands of planted processes must not make a mail too big to deliver
        body = body[:MAIL_BODY_MAX] + f'\n\n(cut at {MAIL_BODY_MAX // 1000} KB; the rest is in {C["STATE_DIR"]})'
    alerts = load('alerts.json')
    if key and now() - alerts.get(key, {}).get('at', 0) < float(C['COOLDOWN_H']) * 3600:
        return False
    subject = re.sub(r'[\r\n]+', ' ', subject)                     # never a second header
    log = load('mail-log.json')
    if level in ('alert', 'info') and category not in NEVER_HELD:
        recent = [m for m in log.get('sent', []) if m.get('category') == category and m['at'] > now() - 3600
                  and m.get('level') in ('alert', 'info')]
        if len(recent) >= int(C['MAIL_MAX_PER_HOUR']):
            entry = {'at': now(), 'subject': subject, 'category': category, 'level': level}
            log.setdefault('held', []).append(entry)
            log['held'] = log['held'][-500:]
            log.setdefault('held_log', []).append(entry)          # kept for the daily report
            log['held_log'] = log['held_log'][-500:]
            save(log, 'mail-log.json')
            print(f'(held: {category} already mailed {len(recent)} times this hour) {subject}')
            return False
    if key:                                   # the cooldown starts with a mail that went out, not a held one
        alerts[key] = {'at': now(), 'subject': subject, 'category': category, 'level': level}
        save(alerts, 'alerts.json')
    held = _held(log, category)
    if held:
        body += (f'\n\n== Held back in the last hour ({len(held)} similar mail(s), flood protection)\n'
                 + '\n'.join(f'  {stamp(h["at"])[11:16]}  {h["subject"]}' for h in held[-20:]))
        log['held'] = [h for h in log.get('held', []) if h not in held]
    full = mail_subject(subject, level, category)
    rcpts = recipients() if to is None else [a for a in to if EMAIL.match(a)]     # to: one admin only (a sign-in code)
    to = ', '.join(rcpts)
    frm = C['MAIL_FROM'] or (rcpts[0] if rcpts else '')
    footer = f'host-guard on {C["SITE"]}{" | " + C["SITE_URL"] if C["SITE_URL"] else ""} | {stamp()}'
    text = '\n'.join(line[:900] for line in f'{body}\n\n-- \n{footer}\n'.splitlines()) + '\n'
    page = base64.encodebytes(mail_html(full, body, level, footer).encode()).decode()
    bnd = 'hg-' + hashlib.sha256(f'{now()}{subject}'.encode()).hexdigest()[:24]
    code, word = SEVERITY.get(level, SEVERITY['info'])
    slug = re.sub(r'[^a-z0-9]+', '-', category.lower()).strip('-')
    site = re.sub(r'[^A-Za-z0-9.-]+', '-', C['SITE']).strip('-') or 'server'
    urgent = 'X-Priority: 1\nImportance: high\n' if level == 'critical' else ''
    msg = (f'To: {to}\nFrom: host-guard {C["SITE"]} <{frm}>\nSubject: {full}\n'
           f'Date: {dt.datetime.now(dt.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")}\n'
           f'List-Id: host-guard {category} <{slug}.{site}.host-guard>\n'
           f'X-Host-Guard-Severity: {code or word}\nX-Host-Guard-Category: {category}\n{urgent}'
           f'MIME-Version: 1.0\nContent-Type: multipart/alternative; boundary="{bnd}"\n\n'
           f'--{bnd}\nContent-Type: text/plain; charset=UTF-8\nContent-Transfer-Encoding: 8bit\n\n{text}\n'
           f'--{bnd}\nContent-Type: text/html; charset=UTF-8\nContent-Transfer-Encoding: base64\n\n{page}\n'
           f'--{bnd}--\n')
    log.setdefault('sent', []).append({'at': now(), 'subject': full, 'level': level, 'category': category})
    log['sent'] = log['sent'][-200:]
    save(log, 'mail-log.json')
    if not rcpts:
        print(f'(no MAIL_TO) {full}\n{body}')
        return False
    rc, text = sh(f'{C["NOTIFY_CMD"]} ' + ' '.join(shlex.quote(a) for a in rcpts), input=msg, timeout=60)
    if rc != 0:
        print(f'mail failed ({rc}): {text[:300]}', file=sys.stderr)
    return rc == 0


def resolved(key, subject, body=''):
    alerts = load('alerts.json')
    if key in alerts:
        old = alerts.pop(key)
        save(alerts, 'alerts.json')
        mail(subject, body or 'Back to normal.', level='resolved', category=old.get('category'))


# ---------------------------------------------------------------- the Docker Compose app (optional)
def compose(args, timeout=120):
    if not C['STACK_DIR']:
        return 1, 'no STACK_DIR set'
    return sh(f'docker compose --project-directory {shlex.quote(C["STACK_DIR"])} {args}', timeout)


def containers():
    """[{name, service, state, health, status}] of the Compose app (none without STACK_DIR)."""
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
        with urllib.request.urlopen(req, timeout=20, context=ctx) as r:  # nosec B310
            return json.load(r)
    except Exception as e:
        return {'error': str(e)[:120]}


def replication():
    """The database replica's state: (ok, text); (None, why) when there is none to check.
    DB_REPLICA is the replica's Compose service (MariaDB or MySQL)."""
    if not C['DB_REPLICA']:
        return None, 'not configured'
    rc, text = compose(f"exec -T {shlex.quote(C['DB_REPLICA'])} sh -c 'mariadb -uroot -p\"$MARIADB_ROOT_PASSWORD\" "
                       f"-e \"SHOW REPLICA STATUS\\G\"'", timeout=30)
    if rc != 0:
        return None, 'replica not reachable: ' + text.splitlines()[-1][:120] if text else 'replica not reachable'
    f = dict(re.findall(r'^[ \t]*(\w+):[ \t]*(.*)$', text, re.M))     # an empty value stays empty
    if not f:
        return None, 'no replication configured'
    io_ok, sql_ok = f.get('Slave_IO_Running', f.get('Replica_IO_Running')), f.get('Slave_SQL_Running', f.get('Replica_SQL_Running'))
    lag = f.get('Seconds_Behind_Master', f.get('Seconds_Behind_Source'))
    ok = io_ok == 'Yes' and sql_ok == 'Yes' and (lag or '').isdigit() and int(lag) <= int(C['LAG_WARN'])
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
    try:
        end = dt.datetime.strptime(m.group(1).strip().replace('  ', ' '), '%b %d %H:%M:%S %Y %Z')
    except ValueError:
        return None
    return (end - dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)).days


def https_code():
    target = C['DOMAIN'] or 'localhost'
    rc, text = sh(f'curl -sk -o /dev/null -w "%{{http_code}}" --max-time 20 --resolve {target}:443:127.0.0.1 '
                  + shlex.quote(f'https://{target}{C["HEALTH_PATH"]}'), 30)
    return text.strip()[-3:] if rc == 0 else '000'


def checks():
    """Each check: (key, problem or None, subject, details). A check that crashes is reported
    as its own problem; the other checks and their mails still run."""
    try:
        return _checks()
    except Exception as e:
        return [('health-check', True, 'A health check failed to run', f'{type(e).__name__}: {str(e)[:300]}')]


def _checks():
    """Each check: (key, problem or None, subject, details)."""
    res = []
    free = mem_free_pct()
    res.append(('memory', free < int(C['MEM_FREE_MIN']), f'Low memory: {free}% free',
                out('free -h') + '\n\nTop memory users:\n' + out('ps -eo pid,comm,%mem,rss --sort=-rss | head -8')))
    d = disk_pct()
    res.append(('disk', d >= int(C['DISK_WARN']), f'Disk {d}% full',
                out('df -h /') + '\n\nDocker:\n' + out('docker system df') +
                '\n\nFree space: sudo docker image prune -af (old images); check data/ and backups.'))
    if C['STACK_DIR']:
        rows = containers()
        bad = [r for r in rows if r['service'] not in ONE_SHOT and (r['state'] != 'running' or r['health'] == 'unhealthy')]
        if rows:
            res.append(('containers', bool(bad), 'Container down: ' + ', '.join(r['service'] for r in bad),
                        '\n'.join(f'{r["service"]:<14} {r["status"]}' for r in rows)))
        else:
            res.append(('containers', True, f'{C["APP_NAME"]}: no container running', compose('ps -a')[1][:2000]))
    if C['DOMAIN']:
        code = https_code()
        res.append(('https', not code.startswith(('2', '3')), f'{C["APP_NAME"]} not answering (HTTP {code})',
                    f'https://{C["DOMAIN"]}{C["HEALTH_PATH"]} answered {code} from the server itself.'))
    days = cert_days()
    if days is not None:
        res.append(('cert', days < int(C['CERT_DAYS']), f'TLS certificate expires in {days} days',
                    'certbot renews it about 30 days before expiry; check its logs (docker compose logs certbot, '
                    'or journalctl -u certbot).'))
    ok, detail = replication()
    if ok is not None:
        res.append(('replication', not ok, 'Database replication: ' + detail,
                    'The replica is behind or stopped: check it before relying on it.'))
    if backup_configured():
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
            mail(subject, body, key=key, level='alert', category=KEY_CATEGORY.get(key, 'Health'))
        else:
            resolved(key, {'memory': 'Memory back to normal', 'disk': 'Disk back under the limit',
                           'containers': 'Every container running again', 'https': f'{C["APP_NAME"]} answering again',
                           'cert': 'TLS certificate renewed', 'replication': 'Database replication healthy again',
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
        def num(label, text=text):
            m = re.search(label + r':\s*(\d+)', text)
            return int(m.group(1)) if m else 0
        m = re.search(r'Banned IP list:\s*(.*)', text)
        jails[jail] = {'now': num('Currently banned'), 'total': num('Total banned'),
                       'ips': m.group(1).split() if m else []}
    return jails


WHY = {'sshd': 'guessing SSH logins', 'recidive': 'banned again and again (every port, 1 week)',
       'nginx-limit-req': 'flooding the sign-in pages', 'edgeshell-probe': 'probing for .env, .git or admin pages',
       'web-probe': 'probing for .env, .git or admin pages'}


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
        mail(f'Blocked {len(lines)} address(es)', category='Attack', body= '\n'.join(lines[:50]) +
             '\n\nUnban one: sudo fail2ban-client set <jail> unbanip <address>',
             key='ban-' + hashlib.sha1(''.join(lines).encode(), usedforsecurity=False).hexdigest()[:8], level='alert')
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


def web(action):
    """Stop or start the web server: a Compose service with STACK_DIR, else a systemd unit."""
    svc = shlex.quote(C['WEB_SERVICE'])
    return compose(f'{action} {svc}') if C['STACK_DIR'] else sh(f'systemctl {action} {svc}', 60)


def lockdown(reason):
    s = load()
    if C['LOCKDOWN'] == 'web':
        web('stop')
        s['lockdown'] = {'at': now(), 'reason': reason}
        save(s)
        return (f'{C["WEB_SERVICE"]} stopped: {C["APP_NAME"]} is unreachable from the internet until you run: '
                'sudo hostguard unlock')
    return 'LOCKDOWN is "alert": nothing stopped. Investigate now.'


PASSWD, PROC = '/etc/passwd', '/proc'
CGNAT = ipaddress.ip_network('100.64.0.0/10')          # Tailscale and carrier NAT: not the internet


def root_logins_from_internet(journal):
    """Addresses of root SSH logins from public addresses, from sshd's "Accepted ... for root
    from ADDRESS" lines only. Anything else in the text (a loader warning while
    /etc/ld.so.preload points at a missing library mentions "from /etc/ld.so.preload") is
    not a login. The journal is read with -o cat, so sshd's own line starts with "Accepted":
    a user name an attacker chose ("Invalid user Accepted x for root from ...") never does."""
    found = []
    for m in re.finditer(r'^Accepted (?:password|publickey|keyboard-interactive/pam|'
                         r'gssapi-with-mic|hostbased) for root from (\S+) port \d+ ssh2', journal, re.M):
        try:
            ip = ipaddress.ip_address(m.group(1))
        except ValueError:
            continue
        if not (ip.is_private or ip.is_loopback or ip.is_link_local or ip in CGNAT):
            found.append(str(ip))
    return found


def end_sessions(name):
    """End the SSH logins of one account, found by sshd's process title ("sshd: NAME@pts/0",
    "sshd-session: NAME [priv]"). Never by user ID: a second UID 0 account shares root's ID,
    and killing by it would kill every root process on the server (sshd, Docker, the web
    server, this program). Returns the process IDs ended."""
    title = re.compile(r'^sshd(-session)?: ' + re.escape(name) + r'(@|\s|$)')
    ended = []
    for pid in filter(str.isdigit, os.listdir(PROC)):
        try:
            with open(os.path.join(PROC, pid, 'cmdline'), 'rb') as f:
                cmd = f.read().replace(b'\0', b' ').decode(errors='replace').strip()
        except OSError:
            continue
        if title.match(cmd):
            sh(f'kill -9 {pid}')
            ended.append(int(pid))
    return ended


WATCH_LABELS = (('New account that can log in: ', 'New login account'), ('SSH key(s) added', 'SSH key added'),
                ('A program runs from a temporary folder', 'Program running from a temporary folder'),
                ('Security-relevant files changed', 'Security files changed'))


def watch_subject(alerts):
    """What the watch found, in the subject: 'New login account: support; SSH key added'."""
    parts = []
    for a in alerts:
        for start, label in WATCH_LABELS:
            if a.startswith(start):
                m = re.match(r'New account that can log in: "([^"]+)"', a)
                parts.append(f'{label}: {m.group(1)}' if m else label)
                break
        else:
            parts.append(a.splitlines()[0][:60])
    return '; '.join(dict.fromkeys(parts))[:150] or 'Host security alert'


def watch():
    s = load()
    critical, alerts = [], []
    if s.get('lockdown') and C['LOCKDOWN'] == 'web':
        compose('stop nginx')                                 # keep it stopped across restarts
    with open(PASSWD, encoding='utf-8', errors='replace') as f:
        passwd = [line.split(':') for line in f.read().splitlines() if line.count(':') >= 6]
    for p in passwd:
        if p[2] == '0' and p[0] != 'root':
            sh(f'usermod -L -e 1 {shlex.quote(p[0])}')
            ended = end_sessions(p[0])
            critical.append(f'Extra root (UID 0) account "{p[0]}": locked; '
                            + (f'{len(ended)} of its SSH login process(es) ended' if ended else 'no open login of it'))
    logins = sorted(p[0] for p in passwd if not p[6].endswith(('nologin', 'false', 'sync')) and p[0] != 'root')
    known = s.setdefault('logins', logins)
    for u in sorted(set(logins) - set(known)):
        alerts.append(f'New account that can log in: "{u}". If it is not yours: sudo usermod -L {u}')
    s['logins'] = logins
    if os.path.exists('/etc/ld.so.preload') and open('/etc/ld.so.preload').read().strip():
        critical.append('/etc/ld.so.preload is set (a classic rootkit technique):\n' + open('/etc/ld.so.preload').read()[:300])
    qdir = path('quarantine')
    os.makedirs(qdir, exist_ok=True)
    for pid in filter(str.isdigit, os.listdir(PROC)):
        try:
            exe = os.readlink(f'{PROC}/{pid}/exe')
            comm = open(f'{PROC}/{pid}/comm').read().strip()
            cmd = open(f'{PROC}/{pid}/cmdline', 'rb').read().replace(b'\0', b' ').decode(errors='replace')[:200]
        except OSError:
            continue
        if MINER.search(comm) or MINER.search(os.path.basename(exe)) or exe.startswith(('/dev/shm/', '/run/shm/')):  # nosec B108
            q = os.path.join(qdir, f'{pid}-{os.path.basename(exe).replace(" (deleted)", "")}')
            q = quarantine_copy(f'{PROC}/{pid}/exe', q)
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
    for ip in root_logins_from_internet(journal):
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
    try:
        save(s)
    except OSError as e:                              # a full disk must not silence an intrusion alert
        alerts.append(f'host-guard could not save its state: {e}')
    if critical:
        action = lockdown('; '.join(c.splitlines()[0] for c in critical))
        mail('Intrusion signs on the server', '\n\n'.join(critical + alerts) + '\n\n' + action, level='critical',
             category='Intrusion')
    elif alerts:
        key = 'host-' + hashlib.sha1(''.join(alerts).encode(), usedforsecurity=False).hexdigest()[:10]
        mail(watch_subject(alerts), '\n\n'.join(alerts), key=key, level='alert', category='Host change')
    print(f'watch: {len(critical)} critical, {len(alerts)} alert(s)')


QUARANTINE_MAX = 64 * 1024 * 1024


def quarantine_copy(src, dst, limit=QUARANTINE_MAX):
    """Keep at most limit bytes of a suspicious program (a huge or sparse file must not fill
    the disk). Returns where it was kept, or why not."""
    try:
        with open(src, 'rb') as a, open(os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0),
                                                0o600), 'wb') as b:
            left = limit
            while left > 0:
                chunk = a.read(min(1 << 20, left))
                if not chunk:
                    break
                b.write(chunk)
                left -= len(chunk)
            cut = left == 0 and a.read(1)
        os.chmod(dst, 0)
        return dst + (f' (first {limit // (1024 * 1024)} MiB only)' if cut else '')
    except OSError as e:
        try:
            os.remove(dst)
        except OSError:
            pass
        return f'not kept: {e.strerror or e}'


def unlock():
    s = load()
    s.pop('lockdown', None)
    save(s)
    web('start')
    print(C['WEB_SERVICE'], 'started')


# ---------------------------------------------------------------- feeds (every 6 h)
def get_json(url, data=None, timeout=60):
    req = urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None,
                                 headers={'User-Agent': 'host-guard', 'Accept': 'application/json',
                                          'Accept-Encoding': 'gzip',
                                          **({'Content-Type': 'application/json'} if data is not None else {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec B310
        body = r.read(FEED_MAX + 1)
    if body[:2] == b'\x1f\x8b':                 # AWS's price files come gzip-compressed, asked for or not
        body = gzip.GzipFile(fileobj=io.BytesIO(body)).read(FEED_MAX + 1)
    if len(body) > FEED_MAX:
        raise ValueError(f'answer larger than {FEED_MAX // (1024 * 1024)} MiB')
    return json.loads(body.decode('utf-8', 'replace'))


FEED_MAX = 200 * 1024 * 1024           # the CISA list is about 1.5 MB, AWS's biggest price file about 30 MB


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
        try:
            pkgs = python_packages(svc)
        except Exception as e:
            news.append(f'(Python packages of {svc} not readable: {str(e)[:80]})')
            continue
        if not pkgs:
            continue
        try:
            res = get_json(C['OSV_URL'], {'queries': [{'package': {'name': n, 'ecosystem': 'PyPI'}, 'version': v}
                                                      for n, v in sorted(pkgs.items())]})
        except Exception as e:
            news.append(f'(OSV not reachable for {svc}: {str(e)[:80]})')
            continue
        for (n, v), r in zip(sorted(pkgs.items()), res.get('results', []), strict=False):
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
    s['feeds'] = {'at': now(), 'urgent': len(urgent), 'news': len([n for n in news if not n.startswith('(')])}
    hist = s.setdefault('feed_items', [])
    hist.extend({'at': now(), 'text': t.splitlines()[0]} for t in urgent + news if not t.startswith('('))
    s['feed_items'] = hist[-200:]
    sent = True
    if first:
        mail(category='Advisory', subject='Early warning switched on',
             body=f'Baseline recorded: {len(seen)} known advisories. From now on only new '
             'ones that touch this server are mailed.\n\n' + '\n\n'.join(news[:30]))
    elif urgent:
        sent = mail(f'{len(urgent)} security warning(s) for this server', '\n\n'.join(urgent + news), level='critical',
                    category='Advisory')
    elif [n for n in news if not n.startswith('(')]:
        mail(f'{len(news)} new security notice(s)', '\n\n'.join(news), category='Advisory')
    if sent:                                  # an urgent warning that did not go out is tried again next run
        s['seen'] = sorted(seen)
    save(s)
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
    mail(category='Scan', subject='Weekly security scan' + (' (action needed)' if worst or low else ''), body=
         '\n'.join(report) + ('\n\nCritical with a fix available:\n' + '\n'.join(worst) if worst else '') +
         (f'\n\nLynis below {C["LYNIS_MIN"]}: see {path("lynis-report.dat")}' if low else ''),
         level='alert' if worst or low else 'info')
    print('\n'.join(report))


# ---------------------------------------------------------------- S3 (SigV4, stdlib)
def aws_creds():
    if C['AWS_ACCESS_KEY_ID'] and C['AWS_SECRET_ACCESS_KEY']:
        return C['AWS_ACCESS_KEY_ID'], C['AWS_SECRET_ACCESS_KEY'], None
    try:                                                     # the instance role, through IMDSv2
        tok = urllib.request.urlopen(urllib.request.Request(  # nosec B310
            'http://169.254.169.254/latest/api/token', method='PUT',
            headers={'X-aws-ec2-metadata-token-ttl-seconds': '300'}), timeout=3).read().decode()
        h = {'X-aws-ec2-metadata-token': tok}
        base = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
        role = urllib.request.urlopen(urllib.request.Request(base, headers=h), timeout=3).read().decode().split()[0]  # nosec B310
        c = json.load(urllib.request.urlopen(urllib.request.Request(base + role, headers=h), timeout=3))  # nosec B310
        return c['AccessKeyId'], c['SecretAccessKey'], c['Token']
    except Exception:
        raise RuntimeError('no AWS credentials: give the instance a role, or set AWS_ACCESS_KEY_ID and '
                           'AWS_SECRET_ACCESS_KEY in /etc/host-guard/.env') from None


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
    ctx = ssl.create_default_context(cafile=C['S3_CA_BUNDLE']) if C['S3_CA_BUNDLE'] else None
    try:
        with urllib.request.urlopen(req, timeout=300, context=ctx) as r:  # nosec B310
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()
    except (urllib.error.URLError, OSError) as e:          # unreachable, TLS refused: a failure, not a crash
        return 0, {}, str(e).encode()


REMOTES = ('s3', 'azure', 'oci-par')


def remote_kind():
    """Where the off-site copy goes: s3, azure, oci-par, or '' (none)."""
    kind = (C['BACKUP_REMOTE'] or ('s3' if C['S3_BUCKET'] else '')).lower()
    if kind and kind not in REMOTES:
        raise RuntimeError(f'BACKUP_REMOTE={kind} is not one of: {", ".join(REMOTES)}')
    return kind


def remote(method, name, body=b'', digest=''):
    """One request for the off-site copy NAME: PUT, GET or HEAD. Returns (status, headers, body).
    s3 signs with SigV4; azure (SAS) and oci-par (pre-authenticated request) carry their
    permission in the URL, so the URL is a secret."""
    kind, key = remote_kind(), C['S3_PREFIX'] + name
    if kind == 's3':
        extra = {'x-amz-checksum-sha256': base64.b64encode(bytes.fromhex(digest)).decode(),
                 'x-amz-server-side-encryption': 'AES256', 'content-type': 'application/octet-stream'} if digest else None
        return s3(method, key, body, extra)
    url = C['BACKUP_REMOTE_URL']
    if not url:
        return 0, {}, f'BACKUP_REMOTE={kind} needs BACKUP_REMOTE_URL in {C["ENV_FILE"]}'.encode()
    base, _, query = url.partition('?')
    target = base.rstrip('/') + '/' + urllib.parse.quote(key) + ('?' + query if query else '')
    if urllib.parse.urlparse(target).scheme not in ('https', 'http'):
        return 0, {}, b'BACKUP_REMOTE_URL is not an http(s) URL'
    headers = {'Content-Type': 'application/octet-stream'} if method == 'PUT' else {}
    if kind == 'azure' and method == 'PUT':
        headers.update({'x-ms-blob-type': 'BlockBlob', 'x-ms-version': '2021-08-06'})
    req = urllib.request.Request(target, data=body if method == 'PUT' else None, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=300) as r:  # nosec B310 (http or https only, checked above)
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()
    except (urllib.error.URLError, OSError) as e:
        return 0, {}, str(e).encode()


def remote_confirms(headers, data):
    """Does a HEAD answer prove the store holds exactly data? Every size and MD5 the store
    reports must match, and at least one must be there (stores report different ones:
    Content-Length, x-goog-stored-content-length, Content-MD5, x-goog-hash md5=...)."""
    h = {k.lower(): v for k, v in headers.items()}
    md5 = base64.b64encode(hashlib.md5(data, usedforsecurity=False).digest()).decode()
    seen = []
    for k in ('content-length', 'x-goog-stored-content-length'):
        if h.get(k, '').isdigit():
            seen.append(int(h[k]) == len(data))
    if h.get('content-md5'):
        seen.append(h['content-md5'] == md5)
    for part in h.get('x-goog-hash', '').split(','):
        if part.strip().startswith('md5='):
            seen.append(part.strip()[4:] == md5)
    return bool(seen) and all(seen)


# ---------------------------------------------------------------- backup (nightly) and restore test (weekly)
DUMP = ("exec -T {svc} sh -c 'mariadb-dump -uroot -p\"$MARIADB_ROOT_PASSWORD\" --all-databases --single-transaction "
        "--routines --events --triggers --hex-blob'")
MARIADB_DUMP_LOCAL = 'mariadb-dump --all-databases --single-transaction --routines --events --triggers --hex-blob'
PG_DUMP = "exec -T {svc} pg_dumpall -U {user}"
PG_DUMP_LOCAL = 'sudo -u postgres pg_dumpall'
PG_LIST_DBS = 'SELECT datname FROM pg_database WHERE NOT datistemplate'
PG_COUNT_TABLES = ("SELECT count(*) FROM information_schema.tables "
                   "WHERE table_schema NOT IN ('pg_catalog', 'information_schema')")


def backup_configured():
    return bool(C['BACKUP_CMD'] or C['DB_ENGINE'] in ('mariadb', 'postgres'))


def dump_command():
    """The shell command that writes the backup to stdout, and the file's inner extension."""
    if C['BACKUP_CMD']:
        return C['BACKUP_CMD'], 'gz'
    if C['DB_ENGINE'] == 'mariadb':
        if C['STACK_DIR'] and C['DB_SERVICE']:
            return f'docker compose --project-directory {shlex.quote(C["STACK_DIR"])} ' + DUMP.format(
                svc=shlex.quote(C['DB_SERVICE'])), 'sql.gz'
        return MARIADB_DUMP_LOCAL, 'sql.gz'
    if C['DB_ENGINE'] == 'postgres':
        if C['STACK_DIR'] and C['DB_SERVICE']:
            return f'docker compose --project-directory {shlex.quote(C["STACK_DIR"])} ' + PG_DUMP.format(
                svc=shlex.quote(C['DB_SERVICE']), user=shlex.quote(C['PG_USER'])), 'sql.gz'
        return PG_DUMP_LOCAL, 'sql.gz'
    return None, None


def backup():
    os.makedirs(C['BACKUP_DIR'], mode=0o700, exist_ok=True)
    if not C['BACKUP_PASSPHRASE']:
        raise SystemExit(f'no BACKUP_PASSPHRASE in {C["ENV_FILE"]} (install.sh creates it; keep a copy offline)')
    cmd, ext = dump_command()
    if not cmd:
        print('nothing to back up: set DB_ENGINE or BACKUP_CMD (docs/CONFIGURATION.md)')
        return
    t = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    name = f'{C["BACKUP_PREFIX"]}-{t}.{ext}.gpg'
    target = os.path.join(C['BACKUP_DIR'], name)
    raw = target[:-4]
    rc, text = sh('bash -o pipefail -c ' + shlex.quote(f'{cmd} | gzip -9 > {shlex.quote(raw)}'), 1800)
    size = os.path.getsize(raw) if os.path.exists(raw) else 0
    if rc != 0 or size < int(C['BACKUP_MIN_BYTES']):
        mail('Backup FAILED', f'The backup did not complete (exit {rc}, {size} bytes):\n{text[-800:]}',
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
    uploaded, kind = None, remote_kind()
    if kind:
        data = open(target, 'rb').read()
        st, hdr, body = remote('PUT', name, data, digest)
        if st not in (200, 201):
            mail('Backup upload FAILED', f'The off-site store ({kind}) answered {st}: {body[:400]!r}',
                 key='backup-upload', level='alert')
            raise SystemExit(1)
        st2, hdr2, _ = remote('HEAD', name)
        uploaded = st2 == 200 and remote_confirms(hdr2, data)
        if not uploaded:
            mail('Backup upload not confirmed', f'The off-site store ({kind}) answered {st2} to HEAD',
                 key='backup-upload', level='alert')
            raise SystemExit(1)
        resolved('backup-upload', 'Backup uploads working again')
    for old in sorted(glob.glob(os.path.join(C['BACKUP_DIR'], f'{C["BACKUP_PREFIX"]}-*.gpg')))[:-int(C['BACKUP_KEEP'])]:
        os.remove(old)
    s = load()
    s['backup'] = {'at': now(), 'name': name, 'bytes': os.path.getsize(target), 'sha256': digest, 's3': uploaded,
                   'remote': kind if uploaded else ''}
    save(s)
    resolved('backup-failed', 'Backups working again')
    print(f'backup: {name}, {os.path.getsize(target)} bytes, off-site={kind if uploaded else "no"}')


MARIADB_AS_ROOT = 'MYSQL_PWD="$MARIADB_ROOT_PASSWORD" mariadb -uroot'    # the password stays off every command line


def db_env(name, value):
    """A root-only env file for the throwaway database (a password on a command line is readable in /proc)."""
    f = path('restore-test.env')
    with open(os.open(f, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0), 0o600), 'w') as fh:
        fh.write(f'{name}={value}\n')
    return shlex.quote(f)


def restore_test():
    """The newest backup, from S3 when configured (else local), decrypted and loaded into
    a throwaway MariaDB or PostgreSQL container (table counts reported). Output of
    BACKUP_CMD, or a server without Docker: decrypted and unpacked completely."""
    s = load()
    name = s.get('backup', {}).get('name')
    if not name:
        raise SystemExit('no backup yet')
    work = path('restore-test')
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work, mode=0o700)
    enc = os.path.join(work, name)
    if remote_kind():
        st, hdr, body = remote('GET', name)
        if st != 200:
            mail(category='Backup', subject='Restore test FAILED',
                 body=f'Could not download {name} from the off-site store ({remote_kind()}): {st}',
                 level='alert')
            raise SystemExit(1)
        open(enc, 'wb').write(body)
    else:
        shutil.copy(os.path.join(C['BACKUP_DIR'], name), enc)
    ok_sum = hashlib.sha256(open(enc, 'rb').read()).hexdigest() == s['backup']['sha256']
    rc, text = sh('bash -o pipefail -c ' + shlex.quote(f'gpg --batch --yes --pinentry-mode loopback --passphrase-fd 0 '
                                                       f'-d {enc} | gunzip > {work}/dump.sql'),
                  900, input=C['BACKUP_PASSPHRASE'] + '\n') if ok_sum else (1, 'checksum differs: not opened')
    lines = []
    docker = shutil.which('docker') is not None
    how = 'decrypted and unpacked'
    if rc == 0 and ok_sum and (C['BACKUP_CMD'] or C['DB_ENGINE'] not in ('mariadb', 'postgres') or not docker):
        size = os.path.getsize(f'{work}/dump.sql')
        lines = [f'{size // 1024} KB after unpacking'] if size > 0 else []
    elif rc == 0 and ok_sum and C['DB_ENGINE'] == 'postgres':
        how = 'into a throwaway PostgreSQL'
        pw = base64.b16encode(os.urandom(12)).decode()
        cname = 'host-guard-restore-test'
        sh(f'docker rm -f {cname}', 30)
        sh(f'docker run -d --name {cname} --network none --env-file {db_env("POSTGRES_PASSWORD", pw)} '
           f'-v {work}:/restore:ro {C["PG_IMAGE"]}', 300)
        for _ in range(60):
            if sh(f'docker exec {cname} pg_isready -U postgres', 20)[0] == 0:
                break
            time.sleep(2)
        rc, text = sh(f'docker exec {cname} psql -q -U postgres -v ON_ERROR_STOP=0 -f /restore/dump.sql', 1800)
        if rc == 0:
            psql = f'docker exec {cname} psql -U postgres -At'
            dbs = sh(psql + ' -c ' + shlex.quote(PG_LIST_DBS), 60)[1]
            for db in dbs.split():                     # names only go to -d, quoted; the SQL is fixed
                n = sh(f'{psql} -d {shlex.quote(db)} -c ' + shlex.quote(PG_COUNT_TABLES), 60)[1]
                lines.append(f'{db}: {n.strip()} tables')
        sh(f'docker rm -f {cname}', 60)
    elif rc == 0 and ok_sum:
        how = 'into a throwaway MariaDB'
        pw = base64.b16encode(os.urandom(12)).decode()
        cname = 'host-guard-restore-test'
        sh(f'docker rm -f {cname}', 30)
        sh(f'docker run -d --name {cname} --network none --env-file {db_env("MARIADB_ROOT_PASSWORD", pw)} '
           f'-v {work}:/restore:ro {C["MARIADB_IMAGE"]}', 300)
        for _ in range(60):
            if sh(f'docker exec {cname} healthcheck.sh --connect', 20)[0] == 0:
                break
            time.sleep(2)
        rc, text = sh(f'docker exec {cname} sh -c ' + shlex.quote(MARIADB_AS_ROOT + ' < /restore/dump.sql'), 1800)
        if rc == 0:
            q = ("SELECT concat(table_schema, '.', table_name), table_rows FROM information_schema.tables WHERE "
                 "table_schema NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys') "
                 "ORDER BY table_rows DESC LIMIT 12")
            rc2, rows = sh(f'docker exec {cname} sh -c ' + shlex.quote(MARIADB_AS_ROOT + ' -N -e ' + shlex.quote(q)), 120)
            lines = rows.splitlines()
        sh(f'docker rm -f {cname}', 60)
    shutil.rmtree(work, ignore_errors=True)
    good = rc == 0 and ok_sum and len(lines) > 0
    s = load()
    s['restore_test'] = {'at': now(), 'ok': good, 'backup': name, 'tables': lines[:12]}
    save(s)
    mail(category='Backup', subject='Restore test ' + ('passed' if good else 'FAILED'), body=
         f'Backup {name}: checksum {"matches" if ok_sum else "DOES NOT MATCH"}, restored '
         f'{how if good else "with errors: " + text[-400:]}.\n\nWhat it holds:\n' +
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
        mail(category='Updates', subject='Reboot postponed',
             body='Security updates need a reboot, but data lake replication is not healthy '
             f'({detail}). It is tried again in the next window.', key='reboot-postponed', level='alert')
        return
    backup()
    pkgs = open('/var/run/reboot-required.pkgs').read().split() if os.path.exists('/var/run/reboot-required.pkgs') else []
    s = load()
    s['planned_reboot'] = {'at': now(), 'packages': pkgs}
    save(s)
    mail(category='Updates', subject='Rebooting for security updates',
         body='Packages: ' + ' '.join(pkgs[:30]) + '\nA fresh backup was taken first. '
         'You get a mail when the server is back, with its health.')
    sh('systemctl reboot', 30)


def boot():
    time.sleep(int(os.environ.get('HG_BOOT_WAIT', '90')))
    s = load()
    planned = s.pop('planned_reboot', None)
    save(s)
    problems = [f'{subj}' for key, bad, subj, _ in checks() if bad and key != 'reboot']
    mail(category='Updates' if planned else 'Health',
         subject='Server started' + (' after the planned patch reboot' if planned else ' (not planned by host-guard)'), body=
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
        tok = urllib.request.urlopen(urllib.request.Request(  # nosec B310
            'http://169.254.169.254/latest/api/token', method='PUT',
            headers={'X-aws-ec2-metadata-token-ttl-seconds': '60'}), timeout=2).read().decode()
        return urllib.request.urlopen(urllib.request.Request(  # nosec B310
            'http://169.254.169.254/latest/meta-data/' + path_, headers={'X-aws-ec2-metadata-token': tok}),
            timeout=2).read().decode().strip()
    except Exception:
        return None


MD = 'http://169.254.169.254'
CLOUD_NAMES = {'aws': 'AWS', 'gcp': 'Google Cloud', 'azure': 'Azure', 'oci': 'Oracle Cloud',
               'other': 'not a known cloud (a VPS or bare metal)'}
_CLOUD = {}


def _md(url, headers, timeout=1.0):
    r = urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=timeout)  # nosec B310 (fixed URLs)
    return r.read().decode().strip(), r.headers


def cloud_info():
    """The cloud this server runs on and its machine type and region, from the cloud's own
    metadata service (each answers only with its own header, so a wrong guess fails fast).
    CLOUD=aws|gcp|azure|oci|other skips the guessing. Asked once per run."""
    if _CLOUD:
        return _CLOUD

    def aws():
        t = imds('instance-type')
        return {'type': t, 'region': imds('placement/region') or ''} if t else None

    def gcp():
        h = {'Metadata-Flavor': 'Google'}
        text, hdr = _md(MD + '/computeMetadata/v1/instance/machine-type', h)
        if hdr.get('Metadata-Flavor') != 'Google':
            return None
        return {'type': text.rsplit('/', 1)[-1],
                'region': _md(MD + '/computeMetadata/v1/instance/zone', h)[0].rsplit('/', 1)[-1]}

    def azure():
        d = json.loads(_md(MD + '/metadata/instance/compute?api-version=2021-02-01', {'Metadata': 'true'})[0])
        return {'type': d['vmSize'], 'region': d['location']}

    def oci():
        d = json.loads(_md(MD + '/opc/v2/instance/', {'Authorization': 'Bearer Oracle'})[0])
        return {'type': d['shape'], 'region': d.get('canonicalRegionName') or d.get('region', '')}

    probes = {'aws': aws, 'gcp': gcp, 'azure': azure, 'oci': oci}
    want = C['CLOUD'].lower()
    _CLOUD.update({'cloud': want if want else 'other', 'type': '', 'region': ''})
    for name in ([want] if want in probes else [] if want else list(probes)):
        try:
            got = probes[name]()
        except Exception:
            got = None
        if got:
            _CLOUD.update(cloud=name, **got)
            break
    return _CLOUD


def machine_kind():
    """bare metal, a virtual machine (kvm, xen, microsoft, ...), or a container."""
    rc, text = sh('systemd-detect-virt 2>/dev/null', 10)
    v = text.strip().splitlines()[0] if text.strip() else ''
    if v == 'none':
        return 'bare metal'
    return f'virtual machine ({v})' if v else 'not known (no systemd-detect-virt)'


ADVICE = {
    'aws': ['Off-site copies: an S3 bucket (--s3-bucket NAME --region REGION); give the instance a role that may '
            'write to it, and no keys are needed.',
            'Running cost: estimated from AWS\'s published prices.'],
    'gcp': ['Off-site copies: a Cloud Storage bucket through its S3 interoperability: S3_BUCKET, '
            'S3_ENDPOINT=https://storage.googleapis.com, AWS_REGION=auto, and an HMAC key (a service account\'s) '
            'as AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in .env.',
            'SSH: with OS Login, --login-user is your OS Login name (for example you_example_com).',
            'Running cost: set PRICE_HOUR (and the other PRICE_ values) to Google\'s prices.'],
    'azure': ['Off-site copies: BACKUP_REMOTE=azure in guard.conf and a container SAS URL (read, create, write) '
              'as BACKUP_REMOTE_URL in .env.',
              'SSH: the image\'s admin user is usually azureuser.',
              'Running cost: set PRICE_HOUR (and the other PRICE_ values) to Azure\'s prices.'],
    'oci': ['Off-site copies: BACKUP_REMOTE=oci-par in guard.conf and a bucket pre-authenticated request URL '
            '(objects read and write) as BACKUP_REMOTE_URL in .env; or the S3 compatibility API with a customer '
            'secret key (S3_ENDPOINT=https://NAMESPACE.compat.objectstorage.REGION.oraclecloud.com).',
            'Firewall: Oracle\'s Ubuntu images keep their own rules in /etc/iptables/rules.v4; host-guard adds to them.',
            'Running cost: set PRICE_HOUR (and the other PRICE_ values) to Oracle\'s prices.'],
    'other': ['Off-site copies: any S3-compatible store (Cloudflare R2, Backblaze B2, Wasabi, MinIO, Hetzner) '
              'with S3_BUCKET, S3_ENDPOINT and its keys in .env; Azure Blob or an OCI pre-authenticated URL work too.',
              'Running cost: set PRICE_HOUR (and the other PRICE_ values) to your provider\'s prices, or leave it.'],
}


def whereami():
    """Where host-guard runs and what fits there. --short prints only the cloud name."""
    c = cloud_info()
    if '--short' in sys.argv:
        print(c['cloud'])
        return
    print(f'Cloud: {cloud_text()}')
    print(f'Machine: {machine_kind()}')
    for line in ADVICE.get(c['cloud'], ADVICE['other']):
        print(f'  - {line}')


def cloud_text():
    c = cloud_info()
    where = ', '.join(x for x in (c['type'], c['region']) if x)
    return CLOUD_NAMES.get(c['cloud'], c['cloud']) + (f' ({where})' if where else '')


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
    for a, b in zip(ss, ss[1:], strict=False):
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
    on_aws = cloud_info()['cloud'] == 'aws' or bool(C['INSTANCE_TYPE'])
    itype = C['INSTANCE_TYPE'] or (imds('instance-type') if on_aws else '') or ''
    region = C['AWS_REGION'] or 'ap-south-1'
    pf = price_files(region) if on_aws else {}
    spec = pf.get('ec2', {}).get(itype, {})
    hour = float(C['PRICE_HOUR']) if C['PRICE_HOUR'] else spec.get('price')
    live = bool(spec) and not C['PRICE_HOUR']
    ebs_p = rate(pf.get('ebs'), 'Storage General Purpose gp3 GB Mo', default=float(C['PRICE_EBS_GB_MONTH']))
    egress_p = rate(pf.get('transfer'), 'DataTransfer External Outbound Next 10 TB', default=float(C['PRICE_EGRESS_GB']))
    ipv4_p = rate(pf.get('vpc'), 'In use Public IPv4', default=float(C['PRICE_IPV4_HOUR']))
    s3_p = rate(pf.get('s3'), 'Standard Storage First 50 TB', default=float(C['PRICE_S3_GB_MONTH']))
    public = C['PUBLIC_IPV4'] == 'yes' or (C['PUBLIC_IPV4'] == 'auto' and on_aws and bool(imds('public-ipv4')))
    use = usage_stats() or {}
    disk = ebs_gb()
    b = load().get('backup', {})
    s3_gb = (b.get('bytes', 0) / 1e9) * int(C['S3_RETENTION_DAYS']) if remote_kind() == 's3' else 0.0
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
            'priced': on_aws or bool(C['PRICE_HOUR']),
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
    if not e['priced']:
        return ('== Running cost\n'
                f'This server runs on {cloud_text()}. The estimate is built from AWS\'s published prices, so it is '
                'not made here: set PRICE_HOUR (and PRICE_EBS_GB_MONTH, PRICE_EGRESS_GB, PRICE_IPV4_HOUR) in '
                'guard.conf to your provider\'s prices for one.'), e
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


def _meminfo():
    try:
        m = {}
        for line in open('/proc/meminfo'):
            k, v = line.split(':', 1)
            m[k] = int(v.split()[0]) / 1048576
        return m['MemTotal'], m['MemAvailable']
    except (OSError, KeyError, ValueError):
        return None


def _uptime():
    try:
        days = float(open('/proc/uptime').read().split()[0]) / 86400
        load_ = open('/proc/loadavg').read().split()[:3]
        return f'{days:.0f} days' if days >= 1 else f'{days * 24:.0f} h', ' / '.join(load_)
    except (OSError, ValueError, IndexError):
        return None, None


def report_text():
    s, day = load(), now() - 86400
    glance = []                                   # (area, OK | ATTENTION, detail)

    def mark(area, ok, detail):
        glance.append((area, 'OK' if ok else 'ATTENTION', detail))

    up, load_ = _uptime()
    head = [f'Server: {C["SITE"]}', f'Runs on: {cloud_text()}', f'Report time: {stamp()}']
    head += [f'Up for: {up}', f'Load (1/5/15 min): {load_}'] if up else []

    parts = ['== Memory and disk']
    mem, used = _meminfo(), None
    mem_ok = True
    if mem:
        total, avail = mem
        used = 100 - avail * 100 / total
        parts.append(f'Memory used: {used:.0f}% ({total - avail:.1f} of {total:.1f} GB)')
        mem_ok = avail * 100 / total >= float(C['MEM_FREE_MIN'])
    du = shutil.disk_usage('/')
    disk = int(du.used * 100 / du.total)
    folder = out('du -sh ' + C['BACKUP_DIR'] + ' 2>/dev/null').split('\t')[0]
    parts += [f'Root disk used: {disk}% ({du.free / 1e9:.0f} GB free of {du.total / 1e9:.0f} GB)',
              f'Backups folder: {folder or "empty"}']
    mark('Memory and disk', mem_ok and disk < int(C['DISK_WARN']),
         f'disk {disk}% used' + (f', memory {used:.0f}% used' if used is not None else ''))

    rows = containers()
    bad = [r['service'] for r in rows if r.get('service') not in ONE_SHOT and
           (r.get('state') != 'running' or r.get('health') == 'unhealthy')]
    if C['STACK_DIR']:
        parts += ['', '== Containers'] + [f'  {r["service"]:<14}  {r["status"]}' for r in rows]
        live = [r for r in rows if r.get('service') not in ONE_SHOT]      # one-shot setup containers exit by design
        mark('Containers', not bad, f'{len(live) - len(bad)} of {len(live)} services running'
             + (f'; not well: {", ".join(bad)}' if bad else ''))

    st, fleet, alerts = api('/status'), api('/fleet/summary'), api('/alerts')
    if st:
        parts += ['', '== EdgeShell']
    if st and 'error' not in st:
        parts.append(f'Version {st.get("version")}, nodes online {st["nodes"]["online"]} of {st["nodes"]["total"]}')
        if fleet and 'fleet' in fleet:
            parts += [f'  {c["name"]:<20}  {c["online"]}/{c["total"]} online  availability {c.get("availability_percent")}%'
                      for c in fleet.get('categories', [])]
        crit = 0
        if alerts and 'summary' in alerts:
            a = alerts['summary']
            crit = a.get('critical', 0)
            parts.append(f'Open alerts: {a.get("critical", 0)} critical, {a.get("warning", 0)} warning on '
                         f'{a.get("nodes", 0)} node(s)')
        mark('EdgeShell', not crit, f'{st.get("version")}, {st["nodes"]["online"]}/{st["nodes"]["total"]} nodes online'
             + (f', {crit} critical node alert(s)' if crit else ''))
    elif st:
        parts.append(f'API: {st.get("error")}')

    ok, detail = replication()
    if ok is not None:
        parts += ['', '== Database replica', f'Replication: {detail}']
        mark('Database replication', ok, detail)

    b, rt = s.get('backup', {}), s.get('restore_test', {})
    fresh = bool(b.get('at')) and now() - b['at'] < float(C['BACKUP_MAX_AGE_H']) * 3600
    parts += ['', '== Backups', f'Last backup: {b.get("name", "none")} ({ago(b.get("at"))}, '
              f'{b.get("bytes", 0) // 1024} KB, off-site copy: {b.get("remote") or ("s3" if b.get("s3") else "no")})',
              f'Restore test: {"PASSED" if rt.get("ok") else "not passed yet"} ({ago(rt.get("at"))})']
    mark('Backups', (fresh and rt.get('ok', True)) if backup_configured() else False, f'last {ago(b.get("at"))}, restore test '
         + ('passed' if rt.get('ok') else 'not run yet' if not rt else 'FAILED'))

    rc, ssh_fail = sh("journalctl -u ssh -u sshd --since -24h -o cat 2>/dev/null | grep -cE 'Invalid user|"
                      "authentication failure|Failed password|Connection closed by authenticating'")
    jails = fail2ban()
    day_bans = [x for x in s.get('ban_log', []) if x['at'] > day]
    find = [f['text'] for f in s.get('findings', []) if f['at'] > day]
    parts += ['', '== Security (24 h)', f'SSH failed attempts: {ssh_fail.strip() or 0}',
              f'Addresses banned: {len(day_bans)}',
              'Banned now (since start): ' + (', '.join(f'{j} {v["now"]} ({v["total"]})' for j, v in jails.items())
                                             or 'fail2ban not running (run install.sh again)'),
              f'Host watch: {len(find)} finding(s)'] + ['  ' + f for f in find[:10]]
    if s.get('lockdown'):
        parts.append(f'LOCKDOWN since {stamp(s["lockdown"]["at"])}: {s["lockdown"]["reason"]}')
    mark('Intrusion watch', not find and not s.get('lockdown'),
         f'{len(find)} finding(s), {len(day_bans)} address(es) banned' + (', LOCKDOWN' if s.get('lockdown') else ''))

    items = [f['text'] for f in s.get('feed_items', []) if f['at'] > day]
    parts += ['', '== Early warning (24 h)', f'New items: {len(items)} (last check {ago(s.get("feeds", {}).get("at"))})']
    parts += ['  ' + i for i in items[:15]]
    urgent = s.get('feeds', {}).get('urgent', 0)
    mark('Early warning', not urgent, f'{len(items)} new notice(s)' + (f', {urgent} urgent' if urgent else ''))

    upg = out("grep -h 'Packages that will be upgraded' /var/log/unattended-upgrades/unattended-upgrades.log "
              "2>/dev/null | tail -3")
    pend = out("apt list --upgradable 2>/dev/null | grep -c upgradable")
    reboot = os.path.exists('/var/run/reboot-required')
    parts += ['', '== Updates', f'Pending: {pend}', 'Recently applied: ' + (upg or 'none logged'),
              'Reboot: needed, done in the maintenance window after a backup' if reboot else 'Reboot: not needed']
    mark('Updates', not reboot, f'{pend} pending' + (', reboot in the maintenance window' if reboot else ''))

    sc = s.get('scan', {})
    parts += ['', '== Last weekly scan', f'Ran: {ago(sc.get("at"))}'] + ['  ' + x for x in sc.get('lines', [])]
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
    parts += ['', f'== Mails in 24 h: {len(sent)}'] + [f'  {stamp(m["at"])[11:16]}  {m["subject"]}' for m in sent[-15:]]
    held = [h for h in load('mail-log.json').get('held_log', []) if h['at'] > day]
    if held:
        by_cat = {}
        for h in held:
            by_cat[h['category']] = by_cat.get(h['category'], 0) + 1
        parts += [f'Held back by flood protection: {len(held)} ('
                  + ', '.join(f'{c} {n}' for c, n in sorted(by_cat.items())) + ')']

    problems = [v.get('subject', k) for k, v in sorted(load('alerts.json').items())]
    top = head + ['', '== At a glance'] + [f'  {a:<22}  {st_}  {d}' for a, st_, d in glance]
    if problems:
        top += ['', '== Needs attention'] + ['  ' + p for p in problems]
    return '\n'.join(str(p) for p in top + [''] + parts)


def report():
    text = report_text()
    open_problems = len(load('alerts.json'))
    mail('Daily report' + (f': {open_problems} open problem(s)' if open_problems else ': all good'), text,
         level='daily', category='Daily report')
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


# ---------------------------------------------------------------- the panel's sign-in mails (root)
OUTBOX_NAME = re.compile(r'^\d{10,16}-[0-9a-f]{16}\.json$')


def panel_admins():
    raw = C['PANEL_ADMINS'] or C['MAIL_TO']
    return {a.lower() for a in re.split(r'[,\s]+', raw.strip()) if a and EMAIL.match(a)}


def panel_outbox():
    """Mail what the panel left in its outbox: a sign-in code (only to that address, and only
    if it is an admin) or a sign-in notice (to every admin). The panel runs unprivileged and
    cannot read the mail password; this runs as root (host-guard-panel-mail.path) and trusts
    nothing in the folder: no link is followed, only small regular files of the panel's own
    user are read, every entry is removed, and codes are limited to 5 per address in
    15 minutes and 30 an hour in all, even if the panel itself were taken over."""
    import pwd
    import stat as st_
    d = C['PANEL_OUTBOX']
    try:
        names = sorted(os.listdir(d))
    except OSError:
        print('panel-outbox: nothing to do')
        return
    try:
        uid = pwd.getpwnam(C['PANEL_USER']).pw_uid
    except (KeyError, ImportError):
        uid = None
    admins = panel_admins()
    s = load('panel-mail.json')
    sent = [x for x in s.get('sent', []) if x.get('at', 0) > now() - 3600]
    done = refused = 0
    for n in names:
        p = os.path.join(d, n)
        data = None
        if OUTBOX_NAME.match(n):
            fd = None
            try:
                fd = os.open(p, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
                info = os.fstat(fd)
                if st_.S_ISREG(info.st_mode) and info.st_size <= 2048 and (uid is None or info.st_uid == uid):
                    data = json.loads(os.read(fd, 2049).decode('utf-8'))
            except (OSError, ValueError):
                data = None
            finally:
                if fd is not None:
                    os.close(fd)
        elif n.endswith('.tmp'):
            try:
                if now() - os.lstat(p).st_mtime < 60:
                    continue                                 # being written right now
            except OSError:
                continue
        try:                                                 # every entry goes, used or not (no endless trigger)
            if os.path.isdir(p) and not os.path.islink(p):
                shutil.rmtree(p)
            else:
                os.unlink(p)
        except OSError:
            pass
        if not isinstance(data, dict):
            refused += 1
            continue
        email, kind = str(data.get('email', '')).strip().lower(), data.get('kind')
        try:
            fresh = now() - float(data.get('at', 0)) < 600
        except (TypeError, ValueError):
            fresh = False
        if email not in admins or not fresh:
            refused += 1                                     # not an admin: nothing is sent, the panel cannot tell
            continue
        if kind == 'code' and re.fullmatch(r'\d{6}', str(data.get('code', ''))):
            mine = [x for x in sent if x['email'] == email and x['at'] > now() - 900]
            if len(mine) >= 5 or len(sent) >= 30:
                refused += 1
                print(f'panel-outbox: code for {email} not sent (limit reached)')
                continue
            mail(subject='Your dashboard sign-in code', category='Sign-in', level='info', to=[email], body=
                 f'Code: {data["code"]}\n\nIt works once, for 10 minutes, on the host-guard dashboard of {C["SITE"]}.\n\n'
                 'Did you not ask for it? Someone who can reach the dashboard (it is only reachable through a '
                 'tunnel to this server) entered your address. Nothing happens without the code. Tell the other '
                 'admins, and look at the audit log: sudo -u hgpanel python3 /usr/local/lib/host-guard-panel/hgpanel.py audit')
            sent.append({'at': now(), 'email': email})
            done += 1
        elif kind == 'signed-in':
            mail(subject=f'Dashboard sign-in: {email}', category='Sign-in', level='info', body=
                 f'{email} signed in to the host-guard dashboard of {C["SITE"]} at {stamp()}.\n\n'
                 'Not expected? The session ends after 15 minutes idle or 8 hours. Look at the audit log: '
                 'sudo -u hgpanel python3 /usr/local/lib/host-guard-panel/hgpanel.py audit')
            done += 1
        else:
            refused += 1
    s['sent'] = sent
    save(s, 'panel-mail.json')
    print(f'panel-outbox: {done} mailed, {refused} refused')


def test_mail():
    ok = mail('Test mail', 'If you can read this, host-guard can reach you.', category='Test')
    print('sent' if ok else 'NOT sent: check /etc/msmtprc and the MAIL_TO setting')
    sys.exit(0 if ok else 1)


COMMANDS = {'health': health, 'cost': cost, 'watch': watch, 'feeds': feeds, 'scan': scan, 'backup': backup,
            'restore-test': restore_test, 'patch-window': patch_window, 'boot': boot, 'report': report,
            'status': status, 'test-mail': test_mail, 'unlock': unlock, 'export': export, 'whereami': whereami,
            'panel-outbox': lambda: panel_outbox()}

if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] in COMMANDS or sys.argv[1:] == ['whereami', '--short']:
        COMMANDS[sys.argv[1]]()
    else:
        print(__doc__)
        sys.exit(2)
