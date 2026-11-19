#!/usr/bin/env python3
"""host-guard: install, upgrade, roll back and remove host-guard, with a manifest of every change.

    host-guard install --mail-to you@example.com [install options] [--with-panel] [--panel-port 8650]
    host-guard upgrade                 the version of this copy, with the options saved at install
    host-guard rollback [--to VERSION] undo the last install (or every install back to VERSION)
    host-guard uninstall [--purge] [--delete-backups]
    host-guard status | history | version
    host-guard report | test-mail | backup | restore-test | health | ...   (run by hostguard)

Common flags: --yes (no questions), --force (also undo files an admin changed since),
--allow-downgrade (install an older version over a newer one without asking).

Layout (one folder, nothing else is written by the manager):
    /opt/host-guard/releases/<version>/          the code of each installed version (3 kept)
    /opt/host-guard/current -> releases/<version>
    /opt/host-guard/history/NNNN-<action>-<version>/manifest.json   what that run changed
    /opt/host-guard/history/NNNN-.../files/      byte-for-byte copies of the files it replaced
    /opt/host-guard/state.json                   the installed version and the saved options

Rules
  * Before an install every file in the watched places is recorded (hash, mode, owner, link
    target) and copied; after it, whatever changed goes into the manifest. A file a package
    brought in belongs to that package and is left to dpkg.
  * An install that fails is undone at once, from its own manifest.
  * Rollback restores a file only while it still has the content that install wrote. A file
    an admin changed since is kept and reported (--force restores it anyway).
  * SSH and fail2ban settings are checked (sshd -t, fail2ban-client -t) before they apply;
    if a check fails, the rollback is reverted and nothing changes.
  * Never rolled back: /etc/host-guard (secrets and settings only move forward), the state
    and the backups. Packages are never removed by a rollback; uninstall --purge removes
    only the packages host-guard itself added, and only when nothing else needs them.
"""
import fcntl
import glob
import hashlib
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import time

ROOT = os.environ.get('HG_ROOT', '')           # a prefix for every system path (tests only)
BASE = ROOT + os.environ.get('HG_BASE', '/opt/host-guard')
ENGINE = '/usr/local/sbin/hostguard'
WRAPPER = '/usr/local/sbin/host-guard'
KEEP_RELEASES = 3
MAX_COPY = 8 * 1024 * 1024

# Where install.sh, the base hardening, an app's own hardening and the panel write.
WATCH_DIRS = ['/etc/ssh/sshd_config.d', '/etc/fail2ban/jail.d', '/etc/fail2ban/filter.d', '/etc/sysctl.d',
              '/etc/apt/apt.conf.d', '/etc/apt/sources.list.d', '/etc/apt/keyrings', '/etc/logrotate.d',
              '/etc/systemd/system', '/usr/local/sbin', '/usr/local/lib/host-guard-panel', '/etc/host-guard-panel']
WATCH_GLOBS = ['/etc/systemd/system/*.wants']
WATCH_FILES = ['/etc/msmtprc', '/etc/docker/daemon.json']
NOT_TRACKED = {WRAPPER}                       # the manager itself only ever moves forward
DIRS = ['/etc/host-guard', '/var/lib/host-guard', '/var/backups/host-guard', '/var/lib/host-guard-panel',
        '/var/lib/host-guard-export', '/etc/host-guard-panel', '/usr/local/lib/host-guard-panel']
USERS = ['hgpanel']
# What install.sh asks apt for; uninstall --purge considers these and their automatic dependencies.
KNOWN_PACKAGES = {'msmtp', 'msmtp-mta', 'unattended-upgrades', 'gnupg', 'lynis', 'curl', 'ca-certificates',
                  'iptables', 'openssl', 'fail2ban', 'python3-systemd', 'trivy'}
# Files an install made before the manager existed ("unversioned"), removed by uninstall.
LEGACY = ['/usr/local/sbin/hostguard', '/usr/local/sbin/host-guard-firewall', '/etc/sysctl.d/99-host-guard.conf',
          '/etc/apt/apt.conf.d/52host-guard-unattended', '/etc/ssh/sshd_config.d/01-host-guard.conf',
          '/etc/fail2ban/jail.d/host-guard.local', '/usr/local/lib/host-guard-panel/hgpanel.py',
          '/etc/host-guard-panel/panel.conf']

VALUE_FLAGS = {'--mail-to', '--mail-from', '--domain', '--stack-dir', '--edgeshell-dir', '--profile', '--web-logs',
               '--login-user', '--tz', '--report-time', '--maintenance', '--s3-bucket', '--s3-endpoint', '--region',
               '--smtp-file', '--smtp-host', '--smtp-port', '--admin-ip', '--lockdown'}
BOOL_FLAGS = {'--with-trivy', '--smtp-plain', '--no-base-hardening'}
RELEASE_FILES = ('VERSION', 'LICENSE', 'guard', 'panel', 'examples')
NOT_SAVED = {'--smtp-file', '--mail-to', '--mail-from'}   # one-off, or kept in guard.conf


class Fail(Exception):
    pass


def say(msg):
    print(f'==> {msg}', flush=True)


def R(p):
    return ROOT + p


def unR(p):
    return p[len(ROOT):] if ROOT and p.startswith(ROOT) else p


# ---------------------------------------------------------------- commands on the system
def run(cmd, **kw):
    """Run a command; returns the exit code. Replaced in the tests."""
    try:
        # argument lists only, never a shell
        return subprocess.run(cmd, check=False, **kw).returncode  # nosec B603
    except FileNotFoundError:
        return 127


def run_out(cmd):
    try:
        p = subprocess.run(cmd, check=False, capture_output=True, text=True)  # nosec B603
        return p.returncode, p.stdout
    except FileNotFoundError:
        return 127, ''


def have(cmd):
    return shutil.which(cmd) is not None and not ROOT


def installed_packages():
    if not have('dpkg-query'):
        return set()
    rc, text = run_out(['dpkg-query', '-W', '-f=${db:Status-Abbrev} ${Package}\n'])
    return {line.split()[1] for line in text.splitlines() if line.startswith('ii') and len(line.split()) > 1}


def auto_packages():
    if not have('apt-mark'):
        return set()
    return set(run_out(['apt-mark', 'showauto'])[1].split())


def dpkg_owned(paths):
    if not paths or not have('dpkg-query'):
        return set()
    owned = set()
    for i in range(0, len(paths), 200):
        _, text = run_out(['dpkg-query', '-S', *paths[i:i + 200]])
        for line in text.splitlines():
            if ': ' in line and not line.startswith('diversion'):
                owned.add(line.split(': ', 1)[1].strip())
    return owned


def user_exists(name):
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


# ---------------------------------------------------------------- versions
def parse_version(v):
    m = re.match(r'^v?(\d+)\.(\d+)\.(\d+)', v or '')
    return tuple(int(x) for x in m.groups()) if m else (-1,)


def read_version(payload):
    with open(os.path.join(payload, 'VERSION'), encoding='utf-8') as f:
        v = f.read().strip()
    if parse_version(v) == (-1,):
        raise Fail(f'{payload}/VERSION is not a version: {v!r}')
    return v


def find_payload():
    """The code this copy of the manager installs: bundled in the pip package, a git
    checkout, or (for the copy in /opt/host-guard) the installed release."""
    if os.environ.get('HG_PAYLOAD'):
        return os.environ['HG_PAYLOAD']
    here = os.path.dirname(os.path.abspath(__file__))
    for cand in (os.path.join(here, 'payload'), os.path.normpath(os.path.join(here, '..', '..'))):
        if os.path.isfile(os.path.join(cand, 'guard', 'install.sh')) and os.path.isfile(os.path.join(cand, 'VERSION')):
            return cand
    cur = os.path.join(BASE, 'current')
    if os.path.isdir(cur):
        return os.path.realpath(cur)
    raise Fail('cannot find the host-guard files next to this program')


def verify_payload(payload):
    """The files a pip install brought must still be exactly what the package's RECORD lists
    (SHA-256 of each): a payload changed after install (by anyone who could write the
    site-packages folder) is refused before anything of it runs as root. A git checkout or
    the copy in /opt/host-guard has no RECORD and is not checked here. Returns the number of
    files checked."""
    here = os.path.dirname(os.path.abspath(__file__))
    if os.path.realpath(payload) != os.path.realpath(os.path.join(here, 'payload')):
        return 0
    try:
        from importlib import metadata
        dist = metadata.distribution('host-guard')
        files = dist.files or []
    except Exception:
        return 0
    import base64
    want = {}
    for f in files:
        parts = str(f).replace('\\', '/').split('/')
        if parts[:2] == ['host_guard', 'payload'] and f.hash and f.hash.mode == 'sha256':
            want[os.path.realpath(f.locate())] = f.hash.value
    if not want:
        return 0
    bad = []
    for path_, value in sorted(want.items()):
        try:
            with open(path_, 'rb') as fh:
                got = base64.urlsafe_b64encode(hashlib.sha256(fh.read()).digest()).rstrip(b'=').decode()
        except OSError:
            bad.append(f'missing: {path_}')
            continue
        if got != value:
            bad.append(f'changed: {path_}')
    for d, dirs, names in os.walk(payload):
        dirs[:] = [x for x in dirs if x != '__pycache__']
        bad += [f'added: {os.path.join(d, n)}' for n in names if os.path.realpath(os.path.join(d, n)) not in want]
    if bad:
        raise Fail('the installed host-guard package was changed after it was installed, so nothing of it runs:\n  '
                   + '\n  '.join(bad[:20]) + '\nReinstall it from PyPI:  sudo PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin '
                   'pipx install --force host-guard')
    return len(want)


# ---------------------------------------------------------------- state and history
def load_state():
    try:
        with open(os.path.join(BASE, 'state.json'), encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_json(path, data):
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=1, sort_keys=True)
    os.replace(tmp, path)


def save_state(st):
    os.makedirs(BASE, exist_ok=True)
    save_json(os.path.join(BASE, 'state.json'), st)


def entries():
    """Every history entry, oldest first: (folder, manifest)."""
    out = []
    for d in sorted(glob.glob(os.path.join(BASE, 'history', '[0-9]' * 4 + '-*'))):
        try:
            with open(os.path.join(d, 'manifest.json'), encoding='utf-8') as f:
                out.append((d, json.load(f)))
        except (FileNotFoundError, ValueError):
            continue
    return out


def active_entries():
    return [(d, m) for d, m in entries() if m.get('status') == 'ok' and not m.get('undone')]


def installed_version(st):
    if st.get('version'):
        return st['version']
    return 'unversioned' if os.path.lexists(R(ENGINE)) else None


class Lock:
    def __enter__(self):
        os.makedirs(BASE, exist_ok=True)
        os.chmod(BASE, 0o700)
        self.f = open(os.path.join(BASE, '.lock'), 'w')
        try:
            fcntl.flock(self.f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Fail('another host-guard install, rollback or uninstall is running') from None
        return self

    def __exit__(self, *exc):
        self.f.close()


# ---------------------------------------------------------------- snapshots
def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 16), b''):
            h.update(block)
    return h.hexdigest()


def stat_entry(p):
    rp = R(p)
    try:
        st = os.lstat(rp)
    except (FileNotFoundError, NotADirectoryError):
        return None
    if stat.S_ISLNK(st.st_mode):
        return {'type': 'link', 'target': os.readlink(rp)}
    if stat.S_ISREG(st.st_mode):
        return {'type': 'file', 'sha': sha256(rp), 'mode': st.st_mode & 0o7777, 'uid': st.st_uid,
                'gid': st.st_gid, 'size': st.st_size}
    return None


def same(a, b):
    if a is None or b is None:
        return a is b
    keys = ('type', 'target') if a['type'] == 'link' else ('type', 'sha', 'mode', 'uid', 'gid')
    return all(a.get(k) == b.get(k) for k in keys)


def watched_paths():
    found = set()
    dirs = list(WATCH_DIRS) + [unR(d) for g in WATCH_GLOBS for d in glob.glob(R(g))]
    for d in dirs:
        try:
            with os.scandir(R(d)) as it:
                for e in it:
                    if e.is_symlink() or e.is_file(follow_symlinks=False):
                        found.add(d.rstrip('/') + '/' + e.name)
        except (FileNotFoundError, NotADirectoryError, PermissionError):
            continue
    found.update(p for p in WATCH_FILES if os.path.lexists(R(p)))
    return found - NOT_TRACKED


def copy_into(store, p):
    dst = os.path.join(store, p.lstrip('/'))
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copyfile(R(p), dst)


def snapshot(store):
    """Every watched file now, with a copy of each (small) regular file in store."""
    snap = {}
    for p in sorted(watched_paths()):
        e = stat_entry(p)
        if e is None:
            continue
        if e['type'] == 'file' and e['size'] <= MAX_COPY:
            copy_into(store, p)
            e['copy'] = True
        snap[p] = e
    return snap


def system_facts():
    return {'packages': sorted(installed_packages()),
            'dirs': [d for d in DIRS if os.path.isdir(R(d))],
            'users': [u for u in USERS if user_exists(u)]}


def diff(before, after):
    """The changes between two snapshots; new files that belong to a package are left out."""
    changed = [p for p in sorted(set(before) | set(after)) if not same(before.get(p), after.get(p))]
    owned = dpkg_owned([p for p in changed if p not in before])
    return [{'path': p, 'before': before.get(p), 'after': after.get(p)}
            for p in changed if p in before or p not in owned]


# ---------------------------------------------------------------- applying and undoing
def put(p, meta, src):
    """Make path p look like meta (None: absent), the content coming from file src."""
    rp = R(p)
    if meta is None:
        if os.path.lexists(rp) and not os.path.isdir(rp) or os.path.islink(rp):
            os.unlink(rp)
        return
    os.makedirs(os.path.dirname(rp), exist_ok=True)
    tmp = rp + '.hg-tmp'
    if os.path.lexists(tmp):
        os.unlink(tmp)
    if meta['type'] == 'link':
        os.symlink(meta['target'], tmp)
    else:
        shutil.copyfile(src, tmp)
        os.chmod(tmp, meta['mode'])
        try:
            os.chown(tmp, meta['uid'], meta['gid'])
        except (PermissionError, OSError):
            pass
    os.replace(tmp, rp)


def checks(paths):
    """Settings checked before they apply. Returns (stop, warn): SSH settings sshd rejects
    stop everything (a lockout); fail2ban settings it rejects only warn, since fail2ban then
    stops protecting but nobody is locked out (stock fail2ban on Debian 12 is such a case:
    its sshd jail wants /var/log/auth.log, which a journald-only system does not have)."""
    stop, warn = [], []
    if any(p.startswith('/etc/ssh/') for p in paths) and have('sshd'):
        os.makedirs('/run/sshd', exist_ok=True)
        if run(['sshd', '-t']) != 0:
            stop.append('sshd -t rejected the SSH settings')
    if any(p.startswith('/etc/fail2ban/') for p in paths) and have('fail2ban-client'):
        if run(['fail2ban-client', '-t'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
            warn.append('fail2ban will not start with these settings (fail2ban-client -t), so it is not protecting '
                        'this server. As it was before host-guard: fix /etc/fail2ban/jail.d, or remove fail2ban '
                        '(uninstall --purge does when host-guard installed it)')
    return stop, warn


def unit_of(p):
    if p.startswith('/etc/systemd/system/'):
        name = os.path.basename(p)
        if name.endswith(('.service', '.timer', '.path', '.socket')):
            return name
    return None


def apply_effects(paths):
    """Make the running system follow the files: units, sysctl, sshd, fail2ban."""
    paths = list(paths)
    if any(p.startswith('/etc/systemd/system/') for p in paths):
        run(['systemctl', 'daemon-reload'])
        for u in sorted({unit_of(p) for p in paths} - {None}):
            if not os.path.exists(R('/etc/systemd/system/' + u)) and not glob.glob(R('/lib/systemd/system/' + u)):
                run(['systemctl', 'stop', u], stderr=subprocess.DEVNULL)
            elif u.endswith('.timer') or u == 'host-guard-panel.service':
                enabled = glob.glob(R('/etc/systemd/system/*.wants/' + u))
                run(['systemctl', 'restart' if enabled else 'stop', u], stderr=subprocess.DEVNULL)
    if any(p.startswith('/etc/sysctl.d/') for p in paths):
        run(['sysctl', '--system'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if any(p.startswith('/etc/ssh/') for p in paths):
        if run(['systemctl', 'reload', 'ssh'], stderr=subprocess.DEVNULL) != 0:
            run(['systemctl', 'reload', 'sshd'], stderr=subprocess.DEVNULL)
    if any(p.startswith('/etc/fail2ban/') for p in paths) and have('fail2ban-client'):
        run(['systemctl', 'restart', 'fail2ban'], stderr=subprocess.DEVNULL)


def undo(folder, manifest, force=False):
    """Put every file this entry changed back as it was before it. Returns (restored, kept):
    kept are files an admin changed since (left alone unless force). On a failed check
    the files are put back as they were and Fail is raised."""
    files = os.path.join(folder, 'files')
    plan, kept = [], []
    for ch in manifest['changes']:
        cur = stat_entry(ch['path'])
        if same(cur, ch['before']):
            continue
        if not same(cur, ch['after']) and not force:
            kept.append(ch['path'])
            continue
        if ch['before'] and ch['before']['type'] == 'file' and not ch['before'].get('copy'):
            kept.append(ch['path'] + ' (too large to have been copied)')
            continue
        plan.append((ch, cur))
    if not plan:
        return [], kept
    saved = os.path.join(folder, 'undo-' + time.strftime('%Y%m%d-%H%M%S'))
    for ch, cur in plan:
        if cur and cur['type'] == 'file':
            copy_into(saved, ch['path'])
    done = []
    try:
        for ch, cur in plan:
            put(ch['path'], ch['before'], os.path.join(files, ch['path'].lstrip('/')))
            done.append((ch, cur))
        bad, warn = checks([ch['path'] for ch, _ in plan])
        if bad:
            raise Fail('; '.join(bad))
        for w in warn:
            print(f'  WARNING: {w}')
    except Exception as e:
        for ch, cur in reversed(done):
            put(ch['path'], cur, os.path.join(saved, ch['path'].lstrip('/')))
        raise Fail(f'rollback stopped, nothing changed: {e}') from None
    apply_effects([ch['path'] for ch, _ in plan])
    return [ch['path'] for ch, _ in plan], kept


# ---------------------------------------------------------------- options
def read_kv(path):
    out = {}
    try:
        with open(R(path), encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    k, v = line.split('=', 1)
                    out[k.strip()] = v.strip()
    except (FileNotFoundError, PermissionError):
        pass
    return out


def parse_args(argv):
    """Split the command line into manager flags and install.sh options (checked here, so a
    typo stops before anything changes)."""
    mine = {'yes': False, 'force': False, 'allow_downgrade': False, 'with_panel': False, 'panel_port': None,
            'purge': False, 'delete_backups': False, 'to': None}
    opts, i = {}, 0
    while i < len(argv):
        a = argv[i]
        if a in ('--yes', '-y'):
            mine['yes'] = True
        elif a == '--force':
            mine['force'] = True
        elif a == '--allow-downgrade':
            mine['allow_downgrade'] = True
        elif a == '--with-panel':
            mine['with_panel'] = True
        elif a == '--purge':
            mine['purge'] = True
        elif a == '--delete-backups':
            mine['delete_backups'] = True
        elif a in ('--panel-port', '--to'):
            if i + 1 >= len(argv):
                raise Fail(f'{a} needs a value')
            mine[a[2:].replace('-', '_')] = argv[i + 1]
            i += 1
        elif a in VALUE_FLAGS:
            if i + 1 >= len(argv) or argv[i + 1].startswith('--'):
                raise Fail(f'{a} needs a value')
            opts['--stack-dir' if a == '--edgeshell-dir' else a] = argv[i + 1]
            i += 1
        elif a in BOOL_FLAGS:
            opts[a] = True
        else:
            raise Fail(f'unknown option {a} (see: host-guard --help)')
        i += 1
    if mine['panel_port'] is not None and not re.fullmatch(r'\d{2,5}', mine['panel_port']):
        raise Fail('--panel-port is a number')
    return mine, opts


def infer_options():
    """What an earlier install was given, read back from the files it wrote (for a server
    installed before the manager existed, or an option that was not saved)."""
    o = {}
    conf = read_kv('/etc/host-guard/guard.conf')
    if conf.get('LOGIN_USER'):
        o['--login-user'] = conf['LOGIN_USER']
    if conf.get('STACK_DIR'):
        o['--stack-dir'] = conf['STACK_DIR']
    try:
        with open(R('/etc/systemd/system/host-guard-report.timer'), encoding='utf-8') as f:
            m = re.search(r'^OnCalendar=\*-\*-\* (\d\d:\d\d):00 (\S+)$', f.read(), re.M)
        if m:
            o['--report-time'], o['--tz'] = m.group(1), m.group(2)
    except FileNotFoundError:
        pass
    try:
        with open(R('/etc/systemd/system/host-guard-patch-window.timer'), encoding='utf-8') as f:
            m = re.search(r'^OnCalendar=(.+) (\S+)$', f.read(), re.M)
        if m:
            o['--maintenance'] = m.group(1)
    except FileNotFoundError:
        pass
    try:
        with open(R('/etc/fail2ban/jail.d/host-guard.local'), encoding='utf-8') as f:
            jail = f.read()
        m = re.search(r'^logpath = (/\S+)/error\.log$', jail, re.M)
        if m:
            o['--web-logs'] = m.group(1)
        m = re.search(r'^ignoreip = (.*)$', jail, re.M)
        extra = [x for x in (m.group(1).split() if m else []) if x not in ('127.0.0.1/8', '::1', '172.16.0.0/12')]
        if extra:
            o['--admin-ip'] = extra[0]
    except FileNotFoundError:
        pass
    if os.path.lexists(R('/etc/apt/sources.list.d/trivy.list')):
        o['--with-trivy'] = True
    return o


def resolve_profile(value, payload):
    if not value or os.path.isabs(value):
        return value
    for base in (payload, os.getcwd()):           # the release's own examples first
        if os.path.isfile(os.path.join(base, value)):
            return os.path.join(base, value)
    return value


def options_for(st, given, payload):
    """install.sh options for this run: read back from the server, then the saved ones,
    then the ones given now. Recipients always come from guard.conf when not given (the
    panel can change them)."""
    o = infer_options()
    o.update(st.get('options', {}))
    o.update(given)
    conf = read_kv('/etc/host-guard/guard.conf')
    for flag, key in (('--mail-to', 'MAIL_TO'), ('--mail-from', 'MAIL_FROM')):
        if flag not in given and conf.get(key):
            o[flag] = conf[key]
    if '--profile' in o:
        o['--profile'] = resolve_profile(o['--profile'], payload)
    if '--login-user' not in o and os.environ.get('SUDO_USER') and os.environ['SUDO_USER'] != 'root':
        o['--login-user'] = os.environ['SUDO_USER']       # saved, so an upgrade never changes who may log in
    return o


def to_argv(o):
    argv = []
    for k in sorted(o):
        if o[k] is True:
            argv.append(k)
        elif o[k] not in (None, False, ''):
            argv += [k, str(o[k])]
    return argv


def saved_options(o, payload):
    keep = {k: v for k, v in o.items() if k not in NOT_SAVED}
    p = keep.get('--profile')
    if p and os.path.isabs(p) and p.startswith(os.path.abspath(payload) + os.sep):
        keep['--profile'] = os.path.relpath(p, payload)       # resolved against each release
    return keep


# ---------------------------------------------------------------- questions
def confirm(question, yes):
    if yes:
        return True
    if not sys.stdin.isatty():
        print(f'{question}\nNo terminal to ask on: add --yes to go ahead.')
        return False
    return input(f'{question} [y/N] ').strip().lower() in ('y', 'yes')


# ---------------------------------------------------------------- install, upgrade
def next_folder(action, version):
    os.makedirs(os.path.join(BASE, 'history'), exist_ok=True)
    n = len(glob.glob(os.path.join(BASE, 'history', '[0-9]' * 4 + '-*'))) + 1
    return os.path.join(BASE, 'history', f'{n:04d}-{action}-{version}')


def copy_release(payload, version):
    rel = os.path.join(BASE, 'releases', version)
    if os.path.realpath(payload) == os.path.realpath(rel):
        return rel
    tmp = rel + '.new'
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp)
    for name in RELEASE_FILES:                  # what runs on a server, nothing else
        src = os.path.join(payload, name)
        if os.path.isdir(src):
            shutil.copytree(src, os.path.join(tmp, name), ignore=shutil.ignore_patterns('__pycache__', '*.pyc', 'tests'))
        elif os.path.isfile(src):
            shutil.copyfile(src, os.path.join(tmp, name))
    shutil.rmtree(rel, ignore_errors=True)
    os.replace(tmp, rel)
    return rel


def point_current(version):
    cur = os.path.join(BASE, 'current')
    rel = os.path.join('releases', version)
    if not os.path.isdir(os.path.join(BASE, rel)):
        if os.path.lexists(cur):
            os.unlink(cur)
        return
    tmp = cur + '.new'
    if os.path.lexists(tmp):
        os.unlink(tmp)
    os.symlink(rel, tmp)
    os.replace(tmp, cur)


def prune_releases(keep_version):
    rels = sorted(glob.glob(os.path.join(BASE, 'releases', '*')), key=lambda d: parse_version(os.path.basename(d)))
    rels = [d for d in rels if not d.endswith('.new')]
    for d in rels[:-KEEP_RELEASES]:
        if os.path.basename(d) != keep_version:
            shutil.rmtree(d, ignore_errors=True)


def install_manager_copy(version):
    """Keep /opt/host-guard/manager.py (the newest manager seen) and a small command
    /usr/local/sbin/host-guard that prefers a pip-installed host-guard when there is one."""
    me = os.path.abspath(__file__)
    dst = os.path.join(BASE, 'manager.py')
    old = load_state().get('manager_version')
    if me != dst and (not old or parse_version(version) >= parse_version(old)):
        shutil.copyfile(me, dst + '.new')
        os.chmod(dst + '.new', 0o600)                    # root only, like everything in /opt/host-guard
        os.replace(dst + '.new', dst)
    wrapper = ('#!/bin/sh\n# host-guard manager (not tracked by rollbacks). A pip-installed host-guard wins.\n'
               'for c in /usr/local/bin/host-guard /opt/pipx/bin/host-guard; do\n'
               '  [ -x "$c" ] && exec "$c" "$@"\ndone\n'
               f'exec /usr/bin/python3 -I {BASE[len(ROOT):]}/manager.py "$@"\n')
    os.makedirs(os.path.dirname(R(WRAPPER)), exist_ok=True)
    with open(R(WRAPPER) + '.new', 'w', encoding='utf-8') as f:
        f.write(wrapper)
    os.chmod(R(WRAPPER) + '.new', 0o700)                  # only root runs it (sudo host-guard)
    os.replace(R(WRAPPER) + '.new', R(WRAPPER))


def cmd_install(argv, upgrade=False):
    mine, given = parse_args(argv)
    payload = find_payload()
    checked = verify_payload(payload)
    if checked:
        say(f'package files intact: {checked} files match the package\'s SHA-256 record')
    new = read_version(payload)
    with Lock():
        st = load_state()
        cur = installed_version(st)
        if cur is None and upgrade:
            raise Fail('host-guard is not installed here: use host-guard install --mail-to ...')
        if cur is None and '--mail-to' not in given:
            raise Fail('--mail-to is required for a first install')
        if cur == 'unversioned':
            say('host-guard is installed here without the version manager: adopting it. Everything this run changes is '
                'recorded, so a rollback returns to exactly the setup there is now.')
            action = 'adopt'
        elif cur is None:
            action = 'install'
        elif parse_version(new) > parse_version(cur):
            action = 'upgrade'
        elif parse_version(new) == parse_version(cur):
            action = 'repair'
            say(f'{new} is installed already: applying it again (a repair)')
        else:
            action = 'downgrade'
            print(f'host-guard {cur} is installed; this is {new}, an older version.\n'
                  f'To go back to a version installed before, "host-guard rollback --to {new}" restores it exactly.')
            if not (mine['allow_downgrade'] or confirm(f'Install the older {new} over {cur} anyway?', mine['yes'])):
                raise Fail('nothing changed')
        with_panel = mine['with_panel'] or st.get('with_panel', False)
        port = mine['panel_port'] or st.get('panel_port') or '8650'

        say(f'{action}: host-guard {cur or "(none)"} -> {new}')
        rel = copy_release(payload, new)
        opts = options_for(st, given, rel)
        folder = next_folder(action, new)
        os.makedirs(folder)
        say('recording the system before the change')
        before = snapshot(os.path.join(folder, 'files'))
        facts = system_facts()
        manifest = {'id': os.path.basename(folder), 'action': action, 'version': new, 'before_version': cur,
                    'started': time.time(), 'status': 'running', 'options': saved_options(opts, rel),
                    'with_panel': with_panel}
        save_json(os.path.join(folder, 'manifest.json'), manifest)

        env = dict(os.environ)
        rc = run(['bash', os.path.join(rel, 'guard', 'install.sh'), *to_argv(opts)], env=env)
        if rc == 0 and with_panel:
            say('panel')
            rc = run(['bash', os.path.join(rel, 'panel', 'install.sh'), '--port', str(port)], env=env)

        after = snapshot(os.path.join(folder, 'after'))
        shutil.rmtree(os.path.join(folder, 'after'), ignore_errors=True)
        changes = diff(before, after)
        keep = {c['path'] for c in changes if c['before']}
        prune_copies(os.path.join(folder, 'files'), keep)
        facts_after = system_facts()
        manifest.update({
            'changes': changes, 'finished': time.time(),
            'packages_added': sorted(set(facts_after['packages']) - set(facts['packages'])),
            'dirs_created': sorted(set(facts_after['dirs']) - set(facts['dirs'])),
            'users_created': sorted(set(facts_after['users']) - set(facts['users']))})
        if rc != 0:
            say(f'the install failed (exit {rc}): undoing what it changed')
            restored, kept = undo(folder, manifest, force=True)
            manifest.update({'status': 'failed', 'undone': time.time(), 'exit': rc})
            save_json(os.path.join(folder, 'manifest.json'), manifest)
            added = ' '.join(manifest['packages_added'])
            print(f'  {len(restored)} file(s) put back; host-guard {cur or "(none)"} is as it was.'
                  + (f' Packages it added are kept: {added}' if added else ''))
            raise Fail(f'install failed, rolled back (record: {folder})')
        manifest['status'] = 'ok'
        save_json(os.path.join(folder, 'manifest.json'), manifest)
        st.update({'version': new, 'installed_at': time.time(), 'options': manifest['options'],
                   'with_panel': with_panel, 'panel_port': port})
        point_current(new)
        prune_releases(new)
        install_manager_copy(new)
        if parse_version(new) >= parse_version(st.get('manager_version') or '0.0.0'):
            st['manager_version'] = new
        save_state(st)
        say(f'host-guard {new} installed: {len(changes)} file(s) changed, recorded in {folder}')
        print('Roll back with: sudo host-guard rollback')


def prune_copies(store, keep):
    for dirpath, _, names in os.walk(store, topdown=False):
        for n in names:
            full = os.path.join(dirpath, n)
            if '/' + os.path.relpath(full, store).replace(os.sep, '/') not in keep:
                os.unlink(full)
        if dirpath != store and not os.listdir(dirpath):
            os.rmdir(dirpath)


# ---------------------------------------------------------------- rollback, uninstall
def report_undo(manifest, restored, kept):
    say(f'{manifest["id"]}: {len(restored)} file(s) put back')
    for p in kept:
        print(f'  kept (changed since {manifest["version"]} was installed; --force restores it): {p}')


def cmd_rollback(argv):
    mine, given = parse_args(argv)
    if given:
        raise Fail('rollback takes --to VERSION, --yes and --force only')
    with Lock():
        st = load_state()
        act = active_entries()
        if not act:
            raise Fail('nothing to roll back')
        steps = []
        for folder, m in reversed(act):
            steps.append((folder, m))
            if mine['to'] is None or m.get('before_version') == mine['to']:
                break
        target = steps[-1][1].get('before_version')
        if mine['to'] is not None and target != mine['to']:
            raise Fail(f'{mine["to"]} is not in the install history (see: host-guard history)')
        if target is None:
            raise Fail('that would remove host-guard altogether: use host-guard uninstall')
        print(f'Roll back host-guard {st.get("version")} -> {target}: undo '
              + ', '.join(m['id'] for _, m in steps) + '.')
        if not confirm('Go ahead?', mine['yes']):
            raise Fail('nothing changed')
        for folder, m in steps:
            restored, kept = undo(folder, m, mine['force'])
            m['undone'] = time.time()
            save_json(os.path.join(folder, 'manifest.json'), m)
            report_undo(m, restored, kept)
        st['version'] = target if target != 'unversioned' else None
        prev = [m for _, m in active_entries()]
        st['options'] = prev[-1]['options'] if prev else st.get('options', {})
        if prev:
            st['with_panel'] = prev[-1].get('with_panel', False)
        point_current(target)
        save_state(st)
        say(f'host-guard is at {target} again')


def cmd_uninstall(argv):
    mine, given = parse_args(argv)
    if given:
        raise Fail('uninstall takes --purge, --delete-backups, --yes and --force only')
    with Lock():
        st = load_state()
        if installed_version(st) is None and not entries():
            raise Fail('host-guard is not installed here')
        backups = glob.glob(R('/var/backups/host-guard/*'))
        if mine['purge'] and backups and not mine['delete_backups']:
            raise Fail(f'--purge deletes /etc/host-guard/.env, the only copy of the backup passphrase, while '
                       f'{len(backups)} backup(s) exist. Copy them and the passphrase off the server first, then '
                       'add --delete-backups (or uninstall without --purge, which keeps both).')
        print('This removes host-guard: its timers, programs and the panel, and puts the SSH, fail2ban, sysctl and '
              'mail settings back as they were before host-guard was installed.\n'
              + ('It also deletes its settings, state, the packages it added'
                 + (' and the backups' if mine['delete_backups'] else '') + '.' if mine['purge'] else
                 'Kept: /etc/host-guard (settings, secrets), /var/lib/host-guard, /var/backups/host-guard.'))
        if not confirm('Remove host-guard?', mine['yes']):
            raise Fail('nothing changed')
        all_entries = entries()
        for folder, m in reversed(active_entries()):
            restored, kept = undo(folder, m, mine['force'])
            m['undone'] = time.time()
            save_json(os.path.join(folder, 'manifest.json'), m)
            report_undo(m, restored, kept)
        sweep_legacy()
        if mine['purge']:
            purge(all_entries, mine['delete_backups'])
        for p in (R(WRAPPER),):
            if os.path.lexists(p):
                os.unlink(p)
        shutil.rmtree(os.path.join(BASE, 'releases'), ignore_errors=True)
        for p in ('current', 'manager.py', 'state.json'):
            if os.path.lexists(os.path.join(BASE, p)):
                os.unlink(os.path.join(BASE, p))
        if mine['purge']:
            shutil.rmtree(BASE, ignore_errors=True)
            say('host-guard removed completely')
        else:
            say(f'host-guard removed; the record of what it did stays in {unR(BASE)}/history')


def sweep_legacy():
    """Files of an install made before the manager existed (nothing recorded them)."""
    paths = [p for p in LEGACY if os.path.lexists(R(p))]
    units = [unR(p) for p in glob.glob(R('/etc/systemd/system/host-guard-*'))]
    links = [unR(p) for p in glob.glob(R('/etc/systemd/system/*.wants/host-guard-*'))]
    for u in sorted({os.path.basename(p) for p in units}):
        run(['systemctl', 'disable', '--now', u], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    gone = paths + units + links
    for p in gone:
        if os.path.lexists(R(p)):
            os.unlink(R(p))
    if gone:
        say(f'removed {len(gone)} file(s) from an install made before the version manager')
        apply_effects(gone)


def purge(all_entries, delete_backups):
    added = set()
    for _, m in all_entries:
        added |= set(m.get('packages_added', []))
    auto = auto_packages()
    pkgs = sorted(p for p in added & installed_packages()
                  if p in KNOWN_PACKAGES or (p in auto and not p.startswith('linux-')))
    if pkgs:
        rc, text = run_out(['apt-get', '-s', 'purge', *pkgs])
        would = set(re.findall(r'^Purg (\S+)', text, re.M))
        extra = sorted(would - set(pkgs))
        if rc != 0 or extra:
            print(f'  packages kept: removing them would also remove {" ".join(extra) or "something apt refused"}. '
                  f'Remove by hand if you are sure: apt-get purge {" ".join(pkgs)}')
        else:
            say(f'removing the packages host-guard added: {" ".join(pkgs)}')
            run(['apt-get', 'purge', '-y', '-qq', *pkgs], env=dict(os.environ, DEBIAN_FRONTEND='noninteractive'),
                stdout=subprocess.DEVNULL)
    users, dirs = set(), set()
    for _, m in all_entries:
        users |= set(m.get('users_created', []))
        dirs |= set(m.get('dirs_created', []))
    for u in sorted(users):
        if user_exists(u):
            run(['userdel', u], stderr=subprocess.DEVNULL)
    for d in sorted(dirs | {'/etc/host-guard', '/var/lib/host-guard', '/var/lib/host-guard-panel',
                            '/var/lib/host-guard-export', '/etc/host-guard-panel', '/usr/local/lib/host-guard-panel'}):
        if d == '/var/backups/host-guard' and not delete_backups:
            continue
        shutil.rmtree(R(d), ignore_errors=True)
    if delete_backups:
        shutil.rmtree(R('/var/backups/host-guard'), ignore_errors=True)
    for p in ('/var/log/msmtp.log',):
        if os.path.lexists(R(p)):
            os.unlink(R(p))


# ---------------------------------------------------------------- status
def when(t):
    return time.strftime('%Y-%m-%d %H:%M', time.localtime(t)) if t else '-'


def cmd_history(_argv):
    rows = entries()
    if not rows:
        print('no install history')
    for _, m in rows:
        state = 'undone ' + when(m['undone']) if m.get('undone') else m.get('status', '?')
        print(f'{m["id"]:<28} {when(m.get("started"))}  {m.get("before_version") or "(none)"} -> {m["version"]}  '
              f'{len(m.get("changes", []))} file(s)  {state}')


def cmd_status(_argv):
    st = load_state()
    v = installed_version(st)
    print(f'host-guard: {v or "not installed"}' + (f' (since {when(st.get("installed_at"))})' if st.get('installed_at') else ''))
    try:
        print(f'this copy of the manager carries: {read_version(find_payload())}')
    except Fail:
        pass
    act = active_entries()
    if act:
        print(f'rollback would undo: {act[-1][1]["id"]} (back to {act[-1][1].get("before_version") or "nothing"})')
    if os.path.exists(R(ENGINE)) and not ROOT:
        sys.stdout.flush()
        run([R(ENGINE), 'status'])


def cmd_version(_argv):
    try:
        print(read_version(find_payload()))
    except Fail as e:
        print(e)


ENGINE_COMMANDS = {'health', 'watch', 'feeds', 'scan', 'backup', 'restore-test', 'patch-window', 'report', 'cost',
                   'test-mail', 'unlock', 'export'}
COMMANDS = {'install': cmd_install, 'upgrade': lambda a: cmd_install(a, upgrade=True), 'rollback': cmd_rollback,
            'uninstall': cmd_uninstall, 'status': cmd_status, 'history': cmd_history, 'version': cmd_version}


def need_root():
    if not ROOT and os.geteuid() != 0:
        raise Fail('run as root: sudo host-guard ...')


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] in ('-h', '--help', 'help'):
        print(__doc__)
        return 0 if argv else 2
    if argv[0] in ('--version', '-V'):
        argv = ['version']
    cmd, rest = argv[0], argv[1:]
    try:
        if cmd in ENGINE_COMMANDS:
            need_root()
            if not os.path.exists(R(ENGINE)):
                raise Fail('host-guard is not installed here')
            os.execv(R(ENGINE), [ENGINE, cmd, *rest])
        if cmd not in COMMANDS:
            raise Fail(f'unknown command {cmd} (see: host-guard --help)')
        if cmd not in ('version', 'history'):
            need_root()
        COMMANDS[cmd](rest)
        return 0
    except Fail as e:
        print(f'host-guard: {e}', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('\ninterrupted', file=sys.stderr)
        return 130


if __name__ == '__main__':
    sys.exit(main())
