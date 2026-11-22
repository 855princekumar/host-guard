"""host-guard shield: what runs on this server, what is known to be wrong with it, and
the safe fix. No LLM, no agent: plain rules over official, machine-readable sources.

    inventory     every OS package (and which ones running programs load), the kernel,
                  every container with its packages, upstream server programs (nginx, PHP,
                  Java, Node.js, OpenSSL, ...) on the host and in containers, Python
                  packages and Java archives on disk; plus what is NOT covered
    advisories    the inventory against CISA KEV (exploited), OSV (distributions, PyPI, npm,
                  Maven), NVD, FIRST EPSS and endoflife.date; research labs and news are read
                  as context and never trigger anything on their own
    tiers         Critical (exploited, or CVSS 9+ in something running), Moderate, Low
    fixes         Critical only, when AUTO_FIX=critical: after AUTO_FIX_HOLD_H hours (the
                  admins can hold it or fix it at once), inside FIX_WINDOW, with a restore
                  point first (old packages or the old image, /etc, a fresh backup), a health
                  check after, and an automatic rollback when the check fails

Called by hostguard (the `hg` argument is that module: its settings, shell, state and mail).
"""
import hashlib
import json
import os
import re
import shlex
import shutil
import tarfile
import time
import urllib.parse

TIERS = ('Critical', 'Moderate', 'Low')
TIER_LEVEL = {'Critical': 'critical', 'Moderate': 'alert', 'Low': 'info'}

# Official sources decide; context sources only add what was said about it, and early.
SOURCES = [
    {'id': 'cisa-kev', 'name': 'CISA Known Exploited Vulnerabilities', 'kind': 'official',
     'url': 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'},
    {'id': 'osv', 'name': 'OSV (Ubuntu, Debian, Alpine, Rocky, AlmaLinux, PyPI, npm, Maven, GitHub advisories)',
     'kind': 'official', 'url': 'https://api.osv.dev/v1/querybatch'},
    {'id': 'nvd', 'name': 'NIST National Vulnerability Database', 'kind': 'official',
     'url': 'https://services.nvd.nist.gov/rest/json/cves/2.0'},
    {'id': 'epss', 'name': 'FIRST EPSS (chance of exploitation in 30 days)', 'kind': 'official',
     'url': 'https://api.first.org/data/v1/epss'},
    {'id': 'eol', 'name': 'endoflife.date (latest patch and end of support per version line)', 'kind': 'official',
     'url': 'https://endoflife.date/api/'},
    {'id': 'oss-security', 'name': 'oss-security mailing list (Openwall)', 'kind': 'context',
     'url': 'https://seclists.org/rss/oss-sec.rss'},
    {'id': 'cisa-advisories', 'name': 'CISA advisories', 'kind': 'context',
     'url': 'https://www.cisa.gov/cybersecurity-advisories/all.xml'},
    {'id': 'nginx-org', 'name': 'nginx.org security advisories (fixed and vulnerable versions per CVE)', 'kind': 'official',
     'url': 'https://nginx.org/en/security_advisories.html'},
    {'id': 'project-zero', 'name': 'Google Project Zero', 'kind': 'context', 'url': 'https://projectzero.google/feed.xml'},
    {'id': 'watchtowr', 'name': 'watchTowr Labs', 'kind': 'context', 'url': 'https://labs.watchtowr.com/rss/'},
    {'id': 'qualys-tru', 'name': 'Qualys Threat Research', 'kind': 'context',
     'url': 'https://blog.qualys.com/vulnerabilities-threat-research/feed'},
    {'id': 'thehackernews', 'name': 'The Hacker News', 'kind': 'context',
     'url': 'https://feeds.feedburner.com/TheHackersNews'},
    {'id': 'bleepingcomputer', 'name': 'BleepingComputer', 'kind': 'context',
     'url': 'https://www.bleepingcomputer.com/feed/'},
]

# Upstream server programs: how to read the version, the endoflife.date product, the words
# NVD and CISA use for it. A distribution's own build (version with ubuntu, +deb, .el) is left
# to the distribution's data, which knows its backported fixes.
PRODUCTS = {
    'nginx': {'cmd': 'nginx -v', 'rx': r'nginx/(\d[\w.]*)', 'eol': 'nginx', 'nvd': 'nginx', 'kev': ('nginx',)},
    'apache-httpd': {'cmd': 'apache2 -v || httpd -v', 'rx': r'Apache/(\d[\w.]*)', 'eol': 'apache-http-server',
                     'nvd': 'Apache HTTP Server', 'kev': ('http server',)},
    'php': {'cmd': 'php -v', 'rx': r'PHP (\d+\.\d+\.\d+)', 'eol': 'php', 'nvd': 'PHP', 'kev': ('php',)},
    'java': {'cmd': 'java -version', 'rx': r'version "(\d[\d._]*)', 'eol': 'eclipse-temurin', 'nvd': 'Java SE',
             'kev': ('java se', 'jdk', 'jre')},
    'nodejs': {'cmd': 'node -v', 'rx': r'v(\d+\.\d+\.\d+)', 'eol': 'nodejs', 'nvd': 'Node.js', 'kev': ('node.js',)},
    'openssl': {'cmd': 'openssl version', 'rx': r'OpenSSL (\d+\.\d+\.\d+)', 'eol': 'openssl', 'nvd': 'OpenSSL',
                'kev': ('openssl',)},
    'openssh': {'cmd': 'ssh -V', 'rx': r'OpenSSH_(\d+\.\d+(?:p\d+)?)', 'eol': '', 'nvd': 'OpenSSH', 'kev': ('openssh',)},
    'redis': {'cmd': 'redis-server --version', 'rx': r'v=(\d[\w.]*)', 'eol': 'redis', 'nvd': 'Redis', 'kev': ('redis',)},
    'postgresql': {'cmd': 'postgres --version', 'rx': r'(\d+\.\d+)', 'eol': 'postgresql', 'nvd': 'PostgreSQL',
                   'kev': ('postgresql',)},
    'mariadb': {'cmd': 'mariadbd --version || mysqld --version', 'rx': r'(\d+\.\d+\.\d+)-MariaDB', 'eol': 'mariadb',
                'nvd': 'MariaDB', 'kev': ('mariadb',)},
    'python': {'cmd': 'python3 --version', 'rx': r'Python (\d+\.\d+\.\d+)', 'eol': 'python', 'nvd': 'CPython',
               'kev': ('python',)},
    'sudo': {'cmd': 'sudo -V', 'rx': r'Sudo version (\d[\w.]*)', 'eol': '', 'nvd': 'sudo', 'kev': ('sudo',)},
    'runc': {'cmd': 'runc --version', 'rx': r'runc version (\d[\w.]*)', 'eol': '', 'nvd': 'runc', 'kev': ('runc',)},
    'docker-engine': {'cmd': "docker version --format '{{.Server.Version}}'", 'rx': r'^(\d+\.\d+\.\d+)',
                      'eol': 'docker-engine', 'nvd': 'Docker Engine', 'kev': ('docker',), 'host_only': True},
}
DISTRO_BUILD = re.compile(r'ubuntu|\+deb\d|deb\d+u\d|\.el\d|\.fc\d|\.amzn\d')
PRIORITY_SCORE = {'critical': 9.5, 'high': 8.0, 'medium': 5.5, 'moderate': 5.5, 'important': 8.0, 'low': 3.0,
                  'negligible': 1.0, 'unimportant': 1.0}
NOTICE_WORDS = re.compile(r'CVE-\d{4}-\d{4,}|vulnerab|exploit|remote code|RCE|zero[- ]day|0-day|flaw|'
                          r'privilege escalation|patch', re.I)
CVE_RX = re.compile(r'CVE-\d{4}-\d{4,}')


# ---------------------------------------------------------------- small pure helpers
def vkey(v):
    """A sort key for upstream version strings: 1.30.5 < 1.30.7 < 1.31.0, 21.0.5+11 like 21.0.5."""
    v = str(v).split('+', 1)[0].replace('_', '.')
    return [(1, int(p)) if p.isdigit() else (0, p) for p in re.findall(r'\d+|[a-zA-Z]+', v)]


def version_lt(a, b):
    return vkey(a) < vkey(b)


def parse_os_release(text):
    d = {}
    for line in text.splitlines():
        k, _, v = line.strip().partition('=')
        if k:
            d[k] = v.strip().strip('"')
    return d


def osv_ecosystem(osr):
    """OSV's name for this distribution release, or '' when OSV has none."""
    i, v = osr.get('ID', ''), osr.get('VERSION_ID', '')
    if i == 'ubuntu' and v:
        return f'Ubuntu:{v}' + (':LTS' if 'LTS' in osr.get('VERSION', '') else '')
    if i == 'debian' and v:
        return f'Debian:{v.split(".")[0]}'
    if i == 'alpine' and v:
        return 'Alpine:v' + '.'.join(v.split('.')[:2])
    if i == 'rocky' and v:
        return f'Rocky Linux:{v.split(".")[0]}'
    if i == 'almalinux' and v:
        return f'AlmaLinux:{v.split(".")[0]}'
    return ''


def parse_dpkg_status(text):
    """[(binary package, version, source package)] of installed packages."""
    rows = []
    for para in text.split('\n\n'):
        f = {}
        for line in para.splitlines():
            if line[:1] in (' ', '\t') or ':' not in line:
                continue
            k, _, v = line.partition(':')
            f[k] = v.strip()
        if f.get('Package') and f.get('Version') and 'installed' in f.get('Status', '').split()[-1:]:
            src = f.get('Source', f['Package'])
            src_name = src.split(' ')[0]
            m = re.search(r'\(([^)]+)\)', src)
            rows.append((f['Package'], f['Version'], src_name, m.group(1) if m else f['Version']))
    return [(b, v, s) if sv == v else (b, v, s, sv) for b, v, s, sv in rows]


def parse_apk_installed(text):
    """[(package, version, origin)] from /lib/apk/db/installed."""
    rows, f = [], {}
    for line in text.splitlines() + ['']:
        if not line.strip():
            if f.get('P') and f.get('V'):
                rows.append((f['P'], f['V'], f.get('o', f['P'])))
            f = {}
        elif ':' in line:
            f[line[0]] = line[2:].strip()
    return rows


def parse_rpm(text):
    """[(name, epoch:version-release, source rpm name)] from rpm -qa with host-guard's format."""
    rows = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            name, ver, src = parts[0], parts[1].replace('(none):', ''), re.sub(r'-[^-]+-[^-]+\.src\.rpm$', '', parts[2])
            rows.append((name, ver, src))
    return rows


def parse_products(text):
    """{product: (version, path)} from the probe script's output (blocks headed @@name path)."""
    found, cur, buf = {}, None, []

    def close():
        if cur:
            name, where = cur
            m = re.search(PRODUCTS[name]['rx'], '\n'.join(buf), re.M)
            if m:
                found[name] = (m.group(1).rstrip('.'), where)
    for line in text.splitlines():
        if line.startswith('@@'):
            close()
            bits = line[2:].split(' ', 1)
            cur, buf = ((bits[0], bits[1] if len(bits) > 1 else '') if bits[0] in PRODUCTS else None), []
        else:
            buf.append(line)
    close()
    return found


def probe_script(host=True):
    parts = []
    for name, p in PRODUCTS.items():
        if p.get('host_only') and not host:
            continue
        first = p['cmd'].split()[0]
        parts.append(f'if command -v {first} >/dev/null 2>&1; then echo "@@{name} $(command -v {first})"; '
                     f'({p["cmd"]}) 2>&1 | head -3; fi')
    return '; '.join(parts)


def floating_tag(ref):
    """Does this image reference follow updates when pulled again (nginx:1.30-alpine, redis:7,
    app:latest)? A full version (1.30.5) or a digest is pinned on purpose."""
    if '@sha256:' in ref:
        return False
    tail = ref.rsplit('/', 1)[-1]
    tag = tail.split(':', 1)[1] if ':' in tail else 'latest'
    base = tag.split('-', 1)[0]
    if re.fullmatch(r'\d+\.\d+\.\d+.*', base):
        return False
    return True


def cvss3_score(vector):
    """Base score of a CVSS 3.x vector (FIRST's formula), or None."""
    m = dict(p.split(':', 1) for p in vector.split('/')[1:] if ':' in p) if vector.startswith('CVSS:3') else {}
    try:
        av = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}[m['AV']]
        ac = {'L': 0.77, 'H': 0.44}[m['AC']]
        changed = m['S'] == 'C'
        pr = {'N': 0.85, 'L': 0.68 if changed else 0.62, 'H': 0.5 if changed else 0.27}[m['PR']]
        ui = {'N': 0.85, 'R': 0.62}[m['UI']]
        c, i, a = ({'H': 0.56, 'L': 0.22, 'N': 0.0}[m[k]] for k in ('C', 'I', 'A'))
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    exploit = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    raw = min(1.08 * (impact + exploit), 10) if changed else min(impact + exploit, 10)
    up = round(raw * 100000)
    return up / 100000.0 if up % 10000 == 0 else (int(up / 10000) + 1) / 10.0


def cve_of(vuln):
    m = CVE_RX.search(vuln or '')
    return m.group(0) if m else ''


def tier(cvss, kev, epss, running, scope, fixable=True):
    """Critical: exploited (CISA KEV), or CVSS 9+ (or 7+ with a high chance of exploitation) in
    something running. A library inside an image is at most Moderate unless exploited: the
    weekly image scan lists those. Installed but not running: at most Moderate. No fix released
    yet and not exploited: Low (nothing to do yet; it moves up when the fix arrives)."""
    if kev:
        return 'Critical'
    if not fixable:
        return 'Low'
    cvss, epss = cvss or 0.0, epss or 0.0
    if cvss >= 9.0 or (cvss >= 7.0 and epss >= 0.5):
        t = 'Critical'
    elif cvss >= 7.0 or epss >= 0.1:
        t = 'Moderate'
    else:
        t = 'Low'
    if t == 'Critical' and (not running or scope == 'image-package'):
        t = 'Moderate'
    return t


def fid(*parts):
    return hashlib.sha256('|'.join(parts).encode()).hexdigest()[:8]


def in_window(spec, t=None):
    """FIX_WINDOW like 02:00-05:00 (may cross midnight); empty: any time."""
    if not spec.strip():
        return True
    m = re.fullmatch(r'\s*(\d\d):(\d\d)\s*-\s*(\d\d):(\d\d)\s*', spec)
    if not m:
        return False
    lt = time.localtime(t or time.time())
    cur = lt.tm_hour * 60 + lt.tm_min
    a, b = int(m.group(1)) * 60 + int(m.group(2)), int(m.group(3)) * 60 + int(m.group(4))
    return a <= cur < b if a <= b else cur >= a or cur < b


def fixed_in_text(desc):
    """Versions a description names as the fix ('before 1.30.7', 'fixed in 1.31.9', 'prior to 8.4.27')."""
    return re.findall(r'(?:before|prior to|fixed in|earlier than|up to and excluding)\s+(?:version\s+)?v?(\d+\.\d+(?:\.\d+)?)',
                      desc, re.I)


VENDOR_SEVERITY = {'critical': 9.5, 'major': 8.0, 'high': 8.0, 'medium': 5.5, 'moderate': 5.5, 'minor': 3.0, 'low': 3.0}


def parse_nginx_advisories(html_text):
    """nginx.org's advisory list: [{cve, title, severity, safe: ['1.31.9', '1.30.7'], vulnerable: [('1.9.5', '1.31.8')]}].
    The vendor's own page names the fixed version the day of the release, before NVD and
    endoflife.date catch up."""
    text = re.sub(r'<[^>]+>', ' ', html_text)
    text = re.sub(r'\s+', ' ', text.replace('&nbsp;', ' '))
    out_ = []
    for m in re.finditer(r'([A-Za-z][^:]{3,160}?) Severity: (\w+) Advisory (CVE-[\w-]+?) Not vulnerable: ([\d.+, ]+?) '
                         r'Vulnerable: ([\d., -]+?)(?= [A-Z]|$)', text):
        title, sev, cve, safe, vuln = m.groups()
        cve = re.sub(r'^(CVE-)+', 'CVE-', cve)
        out_.append({'cve': cve, 'title': title.strip(), 'severity': sev.lower(),
                     'safe': [s.strip().rstrip('+') for s in safe.split(',') if s.strip()],
                     'vulnerable': [tuple(r.strip().split('-', 1)) if '-' in r else (r.strip(), r.strip())
                                    for r in vuln.split(',') if r.strip()]})
    return out_


def vendor_affected(version, adv):
    """Is version hit by a vendor advisory? Vulnerable when inside a listed range and not at or
    above a fixed version of its own line (1.30.7+ fixes 1.30.x; the newest line's fix covers newer lines)."""
    if not any(not version_lt(version, lo) and not version_lt(hi, version) for lo, hi in adv['vulnerable']):
        return False
    line = vkey(version)[:2]
    for s in adv['safe']:
        if vkey(s)[:2] == line and not version_lt(version, s):
            return False
    top = max(adv['safe'], key=vkey) if adv['safe'] else ''
    return not (top and not version_lt(version, top))


def vendor_fix(version, adv):
    line = vkey(version)[:2]
    same = [s for s in adv['safe'] if vkey(s)[:2] == line]
    return same[0] if same else (max(adv['safe'], key=vkey) if adv['safe'] else '')


VENDORS = {'nginx': ('nginx-org', parse_nginx_advisories)}


def rss_items(text):
    """[(title, link)] from an RSS or Atom document, without an XML parser (nothing to expand)."""
    items = []
    for block in re.findall(r'<(?:item|entry)\b.*?</(?:item|entry)>', text, re.S | re.I)[:80]:
        t = re.search(r'<title[^>]*>(.*?)</title>', block, re.S | re.I)
        link = re.search(r'<link[^>]*href="([^"]+)"', block, re.I) or re.search(r'<link[^>]*>(.*?)</link>', block, re.S | re.I)
        if t:
            title = re.sub(r'<!\[CDATA\[|\]\]>|<[^>]+>', '', t.group(1)).strip()
            items.append((re.sub(r'\s+', ' ', title)[:300], (link.group(1).strip() if link else '')[:400]))
    return items


MD_LINK = re.compile(r'\[([^\]\n]{8,300})\]\((https?://[^)\s]{1,400})\)')


def page_items(text, url):
    """[(title, link)] from a web page read as Markdown (a reader) or as plain text: the
    links and headings, each line once; a line without its own link points at the page."""
    items, seen = [], set()
    for title, link in MD_LINK.findall(text):
        t = re.sub(r'[*_`#>]+', '', title).strip()
        if t and t not in seen:
            seen.add(t)
            items.append((re.sub(r'\s+', ' ', t)[:300], link))
    for line in text.splitlines():
        t = re.sub(r'^[#>*\-\s]+|[*_`]+', '', line).strip()
        if 20 <= len(t) <= 300 and t not in seen and not MD_LINK.search(line):
            seen.add(t)
            items.append((re.sub(r'\s+', ' ', t), url))
    return items[:200]


# ---------------------------------------------------------------- sources the admins add
SOURCE_FORMATS = ('feed', 'page')


def public_https(url):
    """'' when url is an https address on a public host (every address it resolves to is a
    public one); else why not. Checked when a source is added and again before each read: the
    reader runs as root, so an admin's source must never reach this server, its network or a
    cloud metadata service."""
    import ipaddress
    import socket
    try:
        p = urllib.parse.urlsplit(url)
    except ValueError:
        return 'not a web address'
    if p.scheme != 'https' or not p.hostname or p.username or p.password:
        return 'only https addresses, without a user name or password in them'
    if len(url) > 400 or any(c.isspace() or ord(c) < 32 for c in url):
        return 'too long, or has spaces or control characters'
    try:
        addrs = {a[4][0] for a in socket.getaddrinfo(p.hostname, p.port or 443, proto=socket.IPPROTO_TCP)}
    except (OSError, UnicodeError):
        return f'{p.hostname} does not resolve'
    for a in addrs:
        ip = ipaddress.ip_address(a.split('%')[0])
        if not ip.is_global or ip.is_multicast:
            return f'{p.hostname} resolves to {ip}, which is not a public address'
    return ''


def add_source(hg, state, name, url, fmt='feed', by='an admin on the server'):
    """Add a context source (it adds what was said, never starts a fix). Returns (ok, message)."""
    name = re.sub(r'[\x00-\x1f]', '', str(name)).strip()[:80]
    url, fmt = str(url).strip(), (fmt or 'feed').strip().lower()
    extra = state.setdefault('extra_sources', [])
    if not name:
        return False, 'give the source a name'
    if fmt not in SOURCE_FORMATS:
        return False, f'the format is one of {", ".join(SOURCE_FORMATS)}'
    why = public_https(url)
    if why:
        return False, why
    if any(s['url'] == url for s in all_sources(state)):
        return False, 'that address is already a source'
    if len(extra) >= int(hg.C['SOURCES_MAX']):
        return False, f'at most {hg.C["SOURCES_MAX"]} added sources (SOURCES_MAX); remove one first'
    sid = (re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-') or 'source')[:32]
    while any(s['id'] == sid for s in all_sources(state)):
        sid = sid[:28] + '-' + hashlib.sha256(url.encode()).hexdigest()[:3]
    extra.append({'id': sid, 'name': name, 'url': url, 'fmt': fmt, 'by': str(by)[:120], 'at': time.time()})
    hg.save(state, 'shield.json')
    hg.mail(subject=f'Advisory source added: {name}', category='Advisory', level='info', body=
            f'{by} added a context source:\n\n  {name} ({fmt})\n  {url}\n  id: {sid}\n\n'
            'It is read with the other news and research sources: what it says about software on this '
            'server shows up in the advisory mails, marked as context. It never starts a fix on its own; '
            'fixes need an official source (CISA KEV, OSV, NVD, the vendor\'s own advisories).\n\n'
            f'Not expected? Remove it: sudo hostguard sources remove {sid}')
    return True, f'added {sid} as a context source (it adds what was said, never starts a fix)'


def remove_source(hg, state, sid, by='an admin on the server'):
    extra = state.setdefault('extra_sources', [])
    gone = [s for s in extra if s['id'] == sid]
    if not gone:
        return False, f'no added source {sid} (the built-in sources cannot be removed)'
    state['extra_sources'] = [s for s in extra if s['id'] != sid]
    hg.save(state, 'shield.json')
    hg.mail(subject=f'Advisory source removed: {gone[0]["name"]}', category='Advisory', level='info',
            body=f'{by} removed the context source {gone[0]["name"]} ({gone[0]["url"]}).')
    return True, f'removed {sid}'


# ---------------------------------------------------------------- inventory
def _run(hg, where, cmd, timeout=120):
    if where == 'host':
        return hg.sh(cmd, timeout)
    return hg.sh(f'docker exec {shlex.quote(where)} sh -c {shlex.quote(cmd)}', timeout)


def _packages(hg, where, osr):
    """OS packages as components of one place (the host or a container)."""
    eco = osv_ecosystem(osr)
    rows, kind = [], ''
    rc, text = _run(hg, where, 'cat /var/lib/dpkg/status 2>/dev/null', 60)
    if rc == 0 and 'Package:' in text:
        rows, kind = parse_dpkg_status(text), 'dpkg'
    else:
        rc, text = _run(hg, where, 'cat /lib/apk/db/installed 2>/dev/null', 60)
        if rc == 0 and 'P:' in text:
            rows, kind = parse_apk_installed(text), 'apk'
        else:
            rc, text = _run(hg, where, "rpm -qa --qf '%{NAME} %{EPOCH}:%{VERSION}-%{RELEASE} %{SOURCERPM}\\n' 2>/dev/null", 120)
            if rc == 0:
                rows, kind = parse_rpm(text), 'rpm'
    comps = {}
    for row in rows:
        binary, ver, src = row[0], row[1], row[2]
        src_ver = row[3] if len(row) > 3 else ver
        c = comps.setdefault(src, {'kind': 'os', 'eco': eco, 'name': src, 'version': src_ver, 'where': where,
                                   'binaries': {}, 'pm': kind})
        c['binaries'][binary] = ver
    return list(comps.values()), kind


def _host_running_packages(hg):
    """Binary packages whose programs or libraries are loaded by a process right now (host only)."""
    files = set()
    me = _readlink('/proc/self/ns/mnt')
    for pid in os.listdir('/proc') if os.path.isdir('/proc') else []:
        if not pid.isdigit() or _readlink(f'/proc/{pid}/ns/mnt') != me:
            continue                                  # another mount namespace: a container, inventoried as one
        exe = _readlink(f'/proc/{pid}/exe')
        if exe:
            files.add(exe.replace(' (deleted)', ''))
        try:
            with open(f'/proc/{pid}/maps', encoding='utf-8', errors='replace') as f:
                for line in f:
                    p = line.split(None, 5)
                    if len(p) == 6 and p[5].startswith('/') and '.so' in p[5]:
                        files.add(p[5].strip().replace(' (deleted)', ''))
        except OSError:
            continue
    owned, unowned = set(), set()
    files = sorted(files)
    for i in range(0, len(files), 200):
        chunk = files[i:i + 200]
        _, text = hg.sh('dpkg -S ' + ' '.join(shlex.quote(f) for f in chunk) + ' 2>&1', 120)
        hit = set()
        for line in text.splitlines():
            if ': /' in line and not line.startswith('dpkg-query:'):
                pkgs, _, file_ = line.partition(': ')
                hit.add(file_.strip())
                owned.update(p.strip().split(':')[0] for p in pkgs.split(','))
        unowned.update(f for f in chunk if f not in hit and not f.startswith(('/memfd:', '/dev/', '/tmp/.X')))  # nosec B108 (skips X11 sockets)
    exes = {_readlink(f'/proc/{p}/exe') for p in os.listdir('/proc') if p.isdigit()} if os.path.isdir('/proc') else set()
    return owned, sorted(f for f in unowned if f in exes)


def _readlink(p):
    try:
        return os.readlink(p)
    except OSError:
        return ''


def _lang_on_disk(roots, limit=20000):
    """Python packages (*.dist-info) and Java archives under roots, as components."""
    comps, seen = [], 0
    for root in roots:
        if not os.path.isdir(root):
            continue
        for d, dirs, files in os.walk(root):
            dirs[:] = [x for x in dirs if x not in ('proc', 'sys', '.git', 'node_modules', '__pycache__')]
            seen += 1
            if seen > limit:
                return comps
            for x in dirs:
                if x.endswith('.dist-info'):
                    m = re.match(r'(.+?)-(\d[^-]*)\.dist-info$', x)
                    if m:
                        comps.append({'kind': 'lang', 'eco': 'PyPI', 'name': m.group(1).replace('_', '-').lower(),
                                      'version': m.group(2), 'where': 'host', 'path': os.path.join(d, x)})
            for x in files:
                if x.endswith(('.jar', '.war', '.ear')):
                    comps.extend(jar_components(os.path.join(d, x)))
    return comps


def jar_components(path_, depth=0):
    """Maven artifacts inside a Java archive (and the archives it carries, one level down)."""
    import io
    import zipfile
    comps = []
    try:
        with zipfile.ZipFile(path_ if isinstance(path_, str) else path_) as z:
            for n in z.namelist():
                if n.endswith('pom.properties'):
                    p = dict(line.split('=', 1) for line in z.read(n).decode('utf-8', 'replace').splitlines()
                             if '=' in line and not line.startswith('#'))
                    if p.get('groupId') and p.get('artifactId') and p.get('version'):
                        comps.append({'kind': 'lang', 'eco': 'Maven', 'name': f"{p['groupId']}:{p['artifactId']}",
                                      'version': p['version'], 'where': 'host',
                                      'path': path_ if isinstance(path_, str) else ''})
                elif depth == 0 and n.endswith('.jar') and z.getinfo(n).file_size < 50_000_000:
                    comps.extend(jar_components(io.BytesIO(z.read(n)), 1))
    except (OSError, zipfile.BadZipFile, KeyError, ValueError, RuntimeError):
        pass
    return comps


def inventory(hg):
    """Everything this server runs or has installed, and what is not covered."""
    inv = {'at': time.time(), 'components': [], 'containers': [], 'not_covered': [], 'notes': []}
    try:
        osr = parse_os_release(open('/etc/os-release', encoding='utf-8').read())
    except OSError:
        osr = {}
    inv['os'] = {'name': osr.get('PRETTY_NAME', 'unknown'), 'ecosystem': osv_ecosystem(osr), 'kernel': os.uname().release
                 if hasattr(os, 'uname') else ''}
    comps, pm = _packages(hg, 'host', osr)
    running, unowned = (_host_running_packages(hg) if pm == 'dpkg' else (set(), []))
    kernel_pkg = f'linux-image-{inv["os"]["kernel"]}'
    for c in comps:
        c['running'] = bool(set(c['binaries']) & running) or kernel_pkg in c['binaries']
        c['scope'] = 'host-package'
    if not inv['os']['ecosystem']:
        inv['notes'].append(f'{inv["os"]["name"]}: OSV has no data for this distribution; its packages are listed, not checked')
    inv['components'] += comps
    inv['not_covered'] += [f'{f} (a running program no package owns)' for f in unowned[:50]]
    _, text = hg.sh(probe_script(True), 120)
    for name, (ver, where_) in parse_products(text).items():
        inv['components'].append(_product(name, ver, where_, 'host', comps, True))
    rc, text = hg.sh("docker ps --format '{{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Label \"com.docker.compose.service\"}}\t"
                     "{{.Label \"com.docker.compose.project.working_dir\"}}\t{{.Label \"com.docker.compose.project.config_files\"}}'"
                     if shutil.which('docker') else 'false', 60)
    for line in text.splitlines() if rc == 0 else []:
        name, image, ports, svc, wd, files = (line.split('\t') + [''] * 6)[:6]
        if not name:
            continue
        exposed = '0.0.0.0:' in ports or ':::' in ports or '[::]:' in ports
        inv['containers'].append({'name': name, 'image': image, 'service': svc, 'dir': wd, 'files': files,
                                  'exposed': exposed, 'floating': floating_tag(image)})
        where = name
        rc2, t2 = _run(hg, where, 'cat /etc/os-release 2>/dev/null', 30)
        cosr = parse_os_release(t2) if rc2 == 0 else {}
        ccomps, _ = _packages(hg, where, cosr)
        if not ccomps:
            inv['not_covered'].append(f'container {name} ({image}): no package database (distroless or scratch)')
        for c in ccomps:
            c.update(running=True, scope='image-package', image=image)
        inv['components'] += ccomps
        _, t3 = _run(hg, where, probe_script(False), 120)
        for pname, (ver, where_) in parse_products(t3).items():
            p = _product(pname, ver, where_, where, ccomps, True)
            p.update(image=image, exposed=exposed)
            inv['components'].append(p)
        _, t4 = _run(hg, where, 'python3 -m pip list --format=json 2>/dev/null || pip list --format=json 2>/dev/null', 90)
        try:
            for row in json.loads(t4[t4.index('['):]) if '[' in t4 else []:
                inv['components'].append({'kind': 'lang', 'eco': 'PyPI', 'name': row['name'].lower(), 'version': row['version'],
                                          'where': where, 'image': image, 'running': True, 'scope': 'app'})
        except (ValueError, KeyError, TypeError):
            pass
    roots = hg.C.get('SCAN_PATHS', '').split()
    for c in _lang_on_disk(roots):
        c.update(running=False, scope='app')
        inv['components'].append(c)
    for c in inv['components']:
        c['id'] = fid(c['where'], c['eco'], c['name'])
    return inv


def _product(name, ver, path_, where, packages, running):
    """An upstream program found by its version; owned_by marks a distribution build."""
    owner = ''
    for c in packages:
        if any(b == name or b.startswith(name + '-') or b in (name + '-core', name + '-bin') for b in c['binaries']):
            if DISTRO_BUILD.search(c['version']):
                owner = c['name']
                break
    return {'kind': 'product', 'eco': 'upstream', 'name': name, 'version': ver, 'where': where, 'path': path_,
            'running': running, 'scope': 'product', 'distro_build': owner}


# ---------------------------------------------------------------- sources
def _source_ok(state, sid, ok, err=''):
    s = state.setdefault('sources', {}).setdefault(sid, {'ok': 0, 'fail': 0})
    if ok:
        s.update(ok_at=time.time(), fail=0)
        s['ok'] = s.get('ok', 0) + 1
    else:
        s['fail'] = s.get('fail', 0) + 1
        s['error'] = err[:160]
        s['fail_at'] = time.time()


def all_sources(state):
    extra = [dict(x, kind='context', added=True) for x in state.get('extra_sources', [])]
    return SOURCES + extra


def check(hg, inv, state, budget=None):
    """Findings for the inventory: [{fid, vuln, title, comp, cvss, kev, epss, tier, fixed, refs, src}]."""
    budget = budget if budget is not None else {'osv_details': 300, 'nvd': 12}
    get = hg.get_json
    findings = {}
    kev = {}
    try:
        for v in get(hg.C['KEV_URL']).get('vulnerabilities', []):
            kev[v['cveID']] = v
        _source_ok(state, 'cisa-kev', True)
    except Exception as e:
        _source_ok(state, 'cisa-kev', False, str(e))
    cache = state.setdefault('osv_cache', {})
    queryable = [c for c in inv['components'] if c['eco'] and c['eco'] != 'upstream']
    for i in range(0, len(queryable), 500):
        chunk = queryable[i:i + 500]
        try:
            res = get(hg.C['OSV_URL'], {'queries': [{'package': {'name': c['name'], 'ecosystem': c['eco']}, 'version': c['version']}
                                                    for c in chunk]})
            _source_ok(state, 'osv', True)
        except Exception as e:
            _source_ok(state, 'osv', False, str(e))
            break
        for c, r in zip(chunk, res.get('results', []), strict=False):
            for v in r.get('vulns', []) or []:
                vid = v['id']
                if vid not in cache and budget['osv_details'] > 0:
                    budget['osv_details'] -= 1
                    try:
                        cache[vid] = _osv_summary(get(hg.C['OSV_VULN_URL'] + urllib.parse.quote(vid)))
                    except Exception:
                        cache[vid] = {'summary': '', 'aliases': [], 'score': None, 'fixed': {}, 'refs': [], 'partial': True}
                d = cache.get(vid, {'summary': '', 'aliases': [], 'score': None, 'fixed': {}, 'refs': []})
                cves = list(dict.fromkeys(CVE_RX.findall(' '.join([vid] + d.get('aliases', [])))))
                k = next((kev[x] for x in cves if x in kev), None)
                f = {'vuln': cves[0] if cves else vid, 'ids': sorted({vid, *cves}), 'title': d.get('summary') or vid,
                     'comp': c, 'cvss': d.get('score'), 'kev': bool(k), 'fixed': d.get('fixed', {}).get(c['name'], ''),
                     'refs': d.get('refs', [])[:4], 'src': 'OSV' + (' + CISA KEV' if k else '')}
                if k:
                    f['kev_action'] = k.get('requiredAction', '')[:200]
                f['fid'] = fid(c['id'], f['vuln'])
                findings[f['fid']] = f
    eol_cache = state.setdefault('eol_cache', {})
    nvd_cache = state.setdefault('nvd_cache', {})
    for c in [c for c in inv['components'] if c['kind'] == 'product' and not c.get('distro_build')]:
        p = PRODUCTS[c['name']]
        latest, eol = '', False
        if p['eol']:
            ent = eol_cache.get(p['eol'])
            if not ent or time.time() - ent.get('at', 0) > 6 * 3600:
                try:
                    ent = {'at': time.time(), 'cycles': get(hg.C['EOL_URL'] + p['eol'] + '.json')}
                    eol_cache[p['eol']] = ent
                    _source_ok(state, 'eol', True)
                except Exception as e:
                    _source_ok(state, 'eol', False, str(e))
            cyc = _cycle(ent.get('cycles', []) if ent else [], c['version'])
            if cyc:
                latest = str(cyc.get('latest', ''))
                e = cyc.get('eol')
                eol = e is True or (isinstance(e, str) and e < time.strftime('%Y-%m-%d'))
        c['latest'] = latest
        behind = bool(latest) and version_lt(c['version'], latest)
        if eol:
            f = {'vuln': f'EOL:{c["name"]}', 'ids': [], 'title': f'{c["name"]} {c["version"]}: this version line gets no more '
                 'security fixes (end of life)', 'comp': c, 'cvss': 7.0, 'kev': False, 'fixed': '', 'refs':
                 [f'https://endoflife.date/{p["eol"]}'], 'src': 'endoflife.date', 'eol': True}
            f['fid'] = fid(c['id'], f['vuln'])
            findings[f['fid']] = f
        vendor_cves = set()
        if c['name'] in VENDORS:                          # the vendor's own list decides when there is one
            sid, parse = VENDORS[c['name']]
            src = next(s for s in SOURCES if s['id'] == sid)
            vc = state.setdefault('vendor_cache', {}).get(sid)
            if not vc or time.time() - vc.get('at', 0) > 3600:
                try:
                    vc = {'at': time.time(), 'advisories': parse(hg.get_text(src['url']))}
                    state['vendor_cache'][sid] = vc
                    _source_ok(state, sid, True)
                except Exception as e:
                    _source_ok(state, sid, False, str(e))
            for adv in (vc or {}).get('advisories', []):
                vendor_cves.add(adv['cve'])
                if not vendor_affected(c['version'], adv):
                    continue
                k = kev.get(adv['cve'])
                score = _nvd_score(hg, state, adv['cve'], budget)
                f = {'vuln': adv['cve'], 'ids': [adv['cve']], 'title': f'{adv["title"]} ({src["name"].split(" ")[0]}: '
                     f'{adv["severity"]})', 'comp': c, 'cvss': score if score is not None else VENDOR_SEVERITY.get(adv['severity']),
                     'kev': bool(k), 'fixed': vendor_fix(c['version'], adv), 'refs': [src['url']],
                     'src': src['name'].split(' (')[0] + (' + NVD' if score is not None else '') + (' + CISA KEV' if k else '')}
                f['fid'] = fid(c['id'], f['vuln'])
                findings[f['fid']] = f
        ent = nvd_cache.get(c['name'])
        if (not ent or time.time() - ent.get('at', 0) > 3 * 3600) and budget['nvd'] > 0:
            budget['nvd'] -= 1
            try:
                ent = {'at': time.time(), 'cves': _nvd_recent(hg, p['nvd'])}
                nvd_cache[c['name']] = ent
                _source_ok(state, 'nvd', True)
            except Exception as e:
                _source_ok(state, 'nvd', False, str(e))
        for cv in (ent or {}).get('cves', []):
            if cv['id'] in vendor_cves:
                continue                                  # the vendor already said whether this version is hit
            named = fixed_in_text(cv['desc'])
            relevant = [x for x in named if vkey(x)[:2] == vkey(c['version'])[:2]] or named
            if relevant and not any(version_lt(c['version'], x) for x in relevant):
                continue                                  # the description names a fix this version has
            if not relevant and not behind:
                continue                                  # nothing says this version is affected
            k = kev.get(cv['id'])
            f = {'vuln': cv['id'], 'ids': [cv['id']], 'title': cv['desc'][:240], 'comp': c, 'cvss': cv['score'], 'kev': bool(k),
                 'fixed': next((x for x in relevant if version_lt(c['version'], x)), latest), 'refs': cv['refs'][:4],
                 'src': 'NVD' + (' + CISA KEV' if k else '') + (' + endoflife.date' if latest else '')}
            f['fid'] = fid(c['id'], f['vuln'])
            findings[f['fid']] = f
        for cid, k in kev.items():                       # exploited, named after the product, not matched above
            words = f"{k.get('vendorProject', '')} {k.get('product', '')}".lower()
            if behind and any(re.search(r'\b' + re.escape(w) + r'\b', words) for w in p['kev']) and \
                    time.time() - _date(k.get('dateAdded', '')) < 120 * 86400:
                f = {'vuln': cid, 'ids': [cid], 'title': k.get('shortDescription', '')[:240], 'comp': c, 'cvss': None, 'kev': True,
                     'fixed': latest, 'refs': [], 'src': 'CISA KEV + endoflife.date', 'kev_action': k.get('requiredAction', '')[:200]}
                f['fid'] = fid(c['id'], cid)
                findings.setdefault(f['fid'], f)
    cves = sorted({cve_of(f['vuln']) for f in findings.values()} - {''})
    epss = {}
    for i in range(0, len(cves), 80):
        try:
            for row in get(hg.C['EPSS_URL'] + '?cve=' + ','.join(cves[i:i + 80])).get('data', []):
                epss[row['cve']] = float(row.get('epss', 0))
            _source_ok(state, 'epss', True)
        except Exception as e:
            _source_ok(state, 'epss', False, str(e))
            break
    for f in findings.values():
        c = f['comp']
        f['epss'] = epss.get(cve_of(f['vuln']))
        f['tier'] = 'Moderate' if f.get('eol') else tier(f['cvss'], f['kev'], f['epss'], c.get('running'), c.get('scope'),
                                                          fixable=bool(f.get('fixed')))
        if not f.get('fixed') and not f['kev'] and not f.get('eol'):
            f['no_fix'] = True                             # nothing to install yet: Low until a fix is released
    _trim(cache, 4000)
    return findings


def _trim(d, n):
    for k in list(d)[:-n] if len(d) > n else []:
        d.pop(k, None)


def _date(s):
    try:
        return time.mktime(time.strptime(s[:10], '%Y-%m-%d'))
    except ValueError:
        return 0


def _cycle(cycles, version):
    best = None
    for cy in cycles if isinstance(cycles, list) else []:
        name = str(cy.get('cycle', ''))
        if version == name or version.startswith(name + '.') or version.startswith(name + '_'):
            if not best or len(name) > len(str(best.get('cycle', ''))):
                best = cy
    return best


def _osv_summary(d):
    score = None
    for s in d.get('severity', []) or []:
        if s.get('type') == 'CVSS_V3':
            score = cvss3_score(s.get('score', '')) or score
        elif s.get('type') in ('Ubuntu', 'Debian') and score is None:
            score = PRIORITY_SCORE.get(str(s.get('score', '')).lower())
    for a in d.get('affected', []) or []:
        for s in a.get('severity', []) or []:
            if s.get('type') in ('Ubuntu', 'Debian') and score is None:
                score = PRIORITY_SCORE.get(str(s.get('score', '')).lower())
        ds = (a.get('ecosystem_specific') or {}).get('urgency') or (a.get('database_specific') or {}).get('severity')
        if score is None and isinstance(ds, str):
            score = PRIORITY_SCORE.get(ds.lower())
    fixed = {}
    for a in d.get('affected', []) or []:
        name = (a.get('package') or {}).get('name', '')
        for rg in a.get('ranges', []) or []:
            for e in rg.get('events', []) or []:
                if e.get('fixed'):
                    fixed[name] = e['fixed']
    # Ubuntu's records (UBUNTU-CVE-...) often name the CVE only in 'upstream', not in 'aliases'
    return {'summary': (d.get('summary') or d.get('details') or '')[:240],
            'aliases': list(dict.fromkeys((d.get('aliases') or []) + (d.get('upstream') or []))),
            'score': score, 'fixed': fixed, 'refs': [r.get('url', '') for r in d.get('references', []) or []][:6]}


def _nvd_score(hg, state, cve, budget):
    """The best CVSS score NVD has for one CVE (the CNA's own score counts before NVD's analysis)."""
    cache = state.setdefault('score_cache', {})
    if cve in cache and (cache[cve]['score'] is not None or time.time() - cache[cve]['at'] < 6 * 3600):
        return cache[cve]['score']
    if budget['nvd'] <= 0:
        return None
    budget['nvd'] -= 1
    try:
        data = hg.get_json(hg.C['NVD_URL'] + '?cveId=' + urllib.parse.quote(cve),
                           headers={'apiKey': hg.C['NVD_API_KEY']} if hg.C.get('NVD_API_KEY') else None)
        if not hg.C.get('NVD_API_KEY'):
            time.sleep(float(os.environ.get('HG_NVD_PAUSE', '6')))
        _source_ok(state, 'nvd', True)
    except Exception as e:
        _source_ok(state, 'nvd', False, str(e))
        return None
    score = None
    for item in data.get('vulnerabilities', []):
        for key in ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30'):
            for m in item.get('cve', {}).get('metrics', {}).get(key, []):
                s = m.get('cvssData', {}).get('baseScore')
                score = s if s is not None and (score is None or s > score) else score
            if score is not None:
                break
    cache[cve] = {'at': time.time(), 'score': score}
    _trim(cache, 2000)
    return score


def _nvd_recent(hg, keyword):
    """CVEs about keyword published in the last 120 days (NVD's widest window): id, best score, text, links."""
    end = time.gmtime()
    start = time.gmtime(time.time() - 119 * 86400)
    fmt = '%Y-%m-%dT%H:%M:%S.000'
    url = (hg.C['NVD_URL'] + '?keywordSearch=' + urllib.parse.quote(keyword) + '&keywordExactMatch&noRejected'
           f'&pubStartDate={time.strftime(fmt, start)}&pubEndDate={time.strftime(fmt, end)}&resultsPerPage=200')
    data = hg.get_json(url, headers={'apiKey': hg.C['NVD_API_KEY']} if hg.C.get('NVD_API_KEY') else None)
    if not hg.C.get('NVD_API_KEY'):
        time.sleep(float(os.environ.get('HG_NVD_PAUSE', '6')))       # 5 requests in 30 s without a key
    out_ = []
    for item in data.get('vulnerabilities', []):
        cve = item.get('cve', {})
        desc = next((d['value'] for d in cve.get('descriptions', []) if d.get('lang') == 'en'), '')
        score = None
        for key in ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
            for m in cve.get('metrics', {}).get(key, []):
                s = m.get('cvssData', {}).get('baseScore')
                if s is not None and (score is None or s > score):
                    score = s
            if score is not None:
                break
        out_.append({'id': cve.get('id', ''), 'score': score, 'desc': desc,
                     'refs': [r.get('url', '') for r in cve.get('references', [])][:6]})
    return out_


def context(hg, inv, state):
    """Lines from research labs and news that name something running here: [(source, title, link, cves)]."""
    names = {c['name'] for c in inv['components'] if c['kind'] == 'product'}
    names |= {'linux kernel'} if inv.get('os', {}).get('kernel') else set()
    names |= {c['name'] for c in inv['components'] if c['kind'] == 'os' and c.get('running') and len(c['name']) >= 5
              and c.get('where') == 'host'}
    words = {n: re.compile(r'\b' + re.escape(n.replace('nodejs', 'node.js').replace('-', ' ')) + r'\b', re.I) for n in names}
    words['java'] = re.compile(r'\b(java|jdk|jvm|openjdk)\b', re.I) if 'java' in names else re.compile(r'(?!x)x')
    seen = state.setdefault('context_seen', {})
    found = []
    for src in [s for s in all_sources(state) if s['kind'] == 'context']:
        try:
            if src.get('added'):
                why = public_https(src['url'])                 # again: the name may point elsewhere now
                if why:
                    raise ValueError(why)
            pub = bool(src.get('added'))
            if src.get('fmt') == 'page':
                items = page_items(hg.read_page(src['url'], public_only=pub), src['url'])
            else:
                items = rss_items(hg.get_text(src['url'], public_only=pub))
            _source_ok(state, src['id'], True)
        except Exception as e:
            _source_ok(state, src['id'], False, str(e))
            continue
        for title, link in items:
            key = fid(src['id'], link or title)
            if key in seen or not NOTICE_WORDS.search(title):
                continue
            seen[key] = time.time()
            hit = [n for n, rx in words.items() if rx.search(title)]
            if hit:
                cves = CVE_RX.findall(title)
                found.append({'source': src['name'], 'title': title, 'link': link, 'cves': cves, 'names': hit})
                for cv in cves:                            # which source said it first: the fastest sources, learned
                    state.setdefault('cve_first', {}).setdefault(cv, {'source': src['id'], 'at': time.time()})
    _trim(seen, 5000)
    _trim(state.setdefault('cve_first', {}), 3000)
    return found


def learn_sources(state, findings):
    """Count the sites official advisories cite for what runs here; the most cited ones that
    host-guard does not read are suggested to the admins (never added by themselves)."""
    known = {urllib.parse.urlparse(s['url']).netloc for s in all_sources(state)}
    counts = state.setdefault('ref_domains', {})
    for f in findings.values():
        for r in f.get('refs', []):
            d = urllib.parse.urlparse(r).netloc.lower()
            if d and d not in known:
                counts[d] = counts.get(d, 0) + 1
    _trim(counts, 500)
    return sorted(((n, d) for d, n in counts.items() if n >= 3), reverse=True)[:5]


# ---------------------------------------------------------------- fixes
def plan_fix(hg, f, inv):
    """The automatic fix for a finding, or None with the reason in f['manual']."""
    c = f['comp']
    if c['kind'] == 'os' and c['where'] == 'host' and c.get('pm') == 'dpkg':
        pk = sorted(c['binaries'])
        rc, text = hg.sh('apt-get -s install --only-upgrade ' + ' '.join(shlex.quote(p) for p in pk) + ' 2>&1', 120)
        new = dict(re.findall(r'^Inst (\S+) \[[^\]]*\] \((\S+)', text, re.M))
        if not new:
            f['manual'] = 'no newer package in the configured archives yet; unattended-upgrades installs it when it is published'
            return None
        if f.get('fixed'):
            bad = [p for p, v in new.items() if hg.sh(f'dpkg --compare-versions {shlex.quote(v)} lt {shlex.quote(f["fixed"])}')[0] == 0]
            if len(bad) == len(new):
                f['manual'] = f'the newest package available ({", ".join(new.values())}) is older than the fix {f["fixed"]}'
                return None
        return {'kind': 'apt', 'packages': {p: [c['binaries'].get(p, ''), v] for p, v in new.items()}}
    if c['where'] != 'host':
        ct = next((x for x in inv.get('containers', []) if x['name'] == c['where']), None)
        if not ct or not ct.get('service') or not ct.get('dir'):
            f['manual'] = 'the container is not part of a Docker Compose project: update its image by hand'
            return None
        if not ct.get('floating'):
            f['manual'] = (f'the image {ct["image"]} is pinned to an exact version: change the pin in the Compose file '
                           f'(fixed in {f.get("fixed") or "a newer release"})')
            return None
        return {'kind': 'image', 'container': ct['name'], 'service': ct['service'], 'dir': ct['dir'],
                'files': ct.get('files', ''), 'image': ct['image']}
    if c['kind'] == 'lang':
        f['manual'] = 'an application dependency: ship the update through the application\'s own release (CI), never on the server'
    elif c['kind'] == 'product':
        f['manual'] = 'installed outside the package manager: update it the way it was installed'
    else:
        f['manual'] = 'no automatic fix for this kind of component'
    return None


def _compose(plan):
    files = ' '.join(f'-f {shlex.quote(x)}' for x in plan.get('files', '').split(',') if x)
    return f'docker compose --project-directory {shlex.quote(plan["dir"])} {files}'


def restore_point(hg, f, plan):
    """Everything needed to put things back: returns (directory, manifest)."""
    base = os.path.join(hg.C['BACKUP_DIR'], 'restore-points')
    rid = time.strftime('%Y%m%d-%H%M%S') + '-' + f['fid']
    d = os.path.join(base, rid)
    os.makedirs(d, mode=0o700, exist_ok=True)
    os.chmod(base, 0o700)
    man = {'id': rid, 'at': time.time(), 'finding': {k: f[k] for k in ('fid', 'vuln', 'title', 'tier')},
           'component': {k: f['comp'].get(k) for k in ('name', 'version', 'where')}, 'plan': plan, 'saved': [], 'missing': []}
    with tarfile.open(os.path.join(d, 'etc.tar.gz'), 'w:gz') as t:
        try:
            t.add('/etc', arcname='etc')
            man['saved'].append('etc.tar.gz: /etc as it was')
        except OSError as e:
            man['missing'].append(f'/etc copy: {e}')
    if plan['kind'] == 'apt':
        debs = os.path.join(d, 'debs')
        os.makedirs(debs, exist_ok=True)
        for p, (old, _new) in plan['packages'].items():
            if not old:
                continue
            got = glob_one(f'/var/cache/apt/archives/{p}_{old.replace(":", "%3a")}_*.deb')
            if got:
                shutil.copy2(got, debs)
            elif hg.sh(f'cd {shlex.quote(debs)} && apt-get download {shlex.quote(p + "=" + old)}', 300)[0] != 0 and \
                    not (shutil.which('dpkg-repack') and hg.sh(f'cd {shlex.quote(debs)} && dpkg-repack {shlex.quote(p)}', 300)[0] == 0):
                man['missing'].append(f'{p} {old}: the old package file could not be kept')
                continue
            man['saved'].append(f'debs/: {p} {old}')
    elif plan['kind'] == 'image':
        _, old_id = hg.sh(f'docker inspect --format {{{{.Image}}}} {shlex.quote(plan["container"])}', 30)
        old_id = old_id.strip()
        if old_id.startswith('sha256:'):
            tag = f'host-guard-restore/{plan["service"]}:{rid.lower()}'
            hg.sh(f'docker tag {old_id} {shlex.quote(tag)}', 30)
            man['old_image'] = old_id
            man['saved'].append(f'image {tag} ({old_id[:19]}), the image the container ran')
        else:
            man['missing'].append('the running image id could not be read')
        cfg = os.path.join(d, 'compose')
        os.makedirs(cfg, exist_ok=True)
        for x in [x for x in plan.get('files', '').split(',') if x] + [os.path.join(plan['dir'], '.env')]:
            if os.path.isfile(x):
                shutil.copy2(x, cfg)
        man['saved'].append('compose/: the Compose files')
    try:
        if hg.backup_configured():
            hg.backup()
            man['saved'].append(f'a fresh database or data backup in {hg.C["BACKUP_DIR"]}')
    except Exception as e:                                # a backup failure stops the fix (checked by the caller)
        man['missing'].append(f'backup: {str(e)[:120]}')
        man['backup_failed'] = True
    with open(os.path.join(d, 'manifest.json'), 'w', encoding='utf-8') as fh:
        json.dump(man, fh, indent=1, default=str)
    _prune(hg, base)
    return d, man


def glob_one(pattern):
    import glob
    got = sorted(glob.glob(pattern))
    return got[-1] if got else ''


def _prune(hg, base, keep=10):
    rps = sorted(x for x in os.listdir(base) if os.path.isdir(os.path.join(base, x)))
    for x in rps[:-keep]:
        shutil.rmtree(os.path.join(base, x), ignore_errors=True)
        hg.sh(f"docker images --format '{{{{.Repository}}}}:{{{{.Tag}}}}' | grep -F ':{x.lower()}' | xargs -r docker rmi", 60)


def _snapshot(hg):
    """What should still be true after a fix: running services, listening ports, health."""
    _, units = hg.sh("systemctl list-units --type=service --state=running --no-legend --plain | awk '{print $1}'", 30)
    _, ports = hg.sh("ss -Hltn | awk '{print $4}' | sort -u", 30)
    bad = set()
    try:
        bad = {k for k, b, _s, _b in hg.checks() if b}
    except Exception:
        pass
    return {'units': set(units.split()), 'ports': set(ports.split()), 'bad': bad}


def _healthy(hg, before, plan, wait=None):
    wait = wait if wait is not None else int(os.environ.get('HG_FIX_WAIT', '90'))
    end = time.time() + wait
    problems = ['not checked']
    while True:
        now_ = _snapshot(hg)
        problems = [f'service stopped: {u}' for u in sorted(before['units'] - now_['units'])]
        problems += [f'nothing listens on {p} any more' for p in sorted(before['ports'] - now_['ports'])]
        problems += [f'health check now failing: {k}' for k in sorted(now_['bad'] - before['bad'] - {'reboot', 'backup'})]
        if plan['kind'] == 'image':
            _, st = hg.sh(f"docker inspect --format '{{{{.State.Status}}}} {{{{if .State.Health}}}}{{{{.State.Health.Status}}}}"
                          f"{{{{end}}}}' {shlex.quote(plan['container'])}", 30)
            if not st.startswith('running') or 'unhealthy' in st or 'starting' in st:
                problems.append(f'container {plan["container"]}: {st or "missing"}')
        if not problems or time.time() >= end:
            return problems
        time.sleep(5)


def apply_fix(hg, f, plan):
    """Restore point, the fix, the health check, and a rollback when the check fails.
    Returns a result dict for the report and the mail."""
    d, man = restore_point(hg, f, plan)
    res = {'at': time.time(), 'restore_point': d, 'saved': man['saved'], 'missing': man['missing'], 'plan': plan}
    if man.get('backup_failed') or (plan['kind'] == 'apt' and any('could not be kept' in m for m in man['missing'])):
        res.update(status='not applied', detail='the restore point is incomplete, so nothing was changed: ' + '; '.join(man['missing']))
        return res
    before = _snapshot(hg)
    if plan['kind'] == 'apt':
        pk = ' '.join(shlex.quote(p) for p in plan['packages'])
        rc, text = hg.sh('apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get install -y -q --only-upgrade '
                         f'-o Dpkg::Options::=--force-confold {pk}', 1800)
        if rc == 0 and shutil.which('needrestart'):
            hg.sh('NEEDRESTART_MODE=a needrestart -r a -q', 600)
        done = f'upgraded {", ".join(f"{p} {o} -> {n}" for p, (o, n) in plan["packages"].items())}'
    else:
        rc, text = hg.sh(f'docker pull -q {shlex.quote(plan["image"])}', 900)
        _, new_id = hg.sh(f'docker image inspect --format {{{{.Id}}}} {shlex.quote(plan["image"])}', 30)
        if rc == 0 and new_id.strip() == man.get('old_image'):
            res.update(status='not applied', detail=f'{plan["image"]} has no newer image yet; tried again on the next run')
            return res
        if rc == 0:
            rc, text = hg.sh(f'{_compose(plan)} up -d --no-deps --pull never {shlex.quote(plan["service"])}', 600)
        done = f'pulled {plan["image"]} again and recreated {plan["container"]}'
    problems = _healthy(hg, before, plan) if rc == 0 else [f'the update itself failed: {text[-300:]}']
    if not problems:
        res.update(status='fixed', detail=done)
        return res
    undo_ok, undo_detail = undo(hg, d)
    res.update(status='rolled back' if undo_ok else 'rollback FAILED', detail=f'{done}; then: ' + '; '.join(problems[:6]),
               undo=undo_detail)
    return res


def undo(hg, d):
    """Put back what a restore point holds. Returns (ok, what was done)."""
    try:
        man = json.load(open(os.path.join(d, 'manifest.json'), encoding='utf-8'))
    except (OSError, ValueError) as e:
        return False, f'no restore point at {d}: {e}'
    plan = man['plan']
    if plan['kind'] == 'apt':
        debs = sorted(glob_one(os.path.join(d, 'debs', '*.deb')) and
                      [os.path.join(d, 'debs', x) for x in os.listdir(os.path.join(d, 'debs')) if x.endswith('.deb')])
        if not debs:
            return False, 'no old packages were kept: restore /etc from etc.tar.gz and reinstall by hand'
        rc, text = hg.sh('DEBIAN_FRONTEND=noninteractive dpkg -i --force-confold ' + ' '.join(shlex.quote(x) for x in debs), 900)
        return rc == 0, ('reinstalled ' + ', '.join(os.path.basename(x) for x in debs)) if rc == 0 else text[-300:]
    old = man.get('old_image', '')
    if not old:
        return False, 'the old image id was not kept'
    rc, text = hg.sh(f'docker tag {old} {shlex.quote(plan["image"])} && '
                     f'{_compose(plan)} up -d --no-deps --pull never {shlex.quote(plan["service"])}', 600)
    return rc == 0, (f'{plan["image"]} points at the old image {old[:19]} again; {plan["container"]} recreated') if rc == 0 else text[-300:]


# ---------------------------------------------------------------- the run, mails, commands
def describe(f, with_fix=True):
    c = f['comp']
    where = 'this server' if c['where'] == 'host' else f'container {c["where"]}' + (f' ({c.get("image")})' if c.get('image') else '')
    bits = [f'{f["tier"].upper()}  {c["name"]} {c["version"]} on {where}: {f["vuln"]}']
    bits.append(f'  {f["title"][:240]}')
    why = []
    if f['kev']:
        why.append('exploited in the wild (CISA KEV)')
    if f.get('cvss') is not None:
        why.append(f'CVSS {f["cvss"]}')
    if f.get('epss') is not None:
        why.append(f'{round(f["epss"] * 100, 1)}% chance of exploitation in 30 days (EPSS)')
    why.append('running' if c.get('running') else 'installed, not running')
    if c.get('exposed'):
        why.append('reachable from the internet')
    bits.append('  Why: ' + ', '.join(why) + f'. Source: {f["src"]}.')
    if f.get('fixed'):
        bits.append(f'  Fixed in: {f["fixed"]}')
    elif f.get('no_fix'):
        bits.append('  No fix released yet: host-guard mails again when one is.')
    if f.get('kev_action'):
        bits.append(f'  CISA: {f["kev_action"]}')
    if with_fix:
        if f.get('plan'):
            p = f['plan']
            what = ('upgrade ' + ', '.join(f'{k} to {v[1]}' for k, v in p['packages'].items())) if p['kind'] == 'apt' else \
                   f'pull {p["image"]} again and recreate {p["container"]}'
            bits.append(f'  Fix: {what}')
        elif f.get('manual'):
            bits.append(f'  Fix: {f["manual"]}')
    for r in f.get('refs', [])[:3]:
        bits.append(f'  {r}')
    bits.append(f'  ID: {f["fid"]}')
    return '\n'.join(bits)


def run(hg):
    """The hourly run: inventory, findings, mails by tier, fixes that are due."""
    state = hg.load('shield.json')
    first = 'known' not in state
    inv = inventory(hg)
    findings = check(hg, inv, state)
    chatter = context(hg, inv, state)
    known = state.setdefault('known', {})
    t = time.time()
    hold_h = float(hg.C['AUTO_FIX_HOLD_H'] or 0)
    new = {k: f for k, f in findings.items() if k not in known}
    for k, f in findings.items():
        f['plan'] = plan_fix(hg, f, inv) if f['tier'] == 'Critical' else None
        prev = known.get(k, {})
        known[k] = {'first': prev.get('first', t), 'tier': f['tier'], 'status': prev.get('status', 'open'),
                    'text': describe(f), 'plan': f.get('plan'), 'manual': f.get('manual', ''),
                    'name': f'{f["comp"]["name"]} {f["comp"]["version"]}', 'vuln': f['vuln'], 'where': f['comp']['where'],
                    'fixed': f.get('fixed', ''), 'last': t}
        if f.get('plan') and hg.C['AUTO_FIX'] == 'critical' and known[k]['status'] == 'open':
            known[k]['due'] = known[k]['first'] + hold_h * 3600
    for k in [k for k in known if k not in findings and known[k]['status'] in ('open', 'held', 'not applied')]:
        known[k]['status'] = 'gone'                       # updated by someone, or no longer present
        known[k]['gone_at'] = t
    for k in [k for k, v in known.items() if v.get('status') in ('gone', 'ignored', 'fixed') and t - v.get('last', t) > 30 * 86400]:
        known.pop(k)
    suggestions = learn_sources(state, findings)
    state['last'] = {'at': t, 'components': len(inv['components']), 'containers': len(inv['containers']),
                     'not_covered': inv['not_covered'][:30], 'notes': inv['notes'],
                     'tiers': {x: sum(1 for f in findings.values() if f['tier'] == x and known[f['fid']]['status'] == 'open')
                               for x in TIERS},
                     'chatter': chatter[:20], 'suggested_sources': suggestions}
    hg.save(state, 'shield.json')
    with open(hg.path('inventory.json'), 'w', encoding='utf-8') as fh:
        json.dump(inv, fh, indent=1, default=str)
    if first:
        crit = [f for f in findings.values() if f['tier'] == 'Critical']
        hg.mail(category='Advisory', subject=f'Shield switched on: {len(inv["components"])} components, '
                f'{len(crit)} critical', level='critical' if crit else 'info',
                body=_baseline_body(inv, findings, state, hold_h, hg))
    else:
        _mail_new(hg, new, chatter, hold_h)
    fixes = due_fixes(hg, state)
    print(f'shield: {len(inv["components"])} components in {1 + len(inv["containers"])} places; '
          + ', '.join(f'{n} {x.lower()}' for x, n in state['last']['tiers'].items()) + f'; {len(new)} new; {len(fixes)} fixed')


def _baseline_body(inv, findings, state, hold_h, hg):
    lines = [f'Inventory: {len(inv["components"])} components on {inv["os"]["name"]} (kernel {inv["os"]["kernel"]}) and '
             f'{len(inv["containers"])} container(s).']
    for x in TIERS:
        part = [f for f in findings.values() if f['tier'] == x]
        lines.append(f'{x}: {len(part)}')
    crit = [f for f in findings.values() if f['tier'] == 'Critical']
    if crit:
        lines += ['', 'CRITICAL, act now:'] + [describe(f) for f in crit[:15]]
        lines.append(_auto_note(hg, hold_h))
    mod = [f for f in findings.values() if f['tier'] == 'Moderate']
    if mod:
        lines += ['', 'Moderate (the daily report keeps the list):'] + [describe(f, False) for f in mod[:10]]
    if inv['not_covered']:
        lines += ['', 'Not covered (listed so nothing is silently skipped):'] + ['  ' + x for x in inv['not_covered'][:15]]
    down = [s for s, v in state.get('sources', {}).items() if v.get('fail')]
    if down:
        lines += ['', 'Sources not reachable on this run: ' + ', '.join(down)]
    return '\n'.join(lines)


def _auto_note(hg, hold_h):
    if hg.C['AUTO_FIX'] != 'critical':
        return '\nAutomatic fixes are off (AUTO_FIX=off): fix with  sudo hostguard fix ID'
    win = hg.C['FIX_WINDOW'] or 'any time'
    return (f'\nCritical items with an automatic fix are fixed {hold_h:g} h after this mail, inside the window ({win}), '
            'with a restore point first.\n  Hold one:  sudo hostguard hold ID\n  Fix now:   sudo hostguard fix ID\n'
            '  Ignore:    sudo hostguard ignore ID "reason"')


def _mail_new(hg, new, chatter, hold_h):
    crit = [f for f in new.values() if f['tier'] == 'Critical']
    mod = [f for f in new.values() if f['tier'] == 'Moderate']
    if crit:
        top = max(crit, key=lambda f: (f['kev'], f.get('cvss') or 0))
        subj = (f'{top["comp"]["name"]} {top["comp"]["version"]}: {top["vuln"]}'
                + (' (exploited)' if top['kev'] else f' (CVSS {top["cvss"]})' if top.get('cvss') else '')
                + (f' and {len(crit) - 1} more' if len(crit) > 1 else ''))
        body = '\n\n'.join(describe(f) for f in crit) + '\n' + _auto_note(hg, hold_h)
        if chatter:
            body += '\n\nWhat researchers and the news say about software on this server:\n' + \
                    '\n'.join(f'  {c["source"]}: {c["title"]}  {c["link"]}' for c in chatter[:8])
        hg.mail(subject=subj, body=body, level='critical', category='Advisory')
    if mod:
        hg.mail(subject=f'{len(mod)} moderate security finding(s)', body='\n\n'.join(describe(f, False) for f in mod[:25]),
                level='alert', category='Advisory')
    if chatter and not crit:
        hg.mail(subject=f'{len(chatter)} report(s) about software on this server', level='info', category='Advisory',
                body='Research labs and the news, read as context. Nothing here triggers a fix; the official '
                'sources are checked every hour.\n\n' + '\n'.join(f'{c["source"]}: {c["title"]}\n  {c["link"]}' for c in chatter[:20]))


def due_fixes(hg, state, only=None, force=False):
    """Apply the fixes that are due (or the one asked for). Mails each result."""
    known = state.setdefault('known', {})
    done = []
    for k, v in sorted(known.items()):
        if only and k != only:
            continue
        if not v.get('plan') or v['status'] not in ('open', 'not applied') and not (force and v['status'] == 'held'):
            continue
        if not force and (hg.C['AUTO_FIX'] != 'critical' or time.time() < v.get('due', float('inf'))
                          or not in_window(hg.C['FIX_WINDOW'])):
            continue
        f = {'fid': k, 'vuln': v['vuln'], 'title': v['text'].splitlines()[1].strip() if '\n' in v['text'] else v['vuln'],
             'tier': v['tier'], 'comp': {'name': v['name'].split(' ')[0], 'version': v['name'].split(' ', 1)[-1], 'where': v['where']}}
        res = apply_fix(hg, f, v['plan'])
        v['status'] = res['status'] if res['status'] != 'fixed' else 'fixed'
        v.setdefault('fixes', []).append({k2: res[k2] for k2 in ('at', 'status', 'detail', 'restore_point')})
        state.setdefault('fix_log', []).append({'fid': k, 'name': v['name'], 'vuln': v['vuln'], **{k2: res[k2] for k2 in
                                                ('at', 'status', 'detail', 'restore_point')}})
        state['fix_log'] = state['fix_log'][-100:]
        hg.save(state, 'shield.json')
        _mail_fix(hg, v, res, force)
        done.append(k)
    return done


def _mail_fix(hg, v, res, by_admin):
    rp = res['restore_point']
    rid = os.path.basename(rp)
    head = {'fixed': 'Fixed', 'rolled back': 'Fix rolled back', 'rollback FAILED': 'Fix FAILED and rollback FAILED',
            'not applied': 'Fix not applied'}[res['status']]
    body = [f'{head}: {v["name"]}, {v["vuln"]} ({"by an admin" if by_admin else "automatically, after the hold"}).',
            f'What was done: {res["detail"]}']
    if res.get('undo'):
        body.append(f'Rollback: {res["undo"]}')
    body += ['', f'Restore point: {rp}'] + [f'  {x}' for x in res['saved']]
    if res['missing']:
        body += ['Not kept:'] + [f'  {x}' for x in res['missing']]
    body += ['', 'To undo this fix:', f'  sudo hostguard undo {rid}',
             f'To put back a file from before:  sudo tar -xzf {rp}/etc.tar.gz -C / etc/PATH/TO/FILE']
    level = 'info' if res['status'] == 'fixed' else 'critical' if 'FAILED' in res['status'] or res['status'] == 'rolled back' else 'alert'
    hg.mail(subject=f'{head}: {v["name"]} ({v["vuln"]})', body='\n'.join(body), level=level, category='Advisory')


def report_lines(hg):
    """The daily report's part."""
    state = hg.load('shield.json')
    last = state.get('last')
    if not last:
        return ['Not run yet (hostguard advisories runs every hour).']
    t = last['tiers']
    lines = [f'Inventory: {last["components"]} components, {last["containers"]} container(s); checked {hg.stamp(last["at"])}',
             f'Open: {t.get("Critical", 0)} critical, {t.get("Moderate", 0)} moderate, {t.get("Low", 0)} low']
    open_ = [v for v in state.get('known', {}).values() if v['status'] in ('open', 'held', 'not applied')
             and v['tier'] in ('Critical', 'Moderate')]
    for v in sorted(open_, key=lambda v: (v['tier'] != 'Critical', v['name']))[:15]:
        due = f', automatic fix {hg.stamp(v["due"])}' if v.get('due') and v['status'] == 'open' else ''
        lines.append(f'  {v["tier"]}: {v["name"]} on {v["where"]}: {v["vuln"]} ({v["status"]}{due})')
    day = [x for x in state.get('fix_log', []) if time.time() - x['at'] < 86400]
    for x in day:
        lines.append(f'Fix {x["status"]}: {x["name"]} {x["vuln"]}; restore point {x["restore_point"]}')
    down = [f'{s} ({v.get("error", "")[:60]})' for s, v in state.get('sources', {}).items() if v.get('fail', 0) >= 3]
    if down:
        lines.append('Sources failing 3+ runs: ' + '; '.join(down))
    if last.get('not_covered'):
        lines.append(f'Not covered: {len(last["not_covered"])} (hostguard inventory lists them)')
    if last.get('suggested_sources'):
        lines.append('Sites the advisories for this server cite most (add one: hostguard sources add NAME URL): ' +
                     ', '.join(f'{d} ({n})' for n, d in last['suggested_sources']))
    return lines


def cli(hg, args):
    """hostguard inventory | findings | hold ID | ignore ID REASON | fix ID | undo RESTORE_POINT
    | sources [add NAME https://URL [feed|page] | remove ID]"""
    state = hg.load('shield.json')
    known = state.setdefault('known', {})
    cmd = args[0] if args else ''
    if cmd == 'inventory':
        inv = inventory(hg)
        by = {}
        for c in inv['components']:
            by.setdefault(c['where'], []).append(c)
        for w, cs in by.items():
            print(f'{w}: {len(cs)} components ({sum(1 for c in cs if c.get("running"))} running)')
            for c in sorted(cs, key=lambda c: c['name']):
                if c['kind'] != 'os' or c.get('running'):
                    print(f'  {c["kind"]:8} {c["eco"]:16} {c["name"]} {c["version"]}')
        for x in inv['not_covered']:
            print('not covered:', x)
        return 0
    if cmd == 'findings':
        for k, v in sorted(known.items(), key=lambda kv: TIERS.index(kv[1]['tier'])):
            if v['status'] in ('open', 'held', 'not applied', 'rolled back', 'rollback FAILED'):
                print(f'{k}  {v["tier"]:8} {v["status"]:12} {v["name"]} on {v["where"]}: {v["vuln"]}')
        return 0
    if cmd in ('hold', 'ignore', 'fix') and len(args) >= 2:
        k = args[1]
        if k not in known:
            print(f'no finding {k}: see  hostguard findings')
            return 1
        if cmd == 'hold':
            known[k]['status'] = 'held'
            hg.save(state, 'shield.json')
            hg.mail(subject=f'Automatic fix held: {known[k]["name"]} ({known[k]["vuln"]})', category='Advisory', level='info',
                    body=f'An admin held the automatic fix for {k}. It stays open in the daily report.\n'
                    f'Fix it later:  sudo hostguard fix {k}')
            print('held')
            return 0
        if cmd == 'ignore':
            reason = ' '.join(args[2:]).strip()
            if not reason:
                print('give a reason: hostguard ignore ID "why this does not apply"')
                return 1
            known[k].update(status='ignored', reason=reason[:200], ignored_at=time.time())
            hg.save(state, 'shield.json')
            hg.mail(subject=f'Finding ignored: {known[k]["name"]} ({known[k]["vuln"]})', category='Advisory', level='info',
                    body=f'An admin marked {k} as not applying here: {reason[:200]}')
            print('ignored')
            return 0
        if not known[k].get('plan'):
            print(f'no automatic fix for {k}: {known[k].get("manual") or "see the finding"}')
            return 1
        done = due_fixes(hg, state, only=k, force=True)
        print(known[k]['status'] if done else 'not applied')
        return 0 if known[k]['status'] == 'fixed' else 1
    if cmd == 'undo' and len(args) == 2:
        rid = os.path.basename(args[1])
        d = os.path.join(hg.C['BACKUP_DIR'], 'restore-points', rid)
        ok, detail = undo(hg, d)
        hg.mail(subject=f'Restore point {"put back" if ok else "NOT put back"}: {rid}', body=detail, category='Advisory',
                level='info' if ok else 'alert')
        print(detail)
        return 0 if ok else 1
    if cmd == 'sources':
        if args[1:2] == ['add'] and len(args) in (4, 5):
            ok, msg = add_source(hg, state, args[2], args[3], args[4] if len(args) == 5 else 'feed')
            print(msg)
            return 0 if ok else 1
        if args[1:2] == ['remove'] and len(args) == 3:
            ok, msg = remove_source(hg, state, args[2])
            print(msg)
            return 0 if ok else 1
        if args[1:2] and args[1] in ('add', 'remove'):
            print('hostguard sources add NAME https://URL [feed|page]   |   hostguard sources remove ID')
            return 2
        for s in all_sources(state):
            st = state.get('sources', {}).get(s['id'], {})
            ok = hg.stamp(st['ok_at']) if st.get('ok_at') else 'never'
            print(f'{s["kind"]:8} {s["id"]:18} last read {ok}{"  FAILING: " + st.get("error", "") if st.get("fail") else ""}\n'
                  f'         {s["name"]}: {s["url"]}')
        firsts = {}
        for v in state.get('cve_first', {}).values():
            firsts[v['source']] = firsts.get(v['source'], 0) + 1
        if firsts:
            print('first to name a CVE that touched this server:', ', '.join(f'{k} {n}' for k, n in
                                                                            sorted(firsts.items(), key=lambda x: -x[1])))
        return 0
    print(cli.__doc__)
    return 2
