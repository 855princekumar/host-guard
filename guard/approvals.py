"""host-guard approvals: a short, fixed list of actions (fix a finding, hold its automatic fix,
reboot) that an admin approves by replying to host-guard's mail, on the dashboard (reachable
only through a tunnel) or on the server's console. Nothing a mail says is run as a command:
a reply only names one of these actions with the single-use code host-guard put in its own
mail. Every approval and every refusal is logged with who and through which channel.

Loaded by hostguard.py:  hostguard replies   (read the replies, every 2 minutes when
REPLY_ACTIONS=on)  |  hostguard approvals  (what waits for approval, and the log).
See docs/APPROVALS.md.
"""
import base64
import email
import email.policy
import email.utils
import hashlib
import hmac
import html
import imaplib
import os
import re
import secrets
import ssl
import time

ACTIONS = ('fix', 'hold', 'reboot')
CHANNELS = ('email', 'dashboard', 'console')
TARGET = re.compile(r'[0-9a-f]{8}|now')
LINE_RX = re.compile(r'^\s*(FIX|HOLD|REBOOT)\s+(hg-[a-z2-7]{26})(?![a-z2-7])', re.I)
TOKEN_RX = re.compile(r'hg-[a-z2-7]{26}(?![a-z2-7])', re.I)
QUOTE_START = re.compile(r'^(>|on .{0,300}wrote:?$|-{2,}\s*original message|_{5,}|from:\s|sent from my\s|--$)', re.I)
MSG_MAX = 256 * 1024          # a reply bigger than this is not read
PER_RUN = 50                  # replies read per run
LOG_MAX = 1000
WHAT = {'fix': 'fix now (a restore point first, rolled back if the server is not healthy after)',
        'hold': 'hold the automatic fix (it stays open in the daily report)',
        'reboot': 'reboot now (a backup first)'}


# ---------------------------------------------------------------- codes
def _key(hg):
    """A random key only root can read; codes are derived from it, so the dashboard (which
    cannot read host-guard's state) can never make one, and no code is stored anywhere."""
    p = hg.path('approvals.key')
    for _ in range(2):
        try:
            fd = os.open(p, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
            try:
                k = os.read(fd, 64)
            finally:
                os.close(fd)
            if len(k) >= 32:
                return k
        except FileNotFoundError:
            pass
        try:
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        except FileExistsError:
            continue
        try:
            os.write(fd, secrets.token_bytes(32))
        finally:
            os.close(fd)
    raise RuntimeError(f'approvals: cannot read or make {p}')


def token(hg, rid, nonce):
    mac = hmac.new(_key(hg), f'{rid}|{nonce}'.encode(), hashlib.sha256).digest()[:16]
    return 'hg-' + base64.b32encode(mac).decode().lower().rstrip('=')


def approvers(hg):
    return hg.panel_admins()


def need(hg, action):
    """How many different admins must approve: a reboot needs REBOOT_APPROVALS (2), a fix
    FIX_APPROVALS (1), a hold one; never more than there are admins."""
    n = {'reboot': hg.C['REBOOT_APPROVALS'], 'fix': hg.C['FIX_APPROVALS']}.get(action, '1')
    try:
        n = int(n)
    except ValueError:
        n = 2
    return max(1, min(n, len(approvers(hg)) or 1))


def _live(req, t=None):
    return req.get('status') == 'pending' and (t or time.time()) < req.get('expires', 0)


def offer(hg, action, target, summary):
    """The code for (action, target), made once and kept until it is used or expires."""
    st = hg.load('approvals.json')
    reqs = st.setdefault('requests', {})
    rid = f'{action}:{target}'
    req = reqs.get(rid)
    if not req or not _live(req):
        t = time.time()
        req = reqs[rid] = {'action': action, 'target': target, 'summary': str(summary)[:200], 'nonce': secrets.token_hex(8),
                           'created': t, 'expires': t + float(hg.C['REPLY_TTL_H'] or 24) * 3600, 'status': 'pending',
                           'approvals': []}
        _prune(reqs)
        hg.save(st, 'approvals.json')
    return token(hg, rid, req['nonce']), req


def _prune(reqs):
    t = time.time()
    for rid in [r for r, v in reqs.items() if v.get('status') != 'pending' and t - v.get('expires', 0) > 7 * 86400]:
        reqs.pop(rid)


def offer_text(hg, items):
    """The lines a mail carries so an admin can act by replying: items are (action, target,
    summary). Empty when replies are off."""
    if hg.C['REPLY_ACTIONS'] != 'on' or not items:
        return ''
    lines, until = [], 0
    for action, target, summary in items:
        tok, req = offer(hg, action, target, summary)
        until = req['expires']
        n = need(hg, action)
        lines.append(f'  {action.upper()} {tok}    {WHAT[action]}' + (f'; needs {n} admins' if n > 1 else ''))
    return ('\n\nAct by replying: reply to this mail with one of these lines as the FIRST line of your reply '
            f'(nothing else is read; the code works once, only for that action, until {hg.stamp(until)}, '
            'and only from an admin\'s own mailbox):\n' + '\n'.join(lines))


# ---------------------------------------------------------------- the log
def record(hg, action, target, by, channel, result, st=None):
    """One line of the approvals log: who, through which channel, what came of it."""
    own = st is None
    st = hg.load('approvals.json') if own else st
    log = st.setdefault('log', [])
    log.append({'at': time.time(), 'action': action, 'target': target, 'by': str(by)[:120], 'channel': channel,
                'result': str(result)[:300]})
    st['log'] = log[-LOG_MAX:]
    if own:
        hg.save(st, 'approvals.json')


# ---------------------------------------------------------------- approving
def _run(hg, action, target, by):
    """Do the approved action. Returns (ok, what happened)."""
    if action == 'reboot':
        return hg.approved_reboot(by)
    sh = hg.shield_module()
    state = hg.load('shield.json')
    return sh.act(hg, state, action, target, by)


def approve(hg, action, target, by, channel, tok=None):
    """An admin `by` approves (action, target) through `channel`. On the dashboard and the
    console the request is made if none waits; by mail only a live code counts (tok).
    Returns (ok, message)."""
    if action not in ACTIONS or channel not in CHANNELS or not TARGET.fullmatch(str(target)):
        return False, 'not an action host-guard knows'
    if (action == 'reboot') != (target == 'now'):
        return False, 'not an action host-guard knows'
    st = hg.load('approvals.json')
    reqs = st.setdefault('requests', {})
    rid = f'{action}:{target}'
    req = reqs.get(rid)
    t = time.time()
    if channel == 'email':
        if not req or not _live(req, t) or not hmac.compare_digest(token(hg, rid, req['nonce']), tok or ''):
            record(hg, action, target, by, channel, 'refused: the code is unknown, used or expired', st)
            hg.save(st, 'approvals.json')
            return False, 'the code is unknown, already used or expired'
    elif not req or not _live(req, t):
        req = reqs[rid] = {'action': action, 'target': target, 'summary': f'{action} {target}', 'nonce': secrets.token_hex(8),
                           'created': t, 'expires': t + float(hg.C['REPLY_TTL_H'] or 24) * 3600, 'status': 'pending',
                           'approvals': []}
    if any(a['by'] == by for a in req['approvals']):
        record(hg, action, target, by, channel, 'refused: already approved by this admin', st)
        hg.save(st, 'approvals.json')
        return False, f'you already approved this; it needs another admin ({len(req["approvals"])} of {need(hg, action)})'
    req['approvals'].append({'by': by, 'channel': channel, 'at': t})
    n = need(hg, action)
    if len(req['approvals']) < n:
        record(hg, action, target, by, channel, f'approval {len(req["approvals"])} of {n}', st)
        hg.save(st, 'approvals.json')
        tok_ = token(hg, rid, req['nonce'])
        hg.mail(category='Approval', level='alert', subject=f'Approval {len(req["approvals"])} of {n}: {action} {target}',
                body=f'{by} approved "{req["summary"]}" ({channel}). It needs {n - len(req["approvals"])} more admin(s).\n'
                + (f'\nTo approve, reply to this mail with this line first:\n  {action.upper()} {tok_}\n'
                   if hg.C['REPLY_ACTIONS'] == 'on' else '')
                + '\nOr on the dashboard (Advisories). Not expected? Do nothing: it expires '
                f'{hg.stamp(req["expires"])}.')
        return True, f'approved ({len(req["approvals"])} of {n}); another admin must approve too'
    req['status'] = 'running'
    hg.save(st, 'approvals.json')
    who = ' and '.join(f'{a["by"]} ({a["channel"]})' for a in req['approvals'])
    try:
        ok, what = _run(hg, action, target, who)
    except Exception as e:                                   # the log must say what happened, always
        ok, what = False, f'failed: {e}'
    st = hg.load('approvals.json')
    req = st.setdefault('requests', {}).get(rid, req)
    req['status'] = 'done' if ok else 'failed'
    req['result'] = what
    record(hg, action, target, by, channel, ('done: ' if ok else 'not done: ') + what, st)
    hg.save(st, 'approvals.json')
    return ok, what


# ---------------------------------------------------------------- replies by mail
def sender(msg, hg):
    froms = msg.get_all('From') or []
    if len(froms) != 1:
        return None
    addrs = email.utils.getaddresses([str(froms[0])])
    if len(addrs) != 1:
        return None
    a = addrs[0][1].strip().lower()
    return a if hg.EMAIL.match(a) else None


def authenticated(msg, addr, authserv):
    """True when the receiving mail server (the topmost Authentication-Results, which only it
    adds; anything a sender wrote is below it) says DMARC passed for the From domain."""
    ars = msg.get_all('Authentication-Results') or []
    if not ars:
        return False, 'no Authentication-Results from the mail server'
    top = re.sub(r'\s+', ' ', str(ars[0])).strip()
    serv = top.split(';', 1)[0].strip().split(' ')[0].lower()
    if serv != authserv.lower():
        return False, f'the mail server\'s result is from "{serv[:60]}", not {authserv}'
    dom = addr.rsplit('@', 1)[1]
    for m in re.finditer(r'\bdmarc=([a-z]+)\b[^;]*?\bheader\.from=([^\s;]+)', top, re.I):
        if m.group(1).lower() == 'pass' and m.group(2).strip('"').lower() == dom:
            return True, ''
    return False, f'DMARC did not pass for {dom}'


def first_lines(msg, n=10):
    """The reply's own first lines: up to the first quoted line, signature or forwarded part."""
    try:
        part = msg.get_body(preferencelist=('plain', 'html'))
        text = part.get_content() if part is not None else ''
        if part is not None and part.get_content_type() == 'text/html':
            text = re.sub(r'<blockquote.*', '', text, flags=re.I | re.S)
            text = html.unescape(re.sub(r'<[^>]{0,2000}>', '', re.sub(r'<(br|/p|/div)[^>]{0,200}>', '\n', text, flags=re.I)))
    except Exception:                                        # a broken part is a reply with nothing in it
        return []
    out = []
    for line in str(text).splitlines()[:400]:
        s = line.strip()
        if QUOTE_START.match(s):
            break
        if s:
            out.append(s)
            if len(out) >= n:
                break
    return out


def handle(hg, raw):
    """One reply. Returns (verdict, detail) for the log; never raises: a mail the parser cannot
    read is refused, so one broken mail never stops the replies behind it."""
    try:
        return _handle(hg, raw)
    except Exception as e:
        record(hg, '-', '-', '(unreadable mail)', 'email', f'refused: unreadable ({type(e).__name__})')
        return 'refused', f'unreadable mail ({type(e).__name__})'


def _handle(hg, raw):
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    st = hg.load('approvals.json')
    mid = hashlib.sha256(str(msg.get('Message-ID', '') or raw[:4096]).encode('utf-8', 'replace')).hexdigest()[:24]
    seen = st.setdefault('seen', [])
    if mid in seen:
        return 'skipped', 'already read'
    seen.append(mid)
    st['seen'] = seen[-500:]
    hg.save(st, 'approvals.json')
    addr = sender(msg, hg)
    lines = first_lines(msg)
    cmd = next((m for m in (LINE_RX.match(x) for x in lines[:3]) if m), None)
    if not addr or addr not in approvers(hg):
        record(hg, '-', '-', addr or '(no single sender)', 'email', 'refused: not an admin address')
        return 'refused', 'not an admin'
    ok, why = authenticated(msg, addr, hg.C['REPLY_AUTHSERV'])
    if not ok:
        hit = _void_if_valid(hg, cmd, addr, why)
        record(hg, cmd.group(1).lower() if cmd else '-', '-', addr, 'email', f'refused: {why}' + (' (its code is now void)' if hit else ''))
        return 'refused', why
    if not cmd:
        record(hg, '-', '-', addr, 'email', 'refused: no action line first in the reply')
        hg.mail(category='Approval', level='info', to=[addr], subject='Your reply was not understood',
                body='Nothing was done. Put one of the lines from host-guard\'s mail (for example FIX hg-...) as the '
                'first line of your reply, above the quoted mail.')
        return 'refused', 'no action line'
    verb, tok = cmd.group(1).lower(), cmd.group(2).lower()
    req = _find(hg, tok)
    if not req or req['action'] != verb:
        record(hg, verb, '-', addr, 'email', 'refused: the code is unknown, used, expired or for another action')
        hg.mail(category='Approval', level='info', to=[addr], subject='Your reply did not approve anything',
                body='The code is unknown, already used, expired, or for another action. Nothing was done.')
        return 'refused', 'unknown code'
    ok, what = approve(hg, verb, req['target'], addr, 'email', tok)
    if ok and 'another admin' in what:
        return 'approved', what                              # approve() mailed every admin already
    hg.mail(category='Approval', level='alert' if ok else 'info',
            subject=f'{"Approved" if ok else "Not done"} by mail: {verb} {req["target"]} ({addr})',
            body=f'{addr} replied {verb.upper()} for "{req["summary"]}".\nResult: {what}\n\n'
            'Every approval is in the log:  sudo hostguard approvals  (and on the dashboard).')
    return ('approved' if ok else 'refused'), what


def _find(hg, tok):
    st = hg.load('approvals.json')
    t = time.time()
    for rid, req in st.get('requests', {}).items():
        if _live(req, t) and hmac.compare_digest(token(hg, rid, req['nonce']), tok):
            return req
    return None


def _void_if_valid(hg, cmd, addr, why):
    """A reply that names a live code but fails the mail check: the code was seen by someone
    who is not that admin's mailbox. Void it and tell every admin."""
    if not cmd:
        return False
    req = _find(hg, cmd.group(2).lower())
    if not req:
        return False
    st = hg.load('approvals.json')
    rid = f'{req["action"]}:{req["target"]}'
    st['requests'][rid]['status'] = 'void'
    hg.save(st, 'approvals.json')
    hg.mail(category='Approval', level='critical', subject=f'Forged approval refused: {req["action"]} {req["target"]}',
            body=f'A reply claiming to be from {addr} carried a valid approval code, but the mail server did not '
            f'vouch for it ({why}). Nothing was done and the code is void.\n\nSomeone may be reading host-guard\'s '
            'mail: check who can see the admins\' mailboxes and the sending account.')
    return True


def poll(hg, imap=None):
    """Read new replies in the sending account's inbox (IMAP over TLS) and act on the ones
    that carry an approval line. Mail without a host-guard code is left untouched."""
    C = hg.C
    if C['REPLY_ACTIONS'] != 'on':
        print('replies: off (REPLY_ACTIONS=on in guard.conf turns them on)')
        return 0
    user = C['IMAP_USER'] or C['MAIL_FROM']
    pw = C['IMAP_PASSWORD'] or C['SMTP_PASSWORD']
    if not user or not pw:
        print('replies: no IMAP_USER/MAIL_FROM or no IMAP_PASSWORD/SMTP_PASSWORD in .env')
        return 1
    ctx = ssl.create_default_context(cafile=C['IMAP_CA'] or None)
    im = imap or imaplib.IMAP4_SSL(C['IMAP_HOST'], int(C['IMAP_PORT']), ssl_context=ctx, timeout=60)
    done = 0
    try:
        im.login(user, pw)
        im.select('INBOX')
        since = time.strftime('%d-%b-%Y', time.gmtime(time.time() - 2 * 86400))
        typ, data = im.uid('SEARCH', None, 'UNSEEN', 'SINCE', since)
        uids = (data[0] or b'').split()[-PER_RUN:] if typ == 'OK' else []
        for uid in uids:
            typ, meta = im.uid('FETCH', uid, '(RFC822.SIZE)')
            m = re.search(rb'RFC822\.SIZE (\d+)', b' '.join(x if isinstance(x, bytes) else b' '.join(x) for x in meta or []))
            if not m or int(m.group(1)) > MSG_MAX:
                continue
            typ, parts = im.uid('FETCH', uid, '(BODY.PEEK[])')
            raw = next((p[1] for p in parts or [] if isinstance(p, tuple) and len(p) > 1), b'')
            if not TOKEN_RX.search(raw.decode('utf-8', 'replace')):
                continue                                     # not a reply to host-guard: left as it was
            verdict, detail = handle(hg, raw)
            im.uid('STORE', uid, '+FLAGS', '(\\Seen)')
            print(f'replies: {verdict}: {detail}')
            done += 1
    finally:
        try:
            im.logout()
        except Exception:
            pass
    print(f'replies: {done} read')
    return 0


def lines(hg, n=30):
    """What waits for approval, and the last log lines (hostguard approvals, the daily report)."""
    st = hg.load('approvals.json')
    t = time.time()
    out = []
    for _rid, req in sorted(st.get('requests', {}).items()):
        if _live(req, t):
            got = ', '.join(f'{a["by"]} ({a["channel"]})' for a in req['approvals']) or 'none yet'
            out.append(f'waiting: {req["action"]} {req["target"]}: {req["summary"]}; approvals {len(req["approvals"])} '
                       f'of {need(hg, req["action"])} ({got}); until {hg.stamp(req["expires"])}')
    for x in st.get('log', [])[-n:]:
        out.append(f'{hg.stamp(x["at"])}  {x["channel"]:9} {x["by"]}: {x["action"]} {x["target"]}: {x["result"]}')
    return out or ['nothing waits for approval, and nothing was approved yet']


def export(hg):
    """For the dashboard: what waits (no codes, no nonces) and the last 30 log lines."""
    st = hg.load('approvals.json')
    t = time.time()
    return {'waiting': [{'action': r['action'], 'target': r['target'], 'summary': r['summary'], 'expires': r['expires'],
                         'need': need(hg, r['action']), 'approvals': [{'by': a['by'], 'channel': a['channel'], 'at': a['at']}
                                                                      for a in r['approvals']]}
                        for r in st.get('requests', {}).values() if _live(r, t)],
            'log': st.get('log', [])[-30:]}
