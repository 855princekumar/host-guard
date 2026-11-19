#!/usr/bin/env python3
"""The panel in a real browser (headless Chromium, Playwright), as an admin sees it through an
SSH tunnel: the container shares the target's network namespace, so 127.0.0.1:8650 is the
panel. Signs in with the admin's address and the code mailed to it (read from the admins'
mailbox, mounted at /mail), takes the screenshots for the docs, then attacks it the way a hostile web page
open in the same browser would: reading it across origins (CORS), posting to it from another
site, framing it, and stored script injection through the status data. A page on evil.test
(served here on port 9999) plays the hostile site. Prints one JSON object per check."""
import http.server
import json
import os
import re
import threading
import time

from playwright.sync_api import sync_playwright

PANEL = 'http://127.0.0.1:8650'
EVIL = 'http://evil.test:9999'
ADMIN, MAILBOX = 'security@example.com', '/mail/hg-captured'
OUT = os.environ.get('OUT', '/out')
PAGES = {
    'read.html': f"""<script>
fetch('{PANEL}/', {{credentials: 'include'}}).then(r => r.text())
  .then(t => document.title = 'READ ' + t.length).catch(e => document.title = 'BLOCKED');
</script>""",
    'post.html': f"""<form id=f method=post action="{PANEL}/logout"><input name=csrf value=guessed></form>
<script>document.getElementById('f').submit()</script>""",
    'frame.html': f"""<iframe id=x src="{PANEL}/" width=800 height=600></iframe>""",
}
out = []


def check(id_, technique, attack, expected, ok, evidence, gap=False):
    out.append({'id': id_, 'technique': technique, 'attack': attack, 'expected': expected,
                'result': 'PASS' if ok else ('GAP' if gap else 'FAIL'), 'evidence': evidence})


def mailbox():
    try:
        return open(MAILBOX, encoding='utf-8', errors='replace').read()
    except OSError:
        return ''


def code_after(before, timeout=25):
    """The code mailed to the admin since the mailbox had `before` characters (the admin's inbox)."""
    end = time.time() + timeout
    while time.time() < end:
        for part in reversed(mailbox()[before:].split('=== MAIL to ')[1:]):
            m = re.search(r'Code: (\d{6})', part)
            if part.split('\n', 1)[0].strip() == ADMIN and m:
                return m.group(1)
        time.sleep(0.5)
    return ''


class Evil(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = PAGES.get(self.path.lstrip('/'), 'nothing').encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


threading.Thread(target=http.server.ThreadingHTTPServer(('127.0.0.1', 9999), Evil).serve_forever, daemon=True).start()

with sync_playwright() as p:
    browser = p.chromium.launch(args=['--host-resolver-rules=MAP evil.test 127.0.0.1'])
    ctx = browser.new_context(viewport={'width': 1280, 'height': 900}, color_scheme='light')
    page = ctx.new_page()
    dialogs = []
    page.on('dialog', lambda d: (dialogs.append(d.message), d.dismiss()))

    page.goto(PANEL + '/login')
    page.screenshot(path=f'{OUT}/panel-signin.png')
    check('GUI-1', 'T1078', 'The sign-in page in a browser', 'only an email address: no password field',
          page.locator('#e').count() == 1 and page.locator('input[type=password]').count() == 0
          and 'Sign out' not in page.content(), 'email form shown; screenshot panel-signin.png')

    ctx.add_cookies([{'name': 'hg_s', 'value': 'attacker-chosen-session-id', 'url': PANEL}])
    page.goto(PANEL + '/login')
    before = len(mailbox())
    page.fill('#e', ADMIN)
    page.click('button')
    page.wait_for_selector('#c')
    page.screenshot(path=f'{OUT}/panel-signin-code.png')
    code = code_after(before)
    page.fill('#c', code)
    page.click('button')
    page.wait_for_load_state()
    html = page.content()
    session = next((c['value'] for c in ctx.cookies() if c['name'] == 'hg_s'), '')
    signed_in = 'Sign out' in html and all(s in html for s in ('Open problems', 'Health', 'Backup'))
    page.screenshot(path=f'{OUT}/panel-dashboard.png', full_page=True)
    check('GUI-2', 'T1078', 'An admin signs in with their address and the code mailed to it, in a real browser',
          'the dashboard: open problems, health, backup and the rest', signed_in and ADMIN in html,
          f'code read from the mailbox: {bool(code)}; signed in: {signed_in}; screenshots panel-signin-code.png, '
          'panel-dashboard.png')
    check('PANEL-11', 'T1563', 'Session fixation: a session cookie planted before sign-in',
          'replaced by a new random session at sign-in', bool(session) and session != 'attacker-chosen-session-id',
          f'cookie after sign-in is {"a new value" if session != "attacker-chosen-session-id" else "the planted one"}')

    dark = browser.new_context(viewport={'width': 1280, 'height': 900}, color_scheme='dark',
                               storage_state=ctx.storage_state())
    dp = dark.new_page()
    dp.goto(PANEL + '/')
    dp.screenshot(path=f'{OUT}/panel-dashboard-dark.png', full_page=True)
    dark.close()

    text = page.inner_text('body')
    planted = '<img src=x onerror=' in text and '<script>' in text
    check('PANEL-12', 'T1059.007', 'Stored script injection: <script> and onerror payloads planted in an alert '
          'subject and a mail subject that the panel shows', 'shown as text, never run (escaping, CSP without script)',
          planted and not dialogs and page.title() != 'XSS',
          f'payloads visible as text: {planted}; dialogs: {len(dialogs)}; page title: {page.title()!r}')

    page.goto(EVIL + '/read.html')
    page.wait_for_function("document.title !== ''", timeout=10000)
    check('PANEL-13', 'T1185', 'A hostile page in the same browser reads the panel (fetch with credentials, CORS)',
          'the browser refuses: the panel sends no CORS headers', page.title() == 'BLOCKED',
          f'hostile page result: {page.title()}')

    page.goto(EVIL + '/post.html')
    page.wait_for_url(PANEL + '/logout', timeout=10000)
    after = page.inner_text('body')
    page.goto(PANEL + '/')
    still = 'Sign out' in page.content()
    check('PANEL-14', 'T1185', 'A hostile page posts a sign-out form to the panel (cross-site request forgery)',
          'refused: the cookie is not sent cross-site, the origin is checked, the form token is missing',
          still and ('refused' in after or 'forbidden' in after),
          f'panel answered: {after[:80]!r}; admin still signed in: {still}')

    page.goto(EVIL + '/frame.html')
    page.wait_for_timeout(1500)
    frame = next((f for f in page.frames if f != page.main_frame), None)
    try:
        framed = frame is not None and 'Sign out' in frame.content()
    except Exception:
        framed = False
    check('PANEL-15', 'T1185', 'A hostile page frames the panel (clickjacking)', 'the browser refuses to show it',
          not framed, f'frame shows the dashboard: {framed}; frame url: {frame.url if frame else "none"}')
    browser.close()

for r in out:
    print(json.dumps(r))
