# Approvals: by reply, on the dashboard, on the server

Some actions wait for an admin to approve them:

- fix a Critical finding now;
- hold its automatic fix;
- reboot the server now instead of in the maintenance window.

An admin can approve in three ways, and host-guard logs **who approved what, through which
channel**:

| Channel | How | Proof of who it is |
|---|---|---|
| `email` | reply to host-guard's mail with its action line first | the admin's own mailbox: the receiving mail server's DMARC verdict for the admin's address, and a single-use code that only host-guard's mail carried |
| `dashboard` | **Fix now**, **Hold** or **Approve a reboot now** on the Advisories page | a signed-in session (reachable only through an SSH tunnel) **and** a fresh code mailed to that admin for that one change |
| `console` | `sudo hostguard fix ID`, `hold ID` | root on the server (the `sudo` user is logged) |

Every approval and every refusal is in the log:

- `sudo hostguard approvals` on the server;
- the **Approvals log** on the dashboard;
- a mail to every admin.

## Replying to a mail

Turn it on in `/etc/host-guard/guard.conf`:

```
REPLY_ACTIONS=on
```

It uses the same mailbox host-guard sends from. With Gmail nothing else is needed: the app
password in `.env` (`SMTP_PASSWORD`) also reads the inbox over IMAP. The
`host-guard-replies.timer` reads new replies every 2 minutes.

A Critical advisory mail then ends like this:

```
Act by replying: reply to this mail with one of these lines as the FIRST line of your reply
(nothing else is read; the code works once, only for that action, until 2026-11-24 10:00:00,
and only from an admin's own mailbox):
  FIX hg-k3v7q2m...    fix now (a restore point first, rolled back if the server is not healthy after)
  HOLD hg-p5x9a4c...   hold the automatic fix (it stays open in the daily report)
```

To act, reply and put one line first, for example `HOLD hg-p5x9a4c...`, and send. A mail
comes back to every admin with the result.

### What a reply can never do

- **Run a command.** A reply names one action from a fixed list (fix, hold, reboot). The rest
  of the mail is never read as an instruction. Lines like `touch /tmp/x`, `$(...)` or
  `sudo ...` are ignored. The red team sends exactly these (MAIL-5).
- **Act without the server's own code.** Each code is made for one action on one finding. It
  works once and expires after `REPLY_TTL_H` (24) hours. Codes are derived from a key that only
  root can read (`/var/lib/host-guard/approvals.key`) and are never stored. The dashboard
  cannot make one.
- **Act from a forged sender.** The reply must come from an admin address (`PANEL_ADMINS`, or
  `MAIL_TO`). Only the **topmost** `Authentication-Results` line counts, the one added by the
  inbox's own mail server (`REPLY_AUTHSERV`, `mx.google.com` for Gmail), and it must say
  `dmarc=pass` for that address's domain. Lines a sender wrote are below it and are ignored.
- **Act from quoted text.** Only the reply's own first lines count, down to the first quoted
  line (`>`) or the `On ... wrote:` line. A code that sits only in the quoted mail does
  nothing.
- **Be replayed.** A used code is spent, and the same message is read only once.

**A forged reply that carries a real code** means someone saw host-guard's mail. Nothing is
done, **the code is void**, and every admin gets a P1 mail saying so.

### A reboot needs two admins

`REBOOT_APPROVALS=2`: two **different** admins must approve a reboot, through any channels
(for example one by reply and one on the dashboard). It is never more than the number of admins
there are. The first approval mails every admin with the line to approve. The reboot then
follows the maintenance window's rules:
- it does not run while data lake replication is broken;
- a fresh backup is taken first;
- a mail arrives when the server is back, naming who approved it.

A fix needs `FIX_APPROVALS` (1) admins; raise it to require two.

### The remaining risk

Anyone who can read **and send from** an admin's mailbox can approve what that admin can.
These keep that risk small:

- the codes are single use, for one action;
- a reboot needs a second admin;
- every admin is mailed about every approval;
- nothing outside the fixed list can be done.

Protect the admins' mailboxes with two-step sign-in. Use a separate sending account for
host-guard, not an admin's own mailbox.

### Other mail providers

Gmail stamps `Authentication-Results: mx.google.com; ...`. For another provider, set
`IMAP_HOST`, `IMAP_PORT`, `IMAP_USER`, `IMAP_PASSWORD` (in `.env`), and `REPLY_AUTHSERV` to the
name its mail server writes first in that header. For a mail server with its own certificate,
set `IMAP_CA`. A provider that does not stamp a DMARC verdict cannot be used for replies: every
reply is refused.

## The log

```
$ sudo hostguard approvals
waiting: reboot now: reboot now for the security updates; approvals 1 of 2 (sec@example.com (email)); until 2026-11-24 09:12:00
2026-11-23 09:12:41  email     sec@example.com: reboot now: approval 1 of 2
2026-11-23 08:03:10  dashboard ops@example.com: hold 1a2b3c4d: done: held
2026-11-23 07:55:02  console   ubuntu on the server: fix 5e6f7a8b: done: fixed
2026-11-23 07:41:19  email     ops@example.com: hold -: refused: DMARC did not pass for example.com
```

The log keeps the last 1000 lines in `/var/lib/host-guard/approvals.json`. The dashboard shows
the last 30.
