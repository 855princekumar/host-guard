# host-guard

Security, health and early warning for one Linux server (cloud instance, VPS or
bare metal), plus a small web panel for its single admin. Python 3 standard
library, systemd timers, one SQLite file. No agents, no external services needed.

| Part | What it is | Runs as |
|---|---|---|
| [guard/](guard/) | Health checks, intrusion watch, early warning feeds, weekly scans, encrypted backups with restore tests, patch window, running cost, mail to every admin | root, systemd timers |
| [panel/](panel/) | One page with the status the guard exports, for one admin with password and authenticator code | `hgpanel` (unprivileged), 127.0.0.1 only |

## Install

```bash
sudo bash guard/install.sh --mail-to you@gmail.com,admin2@example.com --domain your.domain ...
sudo bash panel/install.sh
sudo -u hgpanel python3 /usr/local/lib/host-guard-panel/hgpanel.py init-admin <name>
```

Open the panel through a tunnel from your computer:
`ssh -L 8650:127.0.0.1:8650 <server>`, then http://127.0.0.1:8650 (or over
Tailscale with `BIND` set to the tailnet address, `ALLOW_REMOTE=1` and
`ALLOWED_HOSTS`). See [guard/README.md](guard/README.md) for every guard option.

## Security model of the panel

- **Not on the internet.** Listens on 127.0.0.1 by default; any other address is
  refused unless set on purpose. The Host header is checked (no DNS rebinding).
- **No privilege.** Runs as `hgpanel` under a locked-down systemd unit (read-only
  system, no capabilities, syscall filter). It cannot read the guard's state,
  `.env` or backups. Root writes a status file without secrets
  (`hostguard export`, every minute) into a folder the panel can read but not write.
- **One admin.** The table holds one row. Password hashed with scrypt; second
  factor TOTP (any authenticator app) with replay protection. Five failures lock
  the account for 15 minutes; ten failures from one address block that address.
  The message never says which part was wrong.
- **Sessions.** 256-bit random token, only its SHA-256 stored; cookie HttpOnly,
  SameSite=Strict, Secure; 15 minutes idle, 8 hours at most; new token at every
  sign-in.
- **Web.** CSRF token on every form, parameterized SQL only, every value
  HTML-escaped, a Content-Security-Policy that allows no script at all, no
  framing, `no-store` caching, 8 KB request limit. Every sign-in, failure,
  lockout and sign-out is in the audit log (`/audit`, or `hgpanel audit`).

## Roadmap

1. **Now:** read-only panel (this version).
2. Settings from the panel: recipients, thresholds, schedule. Secrets only
   write-only (replace, never shown), through a root helper that accepts a fixed
   list of actions and validates every value.
3. Quick actions through the same helper: test mail, backup now, restore test,
   unban an address, end a lockdown. Each one confirmed with a fresh code and audited.
4. Anomaly detection by statistics on the guard's own numbers (sign-in failures,
   traffic, CPU, new processes), with baselines per hour of the week.
5. Optional small local language model that explains findings and suggests an
   action. It never acts on its own: log text can carry instructions from an attacker.

## Tests

```bash
python -m pytest -q guard/tests panel/tests
```
