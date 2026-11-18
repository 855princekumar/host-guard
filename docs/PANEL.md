# The panel

One page with everything host-guard knows (health, intrusion watch, bans, backup,
restore test, scan, early warning, open problems, recent mails), for one admin.
Read-only in this version: changes are made on the server.

Python 3 standard library and one SQLite file. No framework, no JavaScript.

## Install

host-guard must be installed first.

```bash
sudo host-guard install ... --with-panel        # with host-guard; or later: sudo host-guard upgrade --with-panel
sudo -u hgpanel python3 /usr/local/lib/host-guard-panel/hgpanel.py init-admin yourname
```

(Without the version manager: `sudo bash panel/install.sh`.)

`init-admin` asks for a password twice (12 characters at least, not shown) and
prints an authenticator key once, in your terminal only. Add it to any TOTP app
(Google Authenticator, 1Password, Aegis, ...) and type the code it shows to
confirm. `--reset` replaces the admin and signs everyone out.

## Open it

The panel listens on `127.0.0.1:8650` only: nothing on the internet can reach it, and no
port has to be opened. You bring it to your own computer through a tunnel, then open
**http://127.0.0.1:8650** in your browser. Pick the tunnel that fits the server:

| Where the server runs | Command on your computer | Needs |
|---|---|---|
| Any server you reach by SSH | `ssh -N -L 8650:127.0.0.1:8650 you@your-server` | your SSH key (host-guard keeps `AllowTcpForwarding local` on for this) |
| AWS, without opening SSH at all | `aws ssm start-session --target i-0123456789abcdef0 --document-name AWS-StartPortForwardingSession --parameters portNumber=8650,localPortNumber=8650` | the SSM agent and an instance role with `AmazonSSMManagedInstanceCore` |
| Google Cloud | `gcloud compute start-iap-tunnel VM_NAME 8650 --local-host-port=localhost:8650 --zone ZONE` | IAP TCP forwarding allowed to the VM (firewall rule from 35.235.240.0/20) |
| Azure | `az network bastion tunnel --name BASTION --resource-group RG --target-resource-id VM_ID --resource-port 8650 --port 8650` | Azure Bastion, Standard SKU or higher |
| Oracle Cloud | a Bastion port-forwarding session to the instance's port 8650, then the `ssh -N -L 8650:...` command the console shows | OCI Bastion |
| Tailscale or WireGuard | `BIND=<private address>`, `ALLOW_REMOTE=1`, `ALLOWED_HOSTS=<address>:8650` in `/etc/host-guard-panel/panel.conf`, then open `http://<address>:8650` | the private network; never a public address |

Every route ends in the same place: your browser talks to `127.0.0.1:8650` on your own
computer, which the tunnel carries to `127.0.0.1:8650` on the server. Whoever cannot open
the tunnel cannot even see the sign-in page; whoever can still needs the password and the
authenticator code.

<p align="center">
<img src="assets/panel-signin.png" alt="The panel's sign-in page: name, password and authenticator code" width="49%">
<img src="assets/panel-dashboard.png" alt="The panel's dashboard: open problems, health, intrusion watch, bans, backup, restore test, scan, early warning and recent mails" width="49%">
</p>
<p align="center"><img src="assets/panel-dashboard-dark.png" alt="The dashboard in dark mode" width="70%"></p>

<sub>Screenshots taken by the red team's browser stage in CI (a real headless Chromium,
signed in through the panel's own form), with the red team's attack traffic in the data.</sub>

## Security model

| Concern | How it is handled |
|---|---|
| Exposure | 127.0.0.1 by default; any other address is refused unless set on purpose; the `Host` header must match (no DNS rebinding) |
| Privilege | runs as `hgpanel`: no shell, no home, no capabilities, read-only system, private /tmp, system-call filter (`systemd-analyze security` exposure about 1.3) |
| Secrets | cannot read `/etc/host-guard`, `/var/lib/host-guard` or the backups (also blocked in the unit); root's `hostguard export` writes a status file without secrets into a folder the panel can read but not write |
| Admins | the table holds one row; password hashed with scrypt (N=2^15) |
| Second factor | TOTP (RFC 6238), 30 s steps, a code works once (replay refused) |
| Guessing | 5 failures lock the account for 15 minutes; 10 failures from one address in 15 minutes block that address; the message never says which part was wrong |
| Sessions | 256-bit random token, only its SHA-256 stored; cookie HttpOnly, SameSite=Strict, Secure; 15 minutes idle, 8 hours at most; a new token at every sign-in |
| Web | a CSRF token on every form; parameterized SQL only; every value HTML-escaped; Content-Security-Policy `default-src 'none'` (no script at all); no framing; `no-store`; 8 KB request limit |
| Cross-site | a form post whose `Origin` is another site, or that the browser marks `Sec-Fetch-Site: cross-site`, is refused and audited; no CORS header is ever sent |
| Audit | sign-ins, failures, lockouts, blocked addresses, cross-site posts and sign-outs, at `/audit` or `hgpanel audit` |
| Tested | every change: unit tests, plus the red team in CI with raw HTTP and a real browser (sign-in, session fixation, stored script injection, CORS reads, cross-site posts, framing, unusual methods, path traversal, guessing, code replay); see [REDTEAM.md](REDTEAM.md) |

```mermaid
sequenceDiagram
    participant B as your browser (through ssh -L)
    participant P as hgpanel (127.0.0.1)
    participant D as panel.db
    B->>P: GET / (no session)
    P-->>B: sign-in form + one-time form token cookie
    B->>P: POST /login name, password, code, form token
    P->>D: admin row (parameterized)
    P->>P: scrypt check, TOTP check (step newer than the last used)
    alt all right
        P->>D: new session (token hash), audit "sign-in"
        P-->>B: 303 to /, session cookie (HttpOnly, Strict)
    else anything wrong
        P->>D: failure counted, audit
        P-->>B: 401 "Sign-in failed. Check the name, password and code."
    end
```

## Settings

`/etc/host-guard-panel/panel.conf` (`KEY=value`; environment `HGP_<KEY>` wins):

| Key | Default | What |
|---|---|---|
| `BIND` | `127.0.0.1` | listening address |
| `PORT` | `8650` | listening port |
| `ALLOW_REMOTE` | `0` | `1` allows a non-loopback `BIND` |
| `ALLOWED_HOSTS` | empty | extra accepted `Host` headers, comma separated |
| `COOKIE_SECURE` | `1` | browsers accept Secure cookies on 127.0.0.1 and localhost |
| `IDLE_MIN`, `MAX_HOURS` | `15`, `8` | session limits |
| `LOCK_AFTER`, `LOCK_MIN`, `IP_LIMIT` | `5`, `15`, `10` | lockout and per-address limits |
| `DB`, `STATUS_FILE` | `/var/lib/host-guard-panel/panel.db`, `/var/lib/host-guard-export/status.json` | files |

## Roadmap

1. Read-only panel (this version).
2. Settings from the panel (recipients, thresholds, schedule), with secrets
   write-only, through a root helper that accepts a fixed list of actions and
   checks every value.
3. Quick actions through the same helper (test mail, back up now, restore test,
   unban an address, end a lockdown), each confirmed with a fresh code and audited.
4. Anomaly detection from statistics on host-guard's own numbers, with a baseline
   per hour of the week.
5. Optionally, a small local language model that explains findings and suggests
   an action, and never acts on its own (log text can carry an attacker's words).
