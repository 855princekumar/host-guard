# host-guard

Security, health and early warning for the server that runs EdgeShell: an EC2
(Ubuntu) with the EdgeShell Docker stack. It watches the machine and everything
on it, patches what is safe to patch, warns early about what is not, and mails
you about all of it through your Gmail app password.

It is one Python program (standard library only, nothing to trust beyond the
Ubuntu packages it installs), systemd timers, and a few configuration files.
It is tested on every change and every week by the [test bed](../testbed/README.md).

## What it does

| | What | How often |
|---|---|---|
| **Base hardening** | EdgeShell's own `docker/host-hardening.sh`, run first: SSH by key only (no root, 3 tries), fail2ban for SSH, repeat offenders (1 week, every port), sign-in floods and probes for `.env` or `wp-login` (banned in Docker's `DOCKER-USER` chain, where nginx's ports are filtered), nginx log rotation, security updates | at install |
| **Extra hardening** | Kernel network protections (syncookies, no redirects or source routing, `kptr_restrict`, `ptrace` limited); outbound connections to crypto-mining pool ports refused from the host and from containers; Docker log rotation | at install, at boot |
| **Health** | Disk, memory, every container running and healthy, EdgeShell answering over HTTPS, the TLS certificate (under 14 days), data lake replication (running, lag), backups fresh, reboot pending, new fail2ban bans. Each problem mails once (then at most every 6 h) and again when it is resolved | every 5 min |
| **Intrusion watch** | Extra root (UID 0) accounts are locked and their processes killed; a rootkit preload; crypto miners and programs running from memory-only folders are killed and kept for inspection; root logging in over SSH from the internet; changes to accounts, sudoers, SSH, cron and systemd files; new SSH keys (reported, never removed, so your own key changes are safe). With `LOCKDOWN=web`, a critical sign takes EdgeShell off the internet (nginx stopped) until you run `sudo hostguard unlock` | every 5 min |
| **Early warning** | CISA's Known Exploited Vulnerabilities (flaws attacked in the wild) for what runs here (OpenSSH, the kernel, Docker, nginx, MariaDB, Python, sudo, systemd...); Ubuntu Security Notices for installed packages; OSV for every Python package inside the running EdgeShell and SenseHive containers. The first run records a baseline; after that, only new items are mailed, actively exploited ones as critical | every 6 h |
| **Patching** | Ubuntu security updates applied daily, never an automatic reboot. A reboot happens only in the maintenance window, after a fresh backup and only with replication healthy; you get a mail before and after, with the health | daily, window weekly |
| **Scan** | Trivy on every running image (critical findings with a fix are listed), Lynis on the host (hardening index, with a minimum) | weekly |
| **Backups** | Every database dumped, compressed, encrypted (gpg AES-256, key in `/etc/host-guard/backup.key`), kept locally (3) and uploaded to S3 with a SHA-256 checksum and confirmed | nightly |
| **Restore test** | The newest backup downloaded from S3, checked, decrypted and loaded into a throwaway MariaDB; tables and rows reported | weekly |
| **Running cost** | What the server costs, from **AWS's published price list** for its own instance type and region (read without credentials, refreshed daily) and the usage measured every 5 minutes: instance, disk, public IPv4, egress and S3 backups per day and month; per service (each container's CPU and memory share); per managed node; and where it could cost less (Graviton, a smaller size, the matching Lightsail plan). `sudo hostguard cost` | every 5 min (usage), daily (report) |
| **Mail** | Alerts as they happen; a **daily report** (system, containers, EdgeShell's fleet and open alerts, replication, backups, bans, intrusion findings, new advisories, updates, last scan, running cost, every mail sent); a weekly scan digest; a mail after every boot | |

What it deliberately does not do: change or upgrade EdgeShell (that goes through
EdgeShell's CI and releases), remove SSH keys, use ufw (it does not filter the
ports Docker publishes), or reboot outside the window.

## Install on the EC2

1. **A Gmail app password**: Google Account, Security, 2-Step Verification, App
   passwords: create one named `host-guard`. Never paste it in a chat or a file
   you keep.
2. **An S3 bucket** for backups (same region), with versioning on and, ideally,
   Object Lock. Give the instance a role allowed to `PutObject`, `GetObject` and
   `ListBucket` on it (no delete). Without a role, set the keys in `guard.conf`.
3. **IMDSv2 only** (AWS console or CLI, once):
   `aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required`
4. Copy this folder and EdgeShell's `docker/host-hardening.sh` (into the stack
   folder, next to `compose.yaml`), take a database backup, keep one SSH session
   open, then:

```bash
sudo bash host-guard/install.sh --mail-to you@gmail.com --domain fleet.example.com \
     --edgeshell-dir /home/ubuntu/edgeshell --login-user ubuntu --s3-bucket <bucket> \
     --tz Asia/Kolkata --report-time 09:00 --maintenance "Sun 03:30" --with-trivy
```

It asks for the app password (not shown as you type). Then a test mail arrives.
Open a second SSH session before closing the first.

Every admin can get the mails: give `--mail-to` a comma list
(`--mail-to you@gmail.com,admin2@example.com`). The first address is the Gmail
account that sends (its app password is the one asked for); `--mail-from` names
another. Later, edit `MAIL_TO` in `/etc/host-guard/guard.conf` (read at every
run, no restart) and check with `sudo hostguard test-mail`. Anything that is not
a plain email address is skipped.

5. **Copy the backup passphrase** (`BACKUP_PASSPHRASE` in `/etc/host-guard/.env`)
   somewhere safe and offline: the backups cannot be restored without it.
6. Optional: a read-only EdgeShell service key (API page, scope `read`, 365 days)
   as `EDGESHELL_KEY` in `/etc/host-guard/.env` adds the fleet numbers, open
   alerts and the cost per managed node to the daily report.

## Secrets: one file

Every secret host-guard uses is in **`/etc/host-guard/.env`** (root only, mode 600)
and nowhere else:

| Key | What |
|---|---|
| `SMTP_PASSWORD` | The Gmail app password. msmtp reads it from here (`passwordeval`), so `/etc/msmtprc` holds none |
| `BACKUP_PASSPHRASE` | Encrypts the backups (made at install; keep a copy offline) |
| `EDGESHELL_KEY` | Optional, read-only EdgeShell key for the report |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | Only without an instance role for the backup bucket |

`guard.conf` holds settings only; a secret put there is ignored with a warning.
Secrets are never printed or mailed (the test bed checks every mail for them).

## Day to day

```bash
sudo hostguard status          # last runs, open problems
sudo hostguard report          # the daily report, now
sudo hostguard cost            # what the server costs, and where it could cost less
sudo hostguard test-mail
sudo hostguard unlock          # after a lockdown, once you have looked
sudo fail2ban-client status sshd             # who is banned
sudo fail2ban-client set sshd unbanip <ip>   # unban someone
systemctl list-timers 'host-guard-*'
```

Settings are in `/etc/host-guard/guard.conf` (thresholds, the window, the
lockdown mode, the jails, the feed addresses, `USD_INR` for rupees in the
report); secrets in `/etc/host-guard/.env`. Run `install.sh` again after updating
this folder.
