# Installing host-guard

Ten minutes on any Ubuntu or Debian server: an AWS EC2 instance, a VPS from any
provider, or a bare-metal machine.

## What you need

| | |
|---|---|
| Operating system | Ubuntu 22.04, 24.04 or 26.04, or Debian 12 (systemd and apt). Tested on each in CI. |
| Access | `sudo`, and an SSH **key** login that works for the user you will name with `--login-user` |
| Network out | HTTPS (443) for advisories and packages, SMTP submission (587) for mail |
| Mail | a Gmail or Google Workspace account with 2-step verification and an [app password](https://myaccount.google.com/apppasswords), or another SMTP server ([below](#other-mail-providers)) |
| Optional | Docker, if your app runs in Docker Compose or for database restore tests; an S3 bucket for off-site backups |

## Before you start

> [!IMPORTANT]
> The base hardening allows SSH **by key only** and **only for `--login-user`**
> (default: the user who runs `sudo`). Make sure that user can log in with a key,
> keep your current SSH session open, and test a new login from a second terminal
> before closing the first. Pass `--no-base-hardening` to skip this step.

## 1. Get host-guard onto the server

```bash
git clone https://github.com/855princekumar/host-guard.git
cd host-guard
```

(No git? Download the release archive and unpack it, or `scp -r` the folder.)

## 2. Choose a profile

A profile describes the app on the server: where its Docker Compose folder is,
which database it uses, what to back up. Start with the closest one; everything
can be changed later in `/etc/host-guard/guard.conf`
([every setting](CONFIGURATION.md)).

| Your server | Profile | Extra options |
|---|---|---|
| A VPS or machine with a website or services on the host | `plain-vps.conf` | `--domain`, `--web-logs /var/log/nginx` if it has nginx |
| A Docker Compose app with PostgreSQL | `compose-postgres.conf` | `--stack-dir /srv/yourapp --domain ...` |
| nginx and MariaDB on the host, no Docker | `bare-metal-mariadb.conf` | `--domain ... --web-logs /var/log/nginx` |
| EdgeShell | `edgeshell.conf` | `--stack-dir /home/ubuntu/edgeshell --domain ...` |

Copy a profile and edit it before installing if your app differs (service names,
health path, what to back up).

## 3. Install

```bash
sudo bash guard/install.sh \
  --mail-to you@gmail.com,teammate@example.com \
  --profile examples/profiles/plain-vps.conf \
  --login-user "$USER" --tz Europe/Berlin \
  --report-time 09:00 --maintenance "Sun 03:30" --with-trivy
```

| Option | Meaning |
|---|---|
| `--mail-to` | every admin, comma separated; the first one is the sending account |
| `--mail-from` | the sending account, when it is not the first `--mail-to` |
| `--profile FILE` | the app's settings (step 2) |
| `--stack-dir DIR` | the Docker Compose folder of your app |
| `--domain NAME` | your site's name: checks HTTPS and the certificate |
| `--web-logs DIR` | nginx's log folder: adds fail2ban jails for sign-in floods and probes |
| `--login-user NAME` | the one user allowed to log in over SSH |
| `--admin-ip ADDRESS` | never ban this address (office or home) |
| `--tz`, `--report-time`, `--maintenance` | time zone, daily report time, weekly patch window |
| `--with-trivy` | install Trivy for the weekly image scan |
| `--s3-bucket NAME`, `--region`, `--s3-endpoint URL` | off-site backup copies ([below](#off-site-backups-s3)) |
| `--smtp-host`, `--smtp-port` | another mail server ([below](#other-mail-providers)) |
| `--smtp-file FILE` | read the mail password from a file (deleted afterwards) instead of asking |
| `--lockdown alert\|web` | on a critical intrusion sign only mail (default), or also stop the web server |
| `--no-base-hardening` | leave SSH and fail2ban as they are |

The installer asks for the mail password without showing it, writes it only to
`/etc/host-guard/.env` (root, mode 600), and finishes with a test mail to
everyone.

## 4. Keep the backup passphrase offline

```bash
sudo grep BACKUP_PASSPHRASE /etc/host-guard/.env
```

Store it in a password manager or on paper. Without it the encrypted backups
cannot be restored, and it is not kept anywhere else.

## 5. Check it

```bash
systemctl list-timers 'host-guard-*'     # 8 timers, each with a next run
sudo hostguard status                    # health, watch, feeds and open problems
sudo systemctl start host-guard-backup && sudo systemctl start host-guard-restore-test
sudo hostguard report                    # the daily report, now
```

## Where you run it

### AWS EC2

- **Require IMDSv2** on the instance (`aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required`).
- The security group needs only 22 (from your addresses), 80 and 443.
- The running cost in the daily report is automatic: host-guard reads the instance
  type from the instance metadata and prices from AWS's public price files.
- For S3 backups, give the instance a role ([below](#off-site-backups-s3)) instead of keys.

### Any other VPS (Hetzner, DigitalOcean, Linode, OVH, Vultr, ...)

- Use the provider's firewall too: allow 22 from your addresses, 80 and 443.
- For the running cost, set the plan's price in `guard.conf` and zero what the
  plan includes ([COST.md](COST.md#outside-aws)).
- S3-compatible storage works for backups with `--s3-endpoint` (Backblaze B2,
  Wasabi, Cloudflare R2, MinIO).

### Bare metal or a home lab

- There is no cloud firewall in front: add one on your router, or on the host
  (`ufw allow OpenSSH`, `ufw allow 80,443/tcp`, `ufw enable`). With Docker, ports
  that containers publish bypass ufw: publish only what must be public, or bind
  the rest to `127.0.0.1:` in your Compose file.
- Database restore tests need Docker for their throwaway container; without Docker
  the restore test still decrypts and unpacks the whole backup.
- Set `PRICE_HOUR` to your power and hosting cost per hour if you want the cost
  section, or ignore it.

## Off-site backups (S3)

Backups on the same disk do not survive a lost server or ransomware. Add a copy
that cannot be deleted:

1. Create a bucket with **Object Lock** on (compliance or governance mode,
   for example 30 days) and versioning.
2. Allow only what host-guard needs on its prefix:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Action": ["s3:PutObject", "s3:GetObject"],
       "Resource": "arn:aws:s3:::YOUR-BUCKET/host-guard/*"
     }]
   }
   ```

3. On EC2, attach it to an instance role. Elsewhere, create an access key for a
   user with only this policy and put it in `/etc/host-guard/.env` as
   `AWS_ACCESS_KEY_ID=...` and `AWS_SECRET_ACCESS_KEY=...`.
4. Set `S3_BUCKET` (and `AWS_REGION`, or `S3_ENDPOINT` for an S3-compatible
   store) in `/etc/host-guard/guard.conf`, then run a backup and a restore test.
   The restore test now downloads from S3, which proves the off-site copy.

## Other mail providers

Any SMTP server that accepts STARTTLS on port 587 and signs in with the sender's
address as the user name works:

```bash
sudo bash guard/install.sh --mail-to alerts@example.com,you@example.com \
  --smtp-host smtp.example.com --smtp-port 587 ...
```

Providers whose user name is not the sender's address (for example Amazon SES
SMTP credentials) need `/etc/msmtprc` edited by hand: set `user` to the SMTP user
name. The password stays in `.env`.

## Change recipients later

Edit `MAIL_TO` in `/etc/host-guard/guard.conf` (read at every run, no restart),
then `sudo hostguard test-mail`.

## Update

```bash
cd host-guard && git pull
sudo bash guard/install.sh --mail-to <the same list> ...
```

The installer is idempotent: it keeps `.env`, the backup passphrase and your
settings, and takes the recipients you give it now.

## Uninstall

```bash
sudo systemctl disable --now $(systemctl list-unit-files 'host-guard-*' --no-legend | awk '{print $1}')
sudo rm -f /etc/systemd/system/host-guard-* /usr/local/sbin/hostguard /usr/local/sbin/host-guard-firewall \
  /etc/sysctl.d/99-host-guard.conf /etc/apt/apt.conf.d/52host-guard-unattended
sudo systemctl daemon-reload
# keep or remove: /etc/host-guard (settings and secrets), /var/lib/host-guard (state),
# /var/backups/host-guard (your backups), /etc/msmtprc,
# /etc/ssh/sshd_config.d/01-host-guard.conf and /etc/fail2ban/jail.d/host-guard.local (the hardening)
```
