# Configuration

Two files, both written by the installer:

| File | Holds | Mode |
|---|---|---|
| `/etc/host-guard/guard.conf` | every setting below, **no secrets** | 600, root |
| `/etc/host-guard/.env` | the secrets only | 600, root |

Both are `KEY=value`, one per line, `#` for comments. host-guard reads them at every
run, so a change applies at the next timer without a restart. A secret put in
`guard.conf` is ignored (with a warning): it belongs in `.env`. For a one-off run,
an environment variable `HG_<KEY>` wins over both files
(`sudo HG_DISK_WARN=70 hostguard health`).

Start from a profile in [examples/profiles/](../examples/profiles/) and change what differs.

## Secrets (`.env` only)

| Key | What |
|---|---|
| `SMTP_PASSWORD` | the mail account's password (a Gmail app password); msmtp reads it at send time |
| `BACKUP_PASSPHRASE` | encrypts every backup; made at install; **keep a copy offline** |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | only for S3 backups without an instance role |
| `EDGESHELL_KEY` | only for EdgeShell: a read-only service key for fleet numbers in the report |

## Mail

| Key | Default | What |
|---|---|---|
| `MAIL_TO` | (installer) | every admin, separated by commas or spaces; anything that is not a plain address is skipped |
| `MAIL_FROM` | first of `MAIL_TO` | the sending account |
| `SITE` | host name | the server's name in every subject |
| `COOLDOWN_H` | `6` | the same open problem is mailed at most this often |
| `NOTIFY_CMD` | `msmtp -a default` | the command that sends a mail (the message on stdin, recipients as arguments) |

## The app on the server

All optional: with nothing set, host-guard guards the host itself.

| Key | Default | What |
|---|---|---|
| `APP_NAME` | `the website` | the app's name in mails ("My shop not answering") |
| `DOMAIN` | empty | the site's name; with it, health checks HTTPS (from the server itself) and the certificate's days left |
| `HEALTH_PATH` | `/` | the path checked on `DOMAIN`; any 2xx or 3xx answer is healthy |
| `STACK_DIR` | empty | the Docker Compose folder; with it, every container is checked and listed in the report |
| `WEB_SERVICE` | `nginx` | the web server: a Compose service with `STACK_DIR`, else a systemd unit; stopped by `LOCKDOWN=web` |
| `LOCKDOWN` | `alert` | `alert`: a critical intrusion sign only mails. `web`: it also stops `WEB_SERVICE` until `sudo hostguard unlock` |
| `CONTAINERS_PYTHON` | empty | Compose services whose Python packages are checked against OSV advisories |
| `LOGIN_USER` | installer's `--login-user` | the SSH user whose `authorized_keys` the intrusion watch follows |

## Backups

| Key | Default | What |
|---|---|---|
| `DB_ENGINE` | `none` | `mariadb`, `postgres` or `none` |
| `DB_SERVICE` | empty | the database's Compose service (with `STACK_DIR`); empty: the database runs on the host |
| `DB_REPLICA` | empty | a MariaDB or MySQL replica's Compose service: health checks replication and its delay |
| `BACKUP_CMD` | empty | any command that writes the backup to stdout; used instead of the database dump |
| `BACKUP_PREFIX` | `backup` | the start of each backup's file name |
| `BACKUP_DIR` | `/var/backups/host-guard` | where encrypted backups are kept |
| `BACKUP_KEEP` | `3` | how many are kept there |
| `BACKUP_MAX_AGE_H` | `26` | an older newest backup is a problem |
| `BACKUP_MIN_BYTES` | `1024` | a smaller backup is treated as failed |
| `MARIADB_IMAGE`, `PG_IMAGE` | `mariadb:11.4`, `postgres:17` | the throwaway database of the restore test (match your version) |
| `S3_BUCKET` | empty | with it, every backup is also uploaded, and the restore test downloads from there |
| `S3_PREFIX` | `host-guard/` | the key prefix in the bucket |
| `AWS_REGION` | `ap-south-1` | the bucket's region (and the price list for the cost report) |
| `S3_ENDPOINT` | empty | an S3-compatible service's URL (B2, Wasabi, R2, MinIO) |

What each combination does:

| Settings | Backup | Restore test |
|---|---|---|
| `DB_ENGINE=mariadb`, `STACK_DIR`, `DB_SERVICE` | `mariadb-dump --all-databases` inside the service | loaded into a throwaway `MARIADB_IMAGE` container, tables counted |
| `DB_ENGINE=mariadb` on the host | `mariadb-dump --all-databases` as root (unix socket) | the same, when Docker is installed |
| `DB_ENGINE=postgres`, `STACK_DIR`, `DB_SERVICE` | `pg_dumpall -U PG_USER` inside the service (default user `postgres`) | loaded into a throwaway `PG_IMAGE` container, tables per database counted |
| `DB_ENGINE=postgres` on the host | `sudo -u postgres pg_dumpall` | the same, when Docker is installed |
| `BACKUP_CMD=...` | the command's output | decrypted and unpacked completely, size reported |

Examples of `BACKUP_CMD`:

```ini
# files and folders
BACKUP_CMD=tar -cf - /etc /srv/app/uploads
# a SQLite database, consistent while the app runs
BACKUP_CMD=sqlite3 /srv/app/data.db .dump
# a database and files together
BACKUP_CMD=sh -c 'mkdir -p /tmp/hg && mariadb-dump --all-databases > /tmp/hg/db.sql && tar -cf - /tmp/hg /srv/app/uploads; rm -rf /tmp/hg'
```

The command runs as root with `pipefail`: if it fails, the backup fails and you get a mail.

## Thresholds

| Key | Default | What |
|---|---|---|
| `DISK_WARN` | `85` | root disk use, in percent, that is a problem |
| `MEM_FREE_MIN` | `10` | available memory, in percent, below which it is a problem |
| `CERT_DAYS` | `14` | the certificate expiring sooner is a problem |
| `LAG_WARN` | `300` | replication delay, in seconds, that is a problem |
| `LYNIS_MIN` | `65` | a Lynis hardening index below this marks the weekly scan "action needed" |
| `JAILS` | `sshd recidive nginx-limit-req web-probe edgeshell-probe` | fail2ban jails reported (missing ones are skipped) |

## Early warning sources

| Key | Default |
|---|---|
| `KEV_URL` | CISA's Known Exploited Vulnerabilities feed |
| `USN_URL` | Ubuntu security notices |
| `OSV_URL`, `OSV_VULN_URL` | the OSV advisory database |

## Running cost

See [COST.md](COST.md): `INSTANCE_TYPE`, `PUBLIC_IPV4`, `EBS_GB`,
`S3_RETENTION_DAYS`, `USD_INR`, `PRICE_HOUR`, `PRICE_EBS_GB_MONTH`,
`PRICE_EGRESS_GB`, `PRICE_IPV4_HOUR`, `PRICE_S3_GB_MONTH`, `PRICES_URL`.

## Paths

| Key | Default |
|---|---|
| `STATE_DIR` | `/var/lib/host-guard` |
| `ENV_FILE` | `/etc/host-guard/.env` |
| `EXPORT_FILE`, `EXPORT_GROUP` | `/var/lib/host-guard-export/status.json`, `hgpanel` (for the panel) |

## EdgeShell only

| Key | What |
|---|---|
| `EDGESHELL_URL` | EdgeShell's address for the API (default: `https://DOMAIN` when `EDGESHELL_KEY` is set) |
| `EDGESHELL_DIR` | the former name of `STACK_DIR`; still read |

## Schedules

Times are in the systemd timers, set by the installer (`--report-time`,
`--maintenance`, `--tz`). To change another one, override the timer:

```bash
sudo systemctl edit host-guard-backup.timer
# [Timer]
# OnCalendar=
# OnCalendar=*-*-* 02:45
```
