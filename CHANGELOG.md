# Changelog

## [0.3.1] - 2026-11-19

### Added
- **The package checks itself**: before anything runs as root, the version manager compares
  every file of its pip install with the package's SHA-256 RECORD; a changed or added file
  stops it with the command to reinstall.
- **Published = tested**: CI builds the wheel once (reproducibly) and audits it
  (`ci/package_audit.py`: contents, no drift from the repository, RECORD, metadata with no
  dependencies, archive safety, secrets, a smoke install that must refuse a tampered file);
  the red team, the cloud emulators and the lifecycle all run on that wheel; the release
  publishes that same file, then checks byte for byte that PyPI serves it, that its
  provenance attestation names this repository's `release.yml`, and installs it from PyPI on
  three systems ([docs/RELEASING.md](docs/RELEASING.md)).
- Red team: 5 attacks on the pip package (PKG-1 to PKG-5): a tampered or planted file in the
  installed package is refused before anything runs as root; no dependencies, no `.pth` file
  that runs code, nothing writable by non-root users.

### Changed
- The release publishes the wheel and sdist CI built and tested (no second build), attaches
  `SHA256SUMS` to the GitHub release, and only then creates it.

## [0.3.0] - 2026-11-19

### Added
- **Version manager** (`host-guard`): `install`, `upgrade`, `rollback [--to VERSION]`,
  `uninstall [--purge]`, `status`, `history`. Every install is recorded file by file in
  `/opt/host-guard` (releases, a manifest per install, a copy of every replaced file).
- **Rollback that cannot break the server**: a file is restored only while it holds
  what the install wrote (an admin's later edit is kept and reported); SSH and
  fail2ban settings are checked before they apply; a failed install undoes itself.
- **Downgrade guard**: installing an older version over a newer one asks first
  (`--allow-downgrade` without a terminal).
- **Adoption**: a server installed before the manager is adopted by its first
  upgrade; a rollback returns to exactly that setup.
- **Saved options**: `upgrade` reuses the install options, so who may log in over SSH
  never changes by accident; recipients come from `guard.conf`.
- **pip package** with Trusted Publishing from a tagged release (`pipx install host-guard`).
- CI: the pip package through install, upgrade, refused downgrade, injected failure,
  rollback and `uninstall --purge` on Ubuntu 24.04, 26.04 and Debian 12, ending
  byte-for-byte pristine; ruff lint; package checks.
- **Red team in CI** (`ci/redteam/`): 46 real attacks on an isolated network
  against a server installed by the version manager, each mapped to MITRE ATT&CK and
  scored stopped, gap or failed (a failed defense fails CI): SSH brute force and policy,
  web probes and floods, root backdoor accounts, miners, persistence (keys, sudoers,
  cron, ld.so.preload), mining-pool egress, backup theft and tampering of the off-site
  copy in an emulated S3 (Floci), secret leaks, and the panel (DNS rebinding, CSRF,
  SQL injection, cookie theft and replay, code replay, guessing, unusual methods, path
  traversal), and the dashboard in a real browser (headless Chromium): sign-in, session
  fixation, stored script injection, CORS reads, cross-site posts and framing from a hostile
  page. The report goes to the CI summary; a sample with screenshots is in
  [docs/REDTEAM.md](docs/REDTEAM.md).
- **Dashboard**: a form post from another site (its `Origin`, or `Sec-Fetch-Site:
  cross-site`) is refused and audited; screenshots and a guide to reach it through SSH,
  AWS SSM, Google IAP, Azure Bastion or OCI Bastion, no port opened and no VPN
  ([docs/PANEL.md](docs/PANEL.md)); `host-guard install --with-panel`.
- **Any cloud, detected by itself**: `hostguard whereami` and the installer read the
  cloud from its own metadata service (AWS, Google Cloud, Azure, Oracle Cloud); anything
  else is a VPS or bare metal. The report names it; the cost section uses AWS prices only
  on AWS and otherwise says which setting gives an estimate. Detection never stops anything.
- **Off-site copies on every cloud**: `BACKUP_REMOTE=s3` (AWS, Google Cloud Storage through
  S3 interoperability, OCI's S3 compatibility API, R2, B2, Wasabi, MinIO), `azure` (a
  container SAS URL) and `oci-par` (a bucket pre-authenticated request URL); uploads are
  confirmed by every size and MD5 the store reports; `S3_CA_BUNDLE` for a private CA.
- **Mail that sorts itself**: every subject is `[P1 Critical] Intrusion | server | what`
  (severity P1, P2, P3, Resolved or Daily; ten fixed categories), with `List-Id`,
  `X-Host-Guard-Severity` and `X-Host-Guard-Category` headers for filters and high
  importance on P1. Flood protection: P2 and P3 mails of one category are capped at
  `MAIL_MAX_PER_HOUR` (4); the rest are named in the next one and counted in the daily
  report. P1 is never held. [docs/MAIL.md](docs/MAIL.md).
- **Cloud CI** (`ci/clouds/run.sh`): on AWS, Google Cloud, Azure, Oracle Cloud and bare
  metal (metadata answered like each cloud's), a real backup goes off-site to an emulated
  store (Floci for AWS, Google Cloud and Oracle Cloud, Microsoft's Azurite with a random
  key per run, and AWS's own AWS Emulator with real SigV4 checks over HTTPS) and is restore-tested; forged Azure signatures and wrong AWS secrets
  must be refused.
- **Release gates**: a tag publishes to PyPI only after the whole CI (red team and clouds
  included), CodeQL, and a security audit report for that version with no open confirmed
  finding ([docs/RELEASING.md](docs/RELEASING.md)). CodeQL, secret scanning with push
  protection, Dependabot alerts and private vulnerability reporting are on.

### Security
Found by the security audit of this release ([docs/audits/0.3.0.md](docs/audits/0.3.0.md)), all fixed
with a test each:
- A huge or sparse program named like a miner is kept in quarantine only up to 64 MiB (a copy
  without limit could fill the disk and silence every later alert); the copy never follows a link.
- A full disk no longer stops an intrusion mail or the lockdown.
- A held mail no longer starts its problem's cooldown (a real alert could wait 6 hours).
- Odd text never stops a run: invalid UTF-8 from a container, a lone surrogate in a feed, a
  certificate date or replication lag that does not parse. A health check that crashes is
  reported as its own problem while the others still run.
- An urgent advisory is marked as seen only after its mail went out.
- Feed answers are limited to 200 MiB, also after decompression; mails to 200 KB.
- A root SSH login is read only from sshd's own line: a crafted user name cannot fake one.
- The restore test's throwaway database gets its password from a root-only file, never a
  command line, and runs without a network; a backup is opened only after its checksum matches.
- Panel: a negative, signed or oversized Content-Length is refused before any body is read; a
  stalled client is dropped after 20 s; the service is capped at 256 MB and 64 tasks; the shared
  address block slows guessing but never refuses the right name, password and code; the audit
  listing prints no terminal control characters and keeps 180 days.
- The installer never follows a symbolic link planted in the web log folder.
- A release tag publishes only when it is on main.

### Fixed
- **A root login check mailed a false critical alert** (found by the red team): with
  `/etc/ld.so.preload` pointing at a missing library, loader warnings mention "from
  /etc/ld.so.preload", which was read as a login address. Only sshd's "Accepted ... for
  root from ADDRESS" lines with a public address count now.
- An unreachable S3 store or a refused TLS certificate crashed the backup instead of
  mailing "upload failed".
- **A second root account made the watch kill every root process** (found by the red
  team): `pkill -u NAME` on a UID 0 account matches root itself, so sshd, Docker, the
  web server and host-guard died, and no mail went out. Now the account is locked and
  only its own SSH logins end.
- **The `web-probe` jail never banned** (found by the red team): fail2ban cuts the time
  stamp out of a line before matching and leaves `[]`, which the filter did not accept.
- Rollback and uninstall stopped when fail2ban rejected the restored settings (stock
  fail2ban on Debian 12 does, without rsyslog). Now only an SSH settings failure stops
  them; a fail2ban failure is a warning that says what to do.
- The AWS credentials message pointed at `guard.conf`; keys live in `.env`.

## [0.2.0] - 2026-11-17

### Added
- **Any server, any app**: everything app-specific is a setting, off when empty
  (`APP_NAME`, `STACK_DIR`, `HEALTH_PATH`, `WEB_SERVICE`, `DB_ENGINE`,
  `DB_SERVICE`, `DB_REPLICA`, `BACKUP_CMD`, `BACKUP_PREFIX`, `PG_USER`, ...). A
  plain VPS with nothing set gets host checks only, with no false alarms.
- **PostgreSQL** backups (`pg_dumpall`) and restore tests in a throwaway container,
  next to MariaDB.
- **`BACKUP_CMD`**: back up anything that can be written to stdout (files, SQLite,
  ...); its restore test decrypts and unpacks it completely.
- **Profiles** in `examples/profiles/`: plain VPS, Docker Compose with PostgreSQL,
  bare metal with MariaDB, EdgeShell. `install.sh --profile`.
- **Bundled base hardening** (`guard/conf/base-hardening.sh`) for any Ubuntu or
  Debian server: SSH by key for one user, fail2ban for SSH and repeat offenders, and
  with `--web-logs` for sign-in floods and probes. Local SSH forwarding stays on for
  the panel's tunnel.
- **HTML mail** with a level banner, an at-a-glance table, sections, tables and
  bullet points; the plain text stays in every mail.
- **Mail to every admin**: a comma list in `MAIL_TO`, `--mail-from` for the sender.
- Debian 12 support; CI installs on Ubuntu 24.04, 26.04 and Debian 12, and backs up
  and restore-tests real MariaDB and PostgreSQL databases.
- Docs: install for EC2, any VPS and bare metal; how it works (with diagrams);
  every setting; the running cost; the panel. Community files.

### Fixed
- A first install stopped silently after the secrets step.
- Replication was misread when a field was empty (a false alarm).
- Health and intrusion watch, starting together, could erase each other's result.
- The report's container count included one-shot setup containers.

### Changed
- `EDGESHELL_DIR` is now `STACK_DIR` (the old name is still read);
  `--edgeshell-dir` is now `--stack-dir` (the old option still works).
- Defaults are neutral: `S3_PREFIX=host-guard/`, `BACKUP_PREFIX=backup`, no
  container list for OSV. The EdgeShell values moved to its profile.

## [0.1.0] - 2026-11-13

First version: the guard (from the EdgeShell production server) and the
read-only panel for one admin.
