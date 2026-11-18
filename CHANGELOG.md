# Changelog

## [0.3.0] - 2026-11-18

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

### Fixed
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
