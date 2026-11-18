# Install, upgrade, roll back, remove

`host-guard` (the version manager) installs host-guard on a server and keeps a
record of every file each install changed, so any install can be undone exactly.
`hostguard` (no dash) is the program the timers run; the manager passes its
commands through (`sudo host-guard report` runs `hostguard report`).

## Get the manager

From PyPI (current Ubuntu and Debian refuse a plain `pip install` into the system
Python, so pipx puts it in its own environment):

```bash
sudo apt install -y pipx
sudo PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install host-guard
```

Or from a clone of the repository: `sudo ./host-guard ...` in its folder.

## Commands

| Command | What it does |
|---|---|
| `sudo host-guard install --mail-to a@x.com,b@y.org --profile examples/profiles/plain-vps.conf [--with-panel]` | first install; every [install option](INSTALL.md#3-install) works here |
| `sudo host-guard upgrade` | install the version this copy carries, with the options saved at install |
| `sudo host-guard rollback` | undo the last install |
| `sudo host-guard rollback --to 0.3.0` | undo every install back to 0.3.0 |
| `sudo host-guard uninstall` | remove host-guard; settings, secrets and backups stay |
| `sudo host-guard uninstall --purge --delete-backups` | remove everything, including the packages it added |
| `sudo host-guard status` | installed version, what a rollback would undo, then `hostguard status` |
| `host-guard history` | every install, upgrade and rollback |
| `host-guard version` | the version this copy of the manager carries |

`--yes` answers the questions (needed without a terminal), `--force` also undoes
files an admin changed since, `--allow-downgrade` installs an older version over a
newer one without asking.

## What happens on an install

```mermaid
flowchart TD
    A[host-guard install or upgrade] --> B{installed version?}
    B -- none --> C[install]
    B -- older --> D[upgrade]
    B -- same --> E[repair: apply again]
    B -- newer --> F{asked: install the older one anyway?}
    F -- no / no terminal --> X[stop, nothing changed]
    F -- yes or --allow-downgrade --> G[downgrade]
    B -- "unversioned (installed before the manager)" --> H[adopt]
    C & D & E & G & H --> I[record every watched file: hash, mode, owner, a copy]
    I --> J[run install.sh with the saved options]
    J -- fails --> K[undo at once from the record]
    J -- ok --> L[record what changed: manifest]
    L --> M[current -> releases/version, keep 3 releases]
```

The watched places are where host-guard, its base hardening, an app's own
hardening script and the panel write: `/etc/ssh/sshd_config.d`, `/etc/fail2ban/jail.d`
and `filter.d`, `/etc/sysctl.d`, `/etc/apt/apt.conf.d`, `sources.list.d`, `keyrings`,
`/etc/logrotate.d`, `/etc/systemd/system` (units and the links that enable them),
`/usr/local/sbin`, the panel's folders, `/etc/msmtprc` and `/etc/docker/daemon.json`.
A new file that a package brought in belongs to that package and is left to dpkg.

## The folder

```
/opt/host-guard/
  releases/0.3.0/                   what runs on a server: guard/, panel/, examples/, VERSION
  releases/0.3.1/
  current -> releases/0.3.1
  history/0001-install-0.3.0/
    manifest.json                   version, options, every changed file before and after
    files/etc/msmtprc               the file as it was before this install
  history/0002-upgrade-0.3.1/
  state.json                        installed version and the saved options (no secrets)
  manager.py                        the newest manager seen, used by /usr/local/sbin/host-guard
```

## Rollback rules

* A file is put back only while it still holds what that install wrote. A file an
  admin changed since is kept and named in the output; `--force` puts it back anyway.
* SSH and fail2ban settings are checked (`sshd -t`, `fail2ban-client -t`) before
  they apply. If a check fails, the files go back to how they were a moment before
  and the rollback stops: a rollback cannot lock you out.
* Units, sysctl, sshd and fail2ban are reloaded to match the restored files.
* Never rolled back: `/etc/host-guard` (secrets and settings only move forward; a
  newer version only adds settings, so an older one still reads them), the state
  in `/var/lib/host-guard` and the backups.
* Packages are never removed by a rollback. `uninstall --purge` removes only the
  packages host-guard added, and keeps them when apt would take anything else with them.
* `uninstall --purge` refuses while backups exist unless `--delete-backups` is
  given too: it deletes `.env`, the only copy of the backup passphrase.

## Options are kept

The install options are saved (without secrets or the one-off `--smtp-file`) and
reused by `upgrade`, so an upgrade never changes who may log in over SSH, the
report time or the patch window. Recipients always come from `guard.conf`, where
they may have been changed since. On a server installed before the manager, the
options are read back from the files the old install wrote.

## Tested

CI builds the pip package and, on Ubuntu 24.04, 26.04 and Debian 12, installs it,
upgrades to a changed version, refuses a downgrade without a terminal, injects a
failure into an upgrade (the system must be identical afterwards), rolls back with
a file an admin edited (kept and reported, everything else exactly as before), runs
a backup and a restore test through the manager, and finally runs `uninstall
--purge`: every watched place and the package list must then be byte-for-byte as
they were before host-guard was installed ([ci/lifecycle.sh](../ci/lifecycle.sh)).
