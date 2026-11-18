# host-guard

Hardening, monitoring, encrypted backups with restore tests, and mail alerts for one
Linux server (Ubuntu 22.04 to 26.04, Debian 12 and 13): a cloud instance, a VPS or
bare metal. Python standard library and systemd timers, nothing else to run.

This package is the installer. It installs host-guard on the server, records every
file it changes, and can roll back or remove it again.

## Install

System Python refuses `pip install` on current Ubuntu and Debian (PEP 668), so use pipx:

```bash
sudo apt install -y pipx
sudo PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install host-guard
sudo host-guard install --mail-to you@example.com --profile examples/profiles/plain-vps.conf
```

The installer asks for the Gmail app password that sends the mail (not shown as you type).

## Upgrade, roll back, remove

```bash
sudo PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx upgrade host-guard
sudo host-guard upgrade              # uses the options given at install
sudo host-guard rollback             # undo the last install, exactly
sudo host-guard rollback --to 0.3.0
sudo host-guard uninstall            # keeps settings, secrets and backups
sudo host-guard status
sudo host-guard history
```

Everything lives in `/opt/host-guard`: one folder per release (three kept) and a
manifest per install, with a copy of every file it replaced. A rollback restores a
file only while it still holds what host-guard wrote; a file you changed since is kept
and reported. SSH and fail2ban settings are checked before they apply.

Docs, profiles and the source: https://github.com/855princekumar/host-guard
