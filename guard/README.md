# guard

The part of host-guard that runs on the server, as root, from systemd timers.

| File | What |
|---|---|
| [hostguard.py](hostguard.py) | the program: `hostguard health / watch / feeds / scan / backup / restore-test / patch-window / report / cost / boot / export / status / test-mail / unlock` |
| [install.sh](install.sh) | the installer (idempotent); run it through the version manager, `host-guard install` ([versions](../docs/VERSIONS.md)) |
| [conf/base-hardening.sh](conf/base-hardening.sh) | SSH policy, fail2ban, security updates; run first by the installer |
| [conf/firewall.sh](conf/firewall.sh) | outbound mining ports refused, from the host and from containers (at boot) |
| [conf/sysctl-hardening.conf](conf/sysctl-hardening.conf) | kernel network hardening (safe with Docker) |
| [conf/52host-guard-unattended](conf/52host-guard-unattended) | security updates without automatic reboot |
| [systemd/](systemd/) | the timers and services |
| [tests/](tests/) | the tests (no root, Docker or network needed) |

What it deliberately does not do: upgrade your app (that is your release process),
remove SSH keys, reboot outside the maintenance window, or send anything anywhere
except mail and, if you set it, encrypted backups to your S3 bucket.

Docs: [install](../docs/INSTALL.md), [how it works](../docs/HOW-IT-WORKS.md),
[settings](../docs/CONFIGURATION.md), [running cost](../docs/COST.md).
