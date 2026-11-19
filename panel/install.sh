#!/usr/bin/env bash
# host-guard panel installer. Needs host-guard installed first (guard/install.sh).
#
#   sudo bash panel/install.sh [--port 8650]
#
# The admins sign in with their email address and a code mailed to it (no password): the
# addresses in MAIL_TO (or PANEL_ADMINS) of /etc/host-guard/guard.conf.
#
# Then, from your computer: ssh -L 8650:127.0.0.1:8650 <server>, and open
# http://127.0.0.1:8650 . The panel listens on 127.0.0.1 only and runs as the
# unprivileged user hgpanel, which cannot read host-guard's state, .env or backups.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
PORT=8650
while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2;;
    *) echo "unknown option $1"; exit 2;;
  esac
done
[[ "$PORT" =~ ^[0-9]{2,5}$ ]] || { echo "--port is a number"; exit 2; }
command -v hostguard >/dev/null || { echo "install host-guard first (guard/install.sh)"; exit 1; }

id hgpanel >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin hgpanel
install -d -m 0750 -o hgpanel -g hgpanel /var/lib/host-guard-panel
# sign-in requests from the panel to the root mailer (hostguard panel-outbox)
install -d -m 0700 -o hgpanel -g hgpanel /var/lib/host-guard-panel/outbox
# the exported status: written by root, readable by the panel, not writable by it
install -d -m 0750 -o root -g hgpanel /var/lib/host-guard-export
install -d -m 0755 /usr/local/lib/host-guard-panel /etc/host-guard-panel
install -m 0644 "$HERE/hgpanel.py" /usr/local/lib/host-guard-panel/hgpanel.py
[ -f /etc/host-guard-panel/panel.conf ] || cat > /etc/host-guard-panel/panel.conf <<CONF
# host-guard panel settings (no secrets here; the admins are MAIL_TO in /etc/host-guard/guard.conf)
BIND=127.0.0.1
PORT=$PORT
CONF
chmod 0644 /etc/host-guard-panel/panel.conf
grep -q '^EXPORT_GROUP=' /etc/host-guard/guard.conf || printf 'EXPORT_GROUP=hgpanel\n' >> /etc/host-guard/guard.conf

for f in "$HERE"/systemd/*; do install -m 0644 "$f" /etc/systemd/system/; done
systemctl daemon-reload
hostguard export
systemctl enable --now host-guard-export.timer host-guard-panel-mail.path host-guard-panel.service >/dev/null
systemctl --no-pager --lines=0 status host-guard-panel.service || true
echo
echo "Open it: ssh -N -L $PORT:127.0.0.1:$PORT <this server>  then http://127.0.0.1:$PORT"
echo "Sign in with your admin address ($(sed -n 's/^PANEL_ADMINS=//p; s/^MAIL_TO=//p' /etc/host-guard/guard.conf | head -1)): a code is mailed to it."
