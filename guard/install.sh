#!/usr/bin/env bash
# host-guard installer for the EdgeShell server (Ubuntu 22.04, 24.04 or 26.04, Docker stack
# in EDGESHELL_DIR). Idempotent: run it again after an update of this folder.
#
#   sudo bash install.sh --mail-to you@gmail.com[,admin2@example.com,...] --domain fleet.example.com \
#        [--mail-from you@gmail.com]   (the Gmail account that sends; default: the first --mail-to)
#        [--edgeshell-dir /home/ubuntu/edgeshell] [--login-user ubuntu] [--tz Asia/Kolkata]
#        [--report-time 09:00] [--maintenance "Sun 03:30"] [--s3-bucket NAME] [--with-trivy]
#        [--smtp-file FILE] [--admin-ip ADDRESS] [--no-base-hardening] [--lockdown web|alert]
#
# First it runs EdgeShell's own docker/host-hardening.sh from the stack folder
# (SSH by key only, fail2ban for SSH, repeat offenders, sign-in floods and
# probes, banning in Docker's DOCKER-USER chain, log rotation, security
# updates). host-guard adds what that does not: health, intrusion watch, early
# warning, scans, encrypted backups with restore tests, the patch window, kernel
# network hardening, outbound mining ports blocked, and mail for all of it.
#
# Every secret lives in one file, /etc/host-guard/.env (root only, mode 600):
#   SMTP_PASSWORD      the Gmail app password, asked for interactively (not echoed)
#                      or read from --smtp-file (deleted afterwards); msmtp reads it
#                      from .env, so /etc/msmtprc holds no secret
#   BACKUP_PASSPHRASE  made here once (an older /etc/host-guard/backup.key is moved in)
#   EDGESHELL_KEY, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY   optional, you fill them in
# Secrets are never printed, never written anywhere else, never mailed.
#
# Test bed only: --smtp-host H --smtp-port P --smtp-plain (an SMTP catcher, no TLS).
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"

MAIL_TO="" MAIL_FROM="" DOMAIN="" ES_DIR="/home/ubuntu/edgeshell" LOGIN_USER="ubuntu" TZ_="Asia/Kolkata" REPORT="09:00"
MAINT="Sun 03:30" S3_BUCKET="" WITH_TRIVY=0 SMTP_FILE="" BASE_HARDEN=1 ADMIN_IP="" LOCKDOWN="alert"
SMTP_HOST="smtp.gmail.com" SMTP_PORT=587 SMTP_PLAIN=0 S3_ENDPOINT="" AWS_REGION="ap-south-1"
while [ $# -gt 0 ]; do
  case "$1" in
    --mail-to) MAIL_TO="$2"; shift 2;;
    --mail-from) MAIL_FROM="$2"; shift 2;;
    --domain) DOMAIN="$2"; shift 2;;
    --edgeshell-dir) ES_DIR="$2"; shift 2;;
    --login-user) LOGIN_USER="$2"; shift 2;;
    --tz) TZ_="$2"; shift 2;;
    --report-time) REPORT="$2"; shift 2;;
    --maintenance) MAINT="$2"; shift 2;;
    --s3-bucket) S3_BUCKET="$2"; shift 2;;
    --s3-endpoint) S3_ENDPOINT="$2"; shift 2;;
    --region) AWS_REGION="$2"; shift 2;;
    --with-trivy) WITH_TRIVY=1; shift;;
    --smtp-file) SMTP_FILE="$2"; shift 2;;
    --smtp-host) SMTP_HOST="$2"; shift 2;;
    --smtp-port) SMTP_PORT="$2"; shift 2;;
    --smtp-plain) SMTP_PLAIN=1; shift;;
    --no-base-hardening) BASE_HARDEN=0; shift;;
    --admin-ip) ADMIN_IP="$2"; shift 2;;
    --lockdown) LOCKDOWN="$2"; shift 2;;
    *) echo "unknown option $1"; exit 2;;
  esac
done
[ -n "$MAIL_TO" ] || { echo "--mail-to is required"; exit 2; }
EMAIL_RE='^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'
MAIL_TO="$(printf %s "$MAIL_TO" | tr -s ' ,' ',' | sed 's/^,//; s/,$//')"
IFS=',' read -r -a RCPTS <<< "$MAIL_TO"
for a in "${RCPTS[@]}"; do [[ "$a" =~ $EMAIL_RE ]] || { echo "--mail-to: '$a' is not an email address"; exit 2; }; done
[ -n "$MAIL_FROM" ] || MAIL_FROM="${RCPTS[0]}"
[[ "$MAIL_FROM" =~ $EMAIL_RE ]] || { echo "--mail-from is not an email address"; exit 2; }
[[ "$LOCKDOWN" =~ ^(alert|web)$ ]] || { echo "--lockdown is alert or web"; exit 2; }
step() { printf '\n==> %s\n' "$*"; }

step "Packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq msmtp msmtp-mta unattended-upgrades gnupg lynis python3 curl ca-certificates \
  iptables openssl >/dev/null
if [ "$WITH_TRIVY" = 1 ] && ! command -v trivy >/dev/null; then
  # Aqua Security's signed apt repository (the official install route)
  install -d -m 0755 /etc/apt/keyrings
  curl -fsSL https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor -o /etc/apt/keyrings/trivy.gpg
  echo "deb [signed-by=/etc/apt/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
    > /etc/apt/sources.list.d/trivy.list
  apt-get update -qq && apt-get install -y -qq trivy >/dev/null
fi

step "Secrets: one file, /etc/host-guard/.env (root only)"
install -d -m 0700 /etc/host-guard /var/lib/host-guard /var/backups/host-guard
ENVF=/etc/host-guard/.env
umask 077; [ -f "$ENVF" ] || printf '# host-guard secrets (root only). Never copy this file anywhere else.\n' > "$ENVF"; umask 022
chmod 600 "$ENVF"; chown root:root "$ENVF"
has() { grep -q "^$1=." "$ENVF"; }
setenv() {  # KEY, with the value in HG_VALUE (not on a command line, where ps could show it)
  python3 - "$ENVF" "$1" <<'PY'
import os, sys
f, k = sys.argv[1], sys.argv[2]
lines = [l for l in open(f).read().splitlines() if not l.startswith(k + '=')]
lines.append(f"{k}={os.environ['HG_VALUE']}")
open(f, 'w').write('\n'.join(lines) + '\n')
PY
}
for k in EDGESHELL_KEY AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY; do   # secrets once kept in guard.conf move here
  v="$(sed -n "s/^$k=//p" /etc/host-guard/guard.conf 2>/dev/null | tail -1)"
  [ -n "$v" ] && HG_VALUE="$v" setenv "$k"
  [ -f /etc/host-guard/guard.conf ] && sed -i "/^$k=/d" /etc/host-guard/guard.conf
done
if ! has BACKUP_PASSPHRASE; then
  if [ -s /etc/host-guard/backup.key ]; then
    HG_VALUE="$(cat /etc/host-guard/backup.key)" setenv BACKUP_PASSPHRASE
    shred -u /etc/host-guard/backup.key 2>/dev/null || rm -f /etc/host-guard/backup.key
    echo "  the backup key moved into $ENVF (BACKUP_PASSPHRASE)"
  else
    HG_VALUE="$(head -c 48 /dev/urandom | base64 | tr -d '\n')" setenv BACKUP_PASSPHRASE
    echo "  NEW backup passphrase: BACKUP_PASSPHRASE in $ENVF. Copy it somewhere safe and offline now:"
    echo "  without it the encrypted backups cannot be restored."
  fi
fi
grep -q '^#\?EDGESHELL_KEY=' "$ENVF" || printf '# A read-only EdgeShell service key (API page, scope read) for fleet numbers in the daily report:\nEDGESHELL_KEY=\n' >> "$ENVF"
grep -q '^#\?AWS_ACCESS_KEY_ID=' "$ENVF" || printf '# Only when the instance has no role allowed to use the backup bucket:\nAWS_ACCESS_KEY_ID=\nAWS_SECRET_ACCESS_KEY=\n' >> "$ENVF"

step "Mail (msmtp; the password stays in .env)"
umask 077
if [ "$SMTP_PLAIN" = 1 ]; then
  printf 'defaults\nauth off\ntls off\nlogfile /var/log/msmtp.log\naccount default\nhost %s\nport %s\nfrom %s\n' \
    "$SMTP_HOST" "$SMTP_PORT" "$MAIL_FROM" > /etc/msmtprc
else
  if [ -n "$SMTP_FILE" ] || ! has SMTP_PASSWORD; then
    if [ -n "$SMTP_FILE" ]; then PW="$(tr -d ' \r\n' < "$SMTP_FILE")"; shred -u "$SMTP_FILE" 2>/dev/null || rm -f "$SMTP_FILE"
    else read -r -s -p "Gmail app password for $MAIL_FROM (16 letters, not echoed): " PW; echo; PW="$(printf %s "$PW" | tr -d ' ')"; fi
    [ ${#PW} -ge 16 ] || { echo "that does not look like an app password (16 letters)"; exit 2; }
    HG_VALUE="$PW" setenv SMTP_PASSWORD; unset PW
  fi
  cat > /etc/msmtprc <<EOF
defaults
auth on
tls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
logfile /var/log/msmtp.log
account gmail
host $SMTP_HOST
port $SMTP_PORT
from $MAIL_FROM
user $MAIL_FROM
passwordeval "sed -n 's/^SMTP_PASSWORD=//p' $ENVF"
account default : gmail
EOF
fi
chmod 600 /etc/msmtprc; chown root:root /etc/msmtprc
umask 022

step "host-guard program and settings (no secrets in guard.conf)"
install -m 0755 "$HERE/hostguard.py" /usr/local/sbin/hostguard
CONF=/etc/host-guard/guard.conf
if [ ! -f "$CONF" ]; then
  umask 077
  cat > "$CONF" <<EOF
# host-guard settings, no secrets (those are in /etc/host-guard/.env). Docs: host-guard/README.md
MAIL_TO=$MAIL_TO
MAIL_FROM=$MAIL_FROM
SITE=$(hostname)
DOMAIN=$DOMAIN
EDGESHELL_DIR=$ES_DIR
LOGIN_USER=$LOGIN_USER
LOCKDOWN=$LOCKDOWN
S3_BUCKET=$S3_BUCKET
S3_ENDPOINT=$S3_ENDPOINT
AWS_REGION=$AWS_REGION
# Running cost: the instance type and disk are read from the instance; set them only off EC2.
# USD_INR=88 adds rupees to the report.
EOF
  umask 022
else   # a rerun takes the recipients given now (both values were checked above)
  for k in MAIL_TO MAIL_FROM; do
    v="${!k}"
    if grep -q "^$k=" "$CONF"; then sed -i "s|^$k=.*|$k=$v|" "$CONF"; else printf '%s=%s\n' "$k" "$v" >> "$CONF"; fi
  done
fi
chmod 600 "$CONF"

step "Kernel and network hardening (sysctl)"
install -m 0644 "$HERE/conf/sysctl-hardening.conf" /etc/sysctl.d/99-host-guard.conf
sysctl --system >/dev/null 2>&1 || true

step "Base hardening: EdgeShell's host-hardening.sh (SSH, fail2ban, log rotation, updates)"
if [ "$BASE_HARDEN" = 1 ]; then
  BASE="$ES_DIR/host-hardening.sh"
  [ -f "$BASE" ] || BASE="$HERE/../edgeshell/docker/host-hardening.sh"
  if [ -f "$BASE" ]; then
    # it reads SUDO_USER for the one user allowed to log in over SSH
    SUDO_USER="$LOGIN_USER" bash "$BASE" ${ADMIN_IP:+--admin-ip "$ADMIN_IP"}
  else
    echo "  $ES_DIR/host-hardening.sh not found: copy docker/host-hardening.sh from the EdgeShell release"
    echo "  into $ES_DIR and run this again (or pass --no-base-hardening)"
    exit 1
  fi
fi

step "Automatic security updates (no automatic reboot: the window does it after a backup)"
install -m 0644 "$HERE/conf/52host-guard-unattended" /etc/apt/apt.conf.d/52host-guard-unattended
printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' > /etc/apt/apt.conf.d/20auto-upgrades

step "Docker log rotation"
if [ ! -s /etc/docker/daemon.json ]; then
  install -d /etc/docker
  printf '{\n  "log-driver": "json-file",\n  "log-opts": {"max-size": "20m", "max-file": "5"}\n}\n' > /etc/docker/daemon.json
  echo "  set (applies to containers created from now on; restart Docker in a quiet moment)"
else
  echo "  /etc/docker/daemon.json exists: left as it is"
fi

step "Firewall additions (outbound mining ports blocked, kept across reboots)"
install -m 0755 "$HERE/conf/firewall.sh" /usr/local/sbin/host-guard-firewall
/usr/local/sbin/host-guard-firewall || true

step "Timers"
for f in "$HERE"/systemd/*.service "$HERE"/systemd/*.timer; do
  install -m 0644 "$f" /etc/systemd/system/
done
sed -i "s|@REPORT@|$REPORT|; s|@TZ@|$TZ_|" /etc/systemd/system/host-guard-report.timer
sed -i "s|@MAINT@|$MAINT|; s|@TZ@|$TZ_|" /etc/systemd/system/host-guard-patch-window.timer
systemctl daemon-reload
for t in health watch feeds scan backup restore-test patch-window report; do
  systemctl enable --now "host-guard-$t.timer" >/dev/null
done
systemctl enable host-guard-boot.service host-guard-firewall.service >/dev/null

step "First runs"
/usr/local/sbin/hostguard watch >/dev/null || true       # baseline of files, accounts and keys
/usr/local/sbin/hostguard health >/dev/null || true      # baseline of the bans
/usr/local/sbin/hostguard test-mail || echo "  the test mail did not go out: check the app password, then: sudo hostguard test-mail"
echo
echo "host-guard installed. Status: sudo hostguard status   Report now: sudo hostguard report"
