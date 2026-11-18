#!/usr/bin/env bash
# host-guard base hardening for any Ubuntu or Debian server. Idempotent.
# install.sh runs it first; it can also run on its own:
#
#   sudo bash base-hardening.sh [--user ubuntu] [--admin-ip 203.0.113.7]
#        [--web-logs /var/log/nginx] [--docker]
#
#   SSH       key only, no root login, 3 attempts, short grace time, no X11 or agent
#             forwarding, no reverse tunnels (local forwarding stays, for the panel's
#             ssh -L tunnel), only --user may log in. Checked with `sshd -t` first;
#             open sessions stay open.
#   fail2ban  sshd (3 failures in 10 min: 1 h, doubling up to a week), recidive (banned
#             3 times a day: a week, every port). With --web-logs (nginx's log folder):
#             nginx-limit-req (rate limit tripped: 1 h) and web-probe (asking for .env,
#             .git, wp-login, phpMyAdmin and the like: 1 day). With --docker the web bans
#             go into Docker's DOCKER-USER chain, since published container ports skip INPUT.
#   Updates   unattended security upgrades on.
#
# --admin-ip   an address that is never banned (office or home). Optional.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "Run with sudo." >&2; exit 1; }

SSH_USER="${SUDO_USER:-ubuntu}" ADMIN_IP="" WEB_LOGS="" DOCKER=0
while [ $# -gt 0 ]; do
  case "$1" in
    --user) SSH_USER="$2"; shift 2 ;;
    --admin-ip) ADMIN_IP="$2"; shift 2 ;;
    --web-logs) WEB_LOGS="$2"; shift 2 ;;
    --docker) DOCKER=1; shift ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done
[[ "$SSH_USER" =~ ^[a-z_][a-z0-9_-]*$ ]] || { echo "--user is not a user name" >&2; exit 2; }
id "$SSH_USER" >/dev/null 2>&1 || { echo "user $SSH_USER does not exist: SSH would lock everyone out" >&2; exit 2; }
[ -z "$ADMIN_IP" ] || [[ "$ADMIN_IP" =~ ^[0-9a-fA-F.:/]+$ ]] || { echo "--admin-ip is not an address" >&2; exit 2; }
say() { printf '==> %s\n' "$*"; }

say "Packages: fail2ban, unattended-upgrades"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends fail2ban unattended-upgrades python3-systemd >/dev/null

say "SSH policy (key only, $SSH_USER only)"
POLICY=/etc/ssh/sshd_config.d/01-host-guard.conf
# 01- sorts before the cloud image's drop-ins: the first value sshd reads wins.
cat > "$POLICY" <<EOF
# Managed by host-guard conf/base-hardening.sh
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
PubkeyAuthentication yes
AuthenticationMethods publickey
MaxAuthTries 3
LoginGraceTime 30
MaxStartups 10:30:60
MaxSessions 4
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding local
PermitTunnel no
ClientAliveInterval 300
ClientAliveCountMax 2
AllowUsers $SSH_USER
EOF
chmod 644 "$POLICY"
if sshd -t; then
  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
else
  rm -f "$POLICY"
  echo "sshd rejected the policy; it was removed and nothing changed." >&2
  exit 1
fi

say "fail2ban"
ignore="127.0.0.1/8 ::1"
[ "$DOCKER" = 1 ] && ignore="$ignore 172.16.0.0/12"
[ -n "$ADMIN_IP" ] && ignore="$ignore $ADMIN_IP"
JAIL=/etc/fail2ban/jail.d/host-guard.local
cat > "$JAIL" <<EOF
# Managed by host-guard conf/base-hardening.sh
[DEFAULT]
ignoreip = $ignore
bantime = 1h
findtime = 10m
maxretry = 3
bantime.increment = true
bantime.factor = 2
bantime.maxtime = 1w
banaction = iptables-multiport
banaction_allports = iptables-allports

[sshd]
enabled = true
mode = aggressive
port = ssh
backend = systemd

[recidive]
enabled = true
logpath = /var/log/fail2ban.log
bantime = 1w
findtime = 1d
maxretry = 3
banaction = iptables-allports
EOF
if [ -n "$WEB_LOGS" ]; then
  mkdir -p "$WEB_LOGS"
  touch "$WEB_LOGS/access.log" "$WEB_LOGS/error.log"
  cat > /etc/fail2ban/filter.d/web-probe.conf <<'EOF'
# Requests for files that a normal visitor never asks for.
[Definition]
# fail2ban cuts the time stamp out of the line before matching: the brackets are left empty.
failregex = ^<HOST> \S+ \S+ \[[^\]]*\] "(GET|POST|HEAD|PUT) /[^"]*(\.env|\.git/|\.aws/|\.ssh/|wp-login|wp-admin|xmlrpc\.php|phpmyadmin|/cgi-bin/|/vendor/phpunit|/actuator|/solr/|/boaform|/HNAP1)[^"]*" (400|401|403|404|405|444)
ignoreregex =
EOF
  chain=""
  [ "$DOCKER" = 1 ] && chain=", chain=DOCKER-USER"
  cat >> "$JAIL" <<EOF

[nginx-limit-req]
enabled = true
logpath = $WEB_LOGS/error.log
backend = polling
port = http,https
action = iptables-multiport[name=%(__name__)s, port="80,443", protocol=tcp$chain]

[web-probe]
enabled = true
filter = web-probe
logpath = $WEB_LOGS/access.log
backend = polling
maxretry = 3
bantime = 1d
port = http,https
action = iptables-multiport[name=%(__name__)s, port="80,443", protocol=tcp$chain]
EOF
fi
fail2ban-client -t >/dev/null
systemctl enable fail2ban >/dev/null 2>&1 || true
systemctl restart fail2ban 2>/dev/null || true

say "Automatic security updates"
printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' > /etc/apt/apt.conf.d/20auto-upgrades
systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true

echo "Keep this SSH session open and test a new login from another terminal before closing it."
