#!/usr/bin/env bash
# The red-team target: a clean Ubuntu server with sshd, nginx (with a rate limit) and rsyslog,
# host-guard installed from the built wheel (/dist, the exact file that would be published) with
# pipx, then by its version manager with the panel, a plain VPS profile and off-site
# backup copies to an emulated S3 (Floci). Mail is captured to /var/mail/hg-captured instead
# of being sent. Run by ci/redteam/run.sh inside the target container.
#
# Container-only adaptations (a container has no systemd or journald): systemctl is a stub,
# the services are started by hand, and the sshd jail reads /var/log/auth.log (rsyslog)
# instead of the journal. Everything else is the real install.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq sudo iptables procps openssh-server nginx rsyslog python3 pipx curl netcat-openbsd gnupg >/dev/null 2>&1
printf '#!/bin/sh\nexit 0\n' > /usr/local/bin/systemctl
chmod +x /usr/local/bin/systemctl

sed -i 's/^module(load="imklog"/#&/' /etc/rsyslog.conf
rsyslogd
mkdir -p /run/sshd

useradd -m -s /bin/bash ops
echo 'ops:Correct-Horse-Battery-9' | chpasswd        # a real password: SSH must still refuse it
useradd -m -s /bin/bash intruder                     # exists, has a key, is not allowed in
for u in ops intruder; do
  install -d -m 700 -o "$u" -g "$u" "/home/$u/.ssh"
  install -m 600 -o "$u" -g "$u" "/keys/$u.pub" "/home/$u/.ssh/authorized_keys"
done
install -d -m 700 /root/.ssh
install -m 600 /keys/root.pub /root/.ssh/authorized_keys

# nginx: a site on port 80 with a rate limit (5 requests a second per address, burst 10)
cat > /etc/nginx/conf.d/00-ratelimit.conf <<'EOF'
limit_req_zone $binary_remote_addr zone=site:1m rate=5r/s;
EOF
cat > /etc/nginx/sites-enabled/default <<'EOF'
server {
  listen 80 default_server;
  root /var/www/html;
  location / { limit_req zone=site burst=10 nodelay; try_files $uri $uri/ =404; }
}
EOF
echo '<!doctype html><title>shop</title><p>Welcome.' > /var/www/html/index.html
nginx

cat > /usr/local/bin/capture-mail <<'EOF'
#!/bin/sh
{ printf '=== MAIL to %s\n' "$*"; cat; printf '\n'; } >> /var/mail/hg-captured
EOF
chmod 755 /usr/local/bin/capture-mail
python3 -c "import urllib.request; urllib.request.urlopen(urllib.request.Request('http://floci:4566/hg-backups', method='PUT'))"

export PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin      # as docs/INSTALL.md says
pipx install /dist/host_guard-*.whl >/dev/null
cd /
host-guard install --mail-to security@example.com --profile examples/profiles/plain-vps.conf \
  --login-user ops --web-logs /var/log/nginx --smtp-plain --smtp-host 127.0.0.1 --smtp-port 1025 \
  --s3-bucket hg-backups --s3-endpoint http://floci:4566 --region us-east-1 --with-panel --yes

printf 'NOTIFY_CMD=/usr/local/bin/capture-mail\nSITE=redteam-target\n' >> /etc/host-guard/guard.conf
sed -i 's/^AWS_ACCESS_KEY_ID=$/AWS_ACCESS_KEY_ID=test/; s/^AWS_SECRET_ACCESS_KEY=$/AWS_SECRET_ACCESS_KEY=rt-secret-7f3a9c51e2/' /etc/host-guard/.env

cat > /etc/fail2ban/jail.d/zz-container.local <<'EOF'
# container only: no journald, so the sshd jail reads rsyslog's file
[sshd]
backend = polling
logpath = /var/log/auth.log
EOF
touch /var/log/auth.log
/usr/sbin/sshd
fail2ban-client -x start >/dev/null
for _ in $(seq 30); do fail2ban-client ping >/dev/null 2>&1 && break; sleep 1; done

runuser -u hgpanel -- python3 -I /usr/local/lib/host-guard-panel/hgpanel.py serve > /var/log/hgpanel.log 2>&1 &
python3 - <<'EOF'
# The panel's one admin, with a known password and authenticator secret (test values)
import importlib.util, os, time
spec = importlib.util.spec_from_file_location('hgpanel', '/usr/local/lib/host-guard-panel/hgpanel.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
con = p.db()
con.execute('DELETE FROM admin')
con.execute('INSERT INTO admin (id, username, pw_hash, totp_secret, created) VALUES (1, ?, ?, ?, ?)',
            ('admin', p.hash_password('Panel-Pass-2026!'), 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP', time.time()))
os.system('chown hgpanel:hgpanel /var/lib/host-guard-panel/panel.db*')
EOF
for _ in $(seq 20); do curl -s -o /dev/null http://127.0.0.1:8650/login && break; sleep 0.5; done

hostguard watch >/dev/null      # baselines: files, accounts, keys
hostguard health >/dev/null     # baseline of the bans
hostguard export >/dev/null
: > /var/mail/hg-captured
echo "target ready"
