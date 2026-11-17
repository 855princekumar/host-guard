#!/usr/bin/env bash
# A first install on a clean Ubuntu or Debian (systemctl stubbed, no Docker), with a profile
# and the bundled base hardening (a real sshd validates the SSH policy), then a rerun, then a
# backup and a restore test of the profile's BACKUP_CMD.
# Run: docker run --rm -v "$PWD:/src:ro" ubuntu:26.04 bash /src/ci/fresh_install.sh
set -e
apt-get update -qq >/dev/null
apt-get install -y -qq sudo iptables procps openssh-server >/dev/null 2>&1
printf '#!/bin/sh\nexit 0\n' > /usr/local/bin/systemctl; chmod +x /usr/local/bin/systemctl
mkdir -p /run/sshd
useradd -m -s /bin/bash ops
cp -r /src /root/hg
printf 'abcdefghijklmnop\n' > /root/pw
set +e
bash /root/hg/guard/install.sh --mail-to "a@gmail.com, b@example.org" --profile /root/hg/examples/profiles/plain-vps.conf \
  --login-user ops --tz Asia/Kolkata --report-time 09:00 --maintenance "Sun 03:30" --with-trivy \
  --web-logs /var/log/nginx --smtp-file /root/pw > /root/log 2>&1
rc=$?
grep '^==>' /root/log; tail -4 /root/log; echo "EXIT $rc"
echo "--- checks"
grep -E '^(MAIL_TO|MAIL_FROM|BACKUP_CMD|STACK_DIR)=' /etc/host-guard/guard.conf
grep -E '^(PasswordAuthentication|PermitRootLogin|AllowUsers|AllowTcpForwarding) ' /etc/ssh/sshd_config.d/01-host-guard.conf
grep -E '^\[' /etc/fail2ban/jail.d/host-guard.local | tr '\n' ' '; echo
command -v trivy lynis msmtp hostguard
echo "--- rerun (idempotent)"
printf 'abcdefghijklmnop\n' > /root/pw
bash /root/hg/guard/install.sh --mail-to "a@gmail.com,c@example.net" --login-user ops --smtp-file /root/pw \
  --no-base-hardening > /root/log2 2>&1; rc2=$?; echo "EXIT2 $rc2"
echo "--- backup and restore test of BACKUP_CMD"
HG_NOTIFY_CMD=true hostguard backup > /root/log3 2>&1; rc3=$?
HG_NOTIFY_CMD=true hostguard restore-test >> /root/log3 2>&1; rc4=$?
cat /root/log3
[ "$rc" = 0 ] && [ "$rc2" = 0 ] && [ "$rc3" = 0 ] && [ "$rc4" = 0 ] && grep -q '^host-guard installed' /root/log \
  && grep -q '^SMTP_PASSWORD=abcdefghijklmnop$' /etc/host-guard/.env \
  && ! grep -q abcdefghijklmnop /etc/msmtprc /etc/host-guard/guard.conf \
  && grep -q '^MAIL_TO=a@gmail.com,c@example.net$' /etc/host-guard/guard.conf \
  && grep -q '^BACKUP_CMD=tar ' /etc/host-guard/guard.conf \
  && grep -q '^AllowUsers ops$' /etc/ssh/sshd_config.d/01-host-guard.conf \
  && grep -q '^\[web-probe\]' /etc/fail2ban/jail.d/host-guard.local \
  && grep -q 'restore-test: ok' /root/log3 \
  || { echo "FRESH INSTALL FAILED"; cat /root/log /root/log2; exit 1; }
echo "fresh install ok"
