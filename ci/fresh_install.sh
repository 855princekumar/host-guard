# A first install on a clean Ubuntu (systemctl stubbed, no Docker stack), then a rerun.
# Run: docker run --rm -v "$PWD/guard:/src:ro" -v "$PWD/ci/fresh_install.sh:/t.sh:ro" ubuntu:26.04 bash /t.sh
set -e
apt-get update -qq >/dev/null; apt-get install -y -qq sudo iptables procps >/dev/null 2>&1
printf '#!/bin/sh\nexit 0\n' > /usr/local/bin/systemctl; chmod +x /usr/local/bin/systemctl
cp -r /src /root/host-guard
printf 'abcdefghijklmnop\n' > /root/pw
set +e
bash /root/host-guard/install.sh --mail-to "a@gmail.com, b@example.org" --domain fleet.example.com \
  --edgeshell-dir /root/edgeshell --login-user root --tz Asia/Kolkata --report-time 09:00 \
  --maintenance "Sun 03:30" --with-trivy --smtp-file /root/pw --no-base-hardening > /root/log 2>&1
rc=$?
grep '^==>' /root/log; tail -4 /root/log; echo "EXIT $rc"
echo "--- checks"
ls -l /etc/host-guard; grep -c '^SMTP_PASSWORD=abcdefghijklmnop$' /etc/host-guard/.env; grep -c '^BACKUP_PASSPHRASE=.' /etc/host-guard/.env
grep -E '^MAIL_(TO|FROM)=' /etc/host-guard/guard.conf; grep -E '^(from|user|passwordeval)' /etc/msmtprc
grep -c abcdefghijklmnop /etc/msmtprc /etc/host-guard/guard.conf; test -e /root/pw && echo "pw file left!" || echo "pw file removed"
command -v trivy lynis msmtp hostguard
echo "--- rerun (idempotent)"
printf 'abcdefghijklmnop\n' > /root/pw
bash /root/host-guard/install.sh --mail-to "a@gmail.com,c@example.net" --domain fleet.example.com --edgeshell-dir /root/edgeshell --login-user root --smtp-file /root/pw --no-base-hardening > /root/log2 2>&1; echo "EXIT2 $?"
grep -E '^MAIL_(TO|FROM)=' /etc/host-guard/guard.conf; grep -c BACKUP_PASSPHRASE /etc/host-guard/.env
[ "$rc" = 0 ] && grep -q '^host-guard installed' /root/log && grep -q '^SMTP_PASSWORD=abcdefghijklmnop$' /etc/host-guard/.env \
  && ! grep -q abcdefghijklmnop /etc/msmtprc /etc/host-guard/guard.conf && grep -q '^MAIL_TO=a@gmail.com,c@example.net$' /etc/host-guard/guard.conf \
  || { echo "FRESH INSTALL FAILED"; cat /root/log; exit 1; }
echo "fresh install ok"
