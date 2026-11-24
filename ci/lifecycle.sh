#!/usr/bin/env bash
# The whole life of an install on a clean Ubuntu or Debian, from the built pip package:
# pipx install, host-guard install (with the panel), upgrade to a changed version, a
# downgrade refused, rollback with a file an admin changed, a failing upgrade undone at
# once, then uninstall --purge, after which every watched place must be byte-for-byte as
# it was before host-guard came (packages it added purged too).
# Run: docker run --rm -v "$PWD:/src:ro" -v "$PWD/dist:/dist:ro" ubuntu:24.04 bash /src/ci/lifecycle.sh
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq sudo iptables procps openssh-server python3 pipx >/dev/null 2>&1
printf '#!/bin/sh\nexit 0\n' > /usr/local/bin/systemctl; chmod +x /usr/local/bin/systemctl
mkdir -p /run/sshd
useradd -m -s /bin/bash ops
export PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin
pipx install /dist/host_guard-*.whl >/dev/null
V=$(host-guard version)                                    # the version in the wheel under test
IFS=. read -r MAJ MIN PAT <<< "$V"
N1="$MAJ.$MIN.$((PAT + 100))"; N2="$MAJ.$MIN.$((PAT + 101))"     # made-up newer versions for the upgrade tests
unset SUDO_USER
ok() { printf '  ok: %s\n' "$*"; }
die() { printf 'LIFECYCLE FAILED: %s\n' "$*"; exit 1; }

snap() {   # every place host-guard may touch: path, type, hash or link target, mode, owner
  python3 - "$1" <<'PY'
import hashlib, os, stat, sys
places = ['/etc/ssh/sshd_config.d', '/etc/fail2ban', '/etc/sysctl.d', '/etc/apt/apt.conf.d', '/etc/apt/sources.list.d',
          '/etc/apt/keyrings', '/etc/logrotate.d', '/etc/systemd/system', '/usr/local/sbin', '/usr/local/lib/host-guard', '/usr/local/lib/host-guard-panel',
          '/etc/host-guard-panel', '/etc/host-guard', '/var/lib/host-guard', '/var/lib/host-guard-panel',
          '/var/lib/host-guard-export', '/var/backups/host-guard', '/opt/host-guard', '/etc/msmtprc', '/etc/docker']
rows = []
for top in places:
    walk = [(top, [], [os.path.basename(top)])] if os.path.isfile(top) else os.walk(top) if os.path.isdir(top) else []
    for d, dirs, files in walk:
        base = os.path.dirname(top) if os.path.isfile(top) else d
        for n in sorted(files) + sorted(x for x in dirs if os.path.islink(os.path.join(d, x))):
            p = os.path.join(base, n)
            st = os.lstat(p)
            if stat.S_ISLNK(st.st_mode):
                rows.append(f'{p} link {os.readlink(p)}')
            else:
                rows.append(f'{p} {hashlib.sha256(open(p, "rb").read()).hexdigest()[:16]} {oct(st.st_mode & 0o7777)} {st.st_uid}:{st.st_gid}')
        if not os.path.isfile(top):
            rows += [f'{os.path.join(d, x)}/ dir' for x in dirs if not os.path.islink(os.path.join(d, x))]
open(sys.argv[1], 'w').write('\n'.join(sorted(rows)) + '\n')
PY
}
snap /root/pristine
dpkg-query -W -f='${Package}\n' | sort > /root/pkgs-pristine

echo "--- install $V (pip package, plain VPS profile, panel)"
printf 'abcdefghijklmnop\n' > /root/pw
host-guard install --mail-to a@gmail.com --profile examples/profiles/plain-vps.conf --login-user ops \
  --smtp-file /root/pw --web-logs /var/log/nginx --with-panel > /root/log1 2>&1 || { cat /root/log1; die install; }
[ "$(host-guard version)" = $V ] || die version
grep -q "\"version\": \"$V\"" /opt/host-guard/state.json || die state
[ "$(readlink /opt/host-guard/current)" = "releases/$V" ] || die current
grep -q '^AllowUsers ops$' /etc/ssh/sshd_config.d/01-host-guard.conf || die AllowUsers
grep -q '^BACKUP_CMD=tar ' /etc/host-guard/guard.conf || die profile
[ -f /usr/local/lib/host-guard-panel/hgpanel.py ] && id hgpanel >/dev/null || die panel
sshd -t || die "sshd -t"
ok "installed: $(ls /opt/host-guard/history)"
snap /root/after-030
cp -p /etc/sysctl.d/99-host-guard.conf /root/sysctl-030

echo "--- upgrade to $N1 (sysctl and SSH policy changed), saved options reused"
cp -r /opt/host-guard/releases/$V /root/hg031
echo $N1 > /root/hg031/VERSION
printf '\n# $N1\nnet.ipv4.tcp_rfc1337 = 1\n' >> /root/hg031/guard/conf/sysctl-hardening.conf
sed -i 's/^MaxSessions 4$/MaxSessions 5/' /root/hg031/guard/conf/base-hardening.sh
HG_PAYLOAD=/root/hg031 host-guard upgrade > /root/log2 2>&1 || { cat /root/log2; die upgrade; }
grep -q "\"version\": \"$N1\"" /opt/host-guard/state.json || die "state $N1"
grep -q '^MaxSessions 5$' /etc/ssh/sshd_config.d/01-host-guard.conf || die "policy $N1"
grep -q '^AllowUsers ops$' /etc/ssh/sshd_config.d/01-host-guard.conf || die "login user changed on upgrade"
grep -q 'tcp_rfc1337' /etc/sysctl.d/99-host-guard.conf || die "sysctl $N1"
ok "upgraded, AllowUsers still ops"

echo "--- an older version is refused without a terminal"
if HG_PAYLOAD=/opt/host-guard/releases/$V host-guard install < /dev/null > /root/log3 2>&1; then die "downgrade went through"; fi
grep -q 'older version' /root/log3 || { cat /root/log3; die "downgrade message"; }
grep -q "\"version\": \"$N1\"" /opt/host-guard/state.json || die "downgrade changed the state"
ok "downgrade refused"

echo "--- a failing upgrade is undone at once"
snap /root/before-fail
cp -r /root/hg031 /root/hg032; echo $N2 > /root/hg032/VERSION
sed -i 's/^step "Timers"$/exit 7\n&/' /root/hg032/guard/install.sh
grep -q '^exit 7$' /root/hg032/guard/install.sh || die "failure not injected"
if HG_PAYLOAD=/root/hg032 host-guard upgrade > /root/log4 2>&1; then die "failing upgrade succeeded"; fi
snap /root/after-fail
diff <(grep -v '^/opt/host-guard' /root/before-fail) <(grep -v '^/opt/host-guard' /root/after-fail) || die "failed upgrade left changes"
grep -q "\"version\": \"$N1\"" /opt/host-guard/state.json || die "state after failure"
ok "failed upgrade rolled back, system identical"

echo "--- rollback to $V, keeping a file an admin changed"
echo '# tuned by an admin' >> /etc/sysctl.d/99-host-guard.conf
host-guard rollback --yes > /root/log5 2>&1 || { cat /root/log5; die rollback; }
grep -q "\"version\": \"$V\"" /opt/host-guard/state.json || die "state after rollback"
grep -q '^MaxSessions 4$' /etc/ssh/sshd_config.d/01-host-guard.conf || die "policy not restored"
grep -q 'tuned by an admin' /etc/sysctl.d/99-host-guard.conf || die "admin edit lost"
grep -q 'kept (changed since' /root/log5 || die "admin edit not reported"
sshd -t || die "sshd -t after rollback"
X='^/opt/host-guard\|^/var/lib/host-guard\|^/var/backups\|^/etc/host-guard/\|^/etc/sysctl.d/99-host-guard.conf '
snap /root/after-rollback
diff <(grep -v "$X" /root/after-030) <(grep -v "$X" /root/after-rollback) || die "rollback is not the $V system"
cp /root/sysctl-030 /etc/sysctl.d/99-host-guard.conf      # the admin takes the edit back
ok "rolled back to exactly the $V files"

echo "--- engine commands through the manager"
HG_NOTIFY_CMD=true host-guard backup > /root/log6 2>&1 || { cat /root/log6; die backup; }
HG_NOTIFY_CMD=true host-guard restore-test >> /root/log6 2>&1 || { cat /root/log6; die restore-test; }
grep -q 'restore-test: ok' /root/log6 || die "restore test"
ok "backup and restore test"

echo "--- uninstall --purge leaves the server as it was"
if host-guard uninstall --purge --yes > /root/log7 2>&1; then die "purge with backups went through"; fi
grep -q 'delete-backups' /root/log7 || die "backup warning"
host-guard uninstall --purge --delete-backups --yes > /root/log8 2>&1 || { cat /root/log8; die uninstall; }
grep -q 'kept (changed' /root/log8 && { cat /root/log8; die "uninstall kept files"; }
snap /root/final
diff /root/pristine /root/final || { cat /root/log8; die "the server is not as it was"; }
dpkg-query -W -f='${Package}\n' | sort > /root/pkgs-final
diff /root/pkgs-pristine /root/pkgs-final || die "packages differ"
id hgpanel >/dev/null 2>&1 && die "hgpanel user left"
ok "pristine again: files and packages"
echo "lifecycle ok"
