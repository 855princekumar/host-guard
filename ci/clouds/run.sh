#!/usr/bin/env bash
# host-guard on AWS, Google Cloud, Azure, Oracle Cloud and a plain VPS or bare metal: for each,
# a server whose metadata service answers like that cloud's (169.254.169.254, the cloud's own
# paths and required header) and an emulated object store for the off-site copy:
#   AWS     Floci S3 (SigV4)                         BACKUP_REMOTE=s3
#   GCP     Floci GCP Cloud Storage, S3 interop      BACKUP_REMOTE=s3, S3_ENDPOINT, AWS_REGION=auto
#   Azure   Azurite (Microsoft's, checks every SAS)  BACKUP_REMOTE=azure, a container SAS URL
#           (with a random account key per run; Floci's Azure emulator checks signatures only
#           against its built-in public key, which would have to be written into the repository)
#   OCI     Floci OCI Object Storage                 BACKUP_REMOTE=oci-par, a pre-authenticated URL
#   other   no metadata service                      local backups only
# Each run: hostguard whereami must name the cloud, a real backup (BACKUP_CMD, gpg AES-256)
# goes off-site and is confirmed by checksum, the restore test downloads, decrypts and unpacks
# it, and the cost section must not guess AWS prices off AWS. A forged Azure SAS must be refused.
#
#   bash ci/clouds/run.sh        results in clouds-out/results.md
set -uo pipefail
export MSYS_NO_PATHCONV=1
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
OUT="${OUT:-$REPO/clouds-out}"
NET=hg-clouds
FLOCI=floci/floci@sha256:a0fbf944d7f338cc0856f1ef83831ea749ff2be71956eb7a7fce08fc21458e19
FLOCI_GCP=floci/floci-gcp@sha256:a59403d43d524b1a08282d67d541a6d37bf7868cbd9d1311caa0d2983adf6f46
FLOCI_OCI=floci/floci-oci@sha256:088bb759252560921adf1776c9114e62b26ce589f267d4afb13f2ebba20e4a8c
AZURITE=mcr.microsoft.com/azure-storage/azurite@sha256:647c63a91102a9d8e8000aab803436e1fc85fbb285e7ce830a82ee5d6661cf37
STORES="floci floci-gcp floci-oci azurite"
mkdir -p "$OUT"
printf '| Cloud | Detected | Off-site store | Backup confirmed | Restore test | Cost section |\n|---|---|---|---|---|---|\n' > "$OUT/results.md"
fails=0

cleanup() {
  for c in $STORES hgc-md hgc-target hgc-awsemu; do docker rm -f "$c" >/dev/null 2>&1; done
  docker network rm "$NET" >/dev/null 2>&1
}
trap cleanup EXIT
cleanup

echo "==> network (169.254.169.0/24, so a container can be the metadata service) and stores"
docker network create --subnet 169.254.169.0/24 --gateway 169.254.169.1 "$NET" >/dev/null
docker run -d --name floci --network "$NET" "$FLOCI" >/dev/null
docker run -d --name floci-gcp --network "$NET" "$FLOCI_GCP" >/dev/null
docker run -d --name floci-oci --network "$NET" "$FLOCI_OCI" >/dev/null
AZ_ACCOUNT=hgtest
AZ_KEY=$(head -c 64 /dev/urandom | base64 | tr -d '\n')      # a fresh storage account key for this run only
docker run -d --name azurite --network "$NET" -e AZURITE_ACCOUNTS="$AZ_ACCOUNT:$AZ_KEY" "$AZURITE" azurite-blob --blobHost 0.0.0.0 >/dev/null
printf 'FROM ubuntu:24.04\nRUN apt-get update -qq && apt-get install -y -qq python3 gnupg tar gzip ca-certificates >/dev/null && rm -rf /var/lib/apt/lists/*\n' \
  | docker build -q -t hg-cloud-target:local - >/dev/null
docker run -d --name hgc-target --network "$NET" -v "$REPO:/src:ro" hg-cloud-target:local sleep infinity >/dev/null
T() { docker exec -e AZ_ACCOUNT="$AZ_ACCOUNT" -e AZ_KEY="$AZ_KEY" hgc-target bash -c "$1"; }
T 'install -m 0755 /src/guard/hostguard.py /usr/local/sbin/hostguard && mkdir -p /etc/host-guard && echo "important data $(date)" > /srv-data.txt'
for _ in $(seq 30); do T 'python3 -c "import urllib.request as u; [u.urlopen(x, timeout=2) for x in (\"http://floci:4566/\",)]"' >/dev/null 2>&1 && break; sleep 1; done
sleep 5

S() { T "python3 /src/ci/clouds/probe_stores.py $1 | python3 -c 'import json,sys; print(json.load(sys.stdin).get(sys.argv[1]) or \"\")' $2"; }
T "python3 -c \"import urllib.request; urllib.request.urlopen(urllib.request.Request('http://floci:4566/hg-backups', method='PUT'))\""
S gcp store >/dev/null
OCI_PATH=$(S oci accessUri)
AZURITE_URL=$(S azurite:10000 url)

run_cloud() {   # label provider settings...
  local label="$1" provider="$2"; shift 2
  docker rm -f hgc-md >/dev/null 2>&1
  if [ "$provider" != none ]; then
    docker run -d --name hgc-md --network "$NET" --ip 169.254.169.254 -e PROVIDER="$provider" -v "$REPO:/src:ro" \
      hg-cloud-target:local python3 /src/ci/clouds/fake_metadata.py >/dev/null
    sleep 2
  fi
  {
    printf 'MAIL_TO=\nSITE=%s\nBACKUP_CMD=tar -cf - /srv-data.txt /etc/hostname\nBACKUP_PREFIX=files\nBACKUP_MIN_BYTES=10\n' "$label"
    printf 'PRICES_URL=http://127.0.0.1:9/\nNOTIFY_CMD=cat >/dev/null\n'
    for kv in "$@"; do case "$kv" in BACKUP_REMOTE_URL=*|AWS_*KEY*) ;; *) printf '%s\n' "$kv";; esac; done
  } > "$OUT/guard.conf"
  {
    printf 'BACKUP_PASSPHRASE=cloud-test-%s-passphrase\n' "$label"
    for kv in "$@"; do case "$kv" in BACKUP_REMOTE_URL=*|AWS_*KEY*) printf '%s\n' "$kv";; esac; done
  } > "$OUT/env"
  docker exec -i hgc-target sh -c 'cat > /etc/host-guard/guard.conf' < "$OUT/guard.conf"
  docker exec -i hgc-target sh -c 'umask 077; cat > /etc/host-guard/.env' < "$OUT/env"
  T 'chmod 600 /etc/host-guard/guard.conf /etc/host-guard/.env; rm -rf /var/lib/host-guard /var/backups/host-guard'
  detected=$(T 'hostguard whereami' 2>&1 | head -1 | sed 's/^Cloud: //')
  bout=$(T 'hostguard backup 2>&1' | tail -1)
  rout=$(T 'hostguard restore-test 2>&1' | tail -1)
  cost=$(T 'hostguard cost 2>&1' | head -2 | tail -1)
  remote=$(T "python3 -c \"import json;print(json.load(open('/var/lib/host-guard/state.json'))['backup'].get('remote') or 'local only')\"" 2>/dev/null)
  local want_remote="$REMOTE_WANT" ok=1
  case "$provider" in aws) want_cloud=AWS;; gcp) want_cloud='Google Cloud';; azure) want_cloud=Azure;; oci) want_cloud='Oracle Cloud';; *) want_cloud='not a known cloud';; esac
  [[ "$detected" == "$want_cloud"* ]] || ok=0
  [ "$remote" = "$want_remote" ] || ok=0
  echo "$rout" | grep -q 'restore-test: ok' || ok=0
  if [ "$provider" = aws ]; then echo "$cost" | grep -q 'Instance t3.small' || ok=0; else echo "$cost" | grep -q 'PRICE_HOUR' || ok=0; fi
  printf '| %s | %s | %s | %s | %s | %s |\n' "$label" "$detected" "$want_remote" "$(echo "$bout" | sed 's/^backup: //' | cut -c1-60)" \
    "$(echo "$rout" | cut -c1-50)" "$(echo "$cost" | cut -c1-70)" >> "$OUT/results.md"
  printf '  %-6s %-14s %s\n' "$([ $ok = 1 ] && echo PASS || echo FAIL)" "$label" "$detected; off-site: $remote; $rout"
  [ $ok = 1 ] || { fails=$((fails + 1)); T 'cat /var/lib/host-guard/*.json 2>/dev/null | head -c 600'; }
}

echo "==> clouds"
REMOTE_WANT=s3 run_cloud aws aws S3_BUCKET=hg-backups S3_ENDPOINT=http://floci:4566 AWS_REGION=ap-south-1 \
  AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test-secret
REMOTE_WANT=s3 run_cloud gcp gcp S3_BUCKET=hg-backups S3_ENDPOINT=http://floci-gcp:4588 AWS_REGION=auto \
  AWS_ACCESS_KEY_ID=GOOG1EXAMPLEHMACKEY AWS_SECRET_ACCESS_KEY=hmac-secret
REMOTE_WANT=azure run_cloud azure azure BACKUP_REMOTE=azure "BACKUP_REMOTE_URL=$AZURITE_URL"
REMOTE_WANT=oci-par run_cloud oci oci BACKUP_REMOTE=oci-par "BACKUP_REMOTE_URL=http://floci-oci:4599$OCI_PATH"
REMOTE_WANT='local only' run_cloud bare-metal none

echo "==> AWS's official emulator: real SigV4 checks, per-run keys, HTTPS with its own CA"
docker build -q -t hg-aws-emulator:ci - < "$HERE/aws-emulator.Dockerfile" >/dev/null
docker rm -f hgc-awsemu >/dev/null 2>&1
docker run -d --name hgc-awsemu --network none hg-aws-emulator:ci >/dev/null
for _ in $(seq 30); do docker exec hgc-awsemu test -s /root/.aws/emulator/9297/ca.pem && break; sleep 1; done
sleep 2
EMU_VERSION=$(docker exec hgc-awsemu sh -c 'aws-emulator -v | tr "\n" " "; cut -c1-16 /aws-emulator.rpm.sha256')
KEY=$(docker exec hgc-awsemu sh -c "sed -n 's/^aws_access_key_id *= *//p' /root/.aws/emulator/9297/emulator_credentials")
SECRET=$(docker exec hgc-awsemu sh -c "sed -n 's/^aws_secret_access_key *= *//p' /root/.aws/emulator/9297/emulator_credentials")
CA=$(docker exec hgc-awsemu cat /root/.aws/emulator/9297/ca.pem)
emu() {   # a client in the emulator's own network namespace (its certificate is for 127.0.0.1)
  docker run --rm -i --network container:hgc-awsemu -v "$REPO:/src:ro" -e CA="$CA" -e HG_S3_BUCKET=hg-backups \
    -e HG_S3_ENDPOINT=https://127.0.0.1:9297 -e HG_AWS_REGION=us-east-1 -e HG_S3_CA_BUNDLE=/ca.pem \
    -e HG_AWS_ACCESS_KEY_ID="$KEY" -e HG_AWS_SECRET_ACCESS_KEY="$1" -e HG_BACKUP_PASSPHRASE=aws-emulator-test-passphrase \
    -e HG_BACKUP_CMD='tar -cf - /etc/hostname /etc/os-release' -e HG_BACKUP_MIN_BYTES=10 -e HG_MAIL_TO= -e HG_CLOUD=aws \
    -e HG_NOTIFY_CMD='cat >/dev/null' -e HOSTGUARD_CONF=/nonexistent hg-cloud-target:local bash -c "$2"
}
out=$(emu "$SECRET" 'printf "%s\n" "$CA" > /ca.pem; install -m 0755 /src/guard/hostguard.py /usr/local/sbin/hostguard
  python3 -c "import importlib.machinery as m, importlib.util as u; l=m.SourceFileLoader(\"hg\", \"/usr/local/sbin/hostguard\"); s=u.spec_from_loader(\"hg\", l); h=u.module_from_spec(s); l.exec_module(h); print(\"bucket\", h.s3(\"PUT\", \"\")[0])"
  hostguard backup 2>&1 | tail -1; hostguard restore-test 2>&1 | tail -1')
echo "$out" | sed 's/^/  /'
ok=1; echo "$out" | grep -q 'off-site=s3' || ok=0; echo "$out" | grep -q 'restore-test: ok' || ok=0
bad=$(emu 0000000000000000000000000000000000000000 'printf "%s\n" "$CA" > /ca.pem; python3 /src/ci/clouds/store_test.py s3' 2>&1 | tail -1)
echo "$bad" | grep -q '"put": 403' || ok=0
printf '  %-6s %s\n' "$([ $ok = 1 ] && echo PASS || echo FAIL)" "AWS Emulator $EMU_VERSION: signed backup off-site, restore test, a wrong secret refused"
printf '| aws (AWS Emulator %s) | AWS | s3, SigV4 checked, HTTPS | %s | %s | wrong secret: %s |\n' "$(echo "$EMU_VERSION" | awk '{print $2}')" \
  "$(echo "$out" | grep -o 'off-site=s3' || echo FAILED)" "$(echo "$out" | grep -o 'restore-test: ok' || echo FAILED)" \
  "$(echo "$bad" | grep -q '"put": 403' && echo 'refused (403)' || echo ACCEPTED)" >> "$OUT/results.md"
printf '\nAWS Emulator used: %s\n' "$EMU_VERSION" >> "$OUT/results.md"
[ $ok = 1 ] || fails=$((fails + 1))
docker rm -f hgc-awsemu >/dev/null 2>&1

echo "==> a forged Azure SAS is refused (Azurite checks the signature)"
FORGED=$(printf '%s' "$AZURITE_URL" | sed 's/sig=[^&]*/sig=Zm9yZ2Vk/')
out=$(T "python3 /src/ci/clouds/store_test.py azure 'BACKUP_REMOTE_URL=$FORGED'")
if echo "$out" | grep -q '"put": 403'; then echo "  PASS   forged SAS refused (403)"; else echo "  FAIL   forged SAS: $out"; fails=$((fails + 1)); fi
printf '\nA forged Azure SAS signature: %s\n' "$(echo "$out" | grep -q '"put": 403' && echo 'refused (403), nothing stored' || echo ACCEPTED)" >> "$OUT/results.md"
echo "==> $fails failure(s). Table: $OUT/results.md"
[ "$fails" = 0 ]
