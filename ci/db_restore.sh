#!/usr/bin/env bash
# Backups and restore tests against real databases: a Docker Compose app with MariaDB,
# then one with PostgreSQL. Each gets a table with rows, `hostguard backup` dumps and
# encrypts it, `hostguard restore-test` loads it into a throwaway container and must
# find the table. Needs Docker with the compose plugin, gpg, bash and python3.
#   bash ci/db_restore.sh            (from the repository root)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'for e in mariadb postgres; do docker compose --project-directory "$WORK/$e" down -v >/dev/null 2>&1 || true; done; rm -rf "$WORK"' EXIT
export HOSTGUARD_CONF=/dev/null HG_NOTIFY_CMD=true HG_MAIL_TO=ops@example.com HG_SITE=ci
export HG_BACKUP_PASSPHRASE=ci-passphrase-not-secret GNUPGHOME="$WORK/gnupg"
mkdir -m 700 "$GNUPGHOME"

run() {   # engine, compose file text, SQL to create rows, wait command
  local e="$1" compose="$2" sql="$3" ready="$4"
  echo "=== $e"
  mkdir -p "$WORK/$e"
  printf '%s\n' "$compose" > "$WORK/$e/compose.yaml"
  docker compose --project-directory "$WORK/$e" up -d --quiet-pull
  for _ in $(seq 60); do docker compose --project-directory "$WORK/$e" exec -T db sh -c "$ready" >/dev/null 2>&1 && break; sleep 2; done
  docker compose --project-directory "$WORK/$e" exec -T db sh -c "$sql"
  export HG_STACK_DIR="$WORK/$e" HG_DB_ENGINE="$e" HG_DB_SERVICE=db HG_BACKUP_PREFIX="ci-$e"
  export HG_STATE_DIR="$WORK/state-$e" HG_BACKUP_DIR="$WORK/backups-$e"
  python3 "$ROOT/guard/hostguard.py" backup
  python3 "$ROOT/guard/hostguard.py" restore-test
  python3 - "$WORK/state-$e/state.json" <<'PY'
import json, sys
rt = json.load(open(sys.argv[1]))['restore_test']
print('restore test:', rt)
assert rt['ok'], 'restore test failed'
assert any('orders' in line or 'shop:' in line for line in rt['tables']), 'the table was not restored'
PY
}

run mariadb 'services:
  db:
    image: mariadb:11.4
    environment: {MARIADB_ROOT_PASSWORD: ci-root-not-secret}' \
  'mariadb -uroot -p"$MARIADB_ROOT_PASSWORD" -e "CREATE DATABASE shop; CREATE TABLE shop.orders (id INT PRIMARY KEY, item TEXT); INSERT INTO shop.orders VALUES (1, \"tea\"), (2, \"coffee\");"' \
  'mariadb -uroot -p"$MARIADB_ROOT_PASSWORD" -e "SELECT 1"'

run postgres 'services:
  db:
    image: postgres:17
    environment: {POSTGRES_PASSWORD: ci-root-not-secret}' \
  'psql -U postgres -c "CREATE DATABASE shop" && psql -U postgres -d shop -c "CREATE TABLE orders (id INT PRIMARY KEY, item TEXT); INSERT INTO orders VALUES (1, '"'"'tea'"'"'), (2, '"'"'coffee'"'"');"' \
  'pg_isready -U postgres'

echo "database backups and restore tests ok"
