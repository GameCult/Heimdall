#!/usr/bin/env bash
# Runs the whole vitest suite with the live-Postgres files enabled, against a
# throwaway local cluster that this script starts and removes. Needs the
# Postgres server binaries (initdb, pg_ctl) on PATH or in PG_BIN.
# SOUL_PG_URL's test drops and recreates schema public, so it only ever sees
# this disposable cluster.
set -euo pipefail
export PATH="${PG_BIN:-/usr/lib/postgresql/16/bin}:$PATH"
dir="$(mktemp -d)"
port="${PG_PORT:-54329}"
trap 'pg_ctl -D "$dir" -m immediate stop >/dev/null 2>&1 || true; rm -rf "$dir"' EXIT
initdb -D "$dir" -U pgadmin --auth=trust >/dev/null
pg_ctl -D "$dir" -o "-p $port -k $dir -c listen_addresses=127.0.0.1" -l "$dir/log" -w start >/dev/null
url="postgres://pgadmin@127.0.0.1:$port/postgres"
HEIMDALL_TEST_PG_ADMIN_URL="$url" SOUL_PG_URL="$url" npx vitest run --config vitest.config.ts "$@"
