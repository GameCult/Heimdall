#!/usr/bin/env bash
# Runs the whole vitest suite with the live-Postgres files enabled, against a
# throwaway local cluster that this script starts and removes. Needs the
# Postgres server binaries (initdb, pg_ctl) on PATH or in PG_BIN.
# SOUL_PG_URL's test drops and recreates schema public, so it only ever sees
# this disposable cluster.
set -euo pipefail
# Prerequisites, done here when missing (each step is skipped once it holds):
#   1. the vendor/CultLib submodule checked out,
#   2. its npm dependencies installed (the vendor packages build with its tsc),
#   3. dist/ built for cultcache-ts, cultnet-ts and cultmesh-ts (package.json
#      points main at dist/index.js),
#   4. this repo's pnpm install (npm install if pnpm fails with EACCES).
cd "$(dirname "$0")/.."
[ -f vendor/CultLib/package.json ] || git submodule update --init vendor/CultLib
[ -d vendor/CultLib/node_modules/typescript ] || (cd vendor/CultLib && npm ci)
for pkg in cultcache-ts cultnet-ts cultmesh-ts; do
  [ -f "vendor/CultLib/packages/$pkg/dist/index.js" ] || (cd "vendor/CultLib/packages/$pkg" && npm run build)
done
[ -d node_modules/vitest ] || pnpm install --frozen-lockfile || npm install  # pnpm can fail with EACCES on its store; npm does not need it
export PATH="${PG_BIN:-/usr/lib/postgresql/16/bin}:$PATH"
dir="$(mktemp -d)"
port="${PG_PORT:-54329}"
trap 'pg_ctl -D "$dir" -m immediate stop >/dev/null 2>&1 || true; rm -rf "$dir"' EXIT
initdb -D "$dir" -U pgadmin --auth=trust >/dev/null
pg_ctl -D "$dir" -o "-p $port -k $dir -c listen_addresses=127.0.0.1" -l "$dir/log" -w start >/dev/null
url="postgres://pgadmin@127.0.0.1:$port/postgres"
HEIMDALL_TEST_PG_ADMIN_URL="$url" SOUL_PG_URL="$url" npx vitest run --config vitest.config.ts "$@"
