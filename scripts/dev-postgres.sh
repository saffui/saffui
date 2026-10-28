#!/bin/sh
# A throwaway PostgreSQL cluster for the tests, kept under .pg/ and reachable
# on the loopback interface only. Usage: scripts/dev-postgres.sh start|stop|reset|env
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
data="${root}/.pg/data"
port="${SAFFUI_DEV_PG_PORT:-55460}"
bin="${SAFFUI_DEV_PG_BIN:-/opt/homebrew/opt/postgresql@15/bin}"

# On macOS the server refuses to start under a locale it cannot load.
LC_ALL=C
export LC_ALL

run_sql() {
  "${bin}/psql" --no-psqlrc --quiet --set ON_ERROR_STOP=1 \
    --host 127.0.0.1 --port "${port}" --username postgres --dbname postgres "$@"
}

start() {
  if [ ! -d "${data}" ]; then
    mkdir -p "${root}/.pg"
    # Trust on loopback: the cluster holds nothing and listens nowhere else.
    "${bin}/initdb" --pgdata "${data}" --username postgres --auth trust \
      --encoding UTF8 --no-locale >/dev/null
  fi
  if ! "${bin}/pg_ctl" --pgdata "${data}" status >/dev/null 2>&1; then
    "${bin}/pg_ctl" --pgdata "${data}" --log "${root}/.pg/server.log" --wait \
      --options "-p ${port} -c listen_addresses=127.0.0.1 -c unix_socket_directories= -c max_connections=200 -c fsync=off" \
      start >/dev/null
  fi
  # Roles are global to a cluster, so no migration creates them: whoever
  # provisions the cluster does, once.
  run_sql <<'SQL'
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'saffui_owner') THEN
    CREATE ROLE saffui_owner LOGIN CREATEDB;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'saffui_app') THEN
    CREATE ROLE saffui_app LOGIN;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'saffui_maintenance') THEN
    CREATE ROLE saffui_maintenance LOGIN BYPASSRLS;
  END IF;
END
$$;
-- Dropping a test database ends the sessions other roles still hold on it.
GRANT pg_signal_backend TO saffui_owner;
SQL
  print_env
}

stop() {
  if [ -d "${data}" ]; then
    "${bin}/pg_ctl" --pgdata "${data}" --mode fast stop >/dev/null 2>&1 || true
  fi
}

print_env() {
  echo "export SAFFUI_TEST_PG='host=127.0.0.1 port=${port} user=saffui_owner dbname=postgres'"
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  reset) stop; rm -rf "${root}/.pg"; start ;;
  env) print_env ;;
  *) echo "usage: $0 start|stop|reset|env" >&2; exit 2 ;;
esac