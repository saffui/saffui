#!/bin/sh
# A throwaway PostgreSQL cluster for the tests, kept under .pg/ and reachable
# on the loopback interface only.
# Usage: scripts/dev-postgres.sh start|stop|reset|env|gen-schema [--check]
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
  -- Roles the check of the serving role must refuse, each for what it may
  -- reach. Only the tests connect as them.
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'saffui_test_member_of_maintenance') THEN
    CREATE ROLE saffui_test_member_of_maintenance LOGIN IN ROLE saffui_maintenance;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'saffui_test_noinherit_owner') THEN
    CREATE ROLE saffui_test_noinherit_owner LOGIN NOINHERIT IN ROLE saffui_owner;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'saffui_test_heir_of_owner') THEN
    CREATE ROLE saffui_test_heir_of_owner LOGIN INHERIT IN ROLE saffui_owner;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'saffui_test_superuser_only') THEN
    CREATE ROLE saffui_test_superuser_only LOGIN SUPERUSER NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'saffui_test_lowered_to_app') THEN
    CREATE ROLE saffui_test_lowered_to_app LOGIN IN ROLE saffui_maintenance, saffui_app;
    ALTER ROLE saffui_test_lowered_to_app SET role = 'saffui_app';
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'saffui_test_reads_all') THEN
    CREATE ROLE saffui_test_reads_all LOGIN IN ROLE pg_read_all_data;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'saffui_test_writes_all') THEN
    CREATE ROLE saffui_test_writes_all LOGIN IN ROLE pg_write_all_data;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'saffui_test_reads_server_files') THEN
    CREATE ROLE saffui_test_reads_server_files LOGIN IN ROLE pg_read_server_files;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'saffui_test_writes_server_files') THEN
    CREATE ROLE saffui_test_writes_server_files LOGIN IN ROLE pg_write_server_files;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'saffui_test_runs_server_programs') THEN
    CREATE ROLE saffui_test_runs_server_programs LOGIN IN ROLE pg_execute_server_program;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'saffui_test_creates_roles') THEN
    CREATE ROLE saffui_test_creates_roles LOGIN CREATEROLE;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'saffui_test_replicates') THEN
    CREATE ROLE saffui_test_replicates LOGIN REPLICATION;
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

# Writes the constants of the schema from a database the migrations build,
# made for it and dropped after: the tool reads an empty database only.
# Called by its package name: a tracked .cargo alias is refused by the CI.
gen_schema() {
  start >/dev/null
  run_sql --command "DROP DATABASE IF EXISTS saffui_gen_schema WITH (FORCE)" \
    --command "CREATE DATABASE saffui_gen_schema OWNER saffui_owner"
  status=0
  (cd "${root}" && GEN_SCHEMA_DATABASE_URL="host=127.0.0.1 port=${port} user=saffui_owner dbname=saffui_gen_schema" \
    cargo run --quiet --package gen-schema -- "$@") || status=$?
  run_sql --command "DROP DATABASE IF EXISTS saffui_gen_schema WITH (FORCE)"
  return "${status}"
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  reset) stop; rm -rf "${root}/.pg"; start ;;
  env) print_env ;;
  gen-schema) shift; gen_schema "$@" ;;
  *) echo "usage: $0 start|stop|reset|env|gen-schema [--check]" >&2; exit 2 ;;
esac