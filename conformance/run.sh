#!/bin/sh
# Runs the conformance suite of the OpenID Foundation against a node built
# from this tree: the node and the cluster of scripts/dev-postgres.sh on this
# machine, the suite and the proxy that gives the node its https origin in
# containers. What a run leaves is under target/conformance/, never tracked.
# Usage: conformance/run.sh [check-tree | -- OPTION...]
#   check-tree   refuses under conformance/ any file but its scripts, lists
#                and settings, in printable ASCII, with no key in them
#   -- OPTION... options handed to the runner before the plans (--verbose,
#                --rerun 2:6)
set -eu
umask 077

root="$(cd "$(dirname "$0")/.." && pwd)"
here="${root}/conformance"
out="${root}/target/conformance"
cd "${root}"

fail() {
  echo "run.sh: $*" >&2
  exit 1
}

# Keeps of each line what a terminal shows and reads as no command:
# printable ASCII and tabs. To a terminal, one line at a time; to a pipe,
# by blocks.
strip_controls() {
  LC_ALL=C sed -E 's/[^[:print:][:blank:]]//g'
}

# Refuses under conformance/ whatever is not one of its scripts, lists and
# settings in printable ASCII, any of them that cannot be read, and any that
# holds a key: PEM armor, a PuTTY key, or a JSON Web Key. A list git could
# not give, or one that does not name this script, is refused too. Each
# marker is written in two pieces, so that this file is not refused for
# holding it.
check_tree() (
  pem_armor="-----""BEGIN"
  private_key="PRIVATE"" KEY"
  putty_key="PuTTY-User-""Key-File"
  jwk_type="k""ty"
  listed="$(git -C "${root}" -c core.quotePath=false ls-files -- conformance)" \
    || fail "git could not list conformance/: nothing of it is checked"
  case "
${listed}
" in
    *"
conformance/run.sh
"*) ;;
    *) fail "git does not list conformance/run.sh: that list is not of this tree" ;;
  esac
  refused=""
  IFS='
'
  set -f
  for file in ${listed}; do
    # What is not a plain file here, a name git quotes included, or cannot
    # be read, is refused.
    if [ -L "${root}/${file}" ] || [ ! -f "${root}/${file}" ] || [ ! -r "${root}/${file}" ]; then
      refused="${refused} ${file}"
      continue
    fi
    case "${file}" in
      conformance/*.sh | conformance/*.py | conformance/*.json | conformance/*.yaml \
        | conformance/*.txt | conformance/*.lock | conformance/Caddyfile) ;;
      *)
        refused="${refused} ${file}"
        continue
        ;;
    esac
    # A read that fails counts as a byte that may not be there.
    others="$({ LC_ALL=C tr -d '\011\012\040-\176' <"${root}/${file}" || printf x; } | wc -c | tr -d ' ')"
    # grep says 0 for a marker found, 1 for none, 2 when it could not read.
    found=0
    grep -q -F -e "${pem_armor}" -e "${private_key}" -e "${putty_key}" -e "${jwk_type}" \
      "${root}/${file}" || found=$?
    if [ "${others}" != 0 ] || [ "${found}" != 1 ]; then
      refused="${refused} ${file}"
    fi
  done
  set +f
  if [ -n "${refused}" ]; then
    printf '%s\n' "run.sh: conformance/ tracks what it may not hold:${refused}" | strip_controls >&2
    exit 1
  fi
)

runner_options=""
case "${1:-}" in
  check-tree)
    check_tree
    echo "run.sh: conformance/ holds its scripts, lists and settings alone"
    exit 0
    ;;
  --)
    shift
    runner_options="$*"
    ;;
  "") ;;
  *) fail "usage: conformance/run.sh [check-tree | -- OPTION...]" ;;
esac

step_started="$(date +%s)"
say_step() {
  now="$(date +%s)"
  echo "run.sh: ${1} took $((now - step_started)) s" || :
  step_started="${now}"
}

check_tree

need() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 is required"
}
need git
need cargo
need curl
need docker
docker compose version >/dev/null 2>&1 || fail "docker compose, version 2 or later, is required"
# The runner runs as the user who runs this script, and writes its exports
# in a directory of that user: a daemon without root maps that user to
# another, which cannot.
case "$(docker info --format '{{json .SecurityOptions}}' 2>/dev/null)" in
  *rootless*) fail "Docker runs without root here: the runner could not write its exports" ;;
esac
need python3
python3 -I -c 'import sys; sys.exit(sys.version_info < (3, 11))' \
  || fail "python3 3.11 or later is required"
python3 -I -m pip --version >/dev/null 2>&1 || fail "pip for python3 is required"

# What the cluster script defaults to, unless the environment says otherwise.
case "$(uname -s)" in
  Darwin) default_bin=/opt/homebrew/opt/postgresql@15/bin ;;
  *) default_bin="$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -n 1)" ;;
esac
pg_port="${SAFFUI_DEV_PG_PORT:-55460}"
pg_bin="${SAFFUI_DEV_PG_BIN:-${default_bin}}"
[ -x "${pg_bin}/psql" ] || fail "no PostgreSQL in ${pg_bin}: set SAFFUI_DEV_PG_BIN"

# The node reads its settings from the environment: none of this machine reaches it.
for name in $(env | sed -n 's/^\(SAFFUI_[A-Za-z0-9_]*\)=.*/\1/p'); do
  unset "${name}"
done

mkdir -p "${out}"
chmod 700 "${out}"
# Nothing of a run before is taken for this one.
rm -rf "${out}/exports" "${out}/summary.txt"
mkdir -p "${out}/exports"

# Where the node listens, and the one peer it believes. On macOS, Docker
# Desktop reaches the loopback of the host; elsewhere a container reaches
# the host on the gateway of its network alone.
node_port=18080
case "$(uname -s)" in
  Darwin)
    listen="127.0.0.1:${node_port}"
    gateway=host-gateway
    proxies=127.0.0.1
    ;;
  *)
    listen="172.29.11.1:${node_port}"
    gateway=172.29.11.1
    proxies=172.29.11.10
    ;;
esac
node="http://${listen}"
origin=https://saffui.test
issuer="${origin}/realms/conformance"
suite=https://localhost.emobix.co.uk:8443

saffui_pid=""
compose_started=""
database_made=""

# Runs a command in a session of its own, its input from /dev/null: an
# interrupt or a quit sent to the group of this script, or typed at its
# terminal, does not reach it, and the script waits for it all the same.
run_apart() {
  python3 -I -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' "$@" </dev/null
}

# What runs psql and compose: nothing, or run_apart while the run is cleaned.
launcher=""

psql_admin() {
  ${launcher} "${pg_bin}/psql" --no-psqlrc --quiet --set ON_ERROR_STOP=1 --host 127.0.0.1 \
    --port "${pg_port}" --username postgres --dbname postgres "$@"
}

compose() {
  ${launcher} env -i PATH="${PATH}" HOME="${HOME}" \
    ${DOCKER_HOST:+"DOCKER_HOST=${DOCKER_HOST}"} \
    ${DOCKER_CONTEXT:+"DOCKER_CONTEXT=${DOCKER_CONTEXT}"} \
    SAFFUI_UPSTREAM="host.docker.internal:${node_port}" SAFFUI_HOST_GATEWAY="${gateway}" \
    SAFFUI_RUNNER_USER="$(id -u):$(id -g)" \
    docker compose --project-name saffui-conformance --file "${here}/compose.yaml" "$@"
}

# Writes what the exports hold, within a minute, once. A summary that could
# not be written is said.
summarized=""
write_summary() {
  summarized=yes
  python3 -I "${here}/summarize.py" --exports "${out}/exports" --plans "${here}/plans.txt" \
    --expected-skips "${here}/expected-skips.json" --out "${out}/summary.txt" --within 60 \
    || { echo "run.sh: the exports could not be summarized" >&2; return 1; }
}

# Shows the summary written, to an output that may be gone.
show_summary() {
  [ -f "${out}/summary.txt" ] && strip_controls <"${out}/summary.txt"
}

# The node, the containers and the database go with the run, whatever fails
# on the way; the exports and the journals stay. A hangup, an interrupt, a
# quit, a termination and the end of the script come here, with the code of
# the run: a signal that arrives before the traps are set again below comes
# here once more, and that call goes to the end, since each step can run
# twice. Neither the summary nor showing it changes the code.
clean_up() {
  status=${1:-$?}
  set +e
  trap - EXIT
  # A run cut short writes what it got, first: what follows may be cut
  # too. Another interrupt stops that summary, never what follows it.
  trap : INT TERM HUP QUIT
  if [ -z "${summarized}" ] && ls "${out}/exports/"*.zip >/dev/null 2>&1; then
    write_summary
  fi
  # This script now ignores those signals, and runs compose and psql in a
  # session of their own: an interrupt or a quit at the terminal reaches
  # neither, though each sets its own handlers.
  trap '' INT TERM HUP QUIT
  launcher=run_apart
  if [ -n "${saffui_pid}" ]; then
    kill "${saffui_pid}" 2>/dev/null || true
    wait "${saffui_pid}" 2>/dev/null || true
  fi
  if [ -n "${compose_started}" ]; then
    compose --profile runner down --volumes --remove-orphans >/dev/null 2>&1 \
      || echo "run.sh: the containers could not be removed: docker compose -p saffui-conformance down -v" >&2
  fi
  if [ -n "${database_made}" ]; then
    # Tried three times: a drop that failed once may pass the next.
    dropped=""
    for attempt in 1 2 3; do
      if psql_admin --command "DROP DATABASE IF EXISTS saffui_conformance WITH (FORCE)" >/dev/null 2>&1; then
        dropped=yes
        break
      fi
    done
    [ -n "${dropped}" ] || echo "run.sh: the database saffui_conformance could not be dropped" >&2
  fi
  # Shown once all is gone, to a terminal that may be gone too.
  [ -n "${summarized}" ] && show_summary
  exit "${status}"
}
trap clean_up EXIT
trap 'clean_up 129' HUP
trap 'clean_up 130' INT
trap 'clean_up 131' QUIT
trap 'clean_up 143' TERM
# A reader gone is an error of the write that meets it, never an end.
trap '' PIPE

say_fetch_failed() {
  fail "$1 could not be fetched: this says nothing of saffui, run again"
}

cargo build --locked -p saffui
saffui="${CARGO_TARGET_DIR:-target}/debug/saffui"
[ -x "${saffui}" ] || fail "no binary at ${saffui}"
say_step "the build"

# The cluster runs on one port: another would be another cluster to this script.
if "${pg_bin}/pg_ctl" --pgdata "${root}/.pg/data" status >/dev/null 2>&1; then
  running="$(sed -n 4p "${root}/.pg/data/postmaster.pid")"
  [ "${running}" = "${pg_port}" ] \
    || fail "the cluster of .pg/ runs on port ${running}, not ${pg_port}: set SAFFUI_DEV_PG_PORT=${running}"
fi
SAFFUI_DEV_PG_PORT="${pg_port}" SAFFUI_DEV_PG_BIN="${pg_bin}" scripts/dev-postgres.sh start >/dev/null
database_made=yes
psql_admin --command "DROP DATABASE IF EXISTS saffui_conformance WITH (FORCE)" \
  --command "CREATE DATABASE saffui_conformance OWNER saffui_owner"
owner_url="host=127.0.0.1 port=${pg_port} user=saffui_owner dbname=saffui_conformance"
app_url="host=127.0.0.1 port=${pg_port} user=saffui_app dbname=saffui_conformance"
SAFFUI_MIGRATION_DATABASE_URL="${owner_url}" "${saffui}" migrate >/dev/null

# Drawn for this run, and given to the commands of saffui alone.
root_key="$(python3 -I -c 'import base64, secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())')"
if [ "${GITHUB_ACTIONS:-}" = true ]; then
  echo "::add-mask::${root_key}"
fi
SAFFUI_CONFORMANCE_ROOT_KEY="${root_key}" SAFFUI_ROOT_KEY=env://SAFFUI_CONFORMANCE_ROOT_KEY \
  SAFFUI_DATABASE_URL="${app_url}" SAFFUI_PUBLIC_ORIGIN="${origin}" \
  "${saffui}" bootstrap --tenant Conformance --realm conformance --client operator --admin \
  >"${out}/bootstrap.txt"
sed -n 's/^client_secret //p' "${out}/bootstrap.txt" >"${out}/admin-secret"
admin_secret="$(cat "${out}/admin-secret")"
[ -n "${admin_secret}" ] || fail "bootstrap gave no secret"
if [ "${GITHUB_ACTIONS:-}" = true ]; then
  echo "::add-mask::${admin_secret}"
  echo "::add-mask::$(printf '%s' "operator:${admin_secret}" \
    | python3 -I -c 'import base64, sys; print(base64.b64encode(sys.stdin.buffer.read()).decode())')"
fi
say_step "the database"

# The scripts of the runner, at the commit of the release, each checked
# against its digest; one already checked is kept.
runner="${out}/runner"
mkdir -p "${runner}/certs-keys"
commit="$(sed -n 's/^commit=//p' "${here}/suite.lock")"
for name in run-test-plan.py conformance.py test_plan_parser.py requirements.txt; do
  digest="$(sed -n "s|^scripts/${name}=||p" "${here}/suite.lock")"
  [ -n "${digest}" ] || fail "suite.lock names no digest for scripts/${name}"
  if ! python3 -I -c 'import hashlib, sys; sys.exit(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest() != sys.argv[2])' \
    "${runner}/${name}" "${digest}" 2>/dev/null; then
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 \
      --fail --silent --show-error --location \
      --output "${runner}/${name}.part" \
      "https://gitlab.com/openid/conformance-suite/-/raw/${commit}/scripts/${name}" \
      || say_fetch_failed "scripts/${name}"
    python3 -I -c 'import hashlib, sys; sys.exit(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest() != sys.argv[2])' \
      "${runner}/${name}.part" "${digest}" \
      || fail "scripts/${name} is not the file suite.lock pins: nothing of it runs"
    mv "${runner}/${name}.part" "${runner}/${name}"
  fi
done

# Its dependencies, fetched here and run in the container of the runner
# alone, which installs them from this directory, each checked against its
# digest again.
wheels="${out}/wheels"
wanted="$(python3 -I -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' \
  "${here}/requirements.txt")"
if [ "$(cat "${wheels}/requirements.sha256" 2>/dev/null || true)" != "${wanted}" ]; then
  rm -rf "${wheels}"
  mkdir -p "${wheels}"
  # The version of Python follows the image of the runner in compose.yaml.
  python3 -I -m pip download --isolated --disable-pip-version-check --no-cache-dir --quiet \
    --require-hashes --no-deps --only-binary :all: --python-version 3.13 \
    --dest "${wheels}" -r "${here}/requirements.txt" \
    || say_fetch_failed "a dependency of the runner"
  printf '%s\n' "${wanted}" >"${wheels}/requirements.sha256"
fi
say_step "the runner and its dependencies"

compose_started=yes
compose --profile runner pull --quiet || say_fetch_failed "an image of the suite"
say_step "the images"
compose up --detach --no-build --pull never || fail "the containers did not start"
say_step "the containers"

# Bound as the node binds it: a port a node of a run before left in
# TIME_WAIT is free, one something listens on is not.
python3 -I -c '
import socket, sys
probe = socket.socket()
probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
probe.bind((sys.argv[1], int(sys.argv[2])))
' "${listen%:*}" "${node_port}" 2>/dev/null \
  || fail "${listen} is taken: the node listens there, and the proxy was told so"
SAFFUI_CONFORMANCE_ROOT_KEY="${root_key}" SAFFUI_ROOT_KEY=env://SAFFUI_CONFORMANCE_ROOT_KEY \
  SAFFUI_DATABASE_URL="${app_url}" SAFFUI_PUBLIC_ORIGIN="${origin}" \
  SAFFUI_LISTEN="${listen}" SAFFUI_OPS_LISTEN=127.0.0.1:0 SAFFUI_RETENTION=off \
  SAFFUI_TRUSTED_PROXIES="${proxies}" \
  SAFFUI_SIGN_IN_ATTEMPTS_PER_ADDRESS=1000 SAFFUI_PENDING_SIGN_INS_PER_ADDRESS=1000 \
  SAFFUI_REGISTRATIONS_PER_ADDRESS=100 \
  "${saffui}" serve >/dev/null 2>"${out}/saffui.log" &
saffui_pid=$!
waited=0
until grep -q ' listening ' "${out}/saffui.log"; do
  kill -0 "${saffui_pid}" 2>/dev/null || fail "the node stopped before it listened: see ${out}/saffui.log"
  [ "${waited}" -lt 60 ] || fail "the node did not listen within 60 s: see ${out}/saffui.log"
  sleep 1
  waited=$((waited + 1))
done

# The network of the suite has no way out, proven again on each run from
# the server of the suite, one answer allowed for each kind of target: its
# gateway is no address at all (no route to host), an address off the
# network is unreachable or silent, no name is known, and IPv6 is off on
# every interface. Anything else stops the run, named with what it gave.
# Each probe ends on a line of its own, done or stopped: without one, it
# did not run, and what compose said is the cause.
probe='
for target in "$@"; do
  kind="${target%%:*}"
  where="${target#*:}"
  case "${kind}" in
    gateway | off-network)
      said="$(timeout 5 bash -c "exec 3<>/dev/tcp/${where}" 2>&1)"
      code=$?
      [ "${code}" -eq 0 ] && said="answers"
      [ "${code}" -eq 124 ] && said="no answer within 5 s"
      said="${said##*: }"
      case "${kind}: ${said}" in
        "gateway: No route to host" | "off-network: Network is unreachable" \
          | "off-network: no answer within 5 s") allowed=yes ;;
        *) allowed="" ;;
      esac
      ;;
    name)
      said="$(getent hosts "${where}")"
      code=$?
      case "${code}" in
        2) allowed=yes said="unknown" ;;
        0) allowed="" said="resolves to ${said%% *}" ;;
        *) allowed="" said="getent ended with ${code}" ;;
      esac
      ;;
    ipv6)
      allowed=yes said="off on all and on every interface"
      for flag in /proc/sys/net/ipv6/conf/*/disable_ipv6; do
        value="$(cat "${flag}" 2>/dev/null)"
        if [ "${value}" != 1 ]; then
          allowed="" said="${flag} is ${value:-unreadable}"
          break
        fi
      done
      ;;
    *) allowed="" said="not a kind of target" ;;
  esac
  echo "probe: ${where}: ${said}"
  if [ -z "${allowed}" ]; then
    echo "probe: stopped"
    exit 1
  fi
done
echo "probe: done"
'
run_probe() {
  probed="$("$@" 2>&1)" || :
  case "${probed}" in
    *"probe: done"*) printf '%s\n' "${probed}" | strip_controls ;;
    *"probe: stopped"*)
      printf '%s\n' "${probed}" | strip_controls >&2
      fail "the network of the suite reaches out: nothing is provisioned"
      ;;
    *)
      printf '%s\n' "${probed}" | strip_controls >&2
      fail "the probe could not run, for what compose said above: nothing is provisioned"
      ;;
  esac
}
# Under Linux, were the engine to ignore that isolation, the gateway would
# be an address of this host, which a firewall that rejects could hide from
# the probe: that is checked first.
if [ "$(uname -s)" = Linux ]; then
  held="$(ip -4 -o addr show)" || fail "ip could not list the addresses of this host"
  case "${held}" in
    *" 172.29.10.1/"*) fail "this host holds 172.29.10.1, the gateway of the network of the suite" ;;
  esac
fi
# The runner is probed for IPv6 alone, in a container of its own that
# mounts what the plans will: its configurations are written later.
mkdir -p "${out}/configs"
run_probe compose exec -T server bash -c "${probe}" probe \
  "gateway:172.29.10.1/${pg_port}" "off-network:172.29.11.1/${node_port}" \
  off-network:1.1.1.1/443 name:host.docker.internal name:gitlab.com ipv6:server
run_probe compose --progress quiet run --rm --no-deps -T --entrypoint bash runner \
  -c "${probe}" probe ipv6:runner </dev/null
say_step "the probe of the network"

python3 -I "${here}/provision.py" --node "${node}" --issuer "${issuer}" --suite "${suite}" \
  --alias saffui --admin-client operator --admin-secret-file "${out}/admin-secret" --out "${out}"
say_step "the node"

set --
while read -r plan configuration; do
  case "${plan}" in
    "" | "#"*) continue ;;
  esac
  set -- "$@" "${plan}" "/configs/${configuration}"
done <"${here}/plans.txt"
# What the runner prints names modules, blocks and conditions, never a
# message, but for the whole entry it prints of a log it cannot read, after
# the time it prefixes to every line: that line stays in runner.log, and
# the others reach the terminal in printable ASCII and tabs, one line at a
# time. The runner runs in the background, so that an interrupt reaches the
# traps at once rather than once it ends: a step of CI cut short is
# interrupted, terminated, then killed within ten seconds.
show_runner() {
  LC_ALL=C sed -E -e '/^([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} )?Log entry: /d' \
    -e 's/[^[:print:][:blank:]]//g'
}
{
  status=0
  # The options of the caller are split into their words.
  compose run --rm --no-deps -T runner ${runner_options} \
    --export-dir /exports \
    --expected-failures-file /conformance/expected-failures.json \
    --expected-skips-file /conformance/expected-skips.json "$@" </dev/null || status=$?
  echo "${status}" >"${out}/runner.status"
} 2>&1 | tee "${out}/runner.log" | show_runner &
wait "$!"
status="$(cat "${out}/runner.status")"
say_step "the plans"

# The summary is written here, and shown by clean_up once the containers and
# the database are gone: an output that blocks keeps nothing alive.
write_summary || :
exit "${status}"
