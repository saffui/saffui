#!/bin/sh
# Runs the runner of the suite in its container (compose.yaml, service
# runner): its dependencies from the wheels run.sh fetched, each checked
# against its digest, in an environment of /tmp the container throws away,
# then the runner, with the options and the plans run.sh gives it.
set -eu
# The exports hold the configuration, secrets included.
umask 077
python -m venv --without-pip /tmp/venv
python -m pip --python /tmp/venv/bin/python install --no-index --find-links /wheels \
  --require-hashes --no-deps --only-binary :all: --no-cache-dir --disable-pip-version-check \
  --quiet -r /conformance/requirements.txt
if ! checked="$(python -m pip --python /tmp/venv/bin/python check --disable-pip-version-check 2>&1)"; then
  printf '%s\n' "${checked}" >&2
  exit 1
fi
# The scripts of the runner import each other from their own directory.
site="$(/tmp/venv/bin/python -I -c 'import sysconfig; print(sysconfig.get_path("purelib"))')"
printf '%s\n' /runner >"${site}/saffui-runner.pth"
exec /tmp/venv/bin/python -I /runner/run-test-plan.py --no-parallel "$@"
