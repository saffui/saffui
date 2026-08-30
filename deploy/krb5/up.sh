#!/bin/sh
# Bring the bench KDC up on localhost:55088 and leave the keytab and a client
# krb5.conf in ./state. Then, to run the bench:
#   export KRB5_CONFIG=$PWD/state/krb5.conf
#   export KRB5_KTNAME=$PWD/state/http.keytab
#   export SAFFUI_TEST_KRB5=SAFFUI.TEST
#   echo wilderness | kinit ada@SAFFUI.TEST
#   cargo test -p server --features kerberos --test spnego_login -- --include-ignored
set -e
cd "$(dirname "$0")"
mkdir -p state
# A keytab from a previous world would sit beside the new one and win: the
# database is fresh on every run, so the keytab must be too.
rm -f state/http.keytab
docker build -t saffui-test-krb5 .
docker rm -f saffui-test-krb5 2>/dev/null || true
docker run -d --name saffui-test-krb5 \
    -p 55088:8888/tcp -p 55088:8888/udp \
    -v "$PWD/state:/keytabs" \
    saffui-test-krb5
sed 's/localhost:8888/localhost:55088/' krb5.conf > state/krb5.conf
echo "waiting for the keytab..."
for _ in $(seq 1 30); do
    [ -s state/http.keytab ] && break
    sleep 1
done
ls -l state/
