#!/bin/sh
# Provision the bench realm and serve it. The keytab lands in /keytabs so a
# bind mount hands it to the server under test.
set -e
kdb5_util create -s -r SAFFUI.TEST -P master-key
kadmin.local -q "addprinc -pw wilderness ada@SAFFUI.TEST"
kadmin.local -q "addprinc -randkey HTTP/localhost@SAFFUI.TEST"
mkdir -p /keytabs
kadmin.local -q "ktadd -k /keytabs/http.keytab HTTP/localhost@SAFFUI.TEST"
chmod 644 /keytabs/http.keytab
exec krb5kdc -n
