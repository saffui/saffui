# A real MIT Kerberos KDC for the SPNEGO bench: one realm, one person, one
# service, and the service's keytab exported for the server under test.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends krb5-kdc krb5-admin-server \
    && rm -rf /var/lib/apt/lists/*

COPY krb5.conf /etc/krb5.conf
COPY provision.sh /provision.sh

EXPOSE 8888/tcp 8888/udp

ENTRYPOINT ["/bin/sh", "/provision.sh"]
