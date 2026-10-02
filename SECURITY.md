# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's
security advisories ("Report a vulnerability" on the repository's Security
tab). Do not open a public issue for anything you believe is exploitable.

You can expect an acknowledgement within 7 days. Please allow up to 90
days of coordinated disclosure before publishing details; we will credit
you in the advisory unless you prefer otherwise.

## Scope

In scope: the OpenID Connect provider and the SAML arm, the credentials a
realm issues and the ones it verifies, the admin plane, the hosted pages,
the account and admin consoles, the LDAP front door, the gRPC authorization
door, and the Kerberos path. The cryptography is in scope whether a key is
held in the process or in an HSM through PKCS#11, and whether a build links
the FIPS-validated algorithms alone or ML-DSA and ML-KEM beside them.

Findings that only reproduce with `SAFFUI_PROXY_*` misconfiguration are
still welcome: deployment-shape traps deserve fixing or documenting.

Out of scope: the rigs under `deploy/`. Every value in them is a development
value and each file says so.

## Supported versions

Until a first release is tagged, only the tip of `develop` is supported.
