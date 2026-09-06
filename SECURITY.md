# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's
security advisories ("Report a vulnerability" on the repository's Security
tab). Do not open a public issue for anything you believe is exploitable.

You can expect an acknowledgement within 7 days. Please allow up to 90
days of coordinated disclosure before publishing details; we will credit
you in the advisory unless you prefer otherwise.

## Scope

The OpenID Connect provider, its admin plane, the hosted pages, the LDAP
front, and the console are all in scope. Findings that only reproduce
with `SAFFUI_PROXY_*` misconfiguration are still welcome: deployment-shape
traps deserve fixing or documenting.

## Supported versions

Until a first release is tagged, only the tip of `develop` is supported.
