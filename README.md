# saffui

An OpenID Connect identity provider: one binary, one Postgres, one image.
It serves the protocol, an admin plane behind it, a hosted sign-in, and an
account console people use for themselves.

## Running one locally

```
docker build -t saffui:local .
docker compose -f deploy/local/compose.yaml up
```

That brings up a realm, a client, and an administrator named ada, ready to
sign in. Every value in the file is a development value.

## The rigs

Each one is a compose file, most with a harness that drives it and a README
saying what it proves. They are driven deliberately, not by CI.

| Rig | What it drives |
| --- | --- |
| `deploy/local` | One instance to develop against. |
| `deploy/ha` | Two instances against one database: logins across both, an audit chain that never forks, no outbox event lost when an instance is killed mid delivery, a rolling restart that drains. |
| `deploy/observability` | Spans into Jaeger and metrics into Prometheus, and the one id that joins a log line, a trace and a journal row. |
| `deploy/load` | What a sign-in, a discovery and a person's claims cost on one machine. |
| `deploy/conformance` | The certification suites, behind a proxy. |
| `deploy/agents` | An agent registered, keyed, signing in as itself and minting a capability token. |
| `deploy/events` | The outbox and what listens to it. |
| `deploy/mesh` | The gRPC authorization door. |
| `deploy/krb5` | Desktop tickets. |

## Operating one

- `deploy/proxy` says what to set when anything stands in front, and why
  nothing is believed until it is set.
- `deploy/ha/RUNBOOK.md` says how several instances are operated together.
- `deploy/observability/README.md` says how to see what a request did.
- `SECURITY.md` says how to report a vulnerability.

## What is in the tree

- `crates/saffui` the binary: `serve`, `migrate`, `provision`, and the
  operator's own `admin`, `chronicle`, `ctx`, `completion` and `manpages`.
- `crates/server` the HTTP and gRPC surface: the protocol, the admin plane,
  the hosted pages.
- `crates/services` what the doors are allowed to do, `crates/store` how it is
  written, `crates/models` what it is.
- `crates/auth` the login engine, `crates/authz` the authorization engine,
  `crates/saml` the SAML arm, `crates/crypto` the keys, `crates/ldapfront`
  the LDAP front door.
- `crates/commons` the errors, features and address rules everything shares,
  `crates/config` the settings read from the environment, `crates/pgcore`
  the migrations, advisory locks and TLS to Postgres.
- `admin/` the admin console, `account/` the account console,
  `packages/saffui-js` the browser library they share.
