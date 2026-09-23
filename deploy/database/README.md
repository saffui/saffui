# Reaching the database

Every connection this server opens to Postgres, the served pool, the
migrations, the owner's grant, the chain reader and the notification
listener, is built from one address and one TLS policy. Seven settings say
what they are.

| Setting | Default | What it says |
| --- | --- | --- |
| `SAFFUI_DATABASE_URL` | required | Where the database is, as a key=value string or a `postgresql://` URL. |
| `SAFFUI_DATABASE_TLS` | unset | `verify-full`, `require` or `disabled`. |
| `SAFFUI_DATABASE_TLS_CA` | unset | The CA bundle `verify-full` checks the server's certificate against. |
| `SAFFUI_DATABASE_POOL_SIZE` | `16` | How many connections the served pool holds at most. |
| `SAFFUI_DATABASE_POOL_WAIT_SECONDS` | `5` | How long a request waits for a free one before it is refused. |
| `SAFFUI_DATABASE_IDLE_IN_TRANSACTION_SECONDS` | `30` | How long a pooled connection may sit inside a transaction nobody uses. |
| `SAFFUI_DATABASE_CONNECT_SECONDS` | `10` | How long opening one connection may take. |

## The mode

- `verify-full` encrypts, and refuses a server whose certificate does not
  chain to `SAFFUI_DATABASE_TLS_CA` or does not name the host being dialled.
  It is the only mode that stops someone standing in the middle.
- `require` encrypts and asks nothing of the certificate. It stops someone
  listening, and nobody else.
- `disabled` sends everything in the clear, queries and results alike.

## Unset is decided by the host

Left unset, the mode is `disabled` when every host the address names is this
machine: a loopback address, `localhost`, or a socket. Nothing crosses a wire
there.

Anywhere else the server refuses to start and says which host it was about:

```
the database at db.internal is not on this machine and no TLS mode was
stated: set SAFFUI_DATABASE_TLS to verify-full with SAFFUI_DATABASE_TLS_CA,
to require, or to disabled to accept the clear
```

The driver's own default would try encryption and fall back to the clear
without a word, so nothing is assumed. `disabled` is accepted when it is
written, because writing it is the decision.

An `sslmode` of `require` or `disable` in the address is a written mode too,
and `prefer` states nothing, being that same silent fallback. When the
address and `SAFFUI_DATABASE_TLS` disagree about encrypting, the server
refuses to start rather than pick one: either pick would be weaker than
somebody wrote.

## The pool

A full pool refuses a request after `SAFFUI_DATABASE_POOL_WAIT_SECONDS`
rather than holding it for ever: a saturated server then fails where it can
be seen, and recovers once the pressure passes.

A pooled connection left inside a transaction is ended by the server after
`SAFFUI_DATABASE_IDLE_IN_TRANSACTION_SECONDS`, and its locks go with it. The
bound is set on the pool only. The migrations hold one transaction for as
long as they need, and ending one part way is worse than the leak the bound
closes.

Statements are prepared once per connection and kept. Behind PgBouncer in
transaction mode that needs 1.21 or later with `max_prepared_statements` set,
or session mode.

## The application role's password

`migrate` with `SAFFUI_APP_ROLE_PASSWORD` gives the application role its
login. The password is turned into a SCRAM verifier before it is sent, so
it crosses neither the wire nor the server's statement log.

## On one machine

The compose stacks in `deploy/` reach Postgres by its service name, which is
not this machine to saffui, so they run `verify-full`: the `postgres` service
draws a certificate for its own name on first start, into a volume the other
services read. Nothing secret is committed, and `docker compose down -v`
draws a new one.
