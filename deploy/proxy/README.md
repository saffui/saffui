# Standing behind a proxy

This server never terminates TLS on its HTTP listener. Whatever a request
says about where it came from and what it spoke, only a proxy this
deployment names is believed. Five settings say who those proxies are and
what they write, and nothing is read until they are set.

| Setting | Default | What it says |
| --- | --- | --- |
| `SAFFUI_PROXY_HOPS` | `0` | How many proxies rewrite the address header. Zero reads no header at all. |
| `SAFFUI_PROXY_HEADER` | `x-forwarded-for` | Which header they write, `x-forwarded-for` or `forwarded`. One, never both. |
| `SAFFUI_PROXY_PEERS` | empty | The addresses or CIDR blocks the proxies dial from. |
| `SAFFUI_PROXY_SCHEME_HEADER` | unset | Which header the terminating proxy writes the client's scheme into. |
| `SAFFUI_PROXY_CLIENT_CERTIFICATE_HEADER` | unset | Which header it writes the client's certificate into. |

## The address

Each proxy appends the peer it saw, so a request that crossed `hops` of them
arrives with the caller `hops` places from the right. That is where the
address is read, and counting from the right is the whole point: the
left-most entry is the one the client chose, and a server that reads it
records an address anybody can name.

Two rules keep that honest:

- **The header is read only when a named proxy dialled.** Reached directly, a
  caller writes the whole header itself, and a count applied to it reads the
  client's own last entry as the proxy's work. Naming the proxies is what
  tells the two apart. An empty `SAFFUI_PROXY_PEERS` believes whoever dialled,
  which is the weaker of the two settings and is what a deployment that names
  none of them gets.
- **A header shorter than the count is not theirs.** It came through fewer
  proxies than the deployment says it has, so the peer that dialled answers
  instead: the one address nobody could have claimed.

With `SAFFUI_PROXY_HOPS` left at zero, none of this runs. The address is the
peer that dialled the socket, which is correct for a deployment reached
directly and wrong for one behind anything.

## The scheme, and insisting on https

A realm may insist that plain requests be turned away, `ssl_enforcement` set
to `always` or to `external-only`. Since this server cannot see the scheme
itself, that insistence needs a proxy it trusts to state it: a named header
and at least one named peer. Without both, the admin plane refuses the
setting rather than storing one it could never consult:

```
insisting on https needs a proxy this deployment trusts to say the scheme:
set SAFFUI_PROXY_SCHEME_HEADER and SAFFUI_PROXY_PEERS first
```

A request a named proxy vouches for as `https` passes without a single read.
Anything else costs one realm read, which on a deployment that is all https
is no request at all.

## The client's certificate

Mutual TLS terminated at the proxy reaches the token endpoint, userinfo and
the caller's own reads through `SAFFUI_PROXY_CLIENT_CERTIFICATE_HEADER`.

This one is stricter than the address: named peers are required. A forwarded
address that falls back to the peer that dialled is harmless, but a
certificate believed from anybody is a certificate anybody may claim, so a
deployment that named no peers reads no certificate rather than everyone's.
The scheme header lives under the same rule, and for the same reason:
`https` is exactly the claim an attacker on the plain port would make.

## Two worked settings

`deploy/local` runs reached directly, so it leaves the count at zero:

```yaml
SAFFUI_PROXY_HOPS: "0"
SAFFUI_PROXY_HEADER: x-forwarded-for
```

`deploy/conformance` runs behind one proxy on a container network, and names
it:

```yaml
SAFFUI_PROXY_HOPS: "1"
SAFFUI_PROXY_PEERS: "172.16.0.0/12"
```

## What to check once it is set

- A sign-in through the proxy is recorded with the caller's address, not the
  proxy's. The sign-in events carry it; the admin journal does not, since it
  records who wrote what and where in the API, and no address at all.
- A realm set to insist on https answers plain requests with a refusal, and
  answers proxied ones normally.
- A bad value in `SAFFUI_PROXY_PEERS` refuses to start rather than emptying
  the list: a typo that silently turns the check off on the day it was meant
  to start is the failure this refuses to have.
