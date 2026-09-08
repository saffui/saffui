# The mesh door

A proxy that asks before it forwards. Envoy calls
`envoy.service.auth.v3.Authorization/Check` on every request; saffui answers
with the realm's own verdict and, when it permits, tells the proxy which
identity headers to put on the request going upstream.

## Opening it

The door is compile-gated and closed by default:

```
cargo run -p saffui --features mesh
```

```
SAFFUI_MESH_BIND=0.0.0.0:9191
SAFFUI_MESH_DANGER_PLAINTEXT=true
```

The second one is not decoration. Every check carries the caller's bearer,
and this server does not terminate TLS itself, so the link belongs inside
whatever the mesh already seals. Saying it by name is how a deployment
confirms it meant to.

## What a check becomes

```
Envoy → Check(method, path, headers)
  the bearer is verified in process, against the keys of the realm its
    issuer names — the same resolution every other bearer gets
  the realm's route map says which permission that path puts at stake
    nothing matches → refused; an unmapped path is not an open one
  the token's audience has to name that application, or it is not this
    application's caller
  the decision engine answers, and the answer is written to the decision log
```

Nothing the proxy hands over decides anything: the headers come from the
caller, so the permission at stake is resolved here, from the map, and never
read off the request.

## What the upstream reads

On a permit, the answer tells the proxy to set:

```
x-saffui-subject       the subject the token stood for
x-saffui-decision-id   the record this decision was written under
```

Both are set with `OVERWRITE_IF_EXISTS_OR_ADD`. A caller that sends its own
`x-saffui-subject` has it replaced rather than joined, which is the whole
point: an upstream reading the first value would otherwise read the
caller's.

## The route map

```
PUT /admin/realms/{realm}/authz/routes/{route}
{
  "method": "GET",           // an exact verb, or *
  "path": "/api/orders/*",   // an exact path, or a prefix ending in *
  "server_id": "orders-api", // the protected application
  "resource": "…",           // its resource, by identifier
  "scope": "read",
  "action": "read",          // the verb the decision record keeps
  "priority": 10             // lower is asked first; the first match answers
}
```

One ordering and no second one: what an operator reads from the top is what
runs. `GET /admin/realms/{realm}/authz/routes` lists them in that order.

## Trying it

Start saffui with the door open, then:

```
docker compose -f deploy/mesh/compose.yaml up
curl -i localhost:8000/api/orders                      # refused, no bearer
curl -i localhost:8000/api/orders -H "authorization: Bearer $TOKEN"
```

Envoy's own administration sits on 9901, published to this machine's
loopback and nowhere else: `curl localhost:9901/stats | grep ext_authz`
counts what the door allowed and denied. Keep it that way. That interface
dumps the running configuration, rewrites runtime settings and stops the
process, so whatever reaches it owns the proxy.

## When the door cannot answer

A refusal and an outage are told apart: the first denies, the second answers
`503`. Which one a proxy should let through is the proxy's to decide, and
`failure_mode_allow` in `envoy.yaml` is where a deployment says so. It ships
`false`.
