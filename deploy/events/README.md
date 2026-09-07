# Events, consumed

Everything the realm commits is offered outward through connectors: SCIM
ears take people, CAEP receivers take signed security events, and webhooks
take any kind as signed JSON. This page is the consumer's contract for the
webhook, and the operator's for the live feed and the dead letters.

## Subscribing

A webhook is one registry row. From the console: Events, Add a webhook.
Over the plane:

```
POST /admin/realms/{realm}/identity-providers
{
  "provider_id": "siem",
  "name": "siem",
  "display_name": "The SIEM",
  "configs": {
    "kind":   { "Str": "webhook" },
    "url":    { "Str": "https://siem.example/hooks/saffui" },
    "filter": { "Str": "session.revoked credential.* user.deleted" },
    "secret": { "Str": "a-secret-of-decent-length" }
  }
}
```

The filter is space-separated: exact kinds, prefixes ending in `*`, or `*`
alone for everything. Only what is named is delivered. The secret is
sealed under the realm's key at write, masked on every read, and never
answered again. `POST .../identity-providers/{alias}/prove` sends a
synthetic `saffui.subscription.test` telling right now, signed like any
other, and answers whether the far side took it.

## What a delivery looks like

```
POST {url}
content-type: application/json
x-saffui-signature: sha256=<hex of HMAC-SHA256(secret, exact body bytes)>
x-saffui-event: user.created
x-saffui-event-id: 4182

{"event_id":4182,"kind":"user.created","realm":"main","user_id":"...",
 "occurred_at":"2026-09-07T18:12:03.412Z","payload":{...}}
```

Verify before trusting: recompute the HMAC over the raw body bytes and
compare to the header, constant-time. `occurred_at` is when the happening
happened; under retries that is not when the delivery arrived.

## Delivery semantics

At-least-once. An event stays due while any listener of the realm fails,
under a linear backoff, and every retry carries the same `event_id`:
dedup on it. The id is a per-realm monotone integer, so "already seen"
is one comparison. After the attempts run out the event turns **dead**:
visible on the console's Events page and over
`GET /admin/realms/{realm}/events/dead`, and
`POST /admin/realms/{realm}/events/dead/{event}/requeue` puts one back in
the queue, due at once, history kept.

## The live feed

`GET /admin/realms/{realm}/events/stream` is Server-Sent Events, fed at
commit through the database's own notify: what it speaks happened. It is
best-effort by contract; a watcher that lags misses frames and the store
misses nothing, so the feed is for eyes and the deliveries above are for
systems.

## Kinds

`user.created`, `user.updated`, `user.deleted`, `session.revoked`,
`credential.changed`. The catalogue grows when a consumer needs a kind,
not before.
