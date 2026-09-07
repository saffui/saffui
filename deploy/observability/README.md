# The telemetry plane, and how its records join

```
docker build -t saffui:local .
node deploy/observability/harness.mjs    # add --keep to look around
```

One saffui, one Postgres, Jaeger taking OTLP on its collector port, and
Prometheus scraping the operations port. With `--keep`, the Jaeger UI is at
http://localhost:36686 and Prometheus at http://localhost:39090.

## One id joins three records

Every request runs under a trace when span export is on, and the same
32-hex id appears in all three places:

- **The log line.** The request's closing line carries `trace_id` beside
  `request_id`, `route` and `realm`.
- **The trace.** Jaeger holds it under that id; a caller that arrived with
  a W3C `traceparent` shows up inside the caller's own trace.
- **The journal.** Every admin write journals the trace id inside its
  hashed envelope, projected into the queryable `trace_id` column.

From a trace to what the plane did under it:

```sql
SELECT seq, kind, actor, occurred_at
FROM audit_events
WHERE trace_id = '<32 hex>'
ORDER BY seq;
```

From a journal row to the trace: open `http://<jaeger>/trace/<trace_id>`.
From a log line to either: the same `trace_id` field is the key.

## The switches

Span export needs all three: the `otel` cargo feature in the build, the
`otel` capability not turned off (`SAFFUI_FEATURES=-otel` turns it off),
and `SAFFUI_OTEL_ENDPOINT` naming a collector. `SAFFUI_OTEL_SAMPLE` sets
the parent-based head-sampling ratio; this rig runs at 1 so what the
harness drives is what Jaeger holds, where a deployment keeps the resting
one-in-ten. Metrics answer at `/metrics` on the operations port under the
same registry's `metrics` capability.
