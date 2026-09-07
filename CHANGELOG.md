# Changelog

All notable changes to saffui are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
No version has been tagged yet; entries accumulate under Unreleased until the
first release is cut.

## [Unreleased]

### Added
- An agent's token exchange can mint a capability token: the tools asked
  for land in `cap`, narrowed against the narrowest root in the room (the
  subject token's own `cap` when it carries one, the agent client's
  registered root otherwise), short-lived by the agent's own span under the
  realm's ceiling. Asking past the root refuses the exchange whole;
  re-exchanging is attenuation, never escape.
- A client may register its subject DN as the one name its certificate
  authenticates by, RFC 8705's third form, compared exactly in the one
  canonical rendering the server states.
- One id joins the three records: the request's trace lands on its log
  line, every admin write journals it inside the hashed envelope (projected
  into a queryable, indexed `trace_id` column), and the telemetry rig
  (`deploy/observability/`) proves the loop against Jaeger and Prometheus,
  correlation queries included.
- Distributed tracing over OTLP, switchable on the same two layers as the
  metrics: the `otel` cargo feature decides whether the export stack is
  linked at all, `SAFFUI_FEATURES=-otel` turns a carrying build off, and
  nothing dials until `SAFFUI_OTEL_ENDPOINT` names a collector. Sampling is
  parent-based (`SAFFUI_OTEL_SAMPLE`, one in ten unless said), a caller's
  W3C `traceparent` ties the request into their trace, and the exporter is
  flushed before the process exits.
- Request metrics in the Prometheus text form, scraped at `/metrics` on the
  operations port: requests, duration and in-progress by method and route
  template (never the raw path, never a realm), plus concluded logins by
  outcome. Switchable on two layers: the `metrics` cargo feature decides
  whether the machinery is linked at all, and `SAFFUI_FEATURES=-metrics`
  turns a carrying build off at runtime. The features endpoint now answers
  the set the process was actually started under.
- A two-instance rig (`deploy/ha/`): compose file, a SCIM-shaped counting
  far side, and a harness that logs in through both instances and across
  them, mutates people through both at once, kills one mid-delivery, and
  asserts the journal verifies whole and no outbox event is lost or lands
  twice. Runbook stubs for rolling restarts and instance loss ride along.
- Registered client defaults (`default_max_age`, `default_acr_values`) now
  instruct the authorization endpoint when the request is silent.
- The consent screen offers the client's registered privacy policy and terms
  pages as links, https only.
- The signup page shows the realm's password rules as a living checklist,
  ticked while the person types; the server keeps sole judgement.
- The verification mail leaves at registration, so the page's promise that
  one is on its way is kept.

### Changed
- The server test harness clones a per-binary template database instead of
  re-migrating and re-provisioning for every test.

### Fixed
- The last test rig that stopped its server gracefully now stops it
  abruptly like the others, and the settings page sheds a "not enforced
  yet" badge that no setting has been able to earn for a while.
- A client grant that ran out under a login still standing is swept away
  instead of sitting unreadable until the login goes; an offline grant
  still running keeps holding its login exactly as before.
- The server drains on SIGTERM as it always did on SIGINT: readiness fails
  first, in-flight requests finish, and only then does it stop. A `docker
  stop` or a pod eviction used to kill it outright.
- A one-time token bound to no login is spendable from whichever login of
  that person follows it.
- Test rigs stop their local servers abruptly on cleanup, so a keep-alive
  connection can no longer hang a run.
