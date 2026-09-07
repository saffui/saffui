# Changelog

All notable changes to saffui are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
No version has been tagged yet; entries accumulate under Unreleased until the
first release is cut.

## [Unreleased]

### Added
- A trusted platform may spell which of its token's claims ride into the
  minted workload token (`carried_claims`), values as data for the
  resource server and never a reserved name, refused at the write door in
  words. And the agent lifecycle reaches the outbox: `agent.registered`,
  `agent.reshaped`, `agent.revoked`, `agent.lifted`, in the same
  transactions that did the thing, so a SIEM subscribed to `agent.*`
  hears every operator act on an agent.
- A range of retained happenings can be replayed into one named webhook,
  dry by default, bounded by the outbox's own retention, under the
  original ids and signatures so the far side's dedup makes repeating it
  harmless. From the console's plane or a terminal: `saffui admin events
  tail / dead / requeue / replay`.
- The realm's happenings, live and accounted for: an admin SSE feed spoken
  at commit through the database's own notify, the dead-letter queue on the
  console's Events page with one-click requeue, webhooks managed beside the
  receivers and connectors they ride with, and the prove door extended so a
  webhook takes a synthetic signed telling before being trusted with real
  ones. The consumer's contract lives in `deploy/events/README.md`.
- The outbox is offered to any system that speaks HTTP: a webhook is a
  connector like the SCIM ear and the CAEP receiver, one registry row with
  a sealed secret, riding the same delivery pass and the same retries.
  Every delivery signs its exact bytes (HMAC-SHA256 in
  `X-Saffui-Signature`), names its kind and its monotone event id in
  headers, and the kind filter speaks the capability grammar, `*` included
  because a spelled firehose is an honest subscription.
- A client's certificate name reaches the console: RFC 8705's one name in
  whichever of its three forms, on the client drawer, read back off the
  same bag the verifier reads. The plane holds the rule the verifier
  already enforced: at most one name ever stands, a body naming two is
  refused in words, and turning it off removes the keys rather than
  storing a lie.
- The flow editor's canvas grows up: a sub-flow is drawn as a container
  holding its own steps, each selectable in place and one click from its
  own editor; the palette can finally add a sub-flow step, which the API
  always accepted and the screen never offered; edges wear arrowheads; and
  a minimap in the corner shows the whole drawing with the window onto it,
  one click to stand elsewhere.
- The sign-in pages stand on a designed ground: two quiet washes of the
  realm's own brand and concentric hairline rings behind the card, and the
  card itself frosts over it where the browser can afford it, stepping back
  to the solid surface under reduced transparency, higher contrast, or a
  browser without the filter. Everything is mixed from the same fifteen
  theme tokens, so a branded realm tints its own ground and the contract
  does not move; a test now holds the sheet to exactly those fifteen.
- An evaluator page in the console: ask what one person would get, in the
  four ways this build answers. What a token would carry, the permission
  question a resource server actually asks, a role or group rule, an
  attribute or time rule, and a walk of the relationship graph. The verdict
  shows what was reported to the caller beside what was computed, which is
  how a permissive decision point is caught telling two stories, and the
  decision log and the disagreements behind it are on screen for the first
  time: both doors existed and nothing called them.
- The sign-in page offers the realm's brokered identity providers as doors:
  one link per browsable provider, straight to the broker, working with no
  script at all. Recognised providers wear their real mark, shipped inline
  because an authentication page dials no third-party host; unknown ones
  wear their initial.
- The sign-in card is retuned: a two-pixel brand hairline at its top edge
  (the accent now stands in exactly four places: hairline, primary action,
  focus ring, realm mark), one corner radius everywhere, a focus ring that
  replaces the field border instead of doubling it, and one wide-tracked
  code field that pastes and autocompletes instead of a row of boxes.
- A scripted demo of the capability rails, `deploy/agents/demo.mjs`: against
  the one-machine deployment it registers an agent, mints and attenuates
  over the MCP door, has a witness resource server admit exactly what
  introspection names and refuse the rest flat, cuts every token with one
  revocation, and reads the realm's switch refusing in words.
- Agents are administered whole: `saffui admin agent
  register/list/show/grant/ungrant/revoke/audit`, the same doors in the
  console's client drawer, and `GET/POST/PUT /admin/realms/{realm}/agents`.
  Keyless by default (the platform is the credential), the root refused at
  the door in words, the registration atomic with its service account, and
  one revocation that kills every minted token everywhere at once.
- The native MCP door: `POST /realms/{realm}/mcp` speaks JSON-RPC 2.0 with
  two tools, `capability.mint` and `capability.attenuate`, a facade over
  the one exchange the token endpoint performs, under the same realm
  switch and every gate the exchange already holds. A re-exchange now
  grows the `act` chain instead of losing it, and a delegation deeper
  than five links is refused whole.
- The agent surface is a switch a realm turns: off, the capability exchange
  refuses in its own words. From the console's security settings, or from a
  terminal: `saffui admin agents [on|off]`. Introspection now tells a
  resource server a token's `cap` and `act` beside the standard claims.
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
- A list in the console no longer shows what a drawer just changed or
  deleted: every write that lands is counted at the one door they all go
  through, and each screen re-reads on it. Creating already refreshed;
  editing and deleting did not, and needed a page reload to tell the
  truth. The screens that must not follow along, the forms and the
  drawers holding what somebody is typing, are named with their reason
  and held to it by a test that walks the pages.
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
