# Changelog

All notable changes to saffui are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
No version has been tagged yet; entries accumulate under Unreleased until the
first release is cut.

## [Unreleased]

### Added
- saffui can serve through a connection pooler. `SAFFUI_DATABASE_POOLER_URL`
  names it and served requests go through it, while `SAFFUI_DATABASE_URL`
  stays the direct address for the live feed's `LISTEN` and the lock
  `migrate` holds; both follow the same TLS rules. PgBouncer in transaction
  mode needs 1.21 or later with `max_prepared_statements` above zero, and a
  pooler that keeps no prepared statements is named in the log at its first
  refusal. `deploy/database/README.md` covers the setting, including the
  pooler dropping its server connections after `migrate`.
- Failed passwords are counted per address, and per address with the name
  typed, at every endpoint that checks one: the sign-in page, the LDAP front
  end and a password change share one count. It is on in a stock realm, at
  100 failures from one address or 10 from one address under one name within
  900 seconds, and the realm settings page holds the switch and the three
  values. A refused address costs one indexed read, never a directory call
  or a password hash. The sign-in page answers 429 with `Retry-After` (or
  its `#throttled` notice without script), the LDAP front end answers busy,
  and a password change answers `too_many_requests`. A browser that signed
  in before under the same name keeps a `saffui_device` cookie (http-only,
  `SameSite=Strict`, 90 days) and is counted on its own rather than with its
  address, so a guesser sharing an office or carrier address no longer shuts
  out the people there who signed in before, and the person's own lockout
  neither refuses nor counts attempts from that browser. A typed name is
  stored only as an HMAC under a key derived from the deployment's
  key-encryption key.
- The database pool is bounded: `SAFFUI_DATABASE_POOL_SIZE` (16
  connections), `SAFFUI_DATABASE_POOL_WAIT_SECONDS` (5) for a free one,
  `SAFFUI_DATABASE_CONNECT_SECONDS` (10), and
  `SAFFUI_DATABASE_IDLE_IN_TRANSACTION_SECONDS` (30), after which the server
  ends a transaction left idle, with its locks. `/readyz` says why no
  connection could be had: every connection in use, none opened in time, the
  TLS handshake, a refusal from the server, or nothing answering.
  `deploy/database/README.md` is the operator's guide to these and the TLS
  settings.
- A realm can reword the fourteen security notices, as it already could the
  four mails that carry a link. A notice owes no `{{link}}`, a placeholder
  its kind never fills reads as nothing, a kind this server never sends is
  refused, and a notice the realm left alone keeps this build's words. The
  console lists the two families apart.
- A realm can carry its own logo, uploaded from Appearance and shown in the
  sign-in page's header in place of its initials. Only raster images are
  taken, judged by their bytes rather than a declared type, up to 64 KiB;
  SVG is refused, since served from this origin it could run script.
- The hosted pages can be previewed from the console before anyone uses
  them, as the realm keeps them or with wording typed and not yet saved. A
  preview opens in its own tab, says it is a preview and carries no form; a
  draft is escaped, checked as a save would be, and expires.
- The token preview shows each token a grant would produce, header and body,
  assembled by the same code that mints them and never signed. A claim a
  registered rule wrote carries the rule's name, claims drawn at minting are
  marked, the identity token appears only when the scope asks for `openid`,
  and a pairwise client is shown the subject it would be told. It is reached
  from the client it previews.
- Protocol mappers gain a hardcoded claim (typed by `jsonType.label`), the
  groups a person stands in (by name, the groups above them included) and
  the organizations they belong to (by slug), and the property rule answers
  the phone number and whether it is verified.
  `GET /admin/realms/{realm}/mapper-kinds` says, for each rule, which keys
  it allows, requires or needs one of, and which switches it reads with
  their default; the console's mapper editor builds its fields from it, with
  the JSON one click away.
- Mails and texts are written in the language the person reads before the
  realm's. A realm's own templates are matched on the person's tag and then
  on its language, so `fr-CA` finds a template filed under `fr` while one
  filed under `fr-CA` still wins, and this build's own wording, now in
  English and French for every message, is matched on the language.
- `THREAT-MODEL.md` describes the product from the adversary's side: the
  agents it assumes, the assets, the trust boundaries, a threat pass per
  component with every countermeasure cited by file and line, and the risks
  still open; it names bounding request rates as the deployment's duty.
  `deploy/proxy/README.md` explains the five `SAFFUI_PROXY_*` settings for a
  deployment behind a proxy, and `README.md` now says what saffui is and how
  to run it.
- A load rig, `deploy/load`: `node deploy/load/harness.mjs` drives a machine
  sign-in, discovery and `userinfo` against one instance and prints
  latencies beside the server's own request count. It asserts only that
  every path answered; its numbers are for comparing a change on one
  machine, not for gating.
- The console gains the admin screens it lacked: renaming an organization, a
  person's claim sources (listed, added and removed, a fetch token never
  shown), a person's required actions asked and taken back one at a time,
  unregistering a realm's required action, the realm's event history under
  the live feed, and a protected client's settings changed in place, its
  protection stopped, and its resources shared with a person or a group's
  members.
- Each realm serves an account console at `/realms/{realm}/account/`, where
  a person reads their profile, sees where they are signed in and ends one
  sign-in or all the others, changes their password, adds and removes
  authenticator apps, passkeys and recovery codes, and sees the applications
  holding something of theirs to withdraw a consent or take back access. A
  change that needs a recent, strong enough sign-in asks for one first. It
  wears the realm's theme through the new
  `/realms/{realm}/protocol/openid-connect/theme.css`, which carries only
  what the realm overrides. It speaks English and French and ships in the
  image through the `embedded-account` build feature.
- A person manages their own account through the account API at
  `/realms/{realm}/account-api/v1`: `GET /me`, `GET /me/recent-sign-in`,
  `PUT /me/password`, their factors under `/me/credentials`, `/me/keys` and
  `/me/recovery-codes`, their sign-ins under `/me/sessions`, and the
  applications holding something of theirs under `/me/applications`. It
  takes only a token the realm's `account-console` client obtained for
  itself with the `account` scope, for a login still open. A password change
  or a factor removal needs a sign-in within five minutes at the strongest
  level the person can reach, and otherwise answers with an RFC 9470 step-up
  challenge; ending a sign-in or taking back an application's access needs
  none, and the application is told by back-channel logout. Every new realm
  gets the `account-console` client, and an existing one gets it from
  `saffui provision --realm <realm>`.
- People are mailed a security notice when their password is set or changed,
  a sign-in factor is added or removed (by them, an administrator, SCIM or
  LDAP), a recovery code is used, an external account is linked to their
  existing account, or their address changes, in which case the notice goes
  to the old address with the new one masked. A notice goes only to a
  verified address, carries no link, is written in English or French, the
  person's language first, and is sent by the outbox job with five attempts;
  a realm turns notices off with `security_notices_enabled`. The events they
  are built from gain `identity.linked`, `previous_email` on `user.updated`,
  and `spent` on a recovery code used at sign-in.
- A realm can broker sign-ins to a SAML 2.0 identity provider. The
  administrator pastes its metadata and picks the name identifier format
  (persistent by default) or the attribute that names the person; saving
  refuses plain `http` off loopback, RSA keys under 2048 bits, curves other
  than P-256, P-384 and P-521, and an email attribute as the person's name.
  Each provider is shown the realm's metadata at
  `/realms/{realm}/broker/{alias}/saml/metadata`, with certificates derived
  from the realm's RSA keys rather than stored, so the realm needs an RSA
  signing key. A login leaves on a request signed over the Redirect binding
  and comes back at `.../saml/acs`, where only a signed answer to that
  request, in the browser that left, is admitted, once. Messages are read
  strictly (no document type, SHA-2 only, a signature covering the very
  element read, unknown conditions refused), and an encrypted assertion
  (AES-GCM, or AES-CBC inside a signed response, under RSA-OAEP) opens with
  any RSA key the realm still holds.
- SAML logout runs both ways at `/realms/{realm}/broker/{alias}/saml/slo`: a
  provider's signed logout request ends the logins it names, whose
  applications are told by back-channel logout, and is answered with a
  signed success; a realm logout of a SAML login is carried to the provider,
  whose answer brings the browser back to where the logout was going. Two
  provider rules, `saml-user-attribute-idp-mapper` and
  `saml-role-idp-mapper`, write an asserted attribute onto the person and
  grant a role while the provider asserts a value, taking it back under
  `syncMode: force` once it stops; the admin API refuses a rule that does
  not fit its provider's protocol. The sign-in page shows a button for a
  SAML provider, and the console sets one up from the catalogue's SAML 2.0
  tile, with the realm's metadata address to copy.
- An identity provider can speak plain OAuth 2.0 (`protocol: oauth2`), as
  GitHub, Bitbucket and X do: the person is read from the provider's account
  API through JSON pointers, and an address counts as verified only where
  the provider says so, including from a separate list that marks it primary
  and verified. Every provider also takes `token_auth`
  (`client_secret_basic` by default, or `client_secret_post`) and `pkce` (on
  unless `false`). The console has ready presets for GitHub, Bitbucket, X
  and LinkedIn; the Instagram card is gone, its API having been retired.
- Every credential change reaches webhooks and CAEP receivers, passkeys
  included, and says what happened: `credential.changed` carries
  `change_type` (`create`, `update`, `revoke` when an administrator removes
  a factor, `delete` when its holder does), and a CAEP event carries the
  profile's `credential_type` and `change_type`. Drawing a recovery sheet or
  pushing a password over SCIM is one event now, not one per code or per
  step. A passkey keeps its authenticator attachment, AAGUID and attestation
  format from registration.
- A trace ties an authorization decision to the admin writes of the same
  request: `?trace_id=` narrows both the decision journal and the admin
  journal, and decisions made at the mesh door, in a token exchange and in
  the console's simulation now record the trace they ran in.
  `GET /admin/realms/{realm}/rebac/tuples` lists the realm's relation edges
  a page at a time, filtered by object type, relation or subject, and the
  console shows them.
- An administrator manages their own account from the console's profile
  page: `PUT /admin/realms/{realm}/account/password` changes the password on
  proof of the current one and ends every other login, and
  `/admin/realms/{realm}/account/credentials`, `/account/keys` and
  `/account/recovery-codes` list and remove their factors, under the new
  `account:read` and `account:write` capabilities. A removal needs a sign-in
  within five minutes, as strong as the flow lets that person reach, and
  never takes the last second factor or the only passkey of an account
  without a password. A factor is added through the new `enrol`
  authorization parameter (`configure-totp`, `configure-webauthn`,
  `configure-recovery-codes`), which any application may send: it forces a
  fresh sign-in, and the person may decline.
- The admin API gains partial import and export, authorization routes,
  decision replay, composite roles, organization themes, business metrics,
  directory federation and client key registration, each held to its realm.
  A client's remote key set must be https and passes the egress guard, and
  an inline one takes public asymmetric keys only.
- The console administers what it could only list or not reach at all:
  generic OpenID Connect providers with their claim and role mappers and a
  board of their own for configured brokers, LDAP directories (a bind secret
  sealed and dropped when the address changes), the SPNEGO setup, agents,
  mail and SMS settings with write-only secrets, protocol mappers and their
  attachments, role composites, organization membership, consents and
  session grants, authorization routes, time policies and the decision
  journal, a person's federated identities and message history, passive
  realm keys, complete and partial realm import and export, and webhook
  redelivery with a dry run. The flow editor gains a keyboard outline and
  checks beside its canvas, ready-made flows (two-factor, phone-first,
  passwordless, mailed link, desktop) are offered unbound, and the live feed
  reconnects by itself.
- The email settings screen asks the relay what it is: how fast it answers,
  what its greeting offers, and the TLS version, cipher and certificate it
  settles on, never falling back to the clear and never writing a credential
  into its transcript. It also lists the realm's recent delivery refusals,
  and the phone screen shows the day's texts against the realm's cap and
  which brakes tripped.
- A realm can close a capability its process carries, never open one the
  process lacks: token exchange (refused at the token endpoint and dropped
  from discovery), SCIM, authorization, the relation store, organizations,
  the USSD bridge, phone-first sign-in, WebAuthn and SMS codes, the last two
  skipped in a flow rather than failed. The console's Features screen warns,
  and asks for the slug, before closing one whose closing weakens the realm,
  and `saffui admin realm-features <slug> on|off|default` switches one from
  a terminal.
- An administrator reads an account's credentials in one listing, passkeys
  included and never a secret, and one holding `user:write` can revoke a
  person's second factor, never their password, so a lost phone no longer
  locks someone out for good.
- A person listing can be narrowed by status, by a prefix and by whether
  something is owed at next sign-in, and a person's password history is
  readable as dates and actors only.
- A realm created through the admin API is born with an administrator whose
  random password is handed back once and must be replaced at first sign-in;
  the console's creation dialog shows it once. The number of realms per
  tenant is enforced at creation and at import, both of which used to skip
  it: the tenant's own limit, else `SAFFUI_MAX_REALMS` (50 unless set, 0 for
  none). A tenant keeps its own hash chain of realm creations, imports and
  deletions, which the served role may append to but not read;
  `saffui chronicle` reads it from the host and `--verify` checks every
  link.
- A mesh door: an Envoy external-authorization service, behind the `mesh`
  build feature and closed unless a deployment names a bind address. A
  proxy calls it on every request it forwards; the bearer is verified in
  process against the realm its issuer names, the realm's route map says
  which permission the path puts at stake, the token's audience has to
  name that application, and the decision is written to the same log every
  other decision is. On a permit the answer tells the proxy to set the
  subject and decision-id headers by overwriting, so one a caller sent
  itself cannot survive beside them. An Envoy rig and its operator notes
  live in `deploy/mesh/`.
- A realm can state what a request path puts at stake: an ordered route
  map (method and path patterns, exact or a prefix ending in `*`) naming
  the protected application, resource and scope behind it. The
  enforcement door accepts a `route` question, so a proxy that knows only
  the request it is forwarding asks without inventing an answer. The
  resolution is the server's: a caller naming the permission it faces
  would name the one it can pass. A path the realm has said nothing about
  is refused, and the decision record keeps the map's words.
- Access recertification campaigns: a campaign freezes one picture of the
  access edges in its scope, a named reviewer certifies, revokes or
  abstains on each with words where words are owed, and closing pulls
  everything nobody stood behind. A certification is checked against the
  picture it was given, so an edge that widened since is reported as
  drifted rather than attested to; the reviewer's own access is left out
  of their campaign and counted. The close renders one canonical report,
  binds each reasoning by its hash rather than carrying it, and appends
  the report's digest to the realm's audit chain, so the served bytes
  hash to the digest the chain vouches for.
- Access requests with four-eyes approval: a request names who would
  hold which role, why, and until when; someone other than its author
  decides it (refused in words at the door, and held by a schema
  constraint underneath), the approval re-weighs separations inside the
  granting transaction, and the grant itself is issued by the governed
  path so the ledger tells where it came from. Denials carry their
  reason; only the asker may withdraw.
- Separation of duties: a rule names roles one pair of hands must not
  hold together and how many trip it; every granting door (direct role,
  group membership, timed grant) weighs the person's effective roles in
  the same transaction under a per-person hold and refuses in words the
  grant completing a toxic set. Dated, justified exceptions excuse one
  exact combination and lapse on their own; standing combinations are
  computed where read, never stored, and shown on the console's
  Governance page.
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
- The work that answers no request left the server for two crates:
  `outbound`, everything the deployment says to the outside (the
  egress-guarded fetch, mail and text delivery, the LDAP client, the SCIM,
  CAEP and webhook pushes), and `scheduler`, the timed passes (sweeps, the
  outbox walk, directory sync, security notices), which the binary starts.
  The server no longer links `ldap3` or `ureq`, and the layering guard
  covers both crates.
- `serve` and `provision` refuse to start when the database role they would
  serve as is a superuser or holds `BYPASSRLS`, since such a role reads
  every realm's rows whatever the row policies say; the refusal names the
  setting to change. The compose stacks already serve as `saffui_app`.
- The server reaches the database only through the services layer: the admin
  API, SCIM, the protocol endpoints, the background passes, the audit
  journal and the tenant chain moved behind it, and a test fails on any
  server source that names the store's rows, allowing only transactions,
  sealing, errors, the live feed and list queries. The services and store
  crates are grouped into modules by responsibility. Answers, refusals and
  their order are unchanged; log lines keep their words but take the module
  path of the code that now writes them as their target, which a log filter
  written against the old targets has to follow.
- A request that finds no database connection is answered 503 in its
  surface's terms: `service_unavailable` on the admin API, the decision
  endpoint, the account API and SCIM, `temporarily_unavailable` on the OAuth
  endpoints (the key set and discovery included), and a page to come back to
  on the hosted pages. The admin guard used to answer 401, signing the
  console out over a busy database, and the token endpoint
  `invalid_request`, which a client reads as its own mistake. A request
  whose realm's https rule cannot be read is refused rather than served in
  the clear, and a store failure once the realm is found is a 500 rather
  than a missing token.
- A request's database transaction owns its connection and gives it back at
  commit, so the mail or fetch that follows no longer holds one. Opening a
  transaction is a single round trip and statements are prepared once per
  connection (512 kept at most), measured two to three times faster than
  before on a local database. Behind PgBouncer in transaction mode this
  needs 1.21 or later with prepared statement tracking, or session mode.
- Mail goes out in two parts: the plain text it always sent, first, and an
  HTML letter in this build's own layout. A realm writes wording, never
  markup; every word is escaped, and a button's address must be http or
  https, or the button is left out while the text keeps the link.
- Every theme is edited in Appearance, where "Applies to" picks the realm or
  one of its organizations and shows what an organization inherits; an
  organization's drawer only says which theme it wears and links there. The
  screen says that the account console wears the realm's theme and the admin
  console does not. Appearance no longer carries the mail, phone and console
  tabs, and the token preview left the navigation rail and the search
  palette for the client it previews and the evaluator.
- A protocol mapper's configuration is checked against the keys its rule
  reads, on creation and on update, and a key nothing reads is refused by
  name instead of stored and ignored.
- Every library moved up, 71 crates in all. Password hashes keep their
  stored format and defaults, and a test now verifies one this build did not
  mint. The SAML Redirect binding's decompression is stricter and refuses
  malformed streams it used to accept.
- A realm's own mail and text wording is checked when saved: the language it
  is filed under must be shaped like a language tag, a mail subject stays on
  one line with no control character, and a body holds no control character
  but line breaks, where it used to fail with an internal error.
- Delivered outbox events are deleted 30 days after they occurred, which is
  how far back a webhook replay or a live feed catch-up reaches; the
  compliance evidence pack states the window. Dead events stay until
  requeued, and broker login states that ran out are swept.
- An action a realm registered and turned off can no longer be required of a
  person (422); instructions the server attaches itself (an expired or
  temporary password, a reset, provisioning) still apply. Redelivering a
  range of events to one connector moved to
  `POST /admin/realms/{realm}/identity-providers/{alias}/redeliveries`;
  `POST .../events/replay` is gone, and `GET` there stays the catch-up of
  missed events.
- The decision latency percentile is read from the window's 10,000 most
  recent decisions and says how many it read; counts and the average still
  cover the whole window.
- The console follows its design: a warm palette in light and dark with
  every state in three tones, one set of buttons, badges and fields, the
  design's shell, a tab row under the directory pages, realm settings and
  authorization split into boards held in the address, and paging at the
  foot of every listing. The overview reads its counters in one request and
  shows standing logins and waiting requests. A password an administrator
  sets is marked for replacement at next sign-in unless unticked, with the
  realm's rules shown beside the field.
- A realm is deleted with a token from that realm, its name typed back to
  confirm.
- The server test harness clones a per-binary template database instead of
  re-migrating and re-provisioning for every test.

### Fixed
- The test mail, the test text and the relay probe no longer hold a database
  connection while they dial; a few probes toward a slow relay could empty
  the pool.
- A commit after a statement that failed in the same transaction is refused;
  it used to be reported as kept although Postgres had rolled it back. A
  sign-out that could not read the realm's keys or record its ending answers
  500 and keeps the cookies so it can be retried, instead of saying the
  person was signed out.
- Lockout settings the schema refuses (zero failures, zero seconds, a
  ceiling below the first lockout) are refused in words instead of an
  internal error.
- Searching people in the console by a term works; the database used to
  refuse the statement.
- The page a reset link opens answers a browser with the page itself,
  showing its refusal or dead-link line instead of a raw JSON body, and
  speaks the realm's language instead of English only; a password set there
  leads to the sign-in page, which says so.
- A realm whose templates are in several languages, none of them its own or
  English, answered in whichever came first, differently from one run to the
  next; it falls back to the first by name, and a language tag matches
  whatever its case.
- A CIBA grant's refresh token renews: its first use was taken for a replay,
  which revoked it and ended the grant, and introspection misread it too. An
  offline CIBA grant outlives its login under the realm's cap, and an online
  one renews past its first window.
- Saving a person's profile in the console no longer rewrites their required
  actions from the list read when the drawer opened, which could put back
  one finished since, such as a verified address.
- The sign-in link and address confirmation mails, registration's included,
  use the wording the realm saved; they always sent the built-in words.
- The identity provider buttons on the sign-in and reset pages open the
  broker; they pointed at an address no route answers.
- A realm export carries the realm's theme and each organization's, checked
  on import. Erasing a person also renames them to an erased subject on the
  authorization decisions about them, which are kept for audit, and deletes
  the relations naming them.
- The authenticator app enrolment shows its QR code; the sign-in page's
  content security policy blocked the image.
- The outbox decides what is due by the database's clock, so a change
  committed just before a delivery pass no longer waits for the next one
  when the database clock runs ahead of the host's.
- Deleting a client deletes its service account, which used to remain with
  its grants. A first sign-in through a provider whose account cannot be
  written answers 500 instead of `refused`, and a directory import tells a
  local failure from a directory that could not be walked.
- A name already taken answers 409 at every admin endpoint, two racing
  requests included, where the database's refusal used to surface as a 500;
  so do a SCIM group renamed onto a taken name, a step placed where another
  stands, and an agent whose service account name an account holds (refused,
  never adopted). A policy naming one member twice is refused (422), and a
  domain claim is taken in its ASCII form and refused as taken only when
  another organization holds it.
- Realm import, whole or partial, answers 422 naming what could not be
  written when the database refuses part of the document, and nothing of it
  lands; a partial document carrying required actions imports, and two steps
  at one position are refused in words.
- A configuration export (`include_users=false`) imports whole under another
  name: it kept role holders and group and organization members the new
  realm does not hold, and the import failed with an internal error. Such an
  export now leaves them out, and an import refuses, naming them, a document
  granting to people it does not carry.
- Listing a resource server's policies answers each as its creation does,
  and one whose rule this build cannot read is listed as such (it decides
  nothing) and offered for erasure in the console instead of vanishing. A
  resource needs a type, and editing one keeps its type, addresses and owner
  instead of blanking them. A blank name or type is refused in words (422)
  and a taken name answers 409, where both were internal errors.
- Decisions made at the mesh door record the trace of the request the proxy
  forwarded, from its `traceparent`, in builds with tracing; they recorded
  none.
- A login answered by two rounds at once is concluded only by the round that
  ends it; a round arriving after the login had ended could still be
  admitted with a session and a code, or sent back with an error. It now
  answers `404 no-such-login`.
- The evaluator and the token preview accept a username; they answered 404
  unless given the person's identifier.
- Authenticator apps: a mistyped code during enrolment no longer throws away
  the secret the app holds, which forced a re-enrolment; the page says why a
  code was refused; and a person holding several apps can answer with any of
  them. The passkey button opens its dialog, a passkey-only flow no longer
  shuts out everyone not yet holding a key (for realms provisioned from now
  on), and an expired login's cookie no longer makes every later attempt
  report the login expired until the window closes. The warning about apps
  that ignore the digest parameter now stands on the page.
- A client can no longer register an identity token or userinfo signing
  algorithm the realm holds no active key for, which made every sign-in of
  that client fail; the admin API and dynamic registration refuse it, and
  discovery and the console offer only what the realm can sign with. An
  event committed while the live feed caught up after a reconnect arrives
  once instead of twice.
- Console: the overview reads the realm once and no longer shows a healthy
  realm blank, and the status light claims nothing it has not observed; the
  evaluator drops an answer that arrives after a newer question; the
  username field follows the realm's rename switch; a person's consents
  render; the relation drawer's erase button says Erase; webhook connectors
  no longer appear among identity brokers; two grant switches show their
  labels; the client scopes link works; and the evaluator's "Copy as
  request" copies the address the console calls.
- The console's email settings keep the reply-to address; saving the screen
  cleared one set from the terminal or an import.
- Creating a realm is journalled in its own audit chain; the audit
  middleware found no realm in the path and wrote nothing.
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

### Security
- Mail and the relay probe are held to the deployment's egress policy: every
  address the relay's name resolves to is weighed before one is dialled, so
  a realm administrator can no longer point the server at a host inside its
  network and read what answered on the probe's screen. A conversation is
  bounded (30 seconds in all, 10 per address, lines of 1000 bytes, replies
  of 100 lines), so a relay that never ends a line can no longer grow the
  server's memory; a reply slipped in before TLS ends it, and the credential
  goes only over TLS. A deployment whose egress policy is `anywhere` still
  reaches a relay on its own network.
- Connections to Postgres are encrypted. None was: every connection fell
  back to the clear, and an address asking for `sslmode=require` could not
  connect. `SAFFUI_DATABASE_TLS` states the mode (with
  `SAFFUI_DATABASE_TLS_CA` for `verify-full`); left unset, the clear is
  accepted only when every host the address names is this machine, and
  elsewhere the process refuses to start, naming the host and the variable.
  A mode written in the address counts, and one that contradicts the setting
  is refused. `migrate` sends the application role's password as a SCRAM
  verifier, and the compose stacks run `verify-full` with a certificate
  drawn on first start.
- `cryptoki` 0.12.1 fixes RUSTSEC-2026-0286, where reading a token's allowed
  mechanisms could run past what the card returned, crashing or handing back
  adjacent memory.
- A form posted to the sign-in page must carry a value sealed for the login
  the page was served to, and a post the browser marks as started by another
  site (`Sec-Fetch-Site`) is refused first, so a forged form spends nothing,
  not even a password attempt. The scripted JSON post is unchanged; before,
  `SameSite=Lax` on the login cookie was the only barrier.
- Back-channel logout, the CIBA ping and the message webhook dial under the
  egress policy like every other outbound call; the first two dialled
  whatever address a client had registered, back-channel logout following up
  to ten redirects. A client whose back-channel logout address is plain
  `http` is no longer told, and the log says why.
- An authorization that owes consent asks for it even when the browser holds
  a login: a client requiring consent could get a code for someone who never
  agreed, a withdrawn consent was not asked again, and `prompt=consent`
  never showed the screen. With `prompt=none` it answers `consent_required`.
- An arrival from a provider trusted for addresses is linked only to an
  account that proved the address and holds it alone. Where registration is
  open, anyone could register an owner's address unverified and receive the
  owner's later sign-ins through that provider. Such an arrival now lands on
  the sign-in page with a notice, or gets an account of its own where the
  realm lets accounts share an address.
- An address changed through the admin API no longer stays verified unless
  the same update says so; applications were told `email_verified: true` for
  an address nobody had proven.
- A brokered login concludes only in the browser that left for the provider,
  checked against that browser's login cookie; a callback address leaked
  through a log or a link, or planted in someone's browser, completed the
  login there.
- The admin console is served under a content security policy, with
  `frame-ancestors 'none'` and `X-Frame-Options: DENY`; before, any page
  could frame it. Scopes and mappers of another protocol no longer shape
  OpenID Connect grants: a `docker` scope could be granted by `/authorize`,
  lend its mappers' claims, or, named like a standard scope, release a claim
  a request named.
- A `code_verifier` sent for a code minted without a `code_challenge` is
  refused with `invalid_grant`, as RFC 9700 asks against PKCE downgrade; a
  confidential client's was accepted unread. An empty `code_verifier` counts
  as none.
- Closing sharing on a protected resource or its server takes effect. The
  update endpoint ignored the flag, so sharing opened when a server was
  first protected could never be closed (a body leaving it out now closes
  it), and shares written before kept granting after a close. A closed
  resource grants nothing through its shares, which grant again if sharing
  reopens, and a share can be taken back while sharing is closed.
- A distributed claim source's fetch token is sealed at rest and read back
  as `**********`; it was stored in clear and returned to anyone allowed to
  read people. It is opened only when released to a relying party.
- Separation of duties is weighed at every endpoint that hands out a role:
  an account whose default groups would breach a rule is not created, SCIM
  membership changes and partial imports that would are refused whole, and
  identity provider role mappers and lifecycle rules withhold the role and
  log the rule.
- A directory write carrying an already sealed bind secret is refused; a
  caller holding one could move it onto another address.
- Plain `http` reaches a brokered provider only when its host is exactly
  `localhost`, `127.0.0.1` or `::1`; the check was a prefix, so
  `http://localhost.evil.example` and `http://localhost@evil.example`
  passed. A provider already stored with such an address answers unavailable
  until it is edited.
- An admin token reaches only the realm that minted it; a token from one
  realm could read, write and delete another realm of the same tenant. A
  neighbouring realm and a missing one answer alike, and `GET /admin/realms`
  answers only for the realm that asked.
