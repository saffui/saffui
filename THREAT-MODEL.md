# Threat model

Who would attack a saffui deployment, what they would be after, where they would
cross from one level of trust to another, and what stands in the way at each
crossing.

Every countermeasure below is cited by file and line. Nothing is claimed that
was not read out of the tree first, and where nothing stands in the way the
document says so in those words. Verified against `develop` at `bf9b1d91` on
2026-09-16.

## What this is, and what it is not

It is the adversary's view of the product. It names the agents, the assets, the
boundaries between them, and the threat each boundary has to answer.

It is not a bug list, not a record of past advisories, and not a roadmap. A
vulnerability report says a specific thing is broken today; this says what the
design has to keep true whether or not anything is broken. It is also not a
promise of certification: no claim here is a lab's finding.

Report a suspected vulnerability the way `SECURITY.md` asks, not as an issue
against a row of this document.

## Scope

Inside:

- the binary and every crate it is built from: `auth`, `authz`, `commons`,
  `config`, `crypto`, `ldapfront`, `models`, `pgcore`, `saffui`, `saml`,
  `server`, `services`, `store`;
- the two consoles as the binary serves them, and the hosted pages;
- the migrations, because the isolation rules are written there rather than in
  the code that queries;
- the ports the binary opens: the data plane, the operations port, and the mesh
  door when the build carries it.

Outside, each becoming an assumption in the next section rather than an
oversight:

- Postgres itself, its own authentication, and its backups;
- any proxy, load balancer or service mesh in front;
- the host, its operating system, its container runtime and its orchestrator;
- a PKCS#11 token when one is configured, and whatever holds its PIN;
- the mail, SMS and USSD providers a realm sends through, and every upstream
  identity provider a realm federates with;
- the browser, and the applications that integrate with a realm.

## Environment assumptions

These are the things the product cannot enforce and does not pretend to. Each
one that fails takes some part of the model with it, and the last column says
which part.

| Id | Assumption | What fails without it |
|---|---|---|
| A.DATABASE | The deployment connects as `saffui_app` or another role with neither superuser nor `BYPASSRLS`, and no untrusted party holds a database session | CJ-2 entirely: a role that bypasses row level security reads every realm while every policy still reads as if it applied |
| A.PROXY | Anything terminating TLS in front is named in `SAFFUI_PROXY_PEERS`, and the deployment sets the hop count to match its own chain | The caller's address and the request's scheme become whatever the caller wrote |
| A.EDGE | The deployment bounds request rates in front of the data plane | T-EDGE-1: nothing inside this product limits how fast anything may be asked of it, but for passwords failed from one address |
| A.HOST | The host and the container are not shared with an untrusted tenant, and process memory is not readable by one | TB-3: opened keys live in process memory while a realm is serving |
| A.KEY-STORE | `SAFFUI_CRYPTO_KEK` resolves to a value held where the deployment keeps its secrets, not in the image or in a repository | CJ-5: the sealed keys open with it, and T-LOG-6: the digests of typed names can be tested against guesses with it |
| A.CLOCK | Nodes agree on the time to within the shortest lifetime a realm issues | Expiry, `not_before` cuts and step-up freshness all read differently on different nodes |
| A.BUILD | The artifact an operator runs is the one this repository built | Everything: the model describes this code |

## Adversaries

Capabilities are cumulative where the position implies it. Each agent is taken
as rational and resourced to the level stated, and no further: an agent nobody
bounded is an agent no design can answer.

| Id | Agent | Position | Assumed capability | Not assumed |
|---|---|---|---|---|
| TA-1 | Unauthenticated caller | In front of the data plane | Any request to the login, token, discovery, SAML and registration doors; timing observation; replay of anything it has seen | Valid credentials, or a position on the wire inside the deployment |
| TA-2 | Signed in person | One ordinary account in one realm | A live session, the account plane, the self service flows, whatever roles the realm gave them | Any administrative action, or reach into another realm |
| TA-3 | Administrator of one realm | Realm A, with delegated administration | The whole admin plane for A: clients, mappers, identity providers, flows, roles, organizations | Realm B, the database, the host |
| TA-4 | Hostile client or upstream provider | Registered in a realm, or trusted for federation | Crafted assertions, tokens, redirect URIs, proofs, mapper inputs, metadata it serves | A realm's signing keys, or a database session |
| TA-5 | Hostile workload in a mesh | Behind the external authorization door | Calls to that door with forged headers and borrowed tokens, aiming at the confused deputy | The deployment's own trust root |
| TA-6 | Network adversary | On a link between components | Observation and modification of anything not authenticated end to end | Breaking TLS 1.3 |
| TA-7 | Operator of one node | A machine running the binary | The configuration and the process memory of that node, and writes to the database as the application role | Superuser on the database, or extraction from a PKCS#11 token |
| TA-8 | Supply chain adversary | A dependency, the build, or the distribution channel | Code in a crate, a tampered artifact, a forged release | Defeating signature verification where the deployment checks it |

TA-3 and TA-7 are the two that shape most of the design. Containing TA-3 is what
tenancy means, since that agent is legitimate everywhere inside its own realm.
Surviving TA-7 is what the audit chain is for, since a node is exactly what an
attacker gets first.

## Assets

Ranked by what their loss costs. The five marked as crown jewels get an attack
tree of their own further down.

| Asset | Why it matters | Crown jewel |
|---|---|---|
| A realm's signing keys | They forge any token or assertion that realm issues, and a forgery cannot be called back | CJ-5 |
| The token issuance path | A logic error there mints authority without any credential being presented | CJ-1 |
| The boundary between tenants and realms | One crossing read or write ends the isolation the product exists to provide | CJ-2 |
| The audit chain | It is the evidence. A silent rewrite makes every other record arguable | CJ-3 |
| The admin plane | Taking it is the pivot to all four above | CJ-4 |
| Credentials at rest | Offline attack on password hashes, second factor seeds and recovery codes | High |
| Sessions and refresh tokens | Fixation, theft and replay | High |
| Provider secrets sealed per realm | Mail, SMS, USSD and federation credentials, each usable elsewhere | High |
| Decision integrity in the authorization engine | A wrong permit is an escalation nobody sees | High |
| Federation configuration | The entry point TA-4 works through | Medium |

## Trust boundaries

Five, each with what actually enforces it. A boundary with no anchor in the tree
is a drawing, so each row carries one.

### TB-1, the network edge

The data plane on `127.0.0.1:8080` by default and the operations port on
`127.0.0.1:8081` by default, bound separately so a probe is never reachable from
wherever the data plane is published
(`crates/saffui/src/main.rs:39`, `crates/saffui/src/main.rs:43`,
`crates/server/src/api/config.rs:564`).

Request bodies are bounded explicitly rather than by whatever a dependency
defaults to: 8 KiB on the protocol doors, 8 KiB on the account plane, 512 KiB
for a posted SAML message, and 8 MiB on the authenticated admin plane
(`crates/server/src/api/config.rs:47`, `:51`, `:55`, `:34`).

This boundary is crossed outbound as well as inbound, since the server fetches
URLs that an administrator or a federation partner supplies. Every such fetch is
dialled through one builder, which reads the scheme against the deployment's
egress policy and resolves the address through a resolver that refuses every
address inside the deployment, checking each address a name answers with rather
than the first (`crates/server/src/api/rest/endpoints/protocol/hosted.rs:84`,
`:101`, `:45`, `:21`).

### TB-2, the decision core

Nothing the caller writes is authority. The clearest statement of it is the
account plane, which admits a token only if the account console itself obtained
it, for a login that is still open, carrying the account scope, and then reads
the person off that login rather than off the subject the token names
(`crates/services/src/account/api.rs:83`, `:108`, `:127`, `:146`).

The sign in door keeps the same rule about what the caller writes. It takes two
shapes of body: the script sends JSON, which a browser will not post to another
origin without asking this server first, and a form, which is the one shape any
other site can post without asking anybody. So the page mints a value into its
form, sealed under the login the browser holds, and the door asks for it on the
form path and on nothing else. Sealed rather than signed: the scope is
authenticated, so a value minted for another login opens as nothing here, and
nothing is stored and nothing expires on its own, because it names the login it
outlives or does not (`crates/server/src/api/rest/endpoints/protocol/forgery.rs:19`,
`:24`, `crates/server/src/api/rest/endpoints/protocol/page.rs:434`,
`crates/server/src/api/rest/endpoints/protocol/ui/login.html:17`).

A realm's word on plain connections is kept here too, and in the order that
matters: the transport is judged before the token. A request the proxy vouches
for as https passes without a read, and anything else pays one realm read. Where
a realm asks for https from outside only, the address judged is the one the
deployment believes, and the private ranges are spelled out rather than inferred
(`crates/server/src/middleware/transport.rs:36`, `:93`). A rule the database
fails to hand over, for want of a connection or on the way to the row, is
answered 503 rather than taken as leave to serve in the clear (`:58`, `:64`).

### TB-3, keys and secrets

The key that wraps a realm's data keys is read through a reference, so the value
itself need not sit in the process environment where a crash dump picks it up. A
reference is a file, a named variable, or the literal value, and a file is
measured before it is read (`crates/config/src/crypto.rs:23`,
`crates/commons/src/secret.rs:43`).

Sealed values are bound to where they live. The scope is authenticated rather
than merely used, so a blob lifted from one column into another opens as nothing
rather than as a working secret in the wrong place, and the generation that
sealed a value is read from the blob's own header, which is what lets a retired
generation keep opening what it sealed (`crates/store/src/keyring.rs:30`).

### TB-4, persistence

The database is a separate trust domain, and the isolation is written in the
schema rather than in the queries. Policies compare two keys, the tenant and the
realm, against settings placed for the life of one transaction, and 99 tables
carry row level security forced, which is what makes it apply to the table's
owner as well. Ninety five of those policies name both keys in their read rule;
the rest name the tenant alone, as the table of realms does, because a realm is
not divided by itself (`crates/store/src/tenancy.rs:14`,
`crates/store/migrations/V002__users_and_clients.sql:147`,
`crates/store/migrations/V001__tenancy.sql:114`).

The role the application connects as is the whole point, and the migration says
so: a superuser or a role holding `BYPASSRLS` reads every realm while every
policy still reads as if it were being applied, which is the failure that looks
most like success (`crates/store/migrations/V001__tenancy.sql:141`).

The link to it carries every query and every answer, sessions and personal
data alike. Every connection the process opens is built from one policy, the
served pool, the migrations and the notification listener alike
(`crates/pgcore/src/database.rs:87`): `verify-full` checks the server's
certificate against a named bundle and the host it was dialled by
(`crates/pgcore/src/tls.rs:101`), and a database that is not on this machine is
refused at startup until a mode is stated, because the driver's own default
falls back to the clear without a word (`crates/pgcore/src/database.rs:113`).
A full pool refuses after a bounded wait instead of holding requests for ever
(`:144`), and a pooled transaction nobody talks to is ended by the server with
its locks (`:158`). The refusal is a 503 in each surface's own words, and the
guards give it as such rather than as a missing token, which would sign a
console out (`crates/server/src/error.rs:30`, `:40`). A store that fails once
the realm is found is a 500 there, and only the token's own refusals answer as
a missing token (`:49`, `:55`, `:63`).

A realm pinned to a region is refused on a node that does not serve it, before
the transaction opens, so nothing is read on the way to finding out
(`crates/store/src/tenancy.rs:229`).

### TB-5, nodes and scheduled work

The seam no single feature owns, since every node runs the same code against one
database.

The audit chain is serialised by the database itself. An append takes the
realm's head row for update, so a second append waits, reads the row the first
wrote, and chains onto it instead of forking
(`crates/store/migrations/V011__audit_chain.sql:130`). The migration states why
an advisory lock would not do: it is not replicated, so a promoted replica can
hand the same lock to a second writer.

Scheduled work is claimed per realm with a transaction scoped advisory lock, and
a node that does not get it moves on rather than doing the work twice: sweeping
(`crates/server/src/jobs.rs:86`), outbox delivery (`:167`), and federation
refresh (`:265`). Outbox rows are taken with skip locked, so two deliverers take
different rows rather than the same ones
(`crates/store/src/providers/events/outbox.rs:122`).

## Threats, by component

One pass per component. Each row is a threat an agent can reach, and what
answers it, or the word that says nothing does.

### The edge, TB-1

| Id | Threat | Agent | What answers it |
|---|---|---|---|
| T-EDGE-1 | Anything asked as fast as the caller likes: credential stuffing, enumeration by volume, resource exhaustion | TA-1 | **No request rate is bounded inside this product.** Failed passwords are counted per address and turn that address away (T-LOG-3); the catalogue's too many requests answer is returned only to a password change turned away (`crates/commons/src/error.rs:51`, `crates/server/src/api/rest/endpoints/account.rs:196`). Volume from many addresses, and every request that is not a password, is A.EDGE's |
| T-EDGE-2 | A body large enough to cost the server more than it costs the caller | TA-1 | Ceilings stated per scope rather than inherited (`crates/server/src/api/config.rs:47`) |
| T-EDGE-3 | A plain request read as a secure one, or a caller's address believed from the caller | TA-1, TA-6 | The scheme and the certificate are read only from a named peer, and a deployment that named none gets nothing rather than everyone's (`crates/config/src/proxying.rs:201`); the address is counted from the right (`:276`) |
| T-EDGE-4 | The server made to fetch inside its own network on somebody's say so | TA-3, TA-4 | One builder for every outbound call, scheme by policy and address by resolver, no redirect followed (`crates/server/src/api/rest/endpoints/protocol/hosted.rs:101`), including the sinks a client's own registration names (`backchannel.rs:20`, `ciba.rs:593`) |

### The sign in door

| Id | Threat | Agent | What answers it |
|---|---|---|---|
| T-LOG-1 | A form posted from another site, riding the browser's cookie, answering somebody's sign in or their consent | TA-1 | The form carries a value sealed for that login, weighed before the flow runs, so a forged form spends nothing, not even one password attempt against an account (`crates/server/src/api/rest/endpoints/protocol/login.rs:226`, `crates/server/src/api/rest/endpoints/protocol/forgery.rs:35`) |
| T-LOG-2 | The same, from a browser that says where the post came from | TA-1 | Refused before anything else where the browser says another site started it; absent, the header says nothing and the sealed value is the barrier (`crates/server/src/api/rest/endpoints/protocol/login.rs:113`, `forgery.rs:58`) |
| T-LOG-3 | A password tried against one account as fast as the caller likes, or one password tried against many accounts | TA-1 | Failures counted per address, and per address with the typed name, on every door that verifies a password, on in a stock realm and weighed before the name is looked up, so an address turned away costs one read and no hash (`crates/auth/src/login/browser.rs:198`, `crates/ldapfront/src/lib.rs:285`, `crates/services/src/account/mod.rs:93`); an IPv6 network of 64 bits is one address (`crates/auth/src/login/throttle.rs:210`); at the sign-in page, a browser holding a token sealed for the typed name is counted in its address's place, under the same thresholds (`crates/auth/src/login/browser.rs:182`, `crates/auth/src/login/throttle.rs:116`); lockout per person where the realm turns it on, and spared to that browser. See R-2 |
| T-LOG-5 | Which names are held, read from when the count turns an address away | TA-1 | Every refusal counts, a name nobody holds and a person the lock refused alike, under the name as typed with case and spacing aside, never under the account it resolves to (`crates/auth/src/login/throttle.rs:11`, `crates/auth/src/login/browser.rs:318`, `crates/ldapfront/src/lib.rs:317`); a device token is read from the token alone before the name is looked up, and one that does not open under the typed name is no token, so holding one says nothing its holder had not proved (`crates/auth/src/login/device.rs:74`) |
| T-LOG-6 | A password typed into the name box, read back out of the failure counts, or out of the notes of a login in progress, in a database dump, or one name matched across realms there | TA-7 | A typed name is kept as a MAC under a key the KEK is expanded to for that use alone, which the database never holds, so the counts read without the KEK test no guess (`crates/auth/src/login/throttle.rs:86`, `crates/crypto/src/envelope.rs:244`, `:113`); the tenant and the realm are keyed with the name, so one name typed in two realms leaves two digests nobody can match without the KEK (`crates/auth/src/login/throttle.rs:242`); a login notes the name it is weighed under in that form, and a device token is sealed under it (`crates/auth/src/login/browser.rs:287`, `:511`); the key is derived once when the process starts and handed to every door, so each counts a name where the others do (`crates/server/src/api/config.rs:110`, `crates/saffui/src/main.rs:420`) |
| T-LOG-4 | A sign-out believed done while the login, and every application it reached, stays signed in for whoever sits down next | TA-1 | A sign-out that could not be written says so and keeps the cookies, so it can be tried again (`crates/server/src/api/rest/endpoints/protocol/logout.rs:197`), and a transaction a failed statement aborted is refused at commit rather than reported as written (`crates/store/src/tenancy.rs:344`) |

### The token path, CJ-1

| Id | Threat | Agent | What answers it |
|---|---|---|---|
| T-TOK-1 | A stolen code spent by another client, or against another redirect | TA-1, TA-4 | The code carries the client and the redirect it was minted for, compared at redemption (`crates/services/src/oidc/grant.rs:434`, `:439`) |
| T-TOK-2 | A code spent twice | TA-1 | One atomic spend (`crates/store/src/providers/protocol/oidc.rs:77`); a replay revokes every token that code bought and closes the client session (`crates/services/src/oidc/grant.rs:413`) |
| T-TOK-3 | A public client's code intercepted in the browser | TA-1 | A challenge is required of a public client, S256 only (`crates/services/src/oidc/authorize.rs:771`, `:774`) |
| T-TOK-4 | The proof key stripped in flight | TA-1 | A verifier presented for a code carrying no challenge is refused whoever the client is (`crates/services/src/oidc/grant.rs:670`) |
| T-TOK-5 | A refresh token stolen and renewed | TA-1, TA-4 | Rotation by default, compared and rotated in one write, and a replay closes the family while leaving the sign in alive (`crates/services/src/oidc/grant.rs:1466`, `crates/store/src/providers/protocol/sessions.rs:510`, `crates/services/src/oidc/grant.rs:1520`) |
| T-TOK-6 | A bearer token replayed by whoever holds it | TA-1 | Binding compared at presentation and at renewal, and a token naming two bindings satisfies both (`crates/services/src/token/mod.rs:201`) |
| T-TOK-7 | Algorithm confusion, or an unsecured token | TA-4 | No unsecured variant exists to select, and the verifying algorithm comes from the stored key rather than the token's header (`crates/services/src/token/mod.rs:101`) |
| T-TOK-8 | A public client acting as a machine | TA-4 | Refused, with the same face as a client that never opted in (`crates/services/src/oidc/grant.rs:193`) |
| T-TOK-9 | Delegation grown wider or deeper than it was given | TA-4 | Scope intersected and never widened, a ceiling of five links, and a bound token cannot be exchanged (`crates/services/src/oidc/grant.rs:1904`, `:1783`, `:1705`) |
| T-TOK-10 | A revoked authority still spending | TA-2, TA-4 | Realm wide and per client cuts are read at every door that takes a token (`crates/services/src/token/mod.rs:253`, `:266`) |

### The admin plane, CJ-4

| Id | Threat | Agent | What answers it |
|---|---|---|---|
| T-ADM-1 | A token from another deployment, or for another realm | TA-3 | The issuer must be one this deployment mints, and the realm in the path is compared against the token's without ever being looked up, so an existing realm and a missing one are refused alike (`crates/server/src/middleware/admin_guard.rs:184`) |
| T-ADM-2 | Probing which capabilities exist by the shape of a refusal | TA-3 | Audience, party, scope, declared, held, in that order, and every refusal renders as one answer (`crates/server/src/middleware/admin_policy.rs:93`, `crates/server/src/error.rs:12`) |
| T-ADM-3 | A toxic combination of roles assembled in one pair of hands | TA-3 | Everyone arriving is weighed against the realm's rules, under a lock (`crates/auth/src/sod.rs:81`) |
| T-ADM-4 | Asking for an entitlement and granting it to yourself | TA-3 | The one who asked cannot decide (`crates/services/src/admin/requests.rs:136`, `:183`) |
| T-ADM-5 | The record of what an administrator did, rewritten | TA-3, TA-7 | Only the database function writes entries, the chain is serialised, and the plane serves verification and anchors (`crates/store/migrations/V011__audit_chain.sql:130`) |
| T-ADM-6 | Refused attempts leaving no trace | TA-3 | **Nothing.** A knock the guard turns away is not journalled; it is a log line only (`crates/server/src/middleware/admin_audit.rs:93`) |

### Tenancy, CJ-2

| Id | Threat | Agent | What answers it |
|---|---|---|---|
| T-TEN-1 | A query that forgets its filter reading another realm | TA-3 | Policies on two keys, forced, on 99 tables (`crates/store/src/tenancy.rs:14`) |
| T-TEN-2 | Connecting as a role that bypasses the rules | TA-7 | Not defensible inside the product: A.DATABASE, with the role's attributes rewritten on every migration run (`crates/store/migrations/V001__tenancy.sql:141`) |
| T-TEN-3 | Learning which realms neighbour yours | TA-3 | The tenant level chain the application may append to and may not read (`crates/store/migrations/V094__tenant_chain.sql:13`) |

### Keys, CJ-5

| Id | Threat | Agent | What answers it |
|---|---|---|---|
| T-KEY-1 | Keys read out of a database dump | TA-7 | Sealed per purpose and per row (`crates/store/src/keyring.rs:30`) |
| T-KEY-2 | A sealed value moved into another column to be read as something else | TA-7 | The scope is authenticated, so it opens as nothing |
| T-KEY-3 | The wrapping key shipped in the image | TA-8 | A reference rather than a value (`crates/commons/src/secret.rs:43`), and A.KEY-STORE |

### The database link, TB-4

| Id | Threat | Agent | What answers it |
|---|---|---|---|
| T-DB-1 | Queries and answers read or rewritten between a node and the database | TA-6 | `verify-full` on every connection the process opens (`crates/pgcore/src/database.rs:87`); `require` encrypts without judging the certificate, and the operator's guide says so |
| T-DB-2 | A deployment running in the clear without anyone having chosen it | TA-6 | A database off this machine with no stated mode refuses to start, and an address and a setting that disagree about encrypting refuse too (`crates/pgcore/src/database.rs:113`, `:105`) |
| T-DB-3 | The application role's password read on its way to the server or out of its statement log | TA-6 | Sent as a SCRAM verifier and never as itself (`crates/pgcore/src/password.rs:5`) |

### Nodes and scheduled work, TB-5

| Id | Threat | Agent | What answers it |
|---|---|---|---|
| T-NOD-1 | Two nodes forking one realm's chain | TA-7 | The append takes the head row for update (`crates/store/migrations/V011__audit_chain.sql:130`) |
| T-NOD-2 | The same scheduled work done twice, or a message delivered twice | TA-7 | A lock per realm per job, and rows taken with skip locked (`crates/server/src/jobs.rs:86`, `crates/store/src/providers/events/outbox.rs:122`) |

### The mesh door

| Id | Threat | Agent | What answers it |
|---|---|---|---|
| T-MESH-1 | Forged headers from a workload behind the proxy | TA-5 | Nothing the proxy hands over is believed: the token is verified against the realm its issuer names, and the identity the upstream reads is overwritten here (`crates/server/src/grpc/mod.rs:153`) |
| T-MESH-2 | A door that fails open under load | TA-5 | No decision means no permission, and the deployment is told to decide that at its own filter |

### The supply chain, TA-8

| Id | Threat | What answers it |
|---|---|---|
| T-SUP-1 | A dependency with a known advisory, or an unexpected licence or source | `cargo-deny` on every push and pull request, with no suppressed advisories (`deny.toml`) |
| T-SUP-2 | Code that the dependency policy cannot see | **Nothing.** The JOSE layer is vendored, 59 files and about 22 thousand lines under `crates/crypto/src/jose/`, compiled but outside that audit (`THIRD-PARTY.md`) |
| T-SUP-3 | A tampered artifact between this repository and an operator | **Nothing yet.** No release pipeline exists: no SBOM, no signature, no provenance |

## Attack trees for the crown jewels

Three levels at most. A tree deeper than that describes an imagination rather
than a system.

**CJ-1, mint a token nobody granted.** Forge a signature, which needs CJ-5.
Steal an authorization code, which needs the browser or the redirect, and then
survives only if the code's client, redirect and proof key all match. Steal a
refresh token, which rotation and replay detection turn into one use and a
closed family. Exchange one authority for a wider one, which the intersection
and the depth ceiling refuse.

**CJ-2, read another realm.** Reach the admin plane of another realm, which the
cross realm comparison refuses without ever looking the realm up. Make a query
forget its filter, which the forced policies answer under the application role.
Connect as a role that bypasses those policies, which is A.DATABASE and outside
the product. Read the tenant chain to learn the neighbours, which the
application role may not do.

**CJ-3, rewrite the record.** Change one entry, which breaks every hash after
it. Rewrite the chain from a point onwards, which needs write access and is
bounded only by an anchor published where the writer does not decide. Fork the
chain from a second node, which the head row taken for update prevents. Prevent
the record being written at all, which the journal's best effort behaviour
turns into a log line rather than a refusal of the work.

**CJ-4, take the admin plane.** Present a token from elsewhere, refused at the
issuer. Hold a capability you were not given, refused at the held check.
Assemble a toxic pair of roles, refused by the weighing. Approve your own
request, refused by identity. Take a session that is already administrative,
which is TA-2 to TA-3 and rests on the token binding and the cuts.

**CJ-5, obtain a signing key.** Read it from the database, which needs the
wrapping key as well. Read it from a node's memory, which is TA-7 and A.HOST.
Extract it from a token, which is outside what TA-7 is assumed to do. Persuade
the deployment to sign with a key of your choosing, which the algorithm coming
from the stored key refuses.

## Residual risks

What is open, stated plainly. Each of these is visible to anyone reading the
tree; none of them is written here as a recipe.

| Id | Open | Consequence |
|---|---|---|
| R-1 | No rate limiting anywhere on the public port | Every volume attack is the deployment's to bound at its edge. A.EDGE |
| R-2 | The lockout per person is off in a stock realm, and the count per address sees one address at a time, as the deployment believes it | A password tried once against many accounts from many addresses trips nothing; a deployment that believes a forwarded address from any peer lets a caller name a new one per attempt (T-EDGE-3) (`crates/models/src/entities/realm.rs:43`, `:102`). People who share one address share its count on the directory front and at a password change, and at the sign-in page from a browser that has not signed in there under the name it types. Once it has, a token sealed under that name has the browser counted in its address's place, turned away past the threshold for one name, and spared the lock per person (`crates/auth/src/login/browser.rs:182`, `:507`, `crates/auth/src/login/device.rs:74`, `crates/auth/src/login/mod.rs:121`, `crates/server/src/api/rest/endpoints/protocol/binding.rs:38`). Whoever lifts that token out of the browser gets the same, for that one name and from any address, until it lapses 90 days after the sign-in that minted it (`crates/auth/src/login/device.rs:24`) |
| R-3 | The session identifier minted before authentication becomes the one used after it | Fixation needs a cookie writing position, which the flags and the path narrow, but no rotation stands behind them |
| R-5 | The stated 8 KiB ceiling on the protocol scope is hung on forms only | A JSON body on that scope falls back to the framework's own default |
| R-6 | Three endpoints are registered outside every scope | They take neither a scope ceiling nor the transport guard |
| R-7 | A knock the admin guard refuses is not journalled | Repeated refusals are a log line and nothing an auditor reads |
| R-8 | The admin scope does not wrap the transport guard, while the provisioning and account scopes do | A realm's insistence on https is not read for that scope |
| R-9 | One capability authorizes both sides of the four eyes rule | Two holders satisfy it; one holder cannot self approve |
| R-10 | Anchoring is an assertion the operator makes | The server publishes nothing itself, so the bound on a rewrite is only as good as where the operator published |
| R-11 | No release pipeline: no SBOM, no signature, no provenance, no fuzzing, and no lint confining unsafe code | T-SUP-3, and unsafe is confined by convention rather than mechanically |
| R-12 | No caching tier of any kind | Every decision reaches the database, which is an availability property rather than a secrecy one |

R-4 is closed and its number is left where it was rather than reused: a form
posted to the sign in door now carries what the page it came from was served
with, and what used to be that row is T-LOG-1 and T-LOG-2 above.

R-13 is closed the same way, by the slice that keyed the name digest: a typed
name is kept as a MAC under a key derived from the KEK, where it was a SHA-256
anybody could recompute from a guess, and what used to be that row is T-LOG-6
above.

## Keeping this true

This document is worth what its citations are worth. A change that moves one of
them should move the line here in the same slice, the way the code and its tests
move together. Three habits keep it honest:

- read the code before writing the claim, never the other way round;
- when a countermeasure is absent, write that it is absent, with the name of
  what was searched for;
- when a residual risk closes, move it out of the table and into the body, and
  say which slice closed it.
