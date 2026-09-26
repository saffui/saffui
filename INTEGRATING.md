# Integrating a client

How an application, a device, a service or an agent gets tokens from a saffui
realm, grant by grant: what has to be set up first, what to send, what comes
back, what is refused and why.

Every value below is the one a new realm starts with, and every rule was read
out of the code of `develop` at `2d0fc7c5` on 2026-09-26. Where the server does
less than a specification allows, or departs from it, this says so in those
words rather than leaving it to be found in production.

Three names are used throughout:

- `{origin}` is the deployment's `SAFFUI_PUBLIC_ORIGIN`;
- `{issuer}` is `{origin}/realms/{realm}`, the `iss` of every token the realm
  mints;
- `{protocol}` is `{issuer}/protocol/openid-connect`, where every protocol
  endpoint lives.

## Before any grant

### What discovery says

The same document is served at `{issuer}/.well-known/openid-configuration` and
at `{origin}/.well-known/oauth-authorization-server/realms/{realm}`, the place
RFC 8414 gives it. It is built from the realm on every request and may be
cached for 300 seconds.

| Member | Value |
| --- | --- |
| `authorization_endpoint` | `{protocol}/auth` |
| `token_endpoint` | `{protocol}/token` |
| `pushed_authorization_request_endpoint` | `{protocol}/par` |
| `device_authorization_endpoint` | `{protocol}/device-authorization` |
| `backchannel_authentication_endpoint` | `{protocol}/bc-authorize` |
| `userinfo_endpoint` | `{protocol}/userinfo` |
| `introspection_endpoint` | `{protocol}/introspect` |
| `revocation_endpoint` | `{protocol}/revoke` |
| `end_session_endpoint` | `{protocol}/logout` |
| `check_session_iframe` | `{protocol}/check-session` |
| `jwks_uri` | `{protocol}/certs` |
| `registration_endpoint` | `{protocol}/register`, only while the realm registers clients |

Read the document rather than building these by hand. Three addresses are not
in it:

- the page where a person types a device code, `{protocol}/device`, which the
  device grant hands out itself;
- the page where a person answers a decoupled request, `{protocol}/requests`;
- the door agents mint capability tokens at, `{origin}/realms/{realm}/mcp`.

Nor is what a single client is held to: `require_pushed_authorization_requests`
is the realm's setting, and a client required to push on its own account is not
shown as one.

`grant_types_supported` names every grant the server speaks, not what a given
client may use: each grant beyond the code flow is switched on per client,
below. The token exchange is the one grant that leaves the list when the realm
turns it off.

`token_endpoint_auth_signing_alg_values_supported` includes `HS256`, `HS384`
and `HS512` because a `client_secret_jwt` assertion is an HMAC; registration
still refuses them as a pinned `token_endpoint_auth_signing_alg`. Nothing
about mutual TLS is published: no endpoint aliases (the same URLs serve both)
and no `tls_client_certificate_bound_access_tokens`.

### Keys and token formats

`{protocol}/certs` publishes every signing key that is not disabled, active and
passive alike, then every encryption key, each with `kid`, `use` and `alg`. A
`kid` is the key's RFC 7638 thumbprint. The set may be cached for 300 seconds.
A new realm holds an RS256 and an ES256 signing key and one RSA-OAEP-256
encryption key.

Select the verification key by `kid`, never by algorithm: access and refresh
tokens are signed with the realm's ES256 key while it has an active one, and
identity tokens with the algorithm the client registered as
`id_token_signed_response_alg`, RS256 when it registered none. On a new realm
the two come from different keys.

No token is opaque. Each is a signed JWT carrying `iss`, `sub`, `aud`, `jti`,
`iat`, `nbf`, `exp`, `azp` (the client it was minted for) and `sid` (the login
it came from).

- An **access token** has the header `typ: at+jwt` and adds a `typ` claim of
  `Bearer`, even when it is bound to a key, and `scope`. `aud` is the client
  itself plus whatever audience mappers add: a string when there is one, an
  array otherwise. `cnf` carries the binding, when there is one.
- A **refresh token** carries `typ: Refresh`. Keep it, send it back, and read
  nothing into it.
- An **identity token** carries `auth_time`, `nonce` when one was sent, `acr`
  when the realm maps levels, and neither `typ` nor `scope`.

A resource server can validate an access token alone, by signature, issuer,
audience and expiry. What it cannot see that way is everything decided after
the token was minted: a revocation, a logout, a person switched off, an
operator's cut. Introspection sees all of them.

### Choosing a grant

| What is signing in | Grant | Switched on by |
| --- | --- | --- |
| A person, in a web, mobile or desktop application | Authorization code, with PKCE | Nothing: every client but an agent has it |
| A person, with an identity token in the front channel | Hybrid (`code id_token` and the like) | Dynamic registration naming such a response type, `saffui provision --implicit`, or a realm import |
| A person, on a device with no browser or keyboard | Device authorization | `device_grant: true` on the client |
| A person reached elsewhere, approving on their own phone | CIBA (decoupled) | `ciba_delivery: poll` or `ping` on a confidential client |
| A service, for itself | Client credentials | A service account: the agents door or a realm import |
| A service, for the person it is serving | Token exchange | `token_exchange: true` on a confidential client, while the realm runs the exchange |
| A workload holding its platform's identity | JWT bearer, or a mesh certificate | A trusted platform, set up as an identity provider |
| An AI agent needing narrow, short tokens | Capability tokens, at the token endpoint or the MCP door | The agents door, and the realm's agent switch |

Refresh tokens come with the code, device and decoupled grants, and with no
other.

### Getting a client

#### From the admin API

`POST /admin/realms/{realm}/clients` with an administrator's token and a JSON
body:

| Field | Meaning |
| --- | --- |
| `client_id` | Required. |
| `confidential` | `true` by default. `false` makes a public client, which holds no secret and must use PKCE. Fixed at creation. |
| `redirect_uris` | Absolute `http` or `https` addresses without a fragment. |
| `root_url` | The application's home address. |
| `web_origins` | Browser origins allowed to call the protocol endpoints from script. `"*"` admits any. |
| `post_logout_redirect_uris`, `backchannel_logout_uri`, `frontchannel_logout_uri` | See logout. |
| `device_grant`, `token_exchange` | Booleans switching those grants on. |
| `ciba_delivery`, `ciba_notification_endpoint` | `off`, `poll` or `ping`; `ping` needs an `https` endpoint. |
| `tls_san_dns`, `tls_san_uri`, `tls_subject_dn` | The one name a client certificate must carry. At most one. |

A confidential client is answered with its `client_secret`, once. `POST
/admin/realms/{realm}/clients/{client}/secret` draws a new one, also shown
once.

Keys and algorithms are set afterwards, with `PUT
/admin/realms/{realm}/clients/{client}` and a `key_configuration` object:
`authentication_method` (which has to restate the client's current method,
since this door does not change it), `jwks` or `jwks_uri`,
`id_token_signed_response_alg`, `userinfo_signed_response_alg`,
`request_object_signing_alg`, `token_endpoint_auth_signing_alg`, and
`id_token_encryption`, `userinfo_encryption` and `request_object_encryption`,
each as `{"alg": "RSA-OAEP-256", "enc": "A256GCM"}`. The block replaces the
one before it whole: a member left out is cleared.

A client made here gets every standard scope and every realm default scope
attached as optional, so it is granted any of them it asks for. `PUT
/admin/realms/{realm}/clients/{client}/scopes/{scope}` with `{"optional":
false}` makes one ride unasked.

What this door cannot set, and where it comes from instead:

| Setting | Where |
| --- | --- |
| Authenticating with `private_key_jwt` or `client_secret_jwt` | Dynamic registration |
| Authenticating with `tls_client_auth` | A realm import |
| Response types, and with them hybrid and implicit | Dynamic registration, `saffui provision --implicit`, an import |
| Pairwise subjects, `default_max_age`, `default_acr_values`, `request_uris`, a per-client PAR requirement | Dynamic registration |
| A consent screen for the client | Dynamic registration, while the realm's `requires_consent` bound holds, as it does by default |
| A service account | The agents door, an import |
| The FAPI 2.0 profile | `saffui provision --fapi-client`, an import |

#### From dynamic registration

A realm registers nothing until its operator says so: `client_registration` is
`disabled` by default, and is set with `PUT /admin/realms/{realm}` to `open` or
to `protected`. A protected realm takes an initial access token, `Authorization:
Bearer <token>`, which is the one realm secret `POST
/admin/realms/{realm}/registration-secret` draws: shown once, reusable, with no
expiry, until `DELETE` on the same path drops it. `registration_bounds` narrows
further: `trusted_hosts` (addresses or blocks registrations may come from),
`max_clients` (how many registration itself may create) and `requires_consent`
(on by default: registered clients show the consent screen).

`POST {protocol}/register` takes the metadata as JSON of at most 8 KiB and
answers `201` with `client_id`, `client_secret` when one was drawn,
`registration_access_token` and `registration_client_uri`.

| Metadata | What is honoured |
| --- | --- |
| `token_endpoint_auth_method` | `client_secret_basic` (the default), `client_secret_post`, `client_secret_jwt`, `private_key_jwt`, `none`. Basic and post are one stored method: either works, and the answer always says `client_secret_basic`. |
| `jwks`, `jwks_uri` | One or the other, never both; `private_key_jwt` needs one. An inline set holds 1 to 64 public keys and no symmetric one. |
| `id_token_signed_response_alg`, `userinfo_signed_response_alg`, `request_object_signing_alg`, `token_endpoint_auth_signing_alg` | RS, PS and ES at 256, 384 and 512, and EdDSA. Never `none` or an HMAC. The first two must be an algorithm the realm holds an active key for. |
| `id_token_encrypted_response_alg` and `_enc`, the same for userinfo and request objects | The eight key-management algorithms and six encodings discovery lists; `enc` defaults to `A128CBC-HS256`; an encrypted request object must also be signed. |
| `subject_type`, `sector_identifier_uri` | `public` (the default) or `pairwise`. The sector document is fetched over `https` and must list every redirect. |
| `redirect_uris` | Absolute, no fragment, `http` or `https`. A `web` client whose response types mint at the authorization endpoint must use `https` and no loopback host. |
| `response_types`, `grant_types` | `response_types` defaults to `["code"]`. `grant_types` may hold only `authorization_code`, `implicit` and `refresh_token`, consistent with the response types. |
| `default_max_age`, `default_acr_values`, `request_uris`, `require_pushed_authorization_requests`, the logout addresses, `client_name` and the other descriptive members | Stored as sent. |

Ignored, without an error: `scope`, `require_auth_time`, `software_statement`,
`dpop_bound_access_tokens`, `tls_client_certificate_bound_access_tokens`, the
`tls_client_auth_*` names, the CIBA members, the two
`*_logout_session_required` flags, and any member this list does not name.

A registered client can run the code flow with refresh, and hybrid or implicit
when one of its response types mints at the authorization endpoint. Nothing
else: the machine and decoupled grants are switched on by an operator.

RFC 7592 manages the registration at `registration_client_uri` with
`Authorization: Bearer <registration_access_token>`:

- `GET` reads it back;
- `PUT` replaces it whole, so resend the method, the keys and every address:
  leaving `token_endpoint_auth_method` out resets it to `client_secret_basic`
  and locks out a client that holds no secret;
- `DELETE` removes the client.

Once the server has fetched a client's `jwks_uri`, `GET` shows the fetched
`jwks` beside it, and a `PUT` carrying both is refused: do not echo a read
back unedited. The registration access token never rotates, and these doors
keep answering after the operator stops registration.

`client_secret_jwt` works only for a client registered this way, because only
registration keeps its secret in a form an HMAC can be checked against.
Rotating that secret through the admin API stores it hashed, and the client can
no longer authenticate.

### Authenticating the client

The token, push, introspection, revocation, device authorization and
decoupled authentication endpoints all authenticate the client the same way.
Bodies are `application/x-www-form-urlencoded`, at most 8 KiB.

| Method | Presented as |
| --- | --- |
| `client_secret_basic` | `Authorization: Basic base64(id ":" secret)`, each half form-urlencoded first |
| `client_secret_post` | `client_id` and `client_secret` in the body |
| `client_secret_jwt` | `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and `client_assertion`, signed with an HMAC keyed by the secret |
| `private_key_jwt` | The same two fields, signed with a key the client publishes |
| `tls_client_auth` | `client_id` alone, and a certificate the proxy in front forwarded |
| `none` (public clients) | `client_id` alone |

- **The registration chooses, never the request.** A client registered for
  assertions is not let in by its secret, nor the reverse. A public client
  sends `client_id` and nothing else: a `client_secret` field, even empty, or a
  Basic header, even `id:` with nothing after the colon, is refused.
- **One method per request.** A Basic header beside a body secret, or a Basic
  header and a body `client_id` naming two clients, is `400 invalid_request`
  "more than one client authentication method was used".
- **Basic is read strictly.** The scheme is matched as `Basic ` exactly, and
  each half is form-decoded, RFC 6749 §2.3.1: a `+` in a secret reads as a
  space unless sent as `%2B`, and a `:` in a client id must be sent as `%3A`.
  Secrets and ids this server draws are base64url and never need escaping.
- **An assertion** has `iss` and `sub` equal to the client id, and an `aud`
  (a string, or an array holding one) naming `{protocol}/token`,
  `{protocol}/par` or `{issuer}`, at every one of the six endpoints: the
  introspection, revocation, device and decoupled URLs are not accepted
  audiences. `exp` is required and at most an hour ahead, `nbf` is honoured,
  and each allows 60 seconds of skew. `jti` is required and spent the moment
  the assertion checks out, before the grant runs, so a request refused for
  any other reason has still used it: draw a fresh assertion for every
  request, retries included. `client_secret_jwt` signs with HS256, HS384 or
  HS512; `private_key_jwt` with RS, PS or ES at 256, 384 or 512, or EdDSA; a
  registered `token_endpoint_auth_signing_alg` admits that one alone.
- **Name the key.** With several keys of one algorithm, set `kid`: without it
  only the first usable key is tried.

#### Keys published at an address

A client that publishes a `jwks_uri` has it read before each use that needs
it: before an assertion is checked, before a request object is read at the
authorization or push endpoint, before a signed decoupled request or its hint
token, and before an identity token or a userinfo answer is encrypted to it. A
set is read again only once the one kept is 30 seconds old, and once for all
the requests arriving together. So publish a new signing key at least 30
seconds before signing with it, and keep decrypting with a withdrawn encryption
key for 30 seconds after withdrawing it.

The address must be `https` (unless the deployment runs with
`SAFFUI_EGRESS=anywhere`) and resolve to a public address, and must answer
`200` within 5 seconds, without a redirect, in at most 64 KiB. Registration does
not try it, so a `jwks_uri` that breaks one of those rules registers fine and
then never verifies. A set that cannot be read leaves the last readable one in
place.

#### Client certificates

This server never terminates TLS itself. The proxy in front does, and writes
the client's certificate into the header named by
`SAFFUI_PROXY_CLIENT_CERTIFICATE_HEADER`: PEM, PEM with its newlines written
`%0A`, or the base64 body of the DER. The header is believed only from the
peers named in `SAFFUI_PROXY_PEERS`; with none named, no certificate is read at
all. The server reads the certificate's names and thumbprint and nothing else:
the chain, the dates and revocation are the proxy's to check.

A `tls_client_auth` client holds exactly one expected name: `tls_san_dns`
(any DNS name of the certificate, case aside, no wildcard logic),
`tls_san_uri` (any URI name, exactly), or `tls_subject_dn` (the subject in RFC
4514 order, short names, joined by `,` with no spaces). No name, or two, refuses
every attempt. IP and email names are not supported, nor is
`self_signed_tls_client_auth`.

A `client_credentials` request that carries a certificate and no client
credential at all is taken as a workload's, and answered as the workload door
answers it: send `client_id` to be taken as a `tls_client_auth` client.

#### Refusals

Every failure to authenticate is `401 invalid_client` "the client could not be
authenticated" with `WWW-Authenticate: Basic realm="saffui"`, whatever the
method: an unknown or switched-off client, a wrong or expired secret, the wrong
method, a failed assertion or certificate. An unknown realm is answered
`invalid_client` too, so a caller cannot map which realms exist. A store fault
while reading the client is `400 invalid_request`.

### Binding tokens to a key or a certificate

#### DPoP, RFC 9449

A proof is a JWT with the header `typ: dpop+jwt`, an asymmetric `alg` (RS, PS
or ES at 256, 384 or 512, or EdDSA) and the public `jwk` it is signed with; a
key with private members is refused. Its claims:

- `htm`, the request's method;
- `htu`, the endpoint's URL as discovery publishes it, built from the public
  origin and not from whatever address the client dialled; the query and
  fragment are dropped before comparing;
- `iat`, within 60 seconds of the server's clock either way;
- `jti`, never seen before in the realm;
- `ath`, the base64url SHA-256 of the access token, where an access token
  rides along (userinfo).

Proofs are read at the token, push and userinfo endpoints only, one `DPoP`
header exactly. A proof is spent as soon as it checks out, whatever the
request then decides, so every request needs a fresh one, a device's every
poll included. There is no server nonce: nothing ever sends `DPoP-Nonce`, and a
client waiting for one waits forever.

A proof at the token endpoint makes `token_type` `DPoP` and binds what is
minted with `cnf.jkt`:

| Grant | Access token | Refresh token |
| --- | --- | --- |
| Authorization code, device | Bound | Bound for a public client only |
| Refresh | Bound to what this renewal proves, and plain when it proves nothing | The successor, for a public client only |
| CIBA | Bound | Never: CIBA refuses public clients |
| Client credentials, token exchange | Bound | None issued |
| JWT bearer, mesh certificate | Never; the proof is not read | None issued |
| Hybrid tokens from the authorization endpoint | Never | Not issued there |

A public client's bound refresh token renews only with a proof by the same key,
and without one the answer is `invalid_grant`, not `invalid_dpop_proof`. A
confidential client's refresh token is never bound: it may prove another key at
each renewal, or none and get a plain bearer token back.

A code can be bound too: `dpop_jkt` on the authorization request, or a proof
sent with a push, names the key, and the code is redeemed only with a proof by
that key. A redemption with another key, or none, is `invalid_grant` and burns
the code.

#### Certificates, RFC 8705

Whenever the proxy forwards a client certificate to the token endpoint, its
thumbprint is bound into what is minted as `cnf["x5t#S256"]`, whatever method
the client authenticated with. There is no per-client choice, and `token_type`
stays `Bearer`. The same certificate must be forwarded again at userinfo and at
the renewal of a bound refresh token.

#### Where bound tokens go

Userinfo takes a key-bound token only under the `DPoP` scheme, with a proof.
Introspection reports `cnf`, and `token_type` `DPoP` for a key-bound token, so a
resource server that introspects can hold the caller to its proof. The
server's own account API, admin API and authorization decision endpoint refuse
every bound token: they prove nothing.

#### FAPI 2.0

A client provisioned with the FAPI 2.0 profile must be confidential,
authenticate by `private_key_jwt` or `tls_client_auth`, sign identity tokens
with PS256, ES256 or EdDSA, push every request, ask for `code` alone with PKCE,
prove a DPoP key or a certificate at the token endpoint, and address its
assertions to the issuer as a plain string. A client provisioned against the
profile is refused whole: `unauthorized_client` at the authorization endpoint,
`401 invalid_client` "the client is provisioned against its profile" at the
token endpoint.

### What every protocol answer looks like

- At the endpoints a client calls itself, a refusal is JSON, `{"error": ...,
  "error_description": ...}`, sent with `Cache-Control: no-store` like every
  token answer. `invalid_client` is `401`, `temporarily_unavailable` is `503`
  (no database connection; retry), and everything else is `400`, a fault inside
  a grant included: "the grant could not be performed" is the server's failure,
  not the request's. Userinfo answers `401`, below.
- A realm may insist on `https`. Its protocol endpoints then answer a plain
  request with `403 invalid_request` "this realm is served over https", unless
  the proxy the deployment names vouches for `https`. Discovery is exempt, as
  the way a client learns the `https` addresses. The admin API and the
  authorization decision endpoint hold their caller to the rule of the realm
  that minted its token, once the token has verified, and answer a plain
  request `403` with `error_code` `transport.https_required`.
- Cross-origin calls from a browser are admitted for an origin some client of
  the realm lists in `web_origins`. A preflight allows `GET`, `POST` and
  `OPTIONS` with the headers `authorization`, `content-type` and `dpop`;
  answers expose `www-authenticate`. Credentials are never allowed.

## Signing people in: the authorization code grant

### The request

The browser is sent to `{protocol}/auth`, with the parameters in the query, or
posted as a form (a `POST` reads its body and never its query).

| Parameter | Rule |
| --- | --- |
| `response_type` | Required. `code`; the hybrid sets are below. Missing, `token` alone, `none` and anything unknown are `unsupported_response_type`. |
| `client_id` | Required, except beside a pushed `request_uri`. |
| `redirect_uri` | Required, even when the client registered one only. |
| `scope` | Required, and must hold `openid`. |
| `state` | Echoed as sent, on success and on refusal. |
| `nonce` | Echoed in the identity token. Required when `response_type` holds `id_token`. |
| `code_challenge`, `code_challenge_method` | PKCE. The method must be sent and be `S256`: an absent one is not read as `plain`, and `plain` is refused. Required from a public client and under FAPI 2.0. |
| `response_mode` | `query` (the default for `code`), `fragment` or `form_post`. JARM is not served. |
| `prompt` | `none`, `login`, `consent`; other values are ignored, and `none` beside anything is refused. |
| `max_age` | Seconds; the client's `default_max_age` when absent. |
| `acr_values` | Voluntary levels; the client's `default_acr_values` when absent. |
| `claims` | The OIDC Core §5.5 object, at most 2048 bytes. |
| `dpop_jkt` | Binds the code to a DPoP key. |
| `request`, `request_uri` | A request object, or a reference to one. |
| `ui_locales` | Read by the hosted pages. |
| `organization` | A saffui extension: the slug of the organization to sign in to. |
| `enrol` | A saffui extension: `configure-totp`, `configure-webauthn` or `configure-recovery-codes`, a factor to enrol after a fresh sign-in. |

Anything else is ignored, `login_hint`, `id_token_hint`, `display` and
`resource` included: the sign-in page is not pre-filled from a hint.

**The redirect** is matched exactly against one the client registered: no
prefix, no pattern, and no loopback port relaxation for native applications
(RFC 8252 §7.3 is not implemented), so register every port a native client
listens on. A registration written as a path, which only a realm import can
store, is joined onto the client's `root_url`. The value sent here is sent
again, identical, when the code is redeemed.

**Scopes.** The granted scope is `openid`, then each asked scope attached to
the client, then every scope attached as required whether asked or not. A scope
the client is not attached to is dropped, never refused. `offline_access` is
dropped too unless `prompt` holds `consent`. The granted scope comes back as
`scope` in the token answer: read it there rather than assuming the request
was honoured whole.

**Levels.** A realm maps `acr` values to levels, `password` at 1 and `mfa` at
2 in a new realm. `acr_values` is voluntary: the requirement is the lowest
level among the values the realm maps, unmapped values are ignored, and a
single sign-on session below it signs in again. An `acr` named essential in
`claims` is held to OIDC Core §5.5.1.1: when the realm maps none of its values
the request is refused `unmet_authentication_requirements` before anybody signs
in, and a login that ends below it is answered the same way at the redirect,
the person staying signed in. The `acr` in the identity token is what the
login reached, never what was asked. A one-time code alone, by text message,
by authenticator application or from the recovery list, reaches `password`,
the level of one factor; beside any other factor of the same sign-in (a
password, a magic link) it reaches `mfa`; a security key reaches `mfa` on its
own.

**Prompts.** `prompt=none` never shows a page: it is answered
`login_required` where a sign-in would be needed (no session, a session too old
for `max_age`, a level too low) and `consent_required` where the consent screen
would be. `prompt=login` signs in again whatever the session. `prompt=consent`
shows the consent screen, even to a client that does not require one, and
sends a browser with a live session through the whole sign-in first.

**`claims`.** Members of `id_token` reach the identity token only for standard
claims whose scope is attached to the client, only when the realm holds a
value, and, where the request states a `value` or `values`, only a value among
them. A `sub` with a value refuses to reuse a session belonging to anybody
else, and a login that ends as somebody else is answered `login_required`.
Members of `userinfo` are answered by userinfo.

### Pushing the request first

`POST {protocol}/par` takes the authorization parameters as a form, with the
client authenticated as at the token endpoint (a public client sends
`client_id` alone), and answers `201` with
`{"request_uri": "urn:ietf:params:oauth:request_uri:...", "expires_in": 60}`.
The browser is then sent to `{protocol}/auth?client_id=...&request_uri=...`.
The reference is spent once, within its 60 seconds; the rest of the browser's
query is not read.

The push is judged where it can be: a request object inside it is opened and
read then (below), and a refusal comes back as `400 invalid_request_object`, or
`request_not_supported` for a client that registered no signing algorithm or
no keys. A push naming another client, or carrying a `request_uri` of its own,
is `400 invalid_request`. A `DPoP` proof on the push binds the code to its key;
a `dpop_jkt` beside it that names another key is `400 invalid_dpop_proof`. The
redirect, the scope and PKCE are judged when the browser arrives.

A realm, or a client through its registration, may require pushing. A request
that was not pushed is then refused `invalid_request` at the redirect.

### Request objects

A request object is a JWT carrying the parameters, sent as `request` (in the
query, the form or a push) or hosted at an address sent as `request_uri`. A
hosted one must sit at an address the client registered in `request_uris`,
exactly; it is fetched over `https` from a public address, and must answer
`200` within 5 seconds, without a redirect, in at most 64 KiB.

- The client must have registered `request_object_signing_alg` and its keys,
  or the object is refused `request_not_supported`. The object is verified with
  the registered algorithm, never the header's, under the key its `kid` names
  or else the first key of that algorithm. Unsigned objects are refused.
- Claims are checked when present: `iss` and `client_id` must be the client,
  as strings; `aud` the issuer, as a string or inside an array; `exp` and `nbf`
  are held with 60 seconds of skew, fractional seconds allowed. `exp`, `iat`
  and `jti` are not required, and nothing records a `jti`. A nested `request`
  or `request_uri` is refused.
- The object wins parameter by parameter and the outer request fills what it
  leaves out; `response_type` and `client_id` stated in both must agree.
- A client that registered `request_object_encryption` sends the object as a
  JWE with exactly the registered `alg` and `enc`, the signed object inside, and
  a plain one from it is refused. The realm opens it with its encryption key of
  that algorithm: a new realm holds RSA-OAEP-256 alone, whatever discovery
  lists.

A failure is `invalid_request_object`.

### How the answer comes back

On success the browser returns to the redirect with `code`, `state` when one
was sent, `iss` (RFC 9207) and, after a browser sign-in, `session_state`. The
code is 64 hexadecimal characters and lives 60 seconds (the realm's
`access_code_lifespan`).

A browser holding a live single sign-on session that satisfies the request is
answered at once. Otherwise it is sent to the sign-in page
(`SAFFUI_LOGIN_UI_URL` when the deployment sets one, `{protocol}/login`
otherwise), and the sign-in has 900 seconds to finish.

A refusal travels one of two ways:

- **Shown**, with `400`, as a page to a browser (`Accept` holding
  `text/html`) and as JSON otherwise, whenever the client or a redirect it
  registered is not yet established: an unknown or switched-off client, a
  missing or unregistered `redirect_uri`, a spent or unknown pushed reference,
  a hosted object that could not be fetched. Sending those onward would make
  the server an open redirector.
- **Sent** to the registered redirect otherwise, carrying `error`, `state` and
  `iss` but never `error_description`, in the response mode the request asked
  for (a mode this server does not know is told in the query). For a pushed or
  signed request, the redirect, the state and the mode are the ones the pushed
  or signed request carries. An object that cannot be read has said nothing
  that can be believed, so its refusal goes to the redirect sent beside it when
  that one is registered, and is shown otherwise.

The end of a sign-in can refuse too, at the redirect: `access_denied` when the
person declines consent or an organization turns them away, `login_required`
when they sign in as somebody the `claims` request did not name, and
`unmet_authentication_requirements` for an essential level not reached. A wrong
password, a lockout or a throttle is told to the person on the page and never to
the client, and an abandoned sign-in reaches the client not at all.

### Redeeming the code

`POST {protocol}/token` with `grant_type=authorization_code`, `code`,
`redirect_uri` and `code_verifier`, the client authenticated, and a DPoP proof
when the code is bound to a key. Anything else in the body is ignored,
`scope` and `resource` included.

The code must be fresh and this client's, the redirect byte for byte the one
asked with, and the verifier's S256 hash the challenge; a verifier sent for a
code that carries no challenge is refused (RFC 9700 §4.8.2). The sign-in the
code came from must still be open, and its person still switched on: a logout,
or an administrator switching the person off, between the redirect and the
redemption kills the code.

Every one of those failures is `invalid_grant` "the grant presented was not
honoured", and every `invalid_grant` spends the code: a wrong verifier or
redirect burns it. Any other refusal leaves it redeemable until it expires.

Present a code once. A second presentation, while the spent code is still
remembered (30 minutes), revokes the tokens the first one bought and closes
what the client held in that sign-in. A retry after a lost answer is a second
presentation: send the person through the authorization request again instead.

### What comes back

`200` with `access_token`, `token_type` (`DPoP` when a proof was sent, `Bearer`
otherwise), `expires_in`, `refresh_token` (always, with or without
`offline_access`), `id_token` (always, since `openid` is required) and `scope`.

The identity token carries `auth_time`, `nonce` when one was sent, `acr` when
the realm maps levels, `sid`, `org_id` and `org_name` when an organization was
chosen, what the `claims` request released, and what protocol mappers add. It
carries no `at_hash` or `c_hash` from this endpoint, and none of the profile
claims a scope stands for: those are userinfo's to answer, unless the `claims`
request or a mapper puts them in the token.

| Token | Lives | Realm setting |
| --- | --- | --- |
| Code | 60 seconds | `access_code_lifespan` |
| Access and identity tokens | 300 seconds | `access_token_lifespan` |
| Refresh token | 1800 seconds, sliding | `refresh_token_lifespan` |
| Refresh token with `offline_access` | 30 days, sliding | `offline_session_lifespan` |
| The single sign-on session | 10 hours from sign-in, fixed | none |

**Pairwise subjects.** A client registered with `subject_type: pairwise` sees
a `sub` of its own for each person, 24 random bytes in base64url, stable per
sector. The sector is the host of `sector_identifier_uri`, or else the one host
every redirect shares; redirects on several hosts without a sector document
fail every redemption with `400 invalid_request`. The same `sub` rides the
access, refresh and identity tokens and the userinfo answer.

**Encrypted identity tokens.** A client that registered `id_token_encryption`
receives the identity token signed, then encrypted as a compact JWE with the
recipient key's `kid` and `cty: JWT`, to the first key of its set whose type
fits and whose `use` and `alg` are absent or agree. Every grant that hands out
an identity token does this. One that cannot be encrypted is refused, `400
invalid_request`, never sent in the clear. Access and refresh tokens are never
encrypted.

### Hybrid and implicit

A response type holding `id_token` or `token` needs the client's implicit flow
switched on, and a client whose registration lists `response_types` may ask
only for one of them. Such a request needs a `nonce` and a mode other than
`query`. `code id_token` adds an identity token carrying `c_hash`, `code token`
an access token, and `code id_token token` both, with `at_hash`; `id_token` and
`id_token token` answer without a code at all. Tokens handed
out in the front channel are signed with the identity token's key, live 300
seconds, are never bound to a key, and the identity token among them carries
only what the `claims` request released. `token` alone, plain OAuth implicit,
is refused.

## Staying signed in: refresh

`POST {protocol}/token` with `grant_type=refresh_token` and `refresh_token`,
the client authenticated as when the token was obtained, with a proof by the
same key or the same certificate when the refresh token is bound to one.

`scope` may narrow the renewal, RFC 6749 §6: the new access token and the
answer's `scope` carry what was asked, and leaving `openid` out leaves the
identity token out. It may never widen it: a scope the grant does not hold is
`400 invalid_scope` "the scope asked for was never granted". The refresh token
handed back keeps the whole grant, so the next renewal may ask for all of it
again.

**Rotation.** Unless the realm turned it off (`revoke_refresh_token: false`),
every renewal hands back a new refresh token, and only the newest renews. The
one it replaced is taken once more for 60 seconds, for a client whose answer
was lost. Anything older is a replay: the client's grant in that sign-in is
ended, the refresh token handed out to the legitimate holder dies with it, and
the answer is the same `invalid_grant` as every other refusal. Access tokens
already minted from the chain live out their lifetime. Two renewals racing with
the same token both succeed and hand out two successors, and the first of them
then works for 60 seconds only: renew from one place at a time, and keep the
token from the latest answer.

A realm that does not rotate lets the same refresh token be presented again,
`refresh_token_max_reuse` times beyond the first when it sets a bound.

**One grant per client and sign-in.** A second authorization of the same client
under the same browser sign-in, from a second tab or a silent
re-authentication, replaces the client's grant. The refresh token of the first
is then neither current nor the one just replaced, so presenting it reads as a
replay and ends the new grant too. Throw the older one away.

**When a chain ends.** A grant without `offline_access` ends with its sign-in:
at logout, when an administrator ends it, when the person resets their password
or changes it from another sign-in, when they are switched off, and in any case
10 hours after they signed in, whatever `refresh_token_lifespan` says. A grant
with `offline_access` outlives logout and the 10 hours, and ends when its
sign-in's record is removed (an administrator, a password reset or change, the
person ending it from their account), when revoked, on a replay, or when the
person holds more offline grants than the realm's `max_offline_grants` allows,
the oldest closing first without a word to its client.

Getting `offline_access`: at the authorization endpoint, ask for it with
`prompt=consent`, or it is dropped; the device and decoupled grants keep it
when asked. In every case the client must be attached to the scope, as clients
made through the admin API and registration are.

**Lifetimes.** Each renewal slides the grant's end to now plus the window
(1800 seconds, 30 days offline), held back by `session_max_lifespan` or
`offline_session_max_lifespan` when the realm sets one, counted from this
client's code exchange rather than the sign-in. The first refresh token states
the window alone, before any bound applies, and no refresh token's `exp` knows
about the 10-hour sign-in: treat `exp` as an upper bound. There is no
`refresh_expires_in`.

**Binding.** A public client's refresh token is bound to the key or certificate
it proved and renews only with the same one. A confidential client's never is;
each renewal binds the new access token to whatever it proves then.

At each renewal the person is read again (a person switched off renews nothing),
organization claims are dropped once they have left the organization, and
protocol mappers and `claims` releases are applied afresh. `auth_time` and `acr`
are carried from the sign-in; `nonce` is not. Consent and the client's scope
attachments are not checked again.

Every refusal is `400 invalid_grant` "the grant presented was not honoured",
but a wider `scope` (`invalid_scope`) and a missing `refresh_token`
(`invalid_request`).

## Devices without a browser: the device grant

RFC 8628. Switched on with `device_grant: true` on the client; public clients
may use it.

**Starting.** `POST {protocol}/device-authorization`, the client authenticated
as at the token endpoint, with `scope`. `openid` is not added for you: without
it there is no identity token later. Scopes the client is not attached to are
dropped.

```json
{
  "device_code": "<64 hexadecimal characters>",
  "user_code": "WDJB-MJHT",
  "verification_uri": "{protocol}/device",
  "verification_uri_complete": "{protocol}/device?user_code=WDJB-MJHT",
  "expires_in": 600,
  "interval": 5
}
```

The user code is 8 letters from `BCDFGHJKMNPQRSTVWXZ`. `expires_in` is the
realm's `device_code_lifespan` (60 to 3600) and `interval` its
`device_poll_interval` (1 to 60), both frozen when the code is drawn.

**The person.** They open `verification_uri` and type the code; case, dashes
and spaces do not matter. The page does not read the code from
`verification_uri_complete`, so show the code on the device even beside a QR
code. A code that does not stand is counted against the address typing it,
and an address that has missed too often is told to wait before the code is
even looked up. A live code opens the realm's own sign-in for the device's
client, factors, consent and organization rules included, with 900 seconds to
finish; at the end the page says the device is signed in, and the browser is
signed in to the realm as well.

There is no way to decline: a person who refuses consent leaves the device
polling `authorization_pending` until the code expires.

**Polling.** `POST {protocol}/token` with
`grant_type=urn:ietf:params:oauth:grant-type:device_code` and `device_code`,
the same client authenticated.

| Answer | When |
| --- | --- |
| `authorization_pending` | The person has not finished. |
| `slow_down` | This poll came sooner than `interval` after the one before. |
| `expired_token` | The code ran out, or the sign-in that approved it ended before collection. |
| `access_denied` | The person who approved was switched off since. |
| `invalid_grant` | The code is unknown, another client's, already collected, or expired and swept away (every `SAFFUI_SWEEP_SECONDS`, 300 by default). |

Every poll resets the clock `slow_down` measures, and the server never widens
the interval: on `slow_down`, add 5 seconds as RFC 8628 §3.5 says and keep to
the new pace, or every poll will be answered `slow_down`. It is checked before
anything else, so an approved code polled too early still answers `slow_down`.
With DPoP, send a fresh proof with every poll.

**What comes back** is the code grant's answer. The identity token, when
`openid` was asked, carries the sign-in's `auth_time`, `acr` and organization,
and is encrypted for a client that registered encryption. The refresh token
hangs off the browser sign-in that approved it and ends with it, 10 hours at
most, unless the scope holds `offline_access`, in which case the realm's
`max_offline_grants` applies.

## Asking a person from afar: CIBA

OpenID Client-Initiated Backchannel Authentication, poll and ping modes, for a
confidential client switched on with `ciba_delivery: poll` or `ping` (ping with
an `https` `ciba_notification_endpoint`). Push mode is not served.

**Starting.** `POST {protocol}/bc-authorize`, the client authenticated:

| Parameter | Rule |
| --- | --- |
| `scope` | `openid` when left blank. |
| `login_hint`, `id_token_hint`, `login_hint_token` | Exactly one. |
| `binding_message` | At most 64 characters, shown to the person. Longer is `invalid_binding_message`. |
| `requested_expiry` | Seconds, a positive integer. Beyond the ceiling it is cut down without a word: read `expires_in`. |
| `user_code` | Checked when the person set one. |
| `client_notification_token` | Required in ping mode, at most 1024 bytes. |
| `request` | A signed request, below. |

The hints:

- `login_hint` holding `@` is an email address, anything else a username, each
  matched exactly. An address two accounts share names neither of them, as at
  the sign-in. There is no lookup by phone number or by identifier.
- `id_token_hint` is an identity token this realm signed, still within its
  lifetime (300 seconds by default) and from a sign-in still open. A pairwise
  subject is translated back through the client.
- `login_hint_token` is a JWT the client signs with its registered request
  signing algorithm, naming the person by `sub` (the account's identifier, never
  a pairwise one) or by `email`, not both; an `email` is read as `login_hint`
  reads one.

`acr_values` is not read, and no level is reported for a decoupled sign-in.

A client whose configuration names a request signing algorithm (set through
a realm import) must send every request signed, as `request`, CIBA §7.1: `iss`
the client, `aud` the issuer as a single string, a non-empty `jti` presented
once only, and integer `exp`, `nbf` and `iat` with `nbf` at most now and `exp`
at least now. Every parameter then comes from inside it. A client without one
may not send one.

The answer is `{"auth_req_id": "...", "expires_in": 300, "interval": 5}`: the
realm's `ciba_expiry` (30 to 600) is both the default and the ceiling once set,
and 300 with a ceiling of 600 until then; `interval` is its `ciba_interval`.

**Nobody is told whether the person exists.** A hint naming nobody, or an
address two accounts share, a person switched off, or a person who set a code
and was not sent it opens a request all the same. It is answered `200`, rings
nobody, and polls `authorization_pending` until it expires.

**How the person answers.**

- A text message with a link to `{protocol}/requests`, when they hold a verified
  phone number, the deployment can send text messages, the realm has settings
  for them and no brake holds (5 a number an hour, 250 a realm a day, by
  default). A held message never refuses the request. It goes by SMS even
  where the realm sends its codes over WhatsApp, whose templates carry a code
  and no link.
- The page `{protocol}/requests` itself, in a browser signed in to the realm: it
  lists what waits, with the client, the scope and the binding message, to
  approve or deny.
- `GET {protocol}/bc-pending` and `POST {protocol}/bc-decide` (JSON
  `{"request": "<handle>", "decision": "approve" | "deny"}`), under a bearer
  token the realm's own account console obtained, carrying its `account` scope,
  bound to nothing, from a sign-in still open. No other client's token decides
  here, since a decision hands a set of tokens to somebody else's client.
- USSD, where the operator runs the realm's USSD bridge: the person dials from
  their verified number and answers on the screen.

There is no push to an authenticator application and no email.

**Collecting.** `POST {protocol}/token` with
`grant_type=urn:openid:params:grant-type:ciba` and `auth_req_id`, the same
client authenticated. The answers are the device grant's, except that
`slow_down` applies only while the request is pending, `access_denied` also
means the person denied, and `invalid_grant` covers an unknown request, another
client's, or one already collected. In ping mode, once the person decides
either way, the notification endpoint receives `POST` with `Authorization:
Bearer <client_notification_token>` and `{"auth_req_id": "..."}`, once, under
the rules every outbound call keeps (`https`, a public address, 5 seconds, no
redirect); nothing is sent when a request expires. Collect by polling
afterwards.

**What comes back** is the code grant's answer. The identity token carries the
approval instant as `auth_time`, and no `acr`, `nonce` or organization. The
sign-in behind a decoupled grant lasts 10 hours and a refresh chain without
`offline_access` ends with it; `offline_access` is kept when asked for and
attached, under the realm's `max_offline_grants`. The refresh token is never
bound.

## Services acting for themselves: client credentials

A confidential client with a service account: a user record standing for the
client, which the token names as its subject. Only the agents door and a realm
import create one; the admin client door and dynamic registration cannot.

`POST {protocol}/token` with `grant_type=client_credentials` and `scope`, the
client authenticated. Scopes the client is not attached to are dropped.
`audience` and `resource` are not read.

One access token comes back, and nothing else, not even an identity token for
`openid`. Its `sub` is the service account, its `aud` and `azp` the client
itself, and it carries no roles, organization or mapper claims. It lives the
realm's `access_token_lifespan`. Each request opens a session record, and a
sign-in event where the realm keeps them, so keep the token until `expires_in`
rather than asking for one per call. A DPoP proof or a forwarded certificate
binds it.

A public client, a client with no service account, or one whose service account
is switched off, is `unauthorized_client`.

## Acting for someone else: token exchange

RFC 8693, delegation only. The realm runs it unless it was turned off (for the
whole process with `SAFFUI_FEATURES=-token-exchange`, or for one realm with
`PUT /admin/realms/{realm}/features/token-exchange` and `{"enabled": false}`),
and then answers `unsupported_grant_type` and drops the grant from discovery.
The client must be confidential and switched on with `token_exchange: true`.

`POST {protocol}/token`, the client authenticated:

| Parameter | Rule |
| --- | --- |
| `grant_type` | `urn:ietf:params:oauth:grant-type:token-exchange` |
| `subject_token` | Required: an access token this realm minted. |
| `subject_token_type` | `urn:ietf:params:oauth:token-type:access_token`, and nothing else. |
| `requested_token_type` | Absent, or the same access token type. |
| `actor_token`, `actor_token_type` | Optional, together; the actor token is an access token of this realm too. |
| `audience` | One client id or resource name. |
| `scope` | Narrows the subject token's scope; names it does not hold are dropped. |
| `capabilities` | For agents, below. |

`resource` is not read.

**What may be exchanged.** A subject token must verify as the userinfo endpoint
verifies one (signature, lifetime, revocation, the realm's and its client's
cuts, its sign-in still open) and must be bound to nothing: a DPoP or
certificate-bound token is refused, since the exchange cannot hold its caller
to the proof. Its person must exist and be switched on. Identity and refresh
tokens, and tokens from anywhere else, are not subject tokens: a workload that
holds a platform's token uses the JWT bearer grant instead.

Any opted-in client may exchange any live access token of the realm it holds,
whatever that token's `aud` or `azp`. Three brakes are the operator's, each
written into the client's configuration by a realm import (the admin API does
not set them):

- `token.exchange.audiences`, the audiences an exchange may point at, as one
  space-separated string or a list. The client's own id always stands. Absent
  bounds nothing; present in any other shape, it allows the client's own id
  alone.
- `token.exchange.policy_server`, `token.exchange.policy_resource` and
  `token.exchange.policy_scope`, a permission the authorization engine decides
  for the subject's person, journalled like every decision. All three or none:
  one or two, or one in a shape nobody reads, refuses every exchange.
- A subject token carrying `may_act` is exchanged only by the actor its `sub`
  names.

**What comes back** is one access token, `issued_token_type`
`urn:ietf:params:oauth:token-type:access_token`, bound to the caller's own proof
when it sent one. Its `sub` is the subject's person, as the audience's client
would know them (pairwise when that client is); `aud` the asked audience or the
exchanging client; `azp` the exchanging client; `scope` as narrowed; `act` the
actor, `{"sub": "<client_id>"}` without an actor token, with the chain the
subject or actor token already carried nested below, at most five links deep;
and `sid` the subject token's own, so the new token dies with the subject's
sign-in. It lives the realm's `access_token_lifespan`, and never longer than
the subject token has left: exchanging again and again cannot keep a grant
alive, and a subject token with no time left is refused. No refresh or identity
token is issued, and no mapper claims ride.

| Refusal | `error` |
| --- | --- |
| The realm closed the exchange | `unsupported_grant_type` |
| A missing subject token, a wrong token type | `invalid_request` |
| A subject or actor token that fails, is bound, is not an access token, names nobody switched on, or has no time left; an act chain too deep | `invalid_grant` |
| Not opted in, a public client, `may_act`, the audience bound, the policy | `unauthorized_client` |

## Workloads: platform tokens and mesh certificates

A workload that already holds an identity from its platform (a Kubernetes
service account token, a CI job's OIDC token, a SPIFFE certificate) trades it
for an access token without holding a secret of saffui's.

**The trusted platform** is an identity provider of the realm: `POST
/admin/realms/{realm}/identity-providers` with `provider_id` (its alias),
`name`, `display_name`, `description`, `enabled`, `trust_email` and `configs`,
each configuration value written as `{"Str": "..."}`:

| Key | Meaning |
| --- | --- |
| `kind` | `workload`. |
| `issuer` | The `iss` the platform's tokens carry, exactly. |
| `jwks_uri` | Where the platform publishes its keys. |
| `audience` | A value the platform token's `aud` must hold. |
| `subject_patterns` | Space-separated subjects admitted: exact, or a prefix ending in `*`. A bare `*` is refused, and `*` anywhere but the end is a literal. |
| `client_id` | The client the workload signs in as; it needs a service account. |
| `allowed_algs` | Space-separated; `RS256` alone when absent. |
| `carried_claims` | Claims of the platform token copied into the access token; the registered and protocol claim names are refused. |

Any other key is refused, with `422`.

**A platform token.** `POST {protocol}/token` with
`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`, `assertion` (the
platform's token) and `scope`. No client authentication is read: the platform
names the client. The first platform, by alias, whose `issuer` is the token's
`iss` is the one tried, so two platforms sharing an issuer cannot both work.
The keys are fetched on every request, under the outbound rules (`https`, a
public address, 5 seconds, 64 KiB, no redirect): an in-cluster address is
refused unless the deployment runs with `SAFFUI_EGRESS=anywhere`. The token is
held to its `iss`, its `aud`, `exp` in the future, `nbf` not, and a `sub` the
patterns admit, with no clock leeway. `iat` and `jti` are not read, so a
platform token is accepted as often as it is presented while it lives: keep
them short-lived, as the platforms do by default.

**A mesh certificate.** `grant_type=client_credentials` with no client
credential at all, and a certificate forwarded by a proxy the deployment
names: the first platform, by alias, whose `subject_patterns` admit one of the
certificate's URI names signs it in. Every refusal on this path is final and
`invalid_grant`.

Either way the access token names the client's service account as `sub`, the
client as `aud` and `azp`, and the workload as `act`: `{"sub": <platform
subject>, "iss": <platform issuer>}`, or `{"sub": <the URI>, "iss": "x509"}`.
It lives the realm's `access_token_lifespan`, is never bound to a key or a
certificate (a `DPoP` header is not read), and comes without a refresh token.
Refusals are `invalid_grant`, but a missing `assertion` (`invalid_request`) and
a client whose service account is missing or switched off
(`unauthorized_client`).

## Agents and capability tokens

An agent is a confidential client with a service account and a capability
root: the tool names, or prefixes ending in `*`, it may ever be granted.

- Register one with `POST /admin/realms/{realm}/agents` and `{"client_id":
  "...", "capabilities": ["search.*", "calendar.read"], "session_seconds":
  900}`: 1 to 100 entries of 1 to 200 characters, no whitespace, `*` only at
  the end and never alone; `session_seconds` from 1 to 86400, 1800 when absent.
  `PUT .../agents/{client}` with `add`, `remove` and `session_seconds` reshapes
  it.
- The realm mints capability tokens only once `agent_exchange_enabled` is set
  to `true` with `PUT /admin/realms/{realm}`, and only while it runs the token
  exchange.
- An agent signs in without a key through a trusted platform whose `client_id`
  is the agent, or with a secret drawn by `POST
  /admin/realms/{realm}/clients/{client}/secret` and `client_credentials`.

**A capability token** is an exchanged access token carrying `cap`, the tools
asked for, in order. Ask with `capabilities` (space-separated) on a token
exchange, or at the MCP door. The root is the subject token's own `cap` when it
has one, and the agent's registered root otherwise: an exact name admits
itself, `p*` admits every name and every narrower prefix beginning with `p`,
and every entry asked must be admitted or the whole ask is refused. So a
capability token can only be narrowed, each time by a new exchange that adds a
link to `act`, five links at most. It lives the agent's `session_seconds`,
capped by the realm's `access_token_lifespan` (300 seconds by default) and by
what its subject token has left.

saffui writes `cap` and introspection reports it; the tool or resource server
enforces it. Cutting an agent's client, `PUT
/admin/realms/{realm}/clients/{client}` with `{"not_before": <now>}`, ends
every token it was minted, wherever a token is checked against the server.

**The MCP door**, `POST {origin}/realms/{realm}/mcp`, speaks JSON-RPC 2.0 in
bodies of at most 8 KiB, under the realm's `https` rule. It is not in discovery
and answers no cross-origin call.

| Method | Answer |
| --- | --- |
| `initialize` | `protocolVersion` `2025-06-18`, whatever the host asked, and one capability, `tools`. |
| `notifications/initialized` | `202`, empty. |
| `tools/list` | `capability.mint`, taking `capabilities`, `audience` and `scope`, and `capability.attenuate`, taking `capabilities` and `audience`. |
| `tools/call` | The exchange, under `Authorization: Bearer <token>`. |

The bearer is the whole credential: it is the subject token, and the client
its `azp` names, while switched on, is the one exchanging, with no client
authentication. Minting and attenuating are the same call; which one happens is
decided by whether the bearer already carries `cap`. The result's
`content[0].text` is a JSON string holding `access_token`, `token_type`,
`expires_in` and `scope`. The door is stateless and streams nothing.

The whole door, `initialize` included, answers error `-32000` "this realm does
not mint capability tokens" while the realm's agent switch is off or its
exchange closed. A missing or failing bearer is `401` with `WWW-Authenticate:
Bearer`; a bearer naming no client that is switched on, and every refused
exchange, are tool results with `isError: true`.

## After the tokens

### UserInfo

`GET` or `POST {protocol}/userinfo`. The access token rides in `Authorization`,
or on a `POST` in the form field `access_token`; never both, and never in the
query, where it would land in logs and history.

The scheme has to say what the token is, RFC 9449 §7.1 and §7.2. A token bound
to a DPoP key comes as `Authorization: DPoP <token>` with a proof whose `htm` is
the method, whose `htu` is the userinfo URL and whose `ath` is the token's hash.
Every other token comes as `Authorization: Bearer <token>` or in the form, a
certificate-bound one with the same certificate forwarded again. Scheme names
are read without regard to case.

Only an access token is answered, for a person who still exists and is switched
on, from a sign-in still open (or holding `offline_access`). Neither the token's
`aud` nor `openid` in its scope is checked.

The answer holds `sub`, then what the token's scope stands for, as far as the
realm holds it:

| Scope | Claims |
| --- | --- |
| `profile` | `name`, `given_name`, `family_name`, `middle_name`, `nickname`, `preferred_username`, `profile`, `picture`, `website`, `gender`, `birthdate`, `zoneinfo`, `locale`, `updated_at` |
| `email` | `email`, `email_verified` |
| `phone` | `phone_number`, `phone_number_verified` |
| `address` | `address` |

`org_id` and `org_name` are echoed from the token; the `userinfo` members of the
`claims` request are released for standard claims whose scope the client is
attached to; brokered providers' claims may arrive aggregated or distributed;
and protocol mappers fill what is still missing. A client that registered
`userinfo_signed_response_alg` receives a JWS, with `iss` and `aud` added, as
`application/jwt`; one that registered `userinfo_encryption` receives a JWE,
nested when also signed. A registered form that cannot be produced is a `500`,
never a readable fallback.

A refusal is `401` with `WWW-Authenticate: Bearer error="invalid_token",
error_description="..."`, even when no token was sent. To a caller speaking
DPoP, by its scheme or by a `DPoP` header, the challenge is
`WWW-Authenticate: DPoP` instead, with `algs` naming what a proof may be signed
with, and `error` is `invalid_dpop_proof` when the proof was the problem. A
token under the wrong scheme is `invalid_token`. No `insufficient_scope` is
ever answered. A store fault is `500 server_error`, and a lost database
connection `503`.

### Introspection

`POST {protocol}/introspect` with `token`, a confidential client authenticated;
a public client is refused, `401 invalid_client`. Any confidential client of the
realm may introspect any token of the realm. `token_type_hint` is not read.

An access token is active while it verifies, is not revoked or cut, its sign-in
is open (or it holds `offline_access`) and its person is switched on. A refresh
token is active while it is the current one of its grant: the one just replaced,
though still taken at the token endpoint for 60 seconds, reads inactive.
Identity and logout tokens are never active.

```json
{
  "active": true,
  "client_id": "<azp>",
  "token_type": "DPoP",
  "scope": "openid profile",
  "sub": "...", "aud": "...", "iss": "...",
  "iat": 1790000000, "nbf": 1790000000, "exp": 1790000300,
  "jti": "...", "sid": "...",
  "cnf": {"jkt": "..."}
}
```

`token_type` is given for access tokens only: `DPoP` for one bound to a key,
`Bearer` otherwise. `act` and `cap` appear when the token carries them, and
`cnf` whenever it is bound. The binding is reported, never demanded: the
resource server holding the caller's proof or certificate is the one that must
compare it with `cnf`. Anything else is `{"active": false}`. Nothing else of the
token is repeated: no `username`, organization, `acr`, `auth_time` or mapper
claims.

### Revocation

`POST {protocol}/revoke` with `token`, the client authenticated, public clients
included. `token_type_hint` is not read.

The token is checked by its signature alone: one that does not verify is
answered `200` and nothing happens, and one that expired still ends its grant.
A token issued to another client is `400 unauthorized_client`. For an access or
refresh token, its `jti` is withdrawn until its own expiry, and the client's
grant in that sign-in ends, so the refresh chain stops either way. Access tokens
minted earlier from the same chain live out their lifetime, and the sign-in and
every other client's grant go on. Revoking an identity token does nothing. No
logout notice is sent. The answer is `200` with an empty body.

### Logout

**Ending a sign-in from the application.** Send the browser to
`{protocol}/logout` with a top-level `GET` carrying `id_token_hint`,
`post_logout_redirect_uri`, `client_id` and `state`. The endpoint takes the same
as a `POST` form, which only a page of the server's own site can send with the
session cookie. `logout_hint` and `ui_locales` are not read.

- Which sign-in ends is decided by the browser's session cookie, never by the
  hint. The cookie is `SameSite=Lax`, so a cross-site form post or a request
  from a server carries none: it ends nothing on the server, although its answer
  tells the browser to drop its cookies. There is no server-to-server way to end
  a sign-in.
- It ends at once when `id_token_hint` verifies against the realm's keys
  (expiry is not held against it) and its `sid` is the browser's sign-in.
  Otherwise the person is asked first, on a page, or with `{"status":
  "confirm"}` to a caller that is not a browser. An encrypted identity token is
  no hint: send the signed one inside it.
- `post_logout_redirect_uri` must equal one the client registered, exactly.
  The client is the hint's `azp`, or `client_id` without a hint; a hint's `azp`
  wins over a different `client_id` without a word. `state` is appended. An
  address that does not match leaves the person on a page saying so, signed out
  all the same.
- A sign-in made through a SAML provider first sends the browser through that
  provider's single logout.
- The pages are in English only.

Once a sign-in ends, every client's refresh tokens without `offline_access` are
refused, and access tokens naming it are refused at userinfo and read inactive
at introspection. Offline grants go on. A token a resource server checks alone
works until it expires.

**Being told a sign-in ended.** A client that registered
`backchannel_logout_uri` and took part in a sign-in is sent `POST` with the form
field `logout_token` when it ends, offline grants included. The logout token is
a JWT with the header `typ: logout+jwt`, signed like the client's identity
tokens, carrying `iss`, `sub` (pairwise where the client is), `aud` (the
client), `azp`, `jti`, `iat`, `nbf`, `exp` (two minutes later), `sid` (always)
and `events: {"http://schemas.openid.net/event/backchannel-logout": {}}`.
Verify its signature, `iss`, `aud` and `events` as Back-Channel Logout 1.0
§2.6 asks, and answer quickly.

| The sign-in ended because | Sent |
| --- | --- |
| The person logged out at the logout endpoint, or an upstream provider logged them out | At once, every client together, one attempt of 5 seconds each |
| An administrator ended it, took back one client's part in it, or ended every sign-in of the realm | By the outbox pass: up to 5 attempts, the wait between them growing by the outbox's pace (`SAFFUI_OUTBOX_SECONDS`, 15 by default) at each one |
| The person reset their password, changed it (their other sign-ins), was switched off, ended a sign-in or took back an application's access from their account | The same |
| A token was revoked, a refresh token replayed, an offline grant evicted over the realm's cap, or the sign-in simply ran out | Not at all |

Every attempt is made under the outbound rules: `https` (unless
`SAFFUI_EGRESS=anywhere`), a public address, no redirect. An error status or
silence counts as a miss.

**In the browser.** A client that registered `frontchannel_logout_uri` is loaded
in a hidden frame of the logout page, with `iss` and `sid` appended, whenever
the answer is a page. The page allows `https` frames only, so an `http` address
registers and then never loads, and it moves on after 2 seconds whether the
frames finished or not.

**Watching the session.** `{protocol}/check-session` is the session management
frame. The authorization answer carries `session_state` after a browser
sign-in; post `client_id + " " + session_state` to the frame and it answers
`changed`, `unchanged` or `error`. The frame reads a cookie set for the
server's own site, so a browser that blocks third-party cookies will not keep it
in step, and the page hosting the client's side must share the redirect's
origin, which is part of `session_state`.

## Where integrations go wrong

Each of these is stated above; they are gathered here because each has cost
someone an afternoon.

**Clients and registration**

- Redirects are `http` or `https` only, at registration and on the admin API
  alike: a native application cannot register a private-use URI scheme, and
  uses a loopback redirect, on a port it registered, or a claimed `https` link.
- A client made on the admin API authenticates with a secret or not at all;
  `private_key_jwt` and `client_secret_jwt` come from dynamic registration only.
- `client_credentials`, the device grant, CIBA and the token exchange are never
  switched on by a registration, whatever its `grant_types` say.
- An RFC 7592 `PUT` replaces the whole registration, and a `GET` echoed back
  after a key fetch carries both `jwks` and `jwks_uri`, which a `PUT` refuses.
- A body over 8 KiB is refused as unreadable, and an inline key set of several
  RSA keys can reach that.
- An origin in any client's `web_origins` is admitted by CORS at every protocol
  endpoint of the realm, whichever client its page belongs to.

**Signing in**

- `openid` is required: a plain OAuth 2.0 code flow is refused `invalid_scope`,
  and `token` alone `unsupported_response_type`.
- `S256` must be named as the challenge method; an absent method is not
  `plain`, and `plain` is refused.
- `offline_access` is dropped without `prompt=consent`, and `prompt=consent`
  sends even a signed-in browser through the whole sign-in.
- `login_hint`, `prompt=select_account` and `display` are ignored at the
  authorization endpoint.
- The single sign-on cookie is `SameSite=Lax` and `Secure`: a silent
  `prompt=none` from a cross-site frame arrives without it and is told
  `login_required`.
- The sign-in has 900 seconds and the session 10 hours, neither configurable.
- A request object needs no `exp`, `iat` or `jti`, and nothing stops the same
  one being presented twice: sign short-lived ones.

**Tokens and renewal**

- A code is spent by any `invalid_grant`, a wrong verifier included, and a
  second presentation revokes what the first one bought.
- The access token's `aud` is the client itself; `resource` is read nowhere.
  To call an API that checks its own audience, exchange the token for one with
  `audience`.
- The identity token lives as long as the access token, 300 seconds, and
  carries no profile claims unless the `claims` request or a mapper asks.
- Access and identity tokens are signed with different keys on a new realm:
  select by `kid`.
- A second authorization of the same client in the same sign-in replaces its
  grant, and presenting the older refresh token then ends the new one too.
- Without `offline_access` no refresh chain outlives the 10-hour sign-in.
- A confidential client that renews without a DPoP proof gets a plain bearer
  token; a public client with a bound refresh token must prove the same key, and
  is told `invalid_grant` when it does not.
- `token_type` says `DPoP` for a key-bound token only; a certificate-bound token
  says `Bearer`.
- DPoP has no nonce: a client waiting for `DPoP-Nonce` waits forever. Build
  `htu` from the published URL, and draw a new `jti` for every request, retries
  included.
- A server fault inside a grant is `400 invalid_request`, not a `5xx`; only a
  lost database connection is `503`.

**Devices and decoupled sign-in**

- The device page does not read the code from `verification_uri_complete`:
  show the code too.
- A device sign-in cannot be declined; a person who refuses leaves the device
  polling until the code expires.
- `slow_down` never widens the server's interval, and every poll resets its
  clock: back off by 5 seconds and stay backed off.
- `expired_token` lasts until the next sweep; after it the same code is
  `invalid_grant`.
- Without `scope`, the device grant asks for no `openid` and CIBA assumes it.
- A decoupled request for somebody who does not exist succeeds, and polls
  `authorization_pending` until it expires.
- Only the person answers a decoupled request: their signed-in browser, the
  realm's account console, or their phone. A client's own tokens do not.
- Ping mode reaches `https` endpoints on public addresses only, under the
  default outbound rule, and pings once.

**Machines and agents**

- Every `client_credentials` or JWT bearer request opens a session record: keep
  tokens until they expire.
- Only this realm's own, unbound access tokens can be exchanged; there is no
  federation of outside JWTs through the exchange.
- An opted-in client may exchange any live access token of the realm it holds;
  `may_act`, the audience bound and the policy are the brakes.
- An exchanged token dies with its subject's sign-in, and a cut on the client
  that obtained the subject token does not reach it.
- Capability tokens live 300 seconds on a default realm, whatever
  `session_seconds` says, until the realm's `access_token_lifespan` is raised.
- A platform token is not checked for replay, and platform keys are fetched on
  every request from a public `https` address.
- One trusted platform answers for one issuer, and `RS256` is the only
  algorithm a platform gets unless it names others.
- A cut spares tokens minted in its own second.

**After the tokens**

- A key-bound token is read at userinfo under the `DPoP` scheme only, and an
  unbound one under `Bearer` only.
- Revocation ends the refresh chain, not the access tokens already minted from
  it.
- Logout follows the browser's cookie: an `id_token_hint` alone, or a call from
  a server, ends nothing.
- A back-channel notice at logout is tried once, for 5 seconds; notices owed
  for other endings are tried up to five times. Revocation and replay send none.
- An `http` front-channel logout address is registered and never loaded.
