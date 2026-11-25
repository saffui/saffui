//! Request objects (RFC 9101, and OpenID Connect Core 1.0, section 6.1): an
//! authorization request its client signed, passed by value in `request`.
//!
//! What the object says is the request, and nothing of the query stands
//! beside it: the client it names, and the two parameters OpenID Connect
//! keeps there, which must say what the object says. An object is read in
//! the one algorithm its client registered, never in the one its header
//! names, and is believed in nothing until it is shown to be made by that
//! client, for this realm, now.

use std::collections::BTreeSet;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value};
use time::{Duration, OffsetDateTime};

use super::authorize::AuthorizationParameters;
use super::response::ResponseType;
use crate::app::App;
use crate::clients::assertion::{CLOCK_SKEW, is_request_object_type};
use crate::clients::authenticate::{ClientSignature, verify_client_signature};
use crate::clients::{AssertionAlgorithm, Client, KeptProof};
use crate::error::Failure;
use crate::ports::storage::UnitOfWork;

/// The largest request object read, in bytes.
const MAX_REQUEST_OBJECT_BYTES: usize = 16 * 1024;

/// The longest a request object may live.
const MAX_REQUEST_OBJECT_LIFETIME: Duration = Duration::hours(1);

/// The parameters of the authorization endpoint an object may carry. The
/// client is read from the query, the browser from the request.
const CARRIED_PARAMETERS: [&str; 11] = [
    "response_type",
    "redirect_uri",
    "scope",
    "state",
    "nonce",
    "code_challenge",
    "code_challenge_method",
    "response_mode",
    "prompt",
    "max_age",
    "id_token_hint",
];

/// A request object as it was written, not yet believed.
// No `Debug`: it carries what the request carries, a hint of identity
// included.
struct ReadRequestObject {
    algorithm: AssertionAlgorithm,
    key_id: Option<String>,
    claims: Map<String, Value>,
    /// The header and the claims, as they were signed.
    signing_input: String,
    signature: Vec<u8>,
}

/// What a request object carries of a request, each parameter written as
/// the query would have written it.
pub(crate) struct CarriedParameters {
    values: Map<String, Value>,
}

/// Reads a request object without believing anything in it. Something
/// longer than the bound is not read at all. A compact JWS of three parts
/// and no fewer: an encrypted object has five. A header with `crit`, a type
/// of another kind, or an algorithm that is not served is no request
/// object.
fn read_request_object(text: &str) -> Option<ReadRequestObject> {
    if text.len() > MAX_REQUEST_OBJECT_BYTES {
        return None;
    }
    let mut parts = text.split('.');
    let (header, claims, signature) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let read_members = |part: &str| -> Option<Map<String, Value>> {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).ok()?).ok()
    };
    let header_members = read_members(header)?;
    if header_members.contains_key("crit") {
        return None;
    }
    if let Some(named) = header_members.get("typ")
        && !is_request_object_type(named.as_str()?)
    {
        return None;
    }
    let algorithm = AssertionAlgorithm::parse(header_members.get("alg")?.as_str()?)?;
    let key_id = match header_members.get("kid") {
        None => None,
        Some(kid) => Some(kid.as_str()?.to_owned()),
    };
    Some(ReadRequestObject {
        algorithm,
        key_id,
        claims: read_members(claims)?,
        signing_input: text[..header.len() + 1 + claims.len()].to_owned(),
        signature: URL_SAFE_NO_PAD.decode(signature).ok()?,
    })
}

/// Reads a date a claim may leave out: seconds since the epoch, with a
/// fraction or without (RFC 7519, section 2). A claim of another type, or
/// past what a date holds, is a fault, never an absence.
fn read_numeric_date(
    claims: &Map<String, Value>,
    name: &str,
) -> Result<Option<OffsetDateTime>, ()> {
    match claims.get(name) {
        None => Ok(None),
        Some(value) => value
            .as_f64()
            .and_then(Duration::checked_seconds_f64)
            .and_then(|since| OffsetDateTime::UNIX_EPOCH.checked_add(since))
            .map(Some)
            .ok_or(()),
    }
}

/// Whether the claims of a request object bind it to `client_id` and to the
/// realm of `issuer` at `now`. `iss` and `client_id`, when written, name the
/// client, as a text. `aud` names the issuer alone, as a text or in a list
/// of nothing else: an object made for several providers, or for another,
/// is taken by none here. `exp` is written, and not past an hour away. Not
/// made, nor valid from, further ahead than the clock of a client may be.
fn check_request_object_claims(
    claims: &Map<String, Value>,
    client_id: &str,
    issuer: &str,
    now: OffsetDateTime,
) -> bool {
    // A subject that names the client is what an assertion of it says: no
    // object says it (RFC 9101, section 10.8).
    if claims.get("sub").and_then(Value::as_str) == Some(client_id) {
        return false;
    }
    let names_client = |name: &str| {
        claims
            .get(name)
            .is_none_or(|named| named.as_str() == Some(client_id))
    };
    let addressed_here = match claims.get("aud") {
        Some(Value::String(audience)) => audience == issuer,
        Some(Value::Array(audiences)) => {
            !audiences.is_empty()
                && audiences
                    .iter()
                    .all(|audience| audience.as_str() == Some(issuer))
        }
        _ => false,
    };
    let dates = (
        read_numeric_date(claims, "exp"),
        read_numeric_date(claims, "iat"),
        read_numeric_date(claims, "nbf"),
    );
    let (Ok(Some(expires_at)), Ok(issued_at), Ok(not_before)) = dates else {
        return false;
    };
    names_client("iss")
        && names_client("client_id")
        && addressed_here
        && expires_at > now
        && expires_at <= now + MAX_REQUEST_OBJECT_LIFETIME
        && issued_at.is_none_or(|issued| issued <= now + CLOCK_SKEW)
        && not_before.is_none_or(|start| start <= now + CLOCK_SKEW)
}

/// Reads the parameters a request object carries. Each is a text, as in a
/// query, but `max_age`, which may be a number and is then written as JSON
/// writes it. An object that carries another, by value or by reference, is
/// refused (RFC 9101, section 4): nothing would bound the chain.
fn read_carried_parameters(claims: &Map<String, Value>) -> Option<CarriedParameters> {
    if claims.contains_key("request") || claims.contains_key("request_uri") {
        return None;
    }
    let mut values = Map::new();
    for name in CARRIED_PARAMETERS {
        let written = match claims.get(name) {
            None => continue,
            Some(Value::String(text)) => text.clone(),
            Some(Value::Number(number)) if name == "max_age" => number.to_string(),
            Some(_) => return None,
        };
        values.insert(name.to_owned(), Value::String(written));
    }
    Some(CarriedParameters { values })
}

impl CarriedParameters {
    fn read(&self, name: &str) -> Option<&str> {
        self.values.get(name).and_then(Value::as_str)
    }

    /// Whether the query says again what the object says, of the two
    /// parameters OpenID Connect keeps in it: a `response_type` or a `scope`
    /// it writes is the one of the object, each read as the set it is
    /// (OpenID Connect Core 1.0, 6.1).
    fn agrees_with(&self, query: &AuthorizationParameters<'_>) -> bool {
        // A parameter sent without a value is one that was not sent (RFC 6749, 3.1).
        let carried_type = self.read("response_type").and_then(ResponseType::read);
        let same_type = query
            .response_type
            .filter(|asked| !asked.is_empty())
            .is_none_or(|asked| {
                ResponseType::read(asked).is_some_and(|asked| carried_type == Some(asked))
            });
        let same_scope = query
            .scope
            .filter(|asked| !asked.is_empty())
            .is_none_or(|asked| {
                self.read("scope")
                    .is_some_and(|carried| read_scope_set(carried) == read_scope_set(asked))
            });
        same_type && same_scope
    }

    /// The request the object makes, read in place of `query`, of which
    /// only the client stands.
    pub(crate) fn over<'a>(
        &'a self,
        query: &AuthorizationParameters<'a>,
    ) -> AuthorizationParameters<'a> {
        AuthorizationParameters {
            response_type: self.read("response_type"),
            client_id: query.client_id,
            redirect_uri: self.read("redirect_uri"),
            scope: self.read("scope"),
            state: self.read("state"),
            nonce: self.read("nonce"),
            code_challenge: self.read("code_challenge"),
            code_challenge_method: self.read("code_challenge_method"),
            response_mode: self.read("response_mode"),
            prompt: self.read("prompt"),
            max_age: self.read("max_age"),
            id_token_hint: self.read("id_token_hint"),
            ..AuthorizationParameters::default()
        }
    }
}

/// The scopes a `scope` names, each once and in no order.
fn read_scope_set(scope: &str) -> BTreeSet<&str> {
    scope.split(' ').filter(|token| !token.is_empty()).collect()
}

/// Reads the request object of `query`, which `client`, kept with `proof`,
/// sent to the realm of `issuer`: in the algorithm the client registered,
/// bound to it and to the realm now, said again where the query repeats it,
/// then signed by its secret or by the key it names. What costs nothing is
/// judged before the signature. Nothing, when any of it fails: an object
/// that does not stand is believed in nothing.
///
/// # Errors
///
/// Returns [`crate::error::ErrorCode::CryptoUnavailable`] when the sealed
/// secret of the client cannot be opened, or the storage failure.
pub(crate) async fn read_signed_request(
    app: &App,
    work: &mut dyn UnitOfWork,
    client: &Client,
    proof: &KeptProof,
    issuer: &str,
    query: &AuthorizationParameters<'_>,
) -> Result<Option<CarriedParameters>, Failure> {
    let Some(read) = query.request.and_then(read_request_object) else {
        return Ok(None);
    };
    // The header names the algorithm, and is never what chooses it.
    if client.request_object_signing_alg != Some(read.algorithm)
        || !check_request_object_claims(&read.claims, &client.client_id, issuer, app.now())
    {
        return Ok(None);
    }
    let Some(carried) =
        read_carried_parameters(&read.claims).filter(|carried| carried.agrees_with(query))
    else {
        return Ok(None);
    };
    let signed = ClientSignature {
        algorithm: read.algorithm,
        key_id: read.key_id.as_deref(),
        signing_input: read.signing_input.as_bytes(),
        signature: &read.signature,
    };
    if !verify_client_signature(app, work, client, proof, &signed).await? {
        return Ok(None);
    }
    Ok(Some(carried))
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::{Map, Value, json};
    use time::OffsetDateTime;

    use super::{
        MAX_REQUEST_OBJECT_BYTES, check_request_object_claims, read_carried_parameters,
        read_request_object,
    };
    use crate::clients::AssertionAlgorithm;
    use crate::oidc::authorize::AuthorizationParameters;
    use crate::ports::crypto::SignatureAlgorithm;

    const ISSUER: &str = "https://id.example.test/realms/acme";
    const CLIENT: &str = "webapp";
    /// Noon on the first day of 2026, to the second.
    const NOW: i64 = 1_767_268_800;

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(NOW).expect("an instant")
    }

    fn write(header: &Value, claims: &Value) -> String {
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string()),
            URL_SAFE_NO_PAD.encode("a signature")
        )
    }

    /// The claims of an object bound to `webapp` and the realm, with each of
    /// `changes` written over them: null takes one out.
    fn bound(changes: &Value) -> Map<String, Value> {
        let mut claims = json!({
            "iss": CLIENT,
            "client_id": CLIENT,
            "aud": ISSUER,
            "exp": NOW + 60,
            "iat": NOW,
        });
        for (name, value) in changes.as_object().expect("changes") {
            if value.is_null() {
                claims.as_object_mut().expect("claims").remove(name);
            } else {
                claims[name] = value.clone();
            }
        }
        claims.as_object().expect("claims").clone()
    }

    fn stands(changes: &Value) -> bool {
        check_request_object_claims(&bound(changes), CLIENT, ISSUER, now())
    }

    #[test]
    fn an_object_of_three_parts_is_read_with_its_algorithm_its_key_and_its_claims() {
        let claims = json!({ "scope": "openid" });
        for typ in [
            None,
            Some("oauth-authz-req+jwt"),
            Some("application/OAuth-Authz-Req+JWT"),
        ] {
            let mut header = json!({ "alg": "ES256", "kid": "k1" });
            if let Some(typ) = typ {
                header["typ"] = json!(typ);
            }
            let text = write(&header, &claims);

            let read = read_request_object(&text).expect("a request object");

            assert_eq!(
                read.algorithm,
                AssertionAlgorithm::Signed(SignatureAlgorithm::Es256),
                "{typ:?}"
            );
            assert_eq!(read.key_id.as_deref(), Some("k1"));
            assert_eq!(read.claims["scope"], "openid");
            assert_eq!(
                read.signing_input,
                text.rsplit_once('.').expect("three parts").0
            );
            assert_eq!(read.signature, b"a signature");
        }
        let read = read_request_object(&write(&json!({ "alg": "HS256" }), &claims))
            .expect("one signed by a secret");
        assert_eq!(read.algorithm, AssertionAlgorithm::Hs256);
        assert_eq!(read.key_id, None);
    }

    #[test]
    fn an_object_past_the_bound_is_not_read() {
        let header = json!({ "alg": "ES256" });
        let padded = |length: usize| write(&header, &json!({ "pad": "a".repeat(length) }));
        let mut length = 0;
        while padded(length + 1).len() <= MAX_REQUEST_OBJECT_BYTES {
            length += 1;
        }

        assert_eq!(padded(length).len(), MAX_REQUEST_OBJECT_BYTES);
        assert!(
            read_request_object(&padded(length)).is_some(),
            "at the bound"
        );
        assert!(read_request_object(&padded(length + 1)).is_none());
    }

    #[test]
    fn an_encrypted_object_or_one_of_another_shape_is_not_read() {
        let signed = write(&json!({ "alg": "ES256" }), &json!({ "scope": "openid" }));
        let encrypted_header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RSA-OAEP","enc":"A256GCM"}"#);
        let part = URL_SAFE_NO_PAD.encode("part");
        let (header, rest) = signed.split_once('.').expect("parts");
        let (claims, _) = rest.split_once('.').expect("parts");
        for (text, why) in [
            (
                format!("{encrypted_header}.{part}.{part}.{part}.{part}"),
                "encrypted",
            ),
            (format!("{signed}.{part}"), "a fourth part"),
            (format!("{header}.{claims}"), "no signature"),
            (
                write(&json!({ "alg": "ES256" }), &json!(["openid"])),
                "claims that are no object",
            ),
            (format!("{header}.{claims}.c2ln=="), "a padded signature"),
        ] {
            assert!(read_request_object(&text).is_none(), "{why}");
        }
    }

    #[test]
    fn a_header_of_another_type_with_critical_members_or_without_a_served_algorithm_is_refused() {
        for (header, why) in [
            (
                json!({ "alg": "ES256", "typ": "JWT" }),
                "a token of another kind",
            ),
            (
                json!({ "alg": "ES256", "typ": "application/jwt" }),
                "the type of every token",
            ),
            (
                json!({ "alg": "ES256", "typ": "text/oauth-authz-req+jwt" }),
                "another top-level type",
            ),
            (
                json!({ "alg": "ES256", "typ": 7 }),
                "a type that is no text",
            ),
            (
                json!({ "alg": "ES256", "crit": ["exp"] }),
                "members it must understand",
            ),
            (json!({ "alg": "none" }), "no signature"),
            (json!({ "alg": "HS512" }), "an algorithm not served"),
            (json!({}), "no algorithm"),
            (
                json!({ "alg": "ES256", "kid": 7 }),
                "a key named by a number",
            ),
        ] {
            assert!(
                read_request_object(&write(&header, &json!({}))).is_none(),
                "{why}"
            );
        }
    }

    #[test]
    fn an_object_bound_to_its_client_and_to_this_realm_now_stands() {
        assert!(stands(&json!({})));
        assert!(
            stands(&json!({ "iss": null, "client_id": null, "iat": null })),
            "each that names the client may be left out"
        );
        assert!(
            stands(&json!({ "aud": [ISSUER] })),
            "the issuer alone, in a list"
        );
    }

    #[test]
    fn an_object_made_for_another_provider_or_for_several_is_taken_by_none_here() {
        for audience in [
            json!(null),
            json!("https://id.example.test/realms/other"),
            json!(format!("{ISSUER}/oauth2/authorize")),
            json!([ISSUER, "https://other.example.org"]),
            json!([]),
            json!(7),
        ] {
            assert!(!stands(&json!({ "aud": audience })), "{audience}");
        }
    }

    #[test]
    fn an_object_that_names_another_client_or_names_it_in_another_shape_is_refused() {
        for (name, value) in [
            ("iss", json!("other")),
            ("iss", json!(["webapp"])),
            ("client_id", json!("other")),
            ("client_id", json!(7)),
        ] {
            let mut changes = json!({});
            changes[name] = value.clone();
            assert!(!stands(&changes), "{name}: {value}");
        }
    }

    #[test]
    fn an_object_whose_subject_is_its_client_is_refused_as_the_assertion_it_would_be() {
        assert!(!stands(&json!({ "sub": CLIENT })));
        assert!(
            stands(&json!({ "sub": "a person of the client" })),
            "a subject that names someone else is not read"
        );
    }

    #[test]
    fn an_object_lives_an_hour_at_most_and_is_not_made_ahead_of_the_skew() {
        for (changes, standing) in [
            (json!({ "exp": null }), false),
            (json!({ "exp": NOW }), false),
            (json!({ "exp": NOW + 1 }), true),
            (json!({ "exp": NOW + 3600 }), true),
            (json!({ "exp": NOW + 3601 }), false),
            (json!({ "exp": NOW - 60 }), false),
            (json!({ "exp": "soon" }), false),
            (json!({ "nbf": NOW + 30 }), true),
            (json!({ "nbf": NOW + 31 }), false),
            (json!({ "nbf": "now" }), false),
            (json!({ "iat": NOW + 30 }), true),
            (json!({ "iat": NOW + 31 }), false),
            (json!({ "iat": null }), true),
            (json!({ "iat": i64::MAX }), false),
        ] {
            assert_eq!(stands(&changes), standing, "{changes}");
        }
    }

    #[test]
    fn a_date_with_a_fraction_is_held_to_as_written() {
        let fraction = |seconds: f64| json!(seconds);
        #[expect(
            clippy::cast_precision_loss,
            reason = "an instant of 2026 is exact in a double"
        )]
        let at = NOW as f64;

        assert!(stands(&json!({ "exp": fraction(at + 0.5) })));
        assert!(!stands(&json!({ "exp": fraction(at - 0.5) })));
        assert!(stands(&json!({ "nbf": fraction(at + 30.0) })));
        assert!(!stands(&json!({ "nbf": fraction(at + 30.5) })));
    }

    fn carried(claims: &Value) -> Option<super::CarriedParameters> {
        read_carried_parameters(claims.as_object().expect("claims"))
    }

    #[test]
    fn the_parameters_an_object_carries_are_read_as_texts_and_max_age_as_a_number_too() {
        let read = carried(&json!({
            "scope": "openid",
            "max_age": 300,
            "login_hint": ["not", "read"],
        }))
        .expect("parameters");
        assert_eq!(read.read("scope"), Some("openid"));
        assert_eq!(read.read("max_age"), Some("300"));
        assert_eq!(
            read.read("login_hint"),
            None,
            "what the endpoint does not read"
        );
        assert_eq!(
            carried(&json!({ "max_age": "60" }))
                .and_then(|read| read.read("max_age").map(str::to_owned)),
            Some("60".to_owned())
        );
        for refused in [
            json!({ "scope": 7 }),
            json!({ "redirect_uri": null }),
            json!({ "prompt": ["none"] }),
            json!({ "request": "a.b.c" }),
            json!({ "request_uri": "https://app.example.org/r" }),
        ] {
            assert!(carried(&refused).is_none(), "{refused}");
        }
    }

    #[test]
    fn the_object_is_the_request_and_the_query_keeps_only_its_client_and_what_it_must_repeat() {
        let read = carried(&json!({
            "response_type": "code",
            "scope": "openid email",
            "redirect_uri": "https://app.example.org/callback",
            "state": "signed-state",
            "nonce": "signed-nonce",
            "id_token_hint": "a.hint.token",
        }))
        .expect("parameters");
        let query = AuthorizationParameters {
            response_type: Some("code"),
            client_id: Some(CLIENT),
            redirect_uri: Some("https://evil.example.org/callback"),
            scope: Some(""),
            state: Some("query-state"),
            prompt: Some("none"),
            request: Some("a.b.c"),
            ..AuthorizationParameters::default()
        };

        assert!(read.agrees_with(&query));
        let asked = read.over(&query);

        assert_eq!(asked.client_id, Some(CLIENT));
        assert_eq!(asked.redirect_uri, Some("https://app.example.org/callback"));
        assert_eq!(asked.scope, Some("openid email"));
        assert_eq!(asked.state, Some("signed-state"));
        assert_eq!(asked.nonce, Some("signed-nonce"));
        assert_eq!(asked.id_token_hint, Some("a.hint.token"));
        assert_eq!(asked.prompt, None, "a prompt of the query is not read");
        assert_eq!((asked.request, asked.request_uri), (None, None));
    }

    #[test]
    fn a_query_that_repeats_a_type_or_a_scope_must_say_what_the_object_says() {
        let read = carried(&json!({ "response_type": "code id_token", "scope": "openid email" }))
            .expect("parameters");
        let query = AuthorizationParameters {
            response_type: Some("code id_token"),
            scope: Some("openid email"),
            ..AuthorizationParameters::default()
        };

        assert!(read.agrees_with(&query));
        assert!(read.agrees_with(&AuthorizationParameters::default()));
        assert!(
            read.agrees_with(&AuthorizationParameters {
                response_type: Some("id_token code"),
                scope: Some("email  openid openid"),
                ..query
            }),
            "each is a set, in any order"
        );
        for differing in [
            AuthorizationParameters {
                response_type: Some("code"),
                ..query
            },
            AuthorizationParameters {
                response_type: Some("code id_token token"),
                ..query
            },
            AuthorizationParameters {
                response_type: Some("code id_token bogus"),
                ..query
            },
            AuthorizationParameters {
                scope: Some("openid"),
                ..query
            },
            AuthorizationParameters {
                scope: Some("openid email phone"),
                ..query
            },
        ] {
            assert!(!read.agrees_with(&differing), "{differing:?}");
        }
        let unsaid = carried(&json!({ "scope": "openid email" })).expect("parameters");
        assert!(
            !unsaid.agrees_with(&query),
            "a type the query writes and the object does not"
        );
    }
}
