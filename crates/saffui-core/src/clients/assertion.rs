//! Client assertions (RFC 7523): a JWT a client signs, with its secret or
//! one of its keys, to prove itself to the realm, once.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value};
use time::{Duration, OffsetDateTime};

use super::AssertionAlgorithm;
use crate::ports::crypto::SignatureAlgorithm;

/// The only type of assertion read (RFC 7523, section 2.2).
pub const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// The largest assertion read, in bytes.
const MAX_ASSERTION_BYTES: usize = 8 * 1024;

/// The longest an assertion may live: its identifier is kept that long.
pub const MAX_ASSERTION_LIFETIME: Duration = Duration::hours(1);

/// How far ahead of this node the clock of a client, or of another node,
/// may be.
pub const CLOCK_SKEW: Duration = Duration::seconds(30);

/// The most keys a client registers, and the most bytes their set takes.
const MAX_CLIENT_KEYS: usize = 10;
const MAX_KEY_SET_BYTES: usize = 16 * 1024;

/// The members of a JWK that carry private key material.
const PRIVATE_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// An assertion as it was written, not yet believed.
// No `Debug`: it is the assertion, signature included.
pub struct ReadAssertion {
    pub algorithm: AssertionAlgorithm,
    pub key_id: Option<String>,
    /// What `iss` and `sub` both say: the client that signed.
    pub client_id: String,
    pub token_id: String,
    /// `aud`, as written: judged by [`is_issuer_audience`] alone.
    pub audience: Value,
    pub expires_at: OffsetDateTime,
    pub issued_at: Option<OffsetDateTime>,
    pub not_before: Option<OffsetDateTime>,
    /// The header and the claims, as they were signed.
    pub signing_input: String,
    pub signature: Vec<u8>,
}

/// Reads an instant a claim may leave out. A claim of the wrong type is a
/// fault, never an absence.
fn read_instant(claims: &Value, name: &str) -> Result<Option<OffsetDateTime>, ()> {
    match claims.get(name) {
        None => Ok(None),
        Some(value) => value
            .as_i64()
            .and_then(|seconds| OffsetDateTime::from_unix_timestamp(seconds).ok())
            .map(Some)
            .ok_or(()),
    }
}

/// Reads an assertion without believing anything in it: what it names only
/// tells which client to check it against. A header with `crit`, an
/// algorithm that is not served, `iss` unlike `sub`, or a claim of the
/// wrong type is no assertion.
#[must_use]
pub fn read_assertion(text: &str) -> Option<ReadAssertion> {
    if text.len() > MAX_ASSERTION_BYTES {
        return None;
    }
    let mut parts = text.split('.');
    let (header, claims, signature) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let read_json = |part: &str| -> Option<Value> {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).ok()?).ok()
    };
    let (header_json, claims_json) = (read_json(header)?, read_json(claims)?);
    if header_json.get("crit").is_some() {
        return None;
    }
    let algorithm = AssertionAlgorithm::parse(header_json.get("alg")?.as_str()?)?;
    let key_id = match header_json.get("kid") {
        None => None,
        Some(kid) => Some(kid.as_str()?.to_owned()),
    };
    let client_id = claims_json.get("iss")?.as_str()?;
    if claims_json.get("sub")?.as_str()? != client_id {
        return None;
    }
    let token_id = claims_json.get("jti")?.as_str()?;
    if !(1..=255).contains(&token_id.len()) {
        return None;
    }
    Some(ReadAssertion {
        algorithm,
        key_id,
        client_id: client_id.to_owned(),
        token_id: token_id.to_owned(),
        audience: claims_json.get("aud")?.clone(),
        expires_at: read_instant(&claims_json, "exp").ok()??,
        issued_at: read_instant(&claims_json, "iat").ok()?,
        not_before: read_instant(&claims_json, "nbf").ok()?,
        signing_input: text[..header.len() + 1 + claims.len()].to_owned(),
        signature: URL_SAFE_NO_PAD.decode(signature).ok()?,
    })
}

/// Whether an assertion is addressed to the realm: its issuer, as one
/// string. A list, or the address of an endpoint, is refused: an assertion
/// a client made for one audience is never taken for another.
#[must_use]
pub fn is_issuer_audience(audience: &Value, issuer: &str) -> bool {
    audience.as_str() == Some(issuer)
}

/// Whether the claims of an assertion stand at `now`, for the realm of
/// `issuer`: not expired, not living past the hour, not made in the future.
#[must_use]
pub fn check_assertion_claims(read: &ReadAssertion, issuer: &str, now: OffsetDateTime) -> bool {
    read.expires_at > now
        && read.expires_at <= now + MAX_ASSERTION_LIFETIME
        && read
            .issued_at
            .is_none_or(|issued| issued <= now + CLOCK_SKEW)
        && read
            .not_before
            .is_none_or(|start| start <= now + CLOCK_SKEW)
        && is_issuer_audience(&read.audience, issuer)
}

/// Whether an assertion is signed in the algorithm its client registered,
/// when it registered one.
#[must_use]
pub fn fits_registered_algorithm(
    registered: Option<AssertionAlgorithm>,
    read: &ReadAssertion,
) -> bool {
    registered.is_none_or(|algorithm| algorithm == read.algorithm)
}

/// Chooses the key of a client that verifies an assertion: the one its
/// `kid` names, or the only key when it names none. A key kept for another
/// algorithm is never chosen.
#[must_use]
pub fn choose_client_key<'a>(jwks: &'a Value, read: &ReadAssertion) -> Option<&'a Value> {
    let keys = jwks.get("keys")?.as_array()?;
    let fits = |key: &&Value| key.get("alg").and_then(Value::as_str) == Some(read.algorithm.name());
    match &read.key_id {
        Some(kid) => keys
            .iter()
            .filter(fits)
            .find(|key| key.get("kid").and_then(Value::as_str) == Some(kid.as_str())),
        None if keys.len() == 1 => keys.first().filter(fits),
        None => None,
    }
}

/// The algorithm a key verifies in: the one it names, or the one its type
/// and curve allow. An RSA key, which two allow, takes the one the client
/// registered, or RS256: it is never read for both.
fn name_key_algorithm(
    key: &Map<String, Value>,
    registered: Option<AssertionAlgorithm>,
) -> Option<SignatureAlgorithm> {
    if let Some(named) = key.get("alg") {
        return SignatureAlgorithm::parse(named.as_str()?);
    }
    let read = |name: &str| key.get(name).and_then(Value::as_str);
    match (read("kty")?, read("crv")) {
        ("EC", Some("P-256")) => Some(SignatureAlgorithm::Es256),
        ("EC", Some("P-384")) => Some(SignatureAlgorithm::Es384),
        ("OKP", Some("Ed25519")) => Some(SignatureAlgorithm::EdDsa),
        ("RSA", _) => match registered {
            Some(AssertionAlgorithm::Signed(
                algorithm @ (SignatureAlgorithm::Rs256 | SignatureAlgorithm::Ps256),
            )) => Some(algorithm),
            _ => Some(SignatureAlgorithm::Rs256),
        },
        _ => None,
    }
}

/// Reads the key set a client registers: one to ten keys in 16 KiB, none
/// with a member a private key carries, each named by the one algorithm it
/// verifies in and written with it. What the signer reads of each key is
/// for the signer to say.
#[must_use]
pub fn read_key_set(
    jwks: &Value,
    registered: Option<AssertionAlgorithm>,
) -> Option<Vec<(SignatureAlgorithm, Value)>> {
    let keys = jwks.get("keys")?.as_array()?;
    if !(1..=MAX_CLIENT_KEYS).contains(&keys.len()) || jwks.to_string().len() > MAX_KEY_SET_BYTES {
        return None;
    }
    keys.iter()
        .map(|key| {
            let mut members = key.as_object()?.clone();
            if PRIVATE_MEMBERS
                .iter()
                .any(|name| members.contains_key(*name))
            {
                return None;
            }
            let algorithm = name_key_algorithm(&members, registered)?;
            members.insert("alg".to_owned(), Value::from(algorithm.name()));
            Some((algorithm, Value::Object(members)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::{Value, json};
    use time::OffsetDateTime;

    use super::{
        MAX_ASSERTION_BYTES, ReadAssertion, check_assertion_claims, choose_client_key,
        fits_registered_algorithm, is_issuer_audience, read_assertion, read_key_set,
    };
    use crate::clients::AssertionAlgorithm;
    use crate::ports::crypto::SignatureAlgorithm;

    const ISSUER: &str = "https://id.example.test/realms/acme";

    fn write(header: &Value, claims: &Value) -> String {
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string()),
            URL_SAFE_NO_PAD.encode(b"signature")
        )
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("an instant")
    }

    fn claims(changes: &Value) -> Value {
        let mut claims = json!({
            "iss": "billing",
            "sub": "billing",
            "aud": ISSUER,
            "jti": "a-1",
            "exp": 1_800_000_060,
            "iat": 1_800_000_000,
        });
        for (name, value) in changes.as_object().expect("an object") {
            if value.is_null() {
                claims.as_object_mut().expect("an object").remove(name);
            } else {
                claims[name] = value.clone();
            }
        }
        claims
    }

    fn read(header: &Value, changes: &Value) -> Option<ReadAssertion> {
        read_assertion(&write(header, &claims(changes)))
    }

    /// An assertion of exactly `length` bytes, padded in its claims and its
    /// signature.
    fn write_of_length(length: usize) -> String {
        let header = URL_SAFE_NO_PAD.encode(json!({ "alg": "RS256" }).to_string());
        (length * 3 / 4 - 200..length)
            .find_map(|pad| {
                let padded = claims(&json!({ "pad": "x".repeat(pad) }));
                let claims = URL_SAFE_NO_PAD.encode(padded.to_string());
                let left = length.checked_sub(header.len() + claims.len() + 2)?;
                (2..=4)
                    .contains(&left)
                    .then(|| format!("{header}.{claims}.{}", "A".repeat(left)))
            })
            .expect("a length the padding reaches")
    }

    fn stands(header: &Value, changes: &Value) -> bool {
        read(header, changes).is_some_and(|read| check_assertion_claims(&read, ISSUER, now()))
    }

    #[test]
    fn an_assertion_is_addressed_to_the_issuer_alone_as_one_string() {
        assert!(is_issuer_audience(&json!(ISSUER), ISSUER));
        for (wrong, why) in [
            (json!([ISSUER]), "a list, even of the issuer alone"),
            (
                json!(format!("{ISSUER}/oauth2/token")),
                "the address of the token endpoint",
            ),
            (
                json!("https://id.example.test/realms/globex"),
                "another issuer",
            ),
            (json!(format!("{ISSUER}/")), "the issuer with one more byte"),
            (json!(null), "nothing"),
        ] {
            assert!(!is_issuer_audience(&wrong, ISSUER), "{why}");
        }
    }

    #[test]
    fn an_assertion_stands_for_the_issuer_within_its_hour_from_one_client_named_twice() {
        let header = json!({ "alg": "RS256", "kid": "k1" });
        assert!(stands(&header, &json!({})));
        for (wrong, why) in [
            (json!({ "aud": [ISSUER] }), "a list of audiences"),
            (
                json!({ "aud": format!("{ISSUER}/oauth2/token") }),
                "the token endpoint",
            ),
            (json!({ "sub": "payroll" }), "the subject is not the issuer"),
            (json!({ "exp": 1_800_000_000 }), "expired"),
            (json!({ "exp": 1_800_003_601 }), "living past the hour"),
            (json!({ "exp": null }), "no expiry"),
            (json!({ "aud": null }), "no audience"),
            (json!({ "jti": null }), "no identifier"),
            (json!({ "jti": "" }), "an empty identifier"),
            (json!({ "iat": 1_800_000_031 }), "made in the future"),
            (json!({ "nbf": 1_800_000_031 }), "not yet good"),
            (json!({ "exp": "soon" }), "an expiry that is no number"),
        ] {
            assert!(!stands(&header, &wrong), "{why}");
        }
        assert!(stands(&header, &json!({ "exp": 1_800_003_600 })), "an hour");
        assert!(
            stands(&header, &json!({ "iat": 1_800_000_030 })),
            "a clock half a minute ahead"
        );
        assert!(
            stands(&header, &json!({ "nbf": 1_800_000_030 })),
            "good half a minute from now"
        );
        assert!(read_assertion(&write_of_length(MAX_ASSERTION_BYTES)).is_some());
        assert!(
            read_assertion(&write_of_length(MAX_ASSERTION_BYTES + 1)).is_none(),
            "one byte longer than an assertion is read"
        );
        for wrong in [
            json!({ "alg": "none" }),
            json!({ "alg": "HS512" }),
            json!({ "alg": "RS256", "crit": ["exp"] }),
            json!({ "alg": "RS256", "kid": 7 }),
        ] {
            assert!(!stands(&wrong, &json!({})), "{wrong}");
        }
    }

    #[test]
    fn an_assertion_in_another_algorithm_than_the_one_registered_does_not_stand() {
        let assertion = read(&json!({ "alg": "ES384" }), &json!({})).expect("an assertion");
        let registered = |name| AssertionAlgorithm::parse(name);

        assert!(!fits_registered_algorithm(registered("ES256"), &assertion));
        assert!(fits_registered_algorithm(registered("ES384"), &assertion));
        assert!(fits_registered_algorithm(None, &assertion));
    }

    #[test]
    fn the_key_is_the_one_named_or_the_only_one_and_never_one_kept_for_another_algorithm() {
        let jwks = json!({ "keys": [
            { "kty": "RSA", "kid": "k1", "alg": "RS256", "n": "x", "e": "AQAB" },
            { "kty": "EC", "kid": "k2", "alg": "ES256", "crv": "P-256", "x": "x", "y": "y" },
        ] });
        let chosen = |jwks: &Value, header: Value| {
            let assertion = read(&header, &json!({})).expect("an assertion");
            choose_client_key(jwks, &assertion).map(|key| key["kid"].clone())
        };

        assert_eq!(
            chosen(&jwks, json!({ "alg": "RS256", "kid": "k1" })),
            Some(json!("k1"))
        );
        assert_eq!(chosen(&jwks, json!({ "alg": "ES256", "kid": "k1" })), None);
        assert_eq!(chosen(&jwks, json!({ "alg": "PS256", "kid": "k1" })), None);
        assert_eq!(
            chosen(&jwks, json!({ "alg": "RS256" })),
            None,
            "two keys and no name"
        );
        let only = json!({ "keys": [{ "kty": "EC", "crv": "P-256", "x": "x", "y": "y", "alg": "ES256" }] });
        assert_eq!(chosen(&only, json!({ "alg": "ES256" })), Some(Value::Null));
        assert_eq!(chosen(&only, json!({ "alg": "ES384" })), None);
    }

    #[test]
    fn a_key_set_is_registered_with_public_keys_each_written_with_its_one_algorithm() {
        let kept = |jwks: Value, registered| {
            read_key_set(&jwks, registered).map(|keys| {
                keys.into_iter()
                    .map(|(algorithm, key)| (algorithm, key["alg"].clone()))
                    .collect::<Vec<_>>()
            })
        };
        let rsa = json!({ "kty": "RSA", "n": "x", "e": "AQAB" });

        assert_eq!(
            kept(json!({ "keys": [rsa] }), None),
            Some(vec![(SignatureAlgorithm::Rs256, json!("RS256"))]),
            "an RSA key is read for one algorithm, never for both"
        );
        assert_eq!(
            kept(json!({ "keys": [rsa] }), AssertionAlgorithm::parse("PS256")),
            Some(vec![(SignatureAlgorithm::Ps256, json!("PS256"))])
        );
        assert_eq!(
            kept(
                json!({ "keys": [
                    { "kty": "EC", "crv": "P-384", "x": "x", "y": "y" },
                    { "kty": "OKP", "crv": "Ed25519", "x": "x" },
                    { "kty": "RSA", "n": "x", "e": "AQAB", "alg": "PS256" },
                ] }),
                None
            ),
            Some(vec![
                (SignatureAlgorithm::Es384, json!("ES384")),
                (SignatureAlgorithm::EdDsa, json!("EdDSA")),
                (SignatureAlgorithm::Ps256, json!("PS256")),
            ])
        );
        let eleven: Vec<Value> = (0..11)
            .map(|_| json!({ "kty": "EC", "crv": "P-256", "x": "x", "y": "y" }))
            .collect();
        for (wrong, why) in [
            (json!({ "keys": [] }), "no key"),
            (json!({ "keys": eleven }), "eleven keys"),
            (
                json!({ "keys": [{ "kty": "EC", "crv": "P-256", "x": "x", "y": "y", "d": "d" }] }),
                "a private member",
            ),
            (
                json!({ "keys": [{ "kty": "oct", "k": "secret" }] }),
                "a secret",
            ),
            (
                json!({ "keys": [{ "kty": "RSA", "n": "x", "e": "AQAB", "alg": "HS256" }] }),
                "an algorithm of a secret",
            ),
            (
                json!({ "keys": [{ "kty": "OKP", "crv": "Ed448", "x": "x" }] }),
                "a curve no algorithm reads",
            ),
            (
                json!({ "keys": [{ "kty": "RSA", "n": "x".repeat(16 * 1024), "e": "AQAB" }] }),
                "more than 16 KiB",
            ),
            (json!({ "key": [] }), "no set"),
        ] {
            assert!(read_key_set(&wrong, None).is_none(), "{why}");
        }
    }
}
