//! The keys of a credential issuer a realm names, read when it is named.
//!
//! An https issuer publishes them through its JWT VC issuer metadata,
//! `/.well-known/jwt-vc-issuer` inserted between its host and its path; a
//! `did:web` issuer through its DID document, the keys it asserts with. Both
//! are read at configuration and kept: a presentation is never the moment this
//! server goes out to ask.

use serde_json::{Map, Value, json};

use super::base58;

/// How much of what an issuer wrote a refusal repeats.
const QUOTED: usize = 200;
/// The most keys kept from one issuer.
const MOST_KEYS: usize = 20;
/// The members a public key is read by; anything else an issuer wrote beside
/// them is not kept.
const PUBLIC_MEMBERS: [&str; 6] = ["kty", "crv", "x", "y", "n", "e"];
/// The members only a private key has.
const PRIVATE_MEMBERS: [&str; 7] = ["d", "p", "q", "dp", "dq", "qi", "k"];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unreadable {
    #[error("{0} is not an issuer: an https address with no query or fragment, or a did:web")]
    NotAnIssuer(String),
    #[error("the issuer's metadata is not a JSON object")]
    NotADocument,
    #[error("the metadata speaks for another issuer: {0}")]
    AnotherIssuer(String),
    #[error("the metadata names neither `jwks` nor `jwks_uri`, or names both")]
    NoKeySet,
    #[error("`jwks_uri` is not an https address")]
    InsecureKeySet,
    #[error("the key set is not a JSON object with a `keys` list")]
    NotAKeySet,
    #[error("the DID document is for another DID: {0}")]
    AnotherDid(String),
    #[error("the issuer publishes private key material")]
    PrivateKey,
    #[error("the issuer publishes no key this server verifies with")]
    NoUsableKey,
}

/// Where an issuer's keys are read from, before anything is fetched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    /// The JWT VC issuer metadata of an https issuer.
    Metadata(String),
    /// The DID document of a `did:web` issuer.
    DidDocument(String),
}

impl KeySource {
    pub fn address(&self) -> &str {
        match self {
            Self::Metadata(held) | Self::DidDocument(held) => held,
        }
    }
}

/// What an issuer's metadata says of its keys: the set itself, or where it is.
#[derive(Debug, Clone, PartialEq)]
pub enum Published {
    Keys(Vec<Value>),
    At(String),
}

pub fn locate_issuer_keys(issuer: &str) -> Result<KeySource, Unreadable> {
    let refused = || Unreadable::NotAnIssuer(quote(issuer));
    if let Some(method_id) = issuer.strip_prefix("did:web:") {
        let mut segments = method_id.split(':');
        let host = segments
            .next()
            .filter(|host| !host.is_empty())
            .ok_or_else(refused)?;
        // A port is written percent-encoded in the DID, and nothing else is.
        let host = host.replace("%3A", ":");
        if host.contains(['/', '?', '#', '%', '@']) {
            return Err(refused());
        }
        let path: Vec<&str> = segments.collect();
        if path
            .iter()
            .any(|segment| segment.is_empty() || segment.contains(['/', '?', '#']))
        {
            return Err(refused());
        }
        return Ok(KeySource::DidDocument(if path.is_empty() {
            format!("https://{host}/.well-known/did.json")
        } else {
            format!("https://{host}/{}/did.json", path.join("/"))
        }));
    }
    if !commons::address::is_https_or_loopback(issuer) {
        return Err(refused());
    }
    let parsed = url::Url::parse(issuer).map_err(|_| refused())?;
    if parsed.query().is_some()
        || parsed.fragment().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(refused());
    }
    let authority = &parsed[..url::Position::BeforePath];
    let path = parsed.path().trim_end_matches('/');
    Ok(KeySource::Metadata(format!(
        "{authority}/.well-known/jwt-vc-issuer{path}"
    )))
}

/// What an https issuer's metadata says of its keys, refusing metadata that
/// speaks for another issuer.
pub fn read_issuer_metadata(issuer: &str, document: &str) -> Result<Published, Unreadable> {
    let Ok(Value::Object(said)) = serde_json::from_str::<Value>(document) else {
        return Err(Unreadable::NotADocument);
    };
    match said.get("issuer").and_then(Value::as_str) {
        Some(same) if same == issuer => {}
        Some(other) => return Err(Unreadable::AnotherIssuer(quote(other))),
        None => return Err(Unreadable::AnotherIssuer(String::new())),
    }
    match (
        said.get("jwks"),
        said.get("jwks_uri").and_then(Value::as_str),
    ) {
        (Some(set), None) => read_keys(set).map(Published::Keys),
        (None, Some(uri)) if commons::address::is_https_or_loopback(uri) => {
            Ok(Published::At(uri.to_owned()))
        }
        (None, Some(_)) => Err(Unreadable::InsecureKeySet),
        _ => Err(Unreadable::NoKeySet),
    }
}

/// The keys a published key set holds.
pub fn read_key_set(document: &str) -> Result<Vec<Value>, Unreadable> {
    let set = serde_json::from_str::<Value>(document).map_err(|_| Unreadable::NotAKeySet)?;
    read_keys(&set)
}

/// The keys a `did:web` issuer asserts with, each named by its method's
/// absolute identifier.
pub fn read_did_document(did: &str, document: &str) -> Result<Vec<Value>, Unreadable> {
    let Ok(Value::Object(said)) = serde_json::from_str::<Value>(document) else {
        return Err(Unreadable::NotADocument);
    };
    match said.get("id").and_then(Value::as_str) {
        Some(same) if same == did => {}
        other => return Err(Unreadable::AnotherDid(quote(other.unwrap_or_default()))),
    }
    let absolute = |id: &str| {
        if id.starts_with('#') {
            format!("{did}{id}")
        } else {
            id.to_owned()
        }
    };
    let methods: Vec<&Map<String, Value>> = said
        .get("verificationMethod")
        .and_then(Value::as_array)
        .map(|listed| listed.iter().filter_map(Value::as_object).collect())
        .unwrap_or_default();
    // Only the keys the issuer asserts with: a credential is signed under the
    // assertion purpose, and a key listed for another purpose is not one.
    let asserted = said
        .get("assertionMethod")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    // MOSIP's issuers list the DID itself there rather than one of its
    // methods: every method its document holds.
    let listed: Vec<Option<&Map<String, Value>>> =
        if asserted.iter().any(|entry| entry.as_str() == Some(did)) {
            methods.iter().copied().map(Some).collect()
        } else {
            asserted
                .iter()
                .map(|entry| match entry {
                    Value::String(id) => {
                        let id = absolute(id);
                        methods
                            .iter()
                            .find(|method| {
                                method.get("id").and_then(Value::as_str).map(absolute)
                                    == Some(id.clone())
                            })
                            .copied()
                    }
                    Value::Object(method) => Some(method),
                    _ => None,
                })
                .collect()
        };
    let mut keys = Vec::new();
    for method in listed {
        let Some(method) = method else { continue };
        let Some(id) = method.get("id").and_then(Value::as_str).map(absolute) else {
            continue;
        };
        if let Some(mut jwk) = method_key(method)? {
            jwk.insert("kid".to_owned(), Value::String(id));
            keys.push(Value::Object(jwk));
        }
        if keys.len() == MOST_KEYS {
            break;
        }
    }
    if keys.is_empty() {
        return Err(Unreadable::NoUsableKey);
    }
    Ok(keys)
}

/// The public key a verification method carries, in whichever of the forms
/// this server reads.
fn method_key(method: &Map<String, Value>) -> Result<Option<Map<String, Value>>, Unreadable> {
    let text = |name: &str| method.get(name).and_then(Value::as_str);
    if let Some(jwk) = method.get("publicKeyJwk") {
        return usable_key(jwk);
    }
    let raw = match (
        text("type"),
        text("publicKeyMultibase"),
        text("publicKeyBase58"),
    ) {
        (Some("Ed25519VerificationKey2020" | "Multikey"), Some(multibase), _) => multibase
            .strip_prefix('z')
            .and_then(base58::decode)
            .and_then(|decoded| decoded.strip_prefix(&[0xed, 0x01][..]).map(<[u8]>::to_vec)),
        (Some("Ed25519VerificationKey2018"), _, Some(written)) => base58::decode(written),
        _ => None,
    };
    Ok(raw.filter(|key| key.len() == 32).map(|key| {
        let mut jwk = Map::new();
        jwk.insert("kty".to_owned(), json!("OKP"));
        jwk.insert("crv".to_owned(), json!("Ed25519"));
        jwk.insert(
            "x".to_owned(),
            json!(data_encoding::BASE64URL_NOPAD.encode(&key)),
        );
        jwk
    }))
}

fn read_keys(set: &Value) -> Result<Vec<Value>, Unreadable> {
    let listed = set
        .get("keys")
        .and_then(Value::as_array)
        .ok_or(Unreadable::NotAKeySet)?;
    let mut keys = Vec::new();
    for key in listed {
        if let Some(mut jwk) = usable_key(key)? {
            if let Some(kid) = key.get("kid").and_then(Value::as_str) {
                jwk.insert("kid".to_owned(), json!(kid));
            }
            keys.push(Value::Object(jwk));
        }
        if keys.len() == MOST_KEYS {
            break;
        }
    }
    if keys.is_empty() {
        return Err(Unreadable::NoUsableKey);
    }
    Ok(keys)
}

/// The public members of a key this server verifies with, `None` for a kind it
/// does not, and a refusal for a key that carries its private half.
fn usable_key(key: &Value) -> Result<Option<Map<String, Value>>, Unreadable> {
    let Some(written) = key.as_object() else {
        return Ok(None);
    };
    if PRIVATE_MEMBERS
        .iter()
        .any(|member| written.contains_key(*member))
    {
        return Err(Unreadable::PrivateKey);
    }
    let text = |name: &str| written.get(name).and_then(Value::as_str);
    let bytes = |name: &str| {
        text(name)
            .and_then(|held| data_encoding::BASE64URL_NOPAD.decode(held.as_bytes()).ok())
            .map_or(0, |decoded| decoded.len())
    };
    let usable = match (text("kty"), text("crv")) {
        (Some("OKP"), Some("Ed25519")) => bytes("x") == 32,
        (Some("EC"), Some("P-256")) => bytes("x") == 32 && bytes("y") == 32,
        (Some("EC"), Some("P-384")) => bytes("x") == 48 && bytes("y") == 48,
        (Some("EC"), Some("P-521")) => bytes("x") == 66 && bytes("y") == 66,
        // A modulus under 2048 bits is not a key this server verifies with.
        (Some("RSA"), _) => bytes("n") >= 256 && bytes("e") > 0,
        _ => false,
    };
    Ok(usable.then(|| {
        PUBLIC_MEMBERS
            .iter()
            .filter_map(|member| Some(((*member).to_owned(), written.get(*member)?.clone())))
            .collect()
    }))
}

fn quote(said: &str) -> String {
    said.chars().take(QUOTED).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED25519_X: &str = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik";
    const ED25519_MULTIBASE: &str = "z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp";

    #[test]
    fn an_issuer_s_keys_are_read_where_its_kind_publishes_them() {
        assert_eq!(
            locate_issuer_keys("https://issuer.example.org/tenant/1234"),
            Ok(KeySource::Metadata(
                "https://issuer.example.org/.well-known/jwt-vc-issuer/tenant/1234".to_owned()
            ))
        );
        assert_eq!(
            locate_issuer_keys("https://issuer.example.org/"),
            Ok(KeySource::Metadata(
                "https://issuer.example.org/.well-known/jwt-vc-issuer".to_owned()
            ))
        );
        assert_eq!(
            locate_issuer_keys("did:web:certify.example.org:v1:certify"),
            Ok(KeySource::DidDocument(
                "https://certify.example.org/v1/certify/did.json".to_owned()
            ))
        );
        assert_eq!(
            locate_issuer_keys("did:web:certify.example.org%3A8443"),
            Ok(KeySource::DidDocument(
                "https://certify.example.org:8443/.well-known/did.json".to_owned()
            ))
        );
        for refused in [
            "http://issuer.example.org",
            "https://issuer.example.org/?tenant=1",
            "did:web:",
            "did:web:host::path",
            "did:key:z6Mk",
        ] {
            assert!(
                matches!(locate_issuer_keys(refused), Err(Unreadable::NotAnIssuer(_))),
                "{refused} was taken"
            );
        }
    }

    #[test]
    fn metadata_speaks_for_its_issuer_and_names_one_key_set() {
        let issuer = "https://issuer.example.org";
        let inline = json!({
            "issuer": issuer,
            "jwks": { "keys": [{ "kty": "OKP", "crv": "Ed25519", "x": ED25519_X, "kid": "k1", "use": "sig" }] }
        })
        .to_string();
        assert_eq!(
            read_issuer_metadata(issuer, &inline),
            Ok(Published::Keys(vec![
                json!({ "kty": "OKP", "crv": "Ed25519", "x": ED25519_X, "kid": "k1" })
            ]))
        );
        let pointed = json!({ "issuer": issuer, "jwks_uri": "https://issuer.example.org/jwks" });
        assert_eq!(
            read_issuer_metadata(issuer, &pointed.to_string()),
            Ok(Published::At("https://issuer.example.org/jwks".to_owned()))
        );
        let other = json!({ "issuer": "https://elsewhere.example", "jwks_uri": "https://elsewhere.example/jwks" });
        assert!(matches!(
            read_issuer_metadata(issuer, &other.to_string()),
            Err(Unreadable::AnotherIssuer(_))
        ));
        let both = json!({ "issuer": issuer, "jwks": { "keys": [] }, "jwks_uri": "https://issuer.example.org/jwks" });
        assert_eq!(
            read_issuer_metadata(issuer, &both.to_string()),
            Err(Unreadable::NoKeySet)
        );
        let plain = json!({ "issuer": issuer, "jwks_uri": "http://issuer.example.org/jwks" });
        assert_eq!(
            read_issuer_metadata(issuer, &plain.to_string()),
            Err(Unreadable::InsecureKeySet)
        );
    }

    #[test]
    fn a_published_private_key_refuses_the_whole_set() {
        let set = json!({ "keys": [
            { "kty": "OKP", "crv": "Ed25519", "x": ED25519_X },
            { "kty": "OKP", "crv": "Ed25519", "x": ED25519_X, "d": ED25519_X },
        ] });
        assert_eq!(read_key_set(&set.to_string()), Err(Unreadable::PrivateKey));
    }

    #[test]
    fn a_key_this_server_does_not_verify_with_is_passed_over() {
        let short_modulus = data_encoding::BASE64URL_NOPAD.encode(&[0xab; 128]);
        let set = json!({ "keys": [
            { "kty": "RSA", "n": short_modulus, "e": "AQAB" },
            { "kty": "EC", "crv": "secp256k1", "x": ED25519_X, "y": ED25519_X },
        ] });
        assert_eq!(read_key_set(&set.to_string()), Err(Unreadable::NoUsableKey));
    }

    #[test]
    fn a_did_web_issuer_is_read_for_the_keys_it_asserts_with() {
        let did = "did:web:certify.example.org";
        let document = json!({
            "id": did,
            "verificationMethod": [
                {
                    "id": format!("{did}#asserts"),
                    "type": "Ed25519VerificationKey2020",
                    "controller": did,
                    "publicKeyMultibase": ED25519_MULTIBASE
                },
                {
                    "id": "#authenticates",
                    "type": "JsonWebKey2020",
                    "controller": did,
                    "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": ED25519_X }
                }
            ],
            "authentication": ["#authenticates"],
            "assertionMethod": ["#asserts"]
        });
        assert_eq!(
            read_did_document(did, &document.to_string()),
            Ok(vec![json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": ED25519_X,
                "kid": format!("{did}#asserts")
            })])
        );
        assert!(matches!(
            read_did_document("did:web:elsewhere.example", &document.to_string()),
            Err(Unreadable::AnotherDid(_))
        ));
        let nothing_asserted =
            json!({ "id": did, "verificationMethod": document["verificationMethod"] });
        assert_eq!(
            read_did_document(did, &nothing_asserted.to_string()),
            Err(Unreadable::NoUsableKey)
        );
    }

    /// The DID listed as its own assertion method, as MOSIP's issuers write it,
    /// asserts with every method its document holds that this server reads.
    #[test]
    fn a_did_listed_as_its_own_assertion_method_asserts_with_each_of_its_keys() {
        let did = "did:web:inji.github.io:inji-config:collab:mosipid-identity";
        let document = json!({
            "id": did,
            "verificationMethod": [
                {
                    "id": format!("{did}#k1"),
                    "type": "EcdsaSecp256k1VerificationKey2019",
                    "controller": did,
                    "publicKeyJwk": { "kty": "EC", "crv": "secp256k1", "x": ED25519_X, "y": ED25519_X }
                },
                {
                    "id": format!("{did}#k2"),
                    "type": "Ed25519VerificationKey2020",
                    "controller": did,
                    "publicKeyMultibase": ED25519_MULTIBASE
                }
            ],
            "assertionMethod": [did]
        });
        assert_eq!(
            read_did_document(did, &document.to_string()),
            Ok(vec![json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": ED25519_X,
                "kid": format!("{did}#k2")
            })])
        );
        let another = json!({
            "id": did,
            "verificationMethod": document["verificationMethod"],
            "assertionMethod": ["did:web:elsewhere.example"]
        });
        assert_eq!(
            read_did_document(did, &another.to_string()),
            Err(Unreadable::NoUsableKey)
        );
    }
}
