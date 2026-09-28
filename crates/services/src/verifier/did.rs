//! The identifier a realm answers to as a verifier, and the document a wallet
//! resolves it to.
//!
//! A wallet that takes a request signed under `did:web` fetches this document
//! and picks the key whose `id` equals the request's `kid`, character for
//! character. The key is the realm's own Ed25519 signing key, minted, rotated
//! and retired like its other keys.

use models::entities::keys::RealmSigningKeyView;
use serde_json::{Value, json};
use url::Url;

use super::base58;

/// The multicodec prefix of an Ed25519 public key.
const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];

/// The `did:web` a realm answers to, read from its issuer.
///
/// The host, a port percent-encoded after it, then each segment of the path:
/// `https://id.example.org/realms/main` is `did:web:id.example.org:realms:main`,
/// whose document is served at `https://id.example.org/realms/main/did.json`.
pub fn realm_did(issuer: &str) -> Option<String> {
    let url = Url::parse(issuer).ok()?;
    let mut did = format!("did:web:{}", url.host_str()?);
    if let Some(port) = url.port() {
        did.push_str(&format!("%3A{port}"));
    }
    for segment in url.path_segments()?.filter(|segment| !segment.is_empty()) {
        did.push(':');
        did.push_str(segment);
    }
    Some(did)
}

/// The document the realm's DID resolves to, or `None` while the realm holds
/// no Ed25519 key to sign a request with.
///
/// Every published Ed25519 key is listed, the one in retreat as well, so a
/// request signed just before a rotation still verifies. The address answers
/// come back to is declared as a service: a wallet may refuse a request whose
/// `response_uri` its verifier's DID does not declare.
pub fn realm_did_document(
    did: &str,
    keys: &[RealmSigningKeyView],
    response_uri: &str,
) -> Option<Value> {
    let methods: Vec<(String, String)> = keys
        .iter()
        .filter_map(|key| Some((format!("{did}#{}", key.kid), multibase_of(&key.public_jwk)?)))
        .collect();
    if methods.is_empty() {
        return None;
    }
    let ids: Vec<&str> = methods.iter().map(|(id, _)| id.as_str()).collect();
    Some(json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        "id": did,
        // One representation of each key. A resolver that picks the field to
        // read and the decoding to apply in two different orders reads a key
        // given twice with the wrong decoder.
        "verificationMethod": methods
            .iter()
            .map(|(id, multibase)| json!({
                "id": id,
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyMultibase": multibase,
            }))
            .collect::<Vec<_>>(),
        "authentication": ids,
        "assertionMethod": ids,
        "service": [{
            "id": format!("{did}#presentation-response"),
            "type": "OpenID4VPResponseEndpoint",
            "serviceEndpoint": response_uri,
        }],
    }))
}

/// An Ed25519 public JWK written as `publicKeyMultibase`: the multicodec
/// prefix and the raw key, in base58btc, marked `z`.
fn multibase_of(jwk: &Value) -> Option<String> {
    if jwk.get("kty")?.as_str()? != "OKP" || jwk.get("crv")?.as_str()? != "Ed25519" {
        return None;
    }
    let raw = data_encoding::BASE64URL_NOPAD
        .decode(jwk.get("x")?.as_str()?.as_bytes())
        .ok()?;
    if raw.len() != 32 {
        return None;
    }
    let mut prefixed = ED25519_MULTICODEC.to_vec();
    prefixed.extend_from_slice(&raw);
    Some(format!("z{}", base58::encode(&prefixed)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::provider::SignAlg;
    use models::entities::keys::{KeyStatus, KeyUse};

    const RESPONSE: &str = "https://id.example.org/realms/main/vp/response";

    fn key(kid: &str, algorithm: SignAlg, public_jwk: Value) -> RealmSigningKeyView {
        RealmSigningKeyView {
            kid: kid.to_owned(),
            realm_id: "main".to_owned(),
            algorithm,
            key_type: "OKP".to_owned(),
            key_use: KeyUse::Sig,
            status: KeyStatus::Active,
            priority: 100,
            public_jwk,
            created_at: 0,
        }
    }

    #[test]
    fn a_realm_did_is_its_issuer_read_as_a_web_did() {
        assert_eq!(
            realm_did("https://id.example.org/realms/main").as_deref(),
            Some("did:web:id.example.org:realms:main")
        );
        assert_eq!(
            realm_did("https://id.example.org:8443/auth/realms/main").as_deref(),
            Some("did:web:id.example.org%3A8443:auth:realms:main")
        );
        assert_eq!(realm_did("not a url"), None);
    }

    /// The first Ed25519 example of the `did:key` specification: the JWK `x`
    /// and the multibase it writes for the same key.
    #[test]
    fn an_ed25519_key_is_written_as_the_did_specifications_write_it() {
        let jwk = json!({ "kty": "OKP", "crv": "Ed25519", "x": "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik" });
        assert_eq!(
            multibase_of(&jwk).as_deref(),
            Some("z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
        );
    }

    #[test]
    fn the_document_lists_the_ed25519_keys_and_nothing_else() {
        let did = "did:web:id.example.org:realms:main";
        let ed = json!({ "kty": "OKP", "crv": "Ed25519", "x": "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik" });
        // A P-256 key whose `x` is 32 bytes too: only its type tells them apart.
        let ec = json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik",
            "y": "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik"
        });

        assert_eq!(
            realm_did_document(did, &[key("es", SignAlg::Es256, ec.clone())], RESPONSE),
            None,
            "a realm with no Ed25519 key has no key to sign a request with"
        );

        let document = realm_did_document(
            did,
            &[key("es", SignAlg::Es256, ec), key("ed", SignAlg::EdDsa, ed)],
            RESPONSE,
        )
        .expect("a document");
        assert_eq!(document["id"], did);
        let methods = document["verificationMethod"].as_array().expect("methods");
        assert_eq!(methods.len(), 1);
        assert_eq!(methods[0]["id"], format!("{did}#ed"));
        assert_eq!(methods[0]["type"], "Ed25519VerificationKey2020");
        assert_eq!(methods[0]["controller"], did);
        assert_eq!(
            methods[0]["publicKeyMultibase"],
            "z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
        );
        assert!(
            methods[0].get("publicKeyJwk").is_none(),
            "a key given twice is read with the wrong decoder"
        );
        assert_eq!(document["authentication"], json!([format!("{did}#ed")]));
        assert_eq!(document["assertionMethod"], json!([format!("{did}#ed")]));
        assert_eq!(
            document["service"][0]["serviceEndpoint"], RESPONSE,
            "the answers' address is not declared"
        );
    }
}
