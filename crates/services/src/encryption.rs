use crypto::envelope::Envelope;
use crypto::jose::jwe::{
    ECDH_ES, ECDH_ES_A128KW, ECDH_ES_A192KW, ECDH_ES_A256KW, JweDecrypter, JweEncrypter, JweHeader,
    RSA_OAEP, RSA_OAEP_256, RSA_OAEP_384, RSA_OAEP_512, deserialize_compact, serialize_compact,
};
use crypto::jose::jwk::{Jwk, JwkSet};
use crypto::jose::jwt;
use deadpool_postgres::Transaction;
use models::entities::client::{ClientModel, JweRegistration};
use models::entities::keys::JweAlgorithm;
use serde_json::Value;
use store::keyring::RealmKeyring;
use store::providers::realm_keys;

/// Why a client that registered encryption could not be encrypted to.
///
/// Every one of these is an error the caller answers with. A client that asked
/// to be answered with something encrypted and is answered in the clear has
/// been told nothing about it, so "encrypted when possible" is how a stripped
/// key set silently turns encryption off.
#[derive(Debug, thiserror::Error)]
pub enum Unsealable {
    #[error("the client published no keys to encrypt to")]
    NoKeys,
    #[error("the client published no key this algorithm can use")]
    NoFittingKey,
    #[error("the payload could not be encrypted")]
    Unusable,
}

/// Wrap a payload for one client, under what that client registered.
///
/// `content_type` is what the wrapped payload is, and it is `JWT` whenever a
/// signature is being wrapped: a nested JWT says so in its header, so the
/// recipient knows to verify what it decrypts rather than read it as claims.
pub fn sealed_for(
    client: &ClientModel,
    registration: JweRegistration,
    payload: &[u8],
    content_type: Option<&str>,
) -> Result<String, Unsealable> {
    let jwk = recipient_key(client, registration.alg)?;
    let encrypter = encrypter_for(registration.alg, &jwk).ok_or(Unsealable::NoFittingKey)?;

    let mut header = JweHeader::new();
    header.set_algorithm(registration.alg.as_str());
    header.set_content_encryption(registration.enc.as_str());
    if let Some(kid) = jwk.key_id() {
        header.set_key_id(kid);
    }
    if let Some(named) = content_type {
        header.set_content_type(named);
    }

    serialize_compact(payload, &header, &*encrypter).map_err(|_| Unsealable::Unusable)
}

/// Choose, among the keys this client published, the one this algorithm needs.
///
/// Choosing, not vetting: the encrypter refuses a key whose kind, use or
/// algorithm does not suit it, so a key that reaches it unsuitable is refused
/// there. What it cannot do is look past it. A client that publishes a signing
/// key beside an encryption one is answered from the second only if something
/// walks to it, and that is this.
fn recipient_key(client: &ClientModel, alg: JweAlgorithm) -> Result<Jwk, Unsealable> {
    let published = client.jwks.as_ref().ok_or(Unsealable::NoKeys)?;
    let set = JwkSet::from_map(published.as_object().cloned().ok_or(Unsealable::NoKeys)?)
        .map_err(|_| Unsealable::NoKeys)?;

    let wanted = alg.as_str();
    let kinds = alg.key_types();
    set.keys()
        .into_iter()
        .find(|key| {
            kinds.contains(&key.key_type())
                && key.key_use().is_none_or(|held| held == "enc")
                && key.algorithm().is_none_or(|stated| stated == wanted)
        })
        .cloned()
        .ok_or(Unsealable::NoFittingKey)
}

fn encrypter_for(alg: JweAlgorithm, jwk: &Jwk) -> Option<Box<dyn JweEncrypter>> {
    let encrypter = match alg {
        JweAlgorithm::RsaOaep => {
            Box::new(RSA_OAEP.encrypter_from_jwk(jwk).ok()?) as Box<dyn JweEncrypter>
        }
        JweAlgorithm::RsaOaep256 => {
            Box::new(RSA_OAEP_256.encrypter_from_jwk(jwk).ok()?) as Box<dyn JweEncrypter>
        }
        JweAlgorithm::RsaOaep384 => {
            Box::new(RSA_OAEP_384.encrypter_from_jwk(jwk).ok()?) as Box<dyn JweEncrypter>
        }
        JweAlgorithm::RsaOaep512 => {
            Box::new(RSA_OAEP_512.encrypter_from_jwk(jwk).ok()?) as Box<dyn JweEncrypter>
        }
        JweAlgorithm::EcdhEs => {
            Box::new(ECDH_ES.encrypter_from_jwk(jwk).ok()?) as Box<dyn JweEncrypter>
        }
        JweAlgorithm::EcdhEsA128kw => {
            Box::new(ECDH_ES_A128KW.encrypter_from_jwk(jwk).ok()?) as Box<dyn JweEncrypter>
        }
        JweAlgorithm::EcdhEsA192kw => {
            Box::new(ECDH_ES_A192KW.encrypter_from_jwk(jwk).ok()?) as Box<dyn JweEncrypter>
        }
        JweAlgorithm::EcdhEsA256kw => {
            Box::new(ECDH_ES_A256KW.encrypter_from_jwk(jwk).ok()?) as Box<dyn JweEncrypter>
        }
    };
    Some(encrypter)
}

/// An identity token as this client registered to receive it.
///
/// Signed first and encrypted after, which is a nested JWT: the header says
/// `cty: "JWT"` so the recipient verifies what it decrypts rather than reading
/// it as claims. Only the identity token is wrapped. The access and refresh
/// tokens stay as they are: they are this server's to read back, not the
/// client's.
pub fn identity_for(client: &ClientModel, signed: String) -> Result<String, Unsealable> {
    match client.id_token_encryption {
        None => Ok(signed),
        Some(registration) => sealed_for(client, registration, signed.as_bytes(), Some("JWT")),
    }
}

/// Why a request object this client sent could not be opened.
#[derive(Debug, thiserror::Error)]
pub enum Unopenable {
    /// Which covers an object sent in the clear: a signature names no `enc`.
    #[error("the object names something other than what this client registered")]
    Misnamed,
    #[error("this realm holds no key of the algorithm the object names")]
    NoKey,
    #[error("the object could not be opened")]
    Unreadable,
}

/// The request object to verify, opened first where this client encrypts.
///
/// A client that registered encryption **must** encrypt: an object in the clear
/// from such a client is refused rather than read, because reading it would
/// accept from anybody what only that client can send.
///
/// The header is checked against what was registered before anything is
/// decrypted. A client that registered one pair and sent another is refused on
/// what it named, not on whether the key happened to work.
pub async fn opened_request_object(
    transaction: &Transaction<'_>,
    ring: &RealmKeyring,
    envelope: &Envelope,
    client: &ClientModel,
    token: &str,
) -> Result<String, Unopenable> {
    let Some(registration) = client.request_object_encryption else {
        return Ok(token.to_owned());
    };
    let header = jwt::decode_header(token).map_err(|_| Unopenable::Misnamed)?;
    // The object in the clear is refused here too, and by `enc` alone: a
    // signature's header never carries one, so a client that registered
    // encryption and signed instead has named something other than its pair.
    if header.claim("alg").and_then(Value::as_str) != Some(registration.alg.as_str())
        || header.claim("enc").and_then(Value::as_str) != Some(registration.enc.as_str())
    {
        return Err(Unopenable::Misnamed);
    }

    let key = realm_keys::active_encryption(transaction, ring, envelope, registration.alg)
        .await
        .map_err(|_| Unopenable::Unreadable)?
        .ok_or(Unopenable::NoKey)?;
    let decrypter = decrypter_for(registration.alg, &key.private_pem).ok_or(Unopenable::NoKey)?;
    let (payload, _) =
        deserialize_compact(token, &*decrypter).map_err(|_| Unopenable::Unreadable)?;
    String::from_utf8(payload).map_err(|_| Unopenable::Unreadable)
}

fn decrypter_for(alg: JweAlgorithm, pem: &[u8]) -> Option<Box<dyn JweDecrypter>> {
    let decrypter = match alg {
        JweAlgorithm::RsaOaep => {
            Box::new(RSA_OAEP.decrypter_from_pem(pem).ok()?) as Box<dyn JweDecrypter>
        }
        JweAlgorithm::RsaOaep256 => {
            Box::new(RSA_OAEP_256.decrypter_from_pem(pem).ok()?) as Box<dyn JweDecrypter>
        }
        JweAlgorithm::RsaOaep384 => {
            Box::new(RSA_OAEP_384.decrypter_from_pem(pem).ok()?) as Box<dyn JweDecrypter>
        }
        JweAlgorithm::RsaOaep512 => {
            Box::new(RSA_OAEP_512.decrypter_from_pem(pem).ok()?) as Box<dyn JweDecrypter>
        }
        JweAlgorithm::EcdhEs => {
            Box::new(ECDH_ES.decrypter_from_pem(pem).ok()?) as Box<dyn JweDecrypter>
        }
        JweAlgorithm::EcdhEsA128kw => {
            Box::new(ECDH_ES_A128KW.decrypter_from_pem(pem).ok()?) as Box<dyn JweDecrypter>
        }
        JweAlgorithm::EcdhEsA192kw => {
            Box::new(ECDH_ES_A192KW.decrypter_from_pem(pem).ok()?) as Box<dyn JweDecrypter>
        }
        JweAlgorithm::EcdhEsA256kw => {
            Box::new(ECDH_ES_A256KW.decrypter_from_pem(pem).ok()?) as Box<dyn JweDecrypter>
        }
    };
    Some(decrypter)
}
