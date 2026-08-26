use crypto::jose::jwe::{
    ECDH_ES, ECDH_ES_A128KW, ECDH_ES_A192KW, ECDH_ES_A256KW, JweEncrypter, JweHeader, RSA_OAEP,
    RSA_OAEP_256, RSA_OAEP_384, RSA_OAEP_512, serialize_compact,
};
use crypto::jose::jwk::{Jwk, JwkSet};
use models::entities::client::{ClientModel, JweRegistration};
use models::entities::keys::JweAlgorithm;

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
