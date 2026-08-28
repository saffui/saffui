use crypto::envelope::Envelope;
use crypto::jose::jwk::alg::ec::EcKeyPair;
use crypto::jose::jwk::alg::ed::EdKeyPair;
use crypto::jose::jwk::alg::rsa::RsaKeyPair;
use crypto::jose::jwk::alg::rsapss::RsaPssKeyPair;
use crypto::jose::jwk::{Ed25519, Jwk, KeyPair, P_256, P_384, P_521};
use crypto::jose::util::HashAlgorithm;
use crypto::provider::{CryptoProvider, SignAlg};
use crypto::thumbprint::jwk_sha256_thumbprint;
use deadpool_postgres::Transaction;
use models::entities::keys::{
    KeyStatus, KeyUse, RealmEncryptionKeyView, RealmSigningKey, RealmSigningKeyView,
};
use store::keyring::RealmKeyring;
use store::providers::realm_keys;

/// Why the plane could not turn a key.
#[derive(Debug)]
pub enum Unturnable {
    /// No key of that name, in either set.
    NotFound,
    /// The key is active. What signs or decrypts today is rotated out of
    /// service, never cut from under the tokens naming it.
    StillActive,
    Backend,
}

impl From<store::error::StoreError> for Unturnable {
    fn from(_: store::error::StoreError) -> Self {
        Unturnable::Backend
    }
}

/// Both sets an administrator audits: what publication shows, plus what it
/// deliberately hides.
pub struct Held {
    pub signing: Vec<RealmSigningKeyView>,
    pub encryption: Vec<RealmEncryptionKeyView>,
}

/// Every key the realm holds, disabled ones included.
pub async fn held(transaction: &Transaction<'_>) -> Result<Held, Unturnable> {
    Ok(Held {
        signing: realm_keys::held(transaction, KeyUse::Sig).await?,
        encryption: realm_keys::held_encryption(transaction).await?,
    })
}

/// Give the realm a fresh signer of this algorithm and retire the one it
/// replaces.
///
/// Only that algorithm's active key steps down, and it steps down to passive:
/// tokens it signed are still in flight, and a client that registered another
/// algorithm keeps the signer it registered for. An algorithm the realm never
/// signed with before simply gains its first key.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about the key being minted"
)]
pub async fn rotate(
    transaction: &Transaction<'_>,
    ring: &RealmKeyring,
    envelope: &Envelope,
    provider: &dyn CryptoProvider,
    tenant: &str,
    realm_id: &str,
    algorithm: SignAlg,
    now: i64,
) -> Result<RealmSigningKeyView, Unturnable> {
    let (mut private, private_pem) = generate(algorithm)?;
    let mut public = private.to_public_key().map_err(|_| Unturnable::Backend)?;
    let kid = jwk_sha256_thumbprint(provider, &public).map_err(|_| Unturnable::Backend)?;
    private.set_key_id(&kid);
    private.set_algorithm(algorithm.name());
    public.set_key_id(&kid);
    public.set_algorithm(algorithm.name());

    // One above everything already held, so the published set leads with the
    // newest key and a relying party that takes the first candidate takes the
    // one that signs.
    let priority = realm_keys::held(transaction, KeyUse::Sig)
        .await?
        .iter()
        .map(|key| key.priority)
        .max()
        .map_or(10, |highest| highest + 1);

    let next = RealmSigningKey {
        tenant: tenant.to_owned(),
        realm_id: realm_id.to_owned(),
        kid,
        algorithm,
        key_use: KeyUse::Sig,
        status: KeyStatus::Active,
        priority,
        private_pem,
        public_jwk: serde_json::to_value(public.as_ref()).map_err(|_| Unturnable::Backend)?,
        created_at: now,
    };
    realm_keys::rotate(transaction, ring, envelope, &next).await?;
    Ok(RealmSigningKeyView::from(&next))
}

/// Stop publishing a key, and stop verifying with it.
///
/// Refused while the key is active: tokens are being signed with it right now,
/// and the way out of service runs through [`rotate`], which keeps them
/// verifiable. Disabling twice changes nothing and is not an error.
pub async fn disable(transaction: &Transaction<'_>, kid: &str) -> Result<(), Unturnable> {
    let keys = held(transaction).await?;
    let status = keys
        .signing
        .iter()
        .find(|key| key.kid == kid)
        .map(|key| key.status)
        .or_else(|| {
            keys.encryption
                .iter()
                .find(|key| key.kid == kid)
                .map(|key| key.status)
        })
        .ok_or(Unturnable::NotFound)?;
    if status == KeyStatus::Active {
        return Err(Unturnable::StillActive);
    }
    realm_keys::disable(transaction, kid)
        .await?
        .then_some(())
        .ok_or(Unturnable::NotFound)
}

/// A fresh pair of the algorithm asked for.
///
/// Exhaustive over the catalogue, like the signer it feeds: an algorithm the
/// build can sign with must be one the plane can mint for, or rotation is
/// refused exactly where a key is most wanted.
fn generate(algorithm: SignAlg) -> Result<(Jwk, Vec<u8>), Unturnable> {
    let pair: Box<dyn KeyPair> = match algorithm {
        SignAlg::Rs256 | SignAlg::Rs384 | SignAlg::Rs512 => {
            Box::new(RsaKeyPair::generate(2048).map_err(|_| Unturnable::Backend)?)
        }
        SignAlg::Ps256 => Box::new(
            RsaPssKeyPair::generate(2048, HashAlgorithm::Sha256, HashAlgorithm::Sha256, 32)
                .map_err(|_| Unturnable::Backend)?,
        ),
        SignAlg::Ps384 => Box::new(
            RsaPssKeyPair::generate(2048, HashAlgorithm::Sha384, HashAlgorithm::Sha384, 48)
                .map_err(|_| Unturnable::Backend)?,
        ),
        SignAlg::Ps512 => Box::new(
            RsaPssKeyPair::generate(2048, HashAlgorithm::Sha512, HashAlgorithm::Sha512, 64)
                .map_err(|_| Unturnable::Backend)?,
        ),
        SignAlg::Es256 => Box::new(EcKeyPair::generate(P_256).map_err(|_| Unturnable::Backend)?),
        SignAlg::Es384 => Box::new(EcKeyPair::generate(P_384).map_err(|_| Unturnable::Backend)?),
        SignAlg::Es512 => Box::new(EcKeyPair::generate(P_521).map_err(|_| Unturnable::Backend)?),
        SignAlg::EdDsa => Box::new(EdKeyPair::generate(Ed25519).map_err(|_| Unturnable::Backend)?),
    };
    Ok((pair.to_jwk_key_pair(), pair.to_pem_private_key()))
}
