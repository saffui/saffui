use crypto::envelope::Envelope;
use crypto::provider::{CryptoProvider, SignAlg};
use crypto::thumbprint::jwk_sha256_thumbprint;
use models::entities::sim_swap::{SimSwapKey, SimSwapSettings, WhenUnanswered};
use secrecy::SecretBox;
use store::keyring::RealmKeyring;
use store::providers::realms::sim_swap;
use store::tenancy::UnitOfWork;

/// What a change is asked back over when a realm says nothing, in hours.
pub const MAX_AGE_HOURS: i32 = 72;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unsettable {
    #[error("this realm has no SIM swap settings")]
    NotFound,
    #[error("the client id is the one the carrier gave this realm")]
    NoClient,
    #[error("each endpoint is an http or https URL, named in full")]
    NotAnEndpoint,
    #[error("a change counts back between 1 and 2400 hours")]
    AgeOutOfRange,
    #[error("the settings could not be read or written")]
    Unwritable,
}

pub async fn read(
    transaction: &UnitOfWork,
    ring: &RealmKeyring,
    envelope: &Envelope,
) -> Result<SimSwapSettings, Unsettable> {
    sim_swap::load(transaction, ring, envelope)
        .await
        .map_err(|_| Unsettable::Unwritable)?
        .ok_or(Unsettable::NotFound)
}

/// What an administrator wrote. The key is never written: it is drawn here
/// the first time and kept on every edit after.
pub struct Wanted {
    pub client_id: String,
    pub authorize_url: String,
    pub token_url: String,
    pub check_url: String,
    pub max_age_hours: Option<i32>,
    pub when_unanswered: Option<WhenUnanswered>,
}

pub async fn write(
    transaction: &UnitOfWork,
    ring: &RealmKeyring,
    envelope: &Envelope,
    provider: &dyn CryptoProvider,
    wanted: Wanted,
) -> Result<(), Unsettable> {
    let client_id = wanted.client_id.trim().to_owned();
    if client_id.is_empty() || client_id.len() > 255 {
        return Err(Unsettable::NoClient);
    }
    let endpoints = [
        wanted.authorize_url.trim().to_owned(),
        wanted.token_url.trim().to_owned(),
        wanted.check_url.trim().to_owned(),
    ];
    if !endpoints
        .iter()
        .all(|held| held.starts_with("https://") || held.starts_with("http://"))
    {
        return Err(Unsettable::NotAnEndpoint);
    }
    let max_age_hours = wanted.max_age_hours.unwrap_or(MAX_AGE_HOURS);
    if !(1..=2400).contains(&max_age_hours) {
        return Err(Unsettable::AgeOutOfRange);
    }
    let key = match sim_swap::load(transaction, ring, envelope)
        .await
        .map_err(|_| Unsettable::Unwritable)?
    {
        Some(held) => held.key,
        None => drawn_key(provider)?,
    };
    let [authorize_url, token_url, check_url] = endpoints;

    sim_swap::keep(
        transaction,
        ring,
        envelope,
        &SimSwapSettings {
            client_id,
            authorize_url,
            token_url,
            check_url,
            max_age_hours,
            when_unanswered: wanted.when_unanswered.unwrap_or(WhenUnanswered::Send),
            key,
        },
    )
    .await
    .map_err(|_| Unsettable::Unwritable)
}

pub async fn forget(transaction: &UnitOfWork) -> Result<(), Unsettable> {
    sim_swap::forget(transaction)
        .await
        .map_err(|_| Unsettable::Unwritable)?
        .then_some(())
        .ok_or(Unsettable::NotFound)
}

/// The public half the carrier checks this realm's assertions with, as a key
/// set, and nothing when the realm asks no carrier.
pub async fn read_public_keys(
    transaction: &UnitOfWork,
) -> Result<Option<serde_json::Value>, Unsettable> {
    Ok(sim_swap::public_key(transaction)
        .await
        .map_err(|_| Unsettable::Unwritable)?
        .map(|key| serde_json::json!({ "keys": [key] })))
}

/// A fresh P-256 pair, named by its thumbprint the way the realm's own keys are.
fn drawn_key(provider: &dyn CryptoProvider) -> Result<SimSwapKey, Unsettable> {
    let (mut private, private_pem) =
        crate::admin::realm_keys::generate(SignAlg::Es256).map_err(|_| Unsettable::Unwritable)?;
    let mut public = private
        .to_public_key()
        .map_err(|_| Unsettable::Unwritable)?;
    let kid = jwk_sha256_thumbprint(provider, &public).map_err(|_| Unsettable::Unwritable)?;
    private.set_key_id(&kid);
    public.set_key_id(&kid);
    public.set_algorithm(SignAlg::Es256.name());
    public
        .set_parameter("use", Some(serde_json::json!("sig")))
        .map_err(|_| Unsettable::Unwritable)?;
    Ok(SimSwapKey {
        kid,
        private_pem: SecretBox::new(Box::new(private_pem)),
        public_jwk: serde_json::to_value(public.as_ref()).map_err(|_| Unsettable::Unwritable)?,
    })
}
