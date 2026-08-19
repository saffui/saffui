//! What a step actually runs.
//!
//! Named rather than looked up. A registry keyed by string turns a flow that
//! names an authenticator this build does not have into a step that quietly
//! does nothing, and a step that does nothing in a flow of alternatives is a
//! way in nobody wrote.

use std::str::FromStr;

use crypto::password::StoredPassword;
use crypto::password::migration::{burn_verification_time, verify_and_plan};
use crypto::provider::CryptoProvider;
use deadpool_postgres::Transaction;
use models::entities::credentials::CredentialType;
use models::entities::realm::RealmModel;
use models::entities::user::UserModel;
use secrecy::SecretBox;
use store::providers::credentials;

use crate::login::step::Outcome;

/// The authenticators this build knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authenticator {
    /// A username and a password, against the credential the realm stores.
    Password,
}

/// A name no build knows. Refused where a flow is read, so a realm cannot be
/// left with a step nothing runs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("no authenticator is named '{0}'")]
pub struct Unknown(pub String);

impl FromStr for Authenticator {
    type Err = Unknown;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name {
            "password" => Ok(Self::Password),
            other => Err(Unknown(other.to_owned())),
        }
    }
}

impl Authenticator {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
        }
    }
}

/// What a caller answered a challenge with.
///
/// Not cloneable, so an answer is moved to the one place that reads it rather
/// than left in a second copy nothing tracks.
#[derive(Debug)]
pub enum Answer {
    Password(SecretBox<String>),
}

/// Say whether an answer satisfies one authenticator.
///
/// The subject is resolved before this: an authenticator says whether the
/// answer is right, not who is answering.
pub async fn verify_answer(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    realm: &RealmModel,
    subject: Option<&UserModel>,
    authenticator: Authenticator,
    answer: Option<&Answer>,
) -> Outcome {
    match authenticator {
        Authenticator::Password => password(transaction, provider, realm, subject, answer).await,
    }
}

async fn password(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    realm: &RealmModel,
    subject: Option<&UserModel>,
    answer: Option<&Answer>,
) -> Outcome {
    let Some(Answer::Password(offered)) = answer else {
        // Nothing was answered, so the caller is asked. A step with no answer
        // has not failed; it has not run.
        return Outcome::Pending;
    };

    let cost = realm.password_policy.as_ref().map(|policy| policy.hashing);

    let Some(subject) = subject else {
        // No such user. The same work is done anyway, because a login that
        // answers faster for an unknown name than for a known one publishes
        // which names exist.
        burn(provider, offered, cost);
        return Outcome::Failed;
    };

    let held =
        credentials::load_for_user_of_type(transaction, &subject.user_id, CredentialType::Password)
            .await;
    let Ok(held) = held else {
        return Outcome::Failed;
    };
    let Some(credential) = held.into_iter().next() else {
        burn(provider, offered, cost);
        return Outcome::Failed;
    };

    // The column holds a PHC string. A credential in a shape this build does
    // not recognise is refused rather than read as the nearest thing it has.
    let Ok(stored) = StoredPassword::Argon2id {
        encoded: credential.secret.expose().to_owned(),
    }
    .to_legacy_hash() else {
        return Outcome::Failed;
    };

    match verify_and_plan(provider, offered, &stored) {
        Ok(plan) if plan.valid => Outcome::Passed,
        _ => Outcome::Failed,
    }
}

/// Spend what a verification would have spent.
fn burn(
    provider: &dyn CryptoProvider,
    offered: &SecretBox<String>,
    cost: Option<crypto::provider::Argon2Params>,
) {
    if let Some(cost) = cost {
        burn_verification_time(provider, offered, cost);
    }
}
