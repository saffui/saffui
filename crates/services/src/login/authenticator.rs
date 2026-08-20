//! What a step actually runs.
//!
//! Named rather than looked up. A registry keyed by string turns a flow that
//! names an authenticator this build does not have into a step that quietly
//! does nothing, and a step that does nothing in a flow of alternatives is a
//! way in nobody wrote.

use std::str::FromStr;

use crypto::otp::totp::{TotpParams, totp_verify_step};
use crypto::password::StoredPassword;
use crypto::password::migration::{burn_verification_time, verify_and_plan};
use crypto::provider::CryptoProvider;
use data_encoding::BASE32_NOPAD;
use deadpool_postgres::Transaction;
use models::entities::credentials::{CredentialType, OtpCredentialData, OtpParameters};
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
    /// A time-based code, against the shared secret the realm stores.
    Totp,
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
            "totp" => Ok(Self::Totp),
            other => Err(Unknown(other.to_owned())),
        }
    }
}

impl Authenticator {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Totp => "totp",
        }
    }

    /// The authentication context this one reaches.
    ///
    /// Not the same vocabulary as the name, and deliberately. A flow names an
    /// authenticator, an `acr` names a *class* of authentication, and a realm
    /// maps the class rather than the mechanism: a second factor is a second
    /// factor whether it arrives by code, by key or by push, and a client asking
    /// for one should not have to name which the realm happens to run.
    pub fn context(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Totp => "mfa",
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
    /// The digits typed, as typed. Parsed where it is verified, so a code with
    /// the spaces an app renders is the code the user read.
    Totp(String),
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
    answers: &[Answer],
) -> Outcome {
    match authenticator {
        Authenticator::Password => password(transaction, provider, realm, subject, answers).await,
        Authenticator::Totp => totp(transaction, provider, subject, answers).await,
    }
}

/// The one answer a step understands, of everything the caller sent.
///
/// A flow runs every step against what it was given, so a login resumed with a
/// second factor still has to satisfy the first. Handing each step the whole set
/// and letting it take its own kind is what makes that possible without the
/// runner remembering which steps already passed.
fn of_kind(answers: &[Answer], wanted: fn(&Answer) -> bool) -> Option<&Answer> {
    answers.iter().find(|answer| wanted(answer))
}

async fn password(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    realm: &RealmModel,
    subject: Option<&UserModel>,
    answers: &[Answer],
) -> Outcome {
    let Some(Answer::Password(offered)) =
        of_kind(answers, |answer| matches!(answer, Answer::Password(_)))
    else {
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

/// How far either side of now a code is still accepted.
///
/// One step, which is thirty seconds at the usual period. It buys tolerance for
/// a clock that drifts and a user who types slowly, and it costs acceptance
/// width: a code stays good for `period * (2 * WINDOW + 1)`, ninety seconds
/// here, which is exactly why the step it was accepted at has to be spent.
const WINDOW: u32 = 1;

/// A time-based code, against what the realm stores.
async fn totp(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    subject: Option<&UserModel>,
    answers: &[Answer],
) -> Outcome {
    let Some(Answer::Totp(typed)) = of_kind(answers, |answer| matches!(answer, Answer::Totp(_)))
    else {
        // Nothing answered, so the caller is asked. A step with no answer has
        // not failed; it has not run.
        return Outcome::Pending;
    };
    // No decoy here. A second factor runs only once a first has said who this
    // is, so the name is already known to whoever is asking and the timing tells
    // them nothing they did not have.
    let Some(subject) = subject else {
        return Outcome::Failed;
    };
    let Some(code) = parse_code(typed) else {
        return Outcome::Failed;
    };

    let held =
        credentials::load_for_user_of_type(transaction, &subject.user_id, CredentialType::Totp)
            .await;
    let Ok(held) = held else {
        return Outcome::Failed;
    };
    let Some(credential) = held.into_iter().next() else {
        return Outcome::Failed;
    };
    let Some(OtpCredentialData {
        algorithm,
        parameters: OtpParameters::Totp { digits, period },
    }) = credential.otp
    else {
        // A row that says `totp` and holds a counter is one no verifier reads,
        // and reading it as the nearest thing it has is how a credential of one
        // kind gets checked as another.
        return Outcome::Failed;
    };

    let Ok(secret) = BASE32_NOPAD.decode(credential.secret.expose().as_bytes()) else {
        return Outcome::Failed;
    };
    let secret = SecretBox::new(Box::new(secret));

    let step = totp_verify_step(
        provider.hmac(),
        &secret,
        code,
        TotpParams {
            period,
            digits,
            hash: algorithm.hash(),
        },
        WINDOW,
    );
    let Ok(Some(step)) = step else {
        return Outcome::Failed;
    };

    // Spent before the step is called a success. RFC 6238 §5.2 refuses a code
    // presented twice, and a failure to record one hands out a login whose code
    // stays replayable for the rest of the window.
    match credentials::consume_otp_step(transaction, &credential.credential_id, step as i64).await {
        Ok(true) => Outcome::Passed,
        _ => Outcome::Failed,
    }
}

/// The digits, tolerating the spaces an authenticator app renders.
fn parse_code(typed: &str) -> Option<u32> {
    typed.split_whitespace().collect::<String>().parse().ok()
}
