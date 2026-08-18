//! What one request established, before anything decides anything with it.
//!
//! Assembled once and read by everything downstream. The alternative is each
//! decision gathering its own facts, and then two decisions in one request can
//! disagree about who is asking: the roles are read, the subject is disabled a
//! moment later, and the second decision answers about a different caller than
//! the first. One context per request makes that unrepresentable.
//!
//! Nothing here is taken on the token's word. The token says which realm to ask
//! and which organization the caller means to act within; the store says
//! whether the subject exists, whether it is enabled, and whether it belongs
//! where it claims. A claim is a question, never an answer.

use chrono::{DateTime, Utc};
use deadpool_postgres::Transaction;
use models::entities::client::ClientModel;
use models::entities::user::UserModel;
use store::providers::{clients, organizations, users};
use store::tenancy::TenantContext;

use crate::token::Verified;

/// Who is asking, resolved against the realm rather than read off a token.
///
/// A subject the realm does not hold is not a subject with no attributes, and a
/// disabled one is not a subject with no roles. Both are refusals, and they are
/// refusals here rather than absences an evaluator has to interpret.
#[derive(Debug, Clone)]
pub enum Principal {
    User(Box<UserModel>),
    /// A client acting for itself, with no user behind it.
    Client(Box<ClientModel>),
}

impl Principal {
    pub fn id(&self) -> &str {
        match self {
            Self::User(user) => &user.user_id,
            Self::Client(client) => &client.client_id,
        }
    }

    /// What the journal's `subject_type` column takes. One producer, so two
    /// call sites cannot spell it two ways.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::User(_) => "user",
            Self::Client(_) => "client",
        }
    }
}

/// Which organization the caller is acting within.
///
/// The token names one and the store confirms it. Neither half is enough on its
/// own: without the claim a subject belonging to three organizations is
/// ambiguous and something has to guess, and without the check the claim is a
/// caller choosing its own confinement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Acting {
    In {
        org_id: String,
    },
    /// The caller named no organization, so it acts across the realm.
    RealmWide,
}

/// Why a request established nothing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NotEstablished {
    /// The token names a subject this realm does not hold.
    #[error("the realm holds no such subject")]
    NoSuchSubject,
    /// It holds one and it is switched off. Distinct from the above, because
    /// one is a typo and the other is somebody having been offboarded.
    #[error("the subject is disabled")]
    Disabled,
    /// The token was issued before the subject's tokens were invalidated. The
    /// bulk revocation lever, which works on tokens already minted.
    #[error("the subject's tokens were invalidated after this one was issued")]
    Superseded,
    /// It claims an organization the subject does not belong to.
    #[error("the subject does not belong to the organization it claims")]
    NotAMember,
    #[error("the store could not be read")]
    Unreadable,
}

/// Everything one request established.
#[derive(Debug, Clone)]
pub struct Context {
    pub tenant: TenantContext,
    pub principal: Principal,
    pub acting: Acting,
    /// The client that obtained the token, from `azp`.
    pub presenter: Option<String>,
    /// Read once, so every decision in this request shares an instant and a
    /// replay of any of them reads the same clock.
    pub now: DateTime<Utc>,
}

/// Establish what a verified token means in this realm.
///
/// The token has already been checked for signature, window and withdrawal.
/// What is left is everything the realm has to say about it, and every one of
/// those is a refusal rather than a fact a decision has to make sense of.
pub async fn establish(
    transaction: &Transaction<'_>,
    tenant: TenantContext,
    verified: &Verified,
    now: DateTime<Utc>,
) -> Result<Context, NotEstablished> {
    let principal = resolve(transaction, &verified.subject).await?;
    live(&principal, verified, now)?;

    let acting = acting(transaction, &principal, verified).await?;

    Ok(Context {
        tenant,
        principal,
        acting,
        presenter: verified
            .claims
            .get("azp")
            .and_then(|party| party.as_str())
            .map(str::to_owned),
        now,
    })
}

/// The subject the token names, as a user or as a client acting for itself.
async fn resolve(
    transaction: &Transaction<'_>,
    subject: &str,
) -> Result<Principal, NotEstablished> {
    if let Some(user) = users::load(transaction, subject)
        .await
        .map_err(|_| NotEstablished::Unreadable)?
    {
        return Ok(Principal::User(Box::new(user)));
    }

    clients::load(transaction, subject)
        .await
        .map_err(|_| NotEstablished::Unreadable)?
        .map(|client| Principal::Client(Box::new(client)))
        .ok_or(NotEstablished::NoSuchSubject)
}

/// Whether the realm still stands behind this subject and this token.
///
/// A window says when a token stops on its own and a withdrawal names one
/// token. Neither reaches the case an administrator actually reaches for:
/// switching an account off, or invalidating everything minted for it before
/// now. Those live on the subject, and nothing was reading them.
fn live(
    principal: &Principal,
    verified: &Verified,
    now: DateTime<Utc>,
) -> Result<(), NotEstablished> {
    let (enabled, not_before) = match principal {
        Principal::User(user) => (user.enabled, user.not_before),
        // An absent flag is a client nobody switched on or off. Read as enabled,
        // which is what a client that authenticated a moment ago must be.
        Principal::Client(client) => (client.enabled.unwrap_or(true), None),
    };

    if !enabled {
        return Err(NotEstablished::Disabled);
    }

    // Against what the token says of itself rather than against the instant, so
    // a token minted before the cut is refused however long it is presented
    // after it.
    if let Some(cut) = not_before {
        let issued = verified
            .claims
            .get("iat")
            .and_then(|iat| iat.as_i64())
            .unwrap_or_else(|| now.timestamp());
        if issued < cut {
            return Err(NotEstablished::Superseded);
        }
    }

    Ok(())
}

/// Which organization the caller acts within, claimed and then confirmed.
async fn acting(
    transaction: &Transaction<'_>,
    principal: &Principal,
    verified: &Verified,
) -> Result<Acting, NotEstablished> {
    let Some(claimed) = verified
        .claims
        .get("org_id")
        .and_then(|org| org.as_str())
        .filter(|org| !org.is_empty())
    else {
        return Ok(Acting::RealmWide);
    };

    // Only a user belongs to an organization; a client acting for itself has no
    // membership to confirm, so a client claiming one is claiming something
    // that cannot be true.
    let Principal::User(user) = principal else {
        return Err(NotEstablished::NotAMember);
    };

    let belongs = organizations::of_member(transaction, &user.user_id)
        .await
        .map_err(|_| NotEstablished::Unreadable)?
        .iter()
        .any(|org| org == claimed);

    if !belongs {
        return Err(NotEstablished::NotAMember);
    }

    Ok(Acting::In {
        org_id: claimed.to_owned(),
    })
}
