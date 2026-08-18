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
use models::entities::user::UserModel;
use models::sessions::records::UserSessionState;
use store::providers::{organizations, sessions, users};
use store::tenancy::TenantContext;

use crate::token::Verified;

/// Who is asking, resolved against the realm rather than read off a token.
///
/// A user, and only a user. What reaches here is an access token bound to a
/// login, and a machine has no login: a client acting for itself is turned away
/// before this, so an arm for one would be an arm nothing can build. When a
/// machine is given a way in it gets its own, named, rather than arriving as a
/// user with something missing.
///
/// A subject the realm does not hold is not a subject with no attributes, and a
/// disabled one is not a subject with no roles. Both are refusals, and they are
/// refusals here rather than absences an evaluator has to interpret.
#[derive(Debug, Clone)]
pub struct Principal(Box<UserModel>);

impl Principal {
    pub fn id(&self) -> &str {
        &self.0.user_id
    }

    pub fn user(&self) -> &UserModel {
        &self.0
    }

    /// What the journal's `subject_type` column takes. One producer, so two
    /// call sites cannot spell it two ways.
    pub fn kind(&self) -> &'static str {
        "user"
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
    /// Not an access token bound to a login. Refused by what it is rather than
    /// by failing some later lookup, so a refresh token, an identity token and
    /// a token minted for a machine are each turned away for the reason they
    /// are turned away for.
    #[error("the token is not an access token bound to a login")]
    NotAnAccessToken,
    /// It names a login that has ended, or one that never existed. The lever
    /// every other one misses: logging out.
    #[error("the login this token was minted for has ended")]
    LoggedOut,
    #[error("the store could not be read")]
    Unreadable,
}

/// Everything one request established.
#[derive(Debug, Clone)]
pub struct Context {
    pub tenant: TenantContext,
    /// The login the token was minted for, still open. What a logout closes.
    pub session_id: String,
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
    let session_id = access_token(verified)?;
    let principal = resolve(transaction, &verified.subject).await?;
    live(&principal, verified, now)?;
    logged_in(transaction, &session_id, &tenant, &principal, now).await?;

    let acting = acting(transaction, &principal, verified).await?;

    Ok(Context {
        tenant,
        session_id,
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

/// The login this token was minted for, or a refusal saying it names none.
///
/// Two claims and both are required. `typ` turns away a refresh token and an
/// identity token, which are minted for other purposes and would otherwise pass
/// every check a bearer passes. `sid` turns away a token minted for a machine,
/// which has no login behind it and therefore nothing a logout could close.
fn access_token(verified: &Verified) -> Result<String, NotEstablished> {
    let claim = |name: &str| {
        verified
            .claims
            .get(name)
            .and_then(|value| value.as_str())
            .filter(|value| !value.is_empty())
    };

    if claim("typ") != Some("Bearer") {
        return Err(NotEstablished::NotAnAccessToken);
    }

    claim("sid")
        .map(str::to_owned)
        .ok_or(NotEstablished::NotAnAccessToken)
}

/// Whether the login is still open, and is the one this token belongs to.
///
/// The only lever that answers a logout. An expiry cannot be brought forward, a
/// withdrawal names one token, and switching an account off ends every login it
/// has: this ends the one that was ended.
///
/// The session has to name the same realm and the same subject as the token,
/// because an identifier on its own is only a string. Without the check, a live
/// session belonging to somebody else, or to another realm, is a way in.
async fn logged_in(
    transaction: &Transaction<'_>,
    session_id: &str,
    tenant: &TenantContext,
    principal: &Principal,
    now: DateTime<Utc>,
) -> Result<(), NotEstablished> {
    let session = sessions::load(transaction, session_id)
        .await
        .map_err(|_| NotEstablished::Unreadable)?
        .ok_or(NotEstablished::LoggedOut)?;

    // One state of the four is open. A logout that is still propagating is not
    // a login, and one that never confirmed is neither usable nor provably
    // ended, which is exactly the case that must not read as usable.
    if session.state != UserSessionState::LoggedIn {
        return Err(NotEstablished::LoggedOut);
    }

    if session
        .expiration
        .is_some_and(|ends| ends <= now.timestamp())
    {
        return Err(NotEstablished::LoggedOut);
    }

    if session.realm_id != tenant.realm_id || session.user_id != principal.id() {
        return Err(NotEstablished::LoggedOut);
    }

    Ok(())
}

/// The subject the token names, as a user or as a client acting for itself.
async fn resolve(
    transaction: &Transaction<'_>,
    subject: &str,
) -> Result<Principal, NotEstablished> {
    users::load(transaction, subject)
        .await
        .map_err(|_| NotEstablished::Unreadable)?
        .map(|user| Principal(Box::new(user)))
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
    let user = principal.user();
    let (enabled, not_before) = (user.enabled, user.not_before);

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

    let belongs = organizations::of_member(transaction, principal.id())
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
