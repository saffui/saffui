use chrono::{DateTime, Utc};
use deadpool_postgres::Transaction;
use models::entities::user::UserModel;
use models::sessions::records::UserSessionState;
use store::providers::{organizations, sessions, users};
use store::tenancy::TenantContext;

use crate::token::Verified;

/// Who is asking, resolved against the realm rather than read off a token.
///
/// A user, and only a user: what reaches here is an access token bound to a
/// login, and a machine has no login. When a machine is given a way in it gets
/// one of its own rather than arriving as a user with something missing.
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

/// Which organization the caller is acting within: the token names one and the
/// store confirms it. Without the claim a subject in three is ambiguous, and
/// without the check the claim is a caller choosing its own confinement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Acting {
    In {
        org_id: String,
    },
    /// The caller named no organization, so it acts across the realm.
    RealmWide,
}

/// Why a request established nothing.
///
/// Each refusal is its own, because the events differ: a subject that does not
/// exist is a typo, a disabled one is somebody offboarded, and a login that
/// ended is somebody logging out. `NotAnAccessToken` refuses by what the token
/// is rather than by failing a later lookup, so a refresh token, an identity
/// token and a token minted for a machine are each turned away for the reason
/// they are turned away for, and none of them by accident.
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
    /// Not an access token bound to a login.
    #[error("the token is not an access token bound to a login")]
    NotAnAccessToken,
    /// It names a login that has ended, or one that never existed. The lever
    /// every other one misses: logging out.
    #[error("the login this token was minted for has ended")]
    LoggedOut,
    #[error("the store could not be read")]
    Unreadable,
    /// The bearer itself did not stand up. Distinct from everything above,
    /// which is about a token that verified and a realm that will not have it.
    #[error("{0}")]
    Unverified(#[from] crate::token::Refused),
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

/// Everything a request established, and the token it came from. The claims
/// travel because a caller downstream reads them, and re-reading the token to
/// find out would be a second verification nobody watches.
#[derive(Debug, Clone)]
pub struct Established {
    pub context: Context,
    pub verified: Verified,
}

/// Verify a bearer and establish what it means, in one transaction.
///
/// Both planes come through here, since two paths doing this are two places for
/// one to skip a step nobody notices missing.
pub async fn admit_bearer(
    transaction: &Transaction<'_>,
    tenant: TenantContext,
    keys: &[models::entities::keys::RealmSigningKeyView],
    bearer: &str,
    now: DateTime<Utc>,
) -> Result<Established, NotEstablished> {
    let verified = crate::token::verify_presented(transaction, keys, bearer, now).await?;
    let context = establish(transaction, tenant, &verified, now).await?;
    Ok(Established { context, verified })
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
    subject_still_admitted(&principal, verified)?;
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
/// `typ` turns away a refresh or identity token, minted for other purposes and
/// otherwise passing everything a bearer passes. `sid` turns away a machine's,
/// which has no login for a logout to close.
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
/// The only lever that answers a logout. The realm and subject are matched too,
/// since an identifier alone is a string: somebody else's live session would
/// otherwise be a way in for anyone who learned it.
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
/// A window and a withdrawal miss what an administrator reaches for: switching
/// an account off, and invalidating everything minted for it before now.
/// When the token says it was minted, in whole seconds.
///
/// A fractional value is read rather than refused. It is what `set_issued_at`
/// writes, so tokens carrying one are already in flight, and refusing them
/// would turn a lever that was doing nothing into one that refuses everybody.
/// Truncating is the safe direction: a token is judged as minted no later than
/// it says.
fn minted_at(verified: &Verified) -> Option<i64> {
    let issued = verified.claims.get("iat")?;
    issued
        .as_i64()
        .or_else(|| issued.as_f64().map(|seconds| seconds.trunc() as i64))
}

/// Whether the realm still stands behind the subject this token names.
///
/// Reads no clock. Both levers are about what the token says of itself against
/// what the realm holds, and an instant would make the same token and the same
/// row answer differently depending on when the question was asked.
fn subject_still_admitted(
    principal: &Principal,
    verified: &Verified,
) -> Result<(), NotEstablished> {
    let user = principal.user();
    let (enabled, not_before) = (user.enabled, user.not_before);

    if !enabled {
        return Err(NotEstablished::Disabled);
    }

    // Against what the token says of itself rather than against the instant, so
    // a token minted before the cut is refused however long it is presented
    // after it. A token that states no readable instant is refused rather than
    // judged against the clock: falling back to now made every past cut pass,
    // which is the whole lever doing nothing.
    if let Some(cut) = not_before {
        let issued = minted_at(verified).ok_or(NotEstablished::Superseded)?;
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
