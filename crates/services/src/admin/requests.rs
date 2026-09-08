use chrono::Utc;
use crypto::provider::CryptoProvider;
use deadpool_postgres::Transaction;
use store::providers::requests::{self, AccessRequest};
use store::providers::{birthright, roles, sod};

/// Why a request could not be lodged, decided or withdrawn.
#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
pub enum Unaskable {
    #[error("{0}")]
    Invalid(&'static str),
    #[error("no such user")]
    NoSuchUser,
    #[error("no such role")]
    NoSuchRole,
    #[error("no such request")]
    NotFound,
    /// The optimistic transition found no pending row: someone decided
    /// first, or the request never was. The loser stops here.
    #[error("this request is already decided")]
    AlreadyDecided,
    #[error("four eyes: the one who asked cannot decide")]
    FourEyes,
    #[error("only the one who asked may withdraw")]
    NotYours,
    #[error("{0}")]
    Toxic(String),
    #[error("the store could not be written")]
    Backend,
}

pub async fn lodge(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    by: &str,
    user: &str,
    role_id: &str,
    reason: &str,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<AccessRequest, Unaskable> {
    let reason = reason.trim();
    if reason.is_empty() {
        return Err(Unaskable::Invalid("reason says why this access is needed"));
    }
    if let Some(end) = expires_at
        && end <= Utc::now()
    {
        return Err(Unaskable::Invalid("expires_at has already passed"));
    }
    let person = crate::admin::users::identified(transaction, user)
        .await
        .map_err(|_| Unaskable::NoSuchUser)?;
    if roles::load(transaction, role_id)
        .await
        .map_err(|_| Unaskable::Backend)?
        .is_none()
    {
        return Err(Unaskable::NoSuchRole);
    }

    // The same face the granting doors show, shown early: a request whose
    // grant the rules would refuse right now is refused right now, and an
    // exception written first unblocks it the same way. The approval
    // weighs again; this is the courtesy, that is the gate.
    let mut would_hold: Vec<String> = roles::effective_roles(transaction, &person.user_id)
        .await
        .map_err(|_| Unaskable::Backend)?
        .into_iter()
        .map(|role| role.role_id)
        .collect();
    if !would_hold.iter().any(|held| held == role_id) {
        would_hold.push(role_id.to_owned());
    }
    let rules = sod::rules(transaction)
        .await
        .map_err(|_| Unaskable::Backend)?;
    let reached = crate::sod::offences(&rules, &would_hold);
    if !reached.is_empty() {
        let standing = sod::exceptions_of(transaction, &person.user_id)
            .await
            .map_err(|_| Unaskable::Backend)?;
        let now = Utc::now();
        if let Some(offence) = reached
            .iter()
            .find(|offence| !crate::sod::excused(offence, &standing, now))
        {
            return Err(Unaskable::Toxic(crate::sod::words(offence)));
        }
    }

    let mut bytes = [0_u8; 16];
    provider
        .rand()
        .fill(&mut bytes)
        .map_err(|_| Unaskable::Backend)?;
    let asked = AccessRequest {
        request_id: crypto::provider::uuid_from(bytes),
        user_id: person.user_id,
        role_id: role_id.to_owned(),
        reason: reason.to_owned(),
        expires_at,
        state: requests::PENDING.to_owned(),
        asked_by: by.to_owned(),
        decided_by: None,
        decided_at: None,
        decided_reason: None,
        created_at: Utc::now(),
    };
    requests::lodge(transaction, &asked)
        .await
        .map_err(|_| Unaskable::Backend)?;
    Ok(asked)
}

pub async fn list(transaction: &Transaction<'_>) -> Result<Vec<AccessRequest>, Unaskable> {
    requests::list(transaction)
        .await
        .map_err(|_| Unaskable::Backend)
}

/// Grant what was asked: the transition claims the pending row first, then
/// the grant is issued by the governed path and weighed like any other. A
/// toxic outcome drops the whole transaction, so the request stays pending
/// and says why in the refusal.
pub async fn approve(
    transaction: &Transaction<'_>,
    request_id: &str,
    by: &str,
) -> Result<AccessRequest, Unaskable> {
    let asked = requests::load(transaction, request_id)
        .await
        .map_err(|_| Unaskable::Backend)?
        .ok_or(Unaskable::NotFound)?;
    if asked.asked_by == by {
        return Err(Unaskable::FourEyes);
    }
    if !requests::decide(transaction, request_id, requests::GRANTED, by, None)
        .await
        .map_err(|_| Unaskable::Backend)?
    {
        return Err(Unaskable::AlreadyDecided);
    }

    sod::hold_person(transaction, &asked.user_id)
        .await
        .map_err(|_| Unaskable::Backend)?;
    roles::grant_to_user(transaction, &asked.user_id, &asked.role_id)
        .await
        .map_err(|_| Unaskable::Backend)?;
    if let Some(end) = asked.expires_at {
        birthright::record_timed_grant(transaction, &asked.user_id, &asked.role_id, by, end)
            .await
            .map_err(|_| Unaskable::Backend)?;
    }
    match crate::sod::weigh(transaction, &asked.user_id).await {
        Ok(()) => {}
        Err(crate::sod::Toxic::Refused(said)) => return Err(Unaskable::Toxic(said)),
        Err(crate::sod::Toxic::Backend) => return Err(Unaskable::Backend),
    }

    requests::load(transaction, request_id)
        .await
        .map_err(|_| Unaskable::Backend)?
        .ok_or(Unaskable::Backend)
}

pub async fn deny(
    transaction: &Transaction<'_>,
    request_id: &str,
    by: &str,
    reason: &str,
) -> Result<(), Unaskable> {
    let reason = reason.trim();
    if reason.is_empty() {
        return Err(Unaskable::Invalid("a denial says why"));
    }
    let asked = requests::load(transaction, request_id)
        .await
        .map_err(|_| Unaskable::Backend)?
        .ok_or(Unaskable::NotFound)?;
    if asked.asked_by == by {
        return Err(Unaskable::FourEyes);
    }
    if !requests::decide(transaction, request_id, requests::DENIED, by, Some(reason))
        .await
        .map_err(|_| Unaskable::Backend)?
    {
        return Err(Unaskable::AlreadyDecided);
    }
    Ok(())
}

/// The asker's own act, not a decision: nothing is granted and no second
/// pair of eyes is owed to stop asking.
pub async fn withdraw(
    transaction: &Transaction<'_>,
    request_id: &str,
    by: &str,
) -> Result<(), Unaskable> {
    let asked = requests::load(transaction, request_id)
        .await
        .map_err(|_| Unaskable::Backend)?
        .ok_or(Unaskable::NotFound)?;
    if asked.asked_by != by {
        return Err(Unaskable::NotYours);
    }
    if !requests::decide(transaction, request_id, requests::WITHDRAWN, by, None)
        .await
        .map_err(|_| Unaskable::Backend)?
    {
        return Err(Unaskable::AlreadyDecided);
    }
    Ok(())
}
