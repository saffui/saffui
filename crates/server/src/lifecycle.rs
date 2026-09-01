use deadpool_postgres::Transaction;
use models::entities::user::UserModel;
use store::providers::{birthright, roles, sessions, users};

pub struct Converged {
    pub granted: u64,
    pub revoked: u64,
    pub sessions_closed: u64,
}

/// Make this person's governed grants match what the rules say they are
/// due. The ledger is the boundary: a role the engine did not grant is a
/// role the engine will not touch.
pub async fn converge_person(
    transaction: &Transaction<'_>,
    person: &UserModel,
) -> Result<Converged, ()> {
    let rules = birthright::rules(transaction).await.map_err(|_| ())?;
    let due = services::lifecycle::desired(&rules, person);
    let governed = birthright::governed_of(transaction, &person.user_id)
        .await
        .map_err(|_| ())?;
    let change = services::lifecycle::diff(&due, &governed);

    let mut told = Converged {
        granted: 0,
        revoked: 0,
        sessions_closed: 0,
    };
    for (role, rule) in &change.grant {
        roles::grant_to_user(transaction, &person.user_id, role)
            .await
            .map_err(|_| ())?;
        birthright::record_grant(transaction, &person.user_id, role, rule)
            .await
            .map_err(|_| ())?;
        told.granted += 1;
    }
    for role in &change.revoke {
        roles::revoke_from_user(transaction, &person.user_id, role)
            .await
            .map_err(|_| ())?;
        birthright::erase_grant(transaction, &person.user_id, role)
            .await
            .map_err(|_| ())?;
        told.revoked += 1;
    }
    // Time-bound access ends by the clock, whatever wrote it: a grant past
    // its own end is taken back the way a rule's verdict is.
    for role in birthright::expired_grants(transaction, &person.user_id, chrono::Utc::now())
        .await
        .map_err(|_| ())?
    {
        roles::revoke_from_user(transaction, &person.user_id, &role)
            .await
            .map_err(|_| ())?;
        birthright::erase_grant(transaction, &person.user_id, &role)
            .await
            .map_err(|_| ())?;
        told.revoked += 1;
    }
    // The leaver's other half: due-nothing because switched off means no
    // standing session should keep working either.
    if !person.enabled && (told.revoked > 0 || !governed.is_empty()) {
        told.sessions_closed = sessions::end_all_of_user(transaction, &person.user_id)
            .await
            .map_err(|_| ())?;
    }
    Ok(told)
}

/// One outbox happening, folded into a convergence. Deletion needs no work
/// of ours: the ledger and the roles go with the person by cascade.
pub async fn converge_event(
    transaction: &Transaction<'_>,
    event: &store::providers::outbox::OutboxEvent,
) -> Result<(), ()> {
    if !event.kind.starts_with("user.") || event.kind == store::providers::outbox::USER_DELETED {
        return Ok(());
    }
    let Some(person) = users::load(transaction, &event.user_id)
        .await
        .map_err(|_| ())?
    else {
        return Ok(());
    };
    let told = converge_person(transaction, &person).await?;
    if told.granted + told.revoked > 0 {
        tracing::info!(
            user = person.user_id,
            granted = told.granted,
            revoked = told.revoked,
            sessions_closed = told.sessions_closed,
            "a person was converged"
        );
    }
    Ok(())
}

/// Every person of the realm, for the first fill and for drift repair.
pub async fn converge_realm(transaction: &Transaction<'_>) -> Result<(u64, Converged), ()> {
    let mut walked = 0;
    let mut totals = Converged {
        granted: 0,
        revoked: 0,
        sessions_closed: 0,
    };
    let mut first: i64 = 0;
    loop {
        let query = store::query::list_query::ListQuery::new(models::paging::Window {
            first,
            max: 200,
            clamped: false,
        });
        let page = users::list(transaction, &query, false)
            .await
            .map_err(|_| ())?;
        if page.items.is_empty() {
            break;
        }
        first += page.items.len() as i64;
        for person in &page.items {
            walked += 1;
            let told = converge_person(transaction, person).await?;
            totals.granted += told.granted;
            totals.revoked += told.revoked;
            totals.sessions_closed += told.sessions_closed;
        }
    }
    Ok((walked, totals))
}
