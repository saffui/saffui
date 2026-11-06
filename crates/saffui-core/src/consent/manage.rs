//! The consents of a person, as they and the administrators of the realm
//! see them. Withdrawn, a consent takes with it what the client holds in the
//! person's name: its refresh tokens are revoked in the same unit of work.

use serde_json::{Value, json};
use uuid::Uuid;

use super::{ListedConsent, MOST_LISTED_CONSENTS};
use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::authz::admin::AdminCaller;
use crate::clients::{check_client_identifier, neutralize_unshowable};
use crate::error::{ErrorCode, Failure};
use crate::login::session::{Session, SessionTicket, find_live_session};
use crate::oidc::refresh::describe_family_end;
use crate::ports::storage::UnitOfWork;
use crate::tenancy::resolve::resolve_realm;

/// The live session a ticket proves, of a person who may still sign in.
async fn find_signed_in_session(
    app: &App,
    work: &mut dyn UnitOfWork,
    ticket: Option<&SessionTicket>,
) -> Result<Session, Failure> {
    let required = || Failure::new(ErrorCode::SessionRequired);
    let ticket = ticket.ok_or_else(required)?;
    let session = find_live_session(app, work, ticket)
        .await?
        .ok_or_else(required)?;
    work.read_person(session.person)
        .await?
        .filter(|person| person.enabled)
        .ok_or_else(required)?;
    Ok(session)
}

/// Removes a consent, revokes every refresh token its client holds for the
/// person, and says so: the consent first, then each family it ended.
async fn withdraw_consent(
    app: &App,
    work: &mut dyn UnitOfWork,
    person: Uuid,
    client_id: &str,
    actor: Value,
) -> Result<(), Failure> {
    // What is not written as a client identifier names no consent.
    if check_client_identifier(client_id).is_err()
        || !work.delete_consent(person, client_id).await?
    {
        return Err(Failure::new(ErrorCode::ConsentNotFound));
    }
    let families = work
        .revoke_refresh_families_of_client(person, client_id, app.now())
        .await?;
    // The events come last: the head of the chain stays locked until the commit.
    let withdrawn = json!({
        "actor": actor,
        "client_id": client_id,
        "person_id": person.to_string(),
        "refresh_families_revoked": families.len(),
    });
    record_event(app, work, EventKind::ConsentWithdrawn, withdrawn).await?;
    for revoked in &families {
        let told = describe_family_end(
            client_id,
            revoked.family,
            person,
            revoked.session,
            "consent_withdrawn",
            &revoked.ended,
        );
        record_event(app, work, EventKind::TokenRevoked, told).await?;
    }
    Ok(())
}

/// The consents of the person signed in, with the names of their clients as
/// a page shows them.
///
/// # Errors
///
/// Returns [`ErrorCode::SessionRequired`] without a live session, or the
/// storage failure.
pub async fn list_my_consents(
    app: &App,
    realm: &str,
    ticket: Option<&SessionTicket>,
) -> Result<Vec<ListedConsent>, Failure> {
    let (_, scope) = resolve_realm(app, realm).await?;
    let mut work = app.storage.begin(scope).await?;
    let session = find_signed_in_session(app, work.as_mut(), ticket).await?;
    let mut listed = work
        .list_consents(session.person, MOST_LISTED_CONSENTS)
        .await?;
    for held in &mut listed {
        held.client_name = neutralize_unshowable(&held.client_name);
    }
    Ok(listed)
}

/// Withdraws a consent of the person signed in.
///
/// # Errors
///
/// Returns [`ErrorCode::SessionRequired`] without a live session,
/// [`ErrorCode::ConsentNotFound`] when they gave that client none, or the
/// storage failure.
pub async fn withdraw_my_consent(
    app: &App,
    realm: &str,
    ticket: Option<&SessionTicket>,
    client_id: &str,
) -> Result<(), Failure> {
    let (_, scope) = resolve_realm(app, realm).await?;
    let mut work = app.storage.begin(scope).await?;
    let session = find_signed_in_session(app, work.as_mut(), ticket).await?;
    let actor = json!({ "person_id": session.person.to_string() });
    withdraw_consent(app, work.as_mut(), session.person, client_id, actor).await?;
    work.commit().await?;
    Ok(())
}

/// The consents of a person, as an administrator reads them.
///
/// # Errors
///
/// Returns [`ErrorCode::PersonNotFound`] for nobody of the realm, or the
/// storage failure.
pub async fn list_person_consents(
    app: &App,
    caller: &AdminCaller,
    person: Uuid,
) -> Result<Vec<ListedConsent>, Failure> {
    let mut work = app.storage.begin(caller.scope).await?;
    work.read_person(person)
        .await?
        .ok_or(Failure::new(ErrorCode::PersonNotFound))?;
    Ok(work.list_consents(person, MOST_LISTED_CONSENTS).await?)
}

/// Withdraws a consent of a person in their place.
///
/// # Errors
///
/// Returns [`ErrorCode::ConsentNotFound`] when they gave that client none,
/// or the storage failure.
pub async fn withdraw_person_consent(
    app: &App,
    caller: &AdminCaller,
    person: Uuid,
    client_id: &str,
) -> Result<(), Failure> {
    let mut work = app.storage.begin(caller.scope).await?;
    let actor = json!({ "client_id": caller.client.client_id });
    withdraw_consent(app, work.as_mut(), person, client_id, actor).await?;
    work.commit().await?;
    Ok(())
}
