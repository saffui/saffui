//! The consents of a person, as they and the administrators of the realm
//! see them. Withdrawn, a consent takes with it what the client holds in the
//! person's name: its refresh tokens are revoked in the same unit of work,
//! and the offline sessions they lived in end.

use serde_json::{Value, json};
use uuid::Uuid;

use super::{ListedConsent, MOST_LISTED_CONSENTS};
use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::authz::admin::AdminCaller;
use crate::clients::{check_client_identifier, neutralize_unshowable};
use crate::error::{ErrorCode, Failure};
use crate::login::session::{Session, SessionTicket, find_answering_session};
use crate::ports::storage::UnitOfWork;
use crate::tenancy::resolve::resolve_realm;

/// How many of the families a withdrawal ended its event names: the rest
/// are counted.
const MOST_NAMED_FAMILIES: u32 = 100;

fn require_session() -> Failure {
    Failure::new(ErrorCode::SessionRequired)
}

/// The live session a ticket proves, when it still answers for its person
/// and that person may still sign in.
async fn find_signed_in_session(
    app: &App,
    work: &mut dyn UnitOfWork,
    ticket: &SessionTicket,
) -> Result<Session, Failure> {
    let session = find_answering_session(app, work, ticket)
        .await?
        .ok_or_else(require_session)?;
    work.read_person(session.person)
        .await?
        .filter(|person| person.enabled)
        .ok_or_else(require_session)?;
    Ok(session)
}

/// Removes a consent, revokes every refresh token its client holds for the
/// person, and says so in one event, however many families it ended.
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
    let revoked = work
        .revoke_refresh_families_of_client(person, client_id, app.now(), MOST_NAMED_FAMILIES)
        .await?;
    let named: Vec<String> = revoked.named.iter().map(Uuid::to_string).collect();
    let offline: Vec<String> = revoked
        .offline_sessions
        .iter()
        .map(Uuid::to_string)
        .collect();
    // The event comes last: the head of the chain stays locked until the commit.
    let withdrawn = json!({
        "actor": actor,
        "client_id": client_id,
        "person_id": person.to_string(),
        "offline_sessions_ended": offline,
        "refresh_families": named,
        "refresh_families_revoked": revoked.families,
        "refresh_tokens_revoked": revoked.tokens,
    });
    record_event(app, work, EventKind::ConsentWithdrawn, withdrawn).await
}

/// The consents of the person signed in, with the names of their clients as
/// a page shows them.
///
/// # Errors
///
/// Returns [`ErrorCode::SessionRequired`] without a live session that
/// answers for its person, or the storage failure.
pub async fn list_my_consents(
    app: &App,
    realm: &str,
    ticket: Option<&SessionTicket>,
) -> Result<Vec<ListedConsent>, Failure> {
    let ticket = ticket.ok_or_else(require_session)?;
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
/// Returns [`ErrorCode::SessionRequired`] without a live session that
/// answers for its person, [`ErrorCode::ConsentNotFound`] when they gave
/// that client none, or the storage failure.
pub async fn withdraw_my_consent(
    app: &App,
    realm: &str,
    ticket: Option<&SessionTicket>,
    client_id: &str,
) -> Result<(), Failure> {
    let ticket = ticket.ok_or_else(require_session)?;
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

#[cfg(test)]
mod tests {
    use time::Duration;
    use uuid::Uuid;

    use super::{MOST_NAMED_FAMILIES, withdraw_person_consent};
    use crate::authz::capability::Capability;
    use crate::consent::Consent;
    use crate::oidc::scenario::{CALLBACK, Scenario};
    use crate::testkit::drive::complete;
    use crate::testkit::fixtures::{Application, register_application};
    use crate::tokens::store::RefreshToken;

    /// The session an access token names.
    fn read_session_of_token(token: &str) -> String {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let payload = token.split('.').nth(1).expect("a compact token");
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("base64url"))
                .expect("claims");
        claims["sid"].as_str().expect("a session").to_owned()
    }

    #[test]
    fn a_withdrawal_is_one_entry_that_counts_every_family_and_names_a_bounded_few() {
        let scenario = Scenario::start();
        let partner = Application {
            client_id: "partner",
            redirect_uri: CALLBACK,
            post_logout_redirect_uri: None,
            public: true,
            requires_consent: true,
        };
        complete(register_application(&scenario.app, scenario.scope, partner));
        let ada = scenario.find_ada();
        let session = scenario.sign_in("openid").ticket.session;
        let operator = scenario.name_operator(&[Capability::UserWrite]);
        let now = scenario.app.now();
        let families = u8::try_from(MOST_NAMED_FAMILIES + 1).expect("a small bound");
        let mut work =
            complete(scenario.app.storage.begin(scenario.scope)).expect("a unit of work");
        complete(work.add_consent(&Consent {
            person: ada,
            client_id: "partner".to_owned(),
            scopes: vec!["openid".to_owned()],
            granted_at: now,
        }))
        .expect("a consent");
        for each in 0..families {
            let mut token_digest = vec![0xee; 32];
            token_digest[0] = each;
            complete(work.insert_refresh_token(&RefreshToken {
                token_digest,
                family: Uuid::from_u128(1_000 + u128::from(each)),
                client_id: "partner".to_owned(),
                person: ada,
                session,
                scopes: vec!["openid".to_owned()],
                issued_at: now,
                expires_at: now + Duration::hours(1),
            }))
            .expect("the first token of a family");
        }
        complete(work.commit()).expect("a commit");
        let before = scenario.read_event_kinds().len();

        complete(withdraw_person_consent(
            &scenario.app,
            &operator,
            ada,
            "partner",
        ))
        .expect("a withdrawal");

        let events = scenario
            .storage
            .read_audit_envelopes(scenario.scope.realm());
        let told = &events[before..];
        assert_eq!(told.len(), 1, "one entry, however many families");
        assert_eq!(told[0]["kind"], "consent.withdrawn");
        let payload = &told[0]["payload"];
        assert_eq!(payload["refresh_families_revoked"], families, "{payload}");
        assert_eq!(payload["refresh_tokens_revoked"], families, "{payload}");
        assert_eq!(
            payload["refresh_families"].as_array().map(Vec::len),
            usize::try_from(MOST_NAMED_FAMILIES).ok(),
            "the first named, the rest counted"
        );
    }

    #[test]
    fn a_withdrawal_ends_the_offline_grant_of_its_client() {
        use super::withdraw_my_consent;
        use crate::oidc::errors::OAuthError;

        let scenario = Scenario::start();
        scenario.register_partner();
        let granted = scenario.sign_in_and_consent("partner", "openid offline_access");
        assert_eq!(granted.tokens.scope, "openid offline_access");
        let refresh_token = granted.tokens.refresh_token.expect("a refresh token");

        complete(withdraw_my_consent(
            &scenario.app,
            "acme",
            Some(&granted.ticket),
            "partner",
        ))
        .expect("a withdrawal");

        assert_eq!(
            scenario
                .refresh_as("partner", &refresh_token, None)
                .map(|tokens| tokens.scope),
            Err(OAuthError::InvalidGrant),
            "the grant ends with the consent"
        );
        assert!(
            !scenario.is_token_active(&granted.tokens.access_token),
            "its offline session ended: its tokens answer for nobody"
        );
        let withdrawn = scenario
            .storage
            .read_audit_envelopes(scenario.scope.realm())
            .into_iter()
            .rev()
            .find(|event| event["kind"] == "consent.withdrawn")
            .expect("the withdrawal");
        let offline = read_session_of_token(&granted.tokens.access_token);
        assert_eq!(
            withdrawn["payload"]["offline_sessions_ended"],
            serde_json::json!([offline]),
            "{withdrawn}"
        );
    }
}
