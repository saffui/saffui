//! Signing out (OpenID Connect RP-Initiated Logout).
//!
//! A link is enough to send a browser here, so a request proves nothing by
//! arriving. The session ends at once only when the request carries an
//! identity token of that very session. Otherwise the person is asked.

use super::authorize::write_query_value;
use super::discovery::name_issuer;
use crate::app::App;
use crate::error::Failure;
use crate::login::session::{SessionTicket, close_session, find_live_session};
use crate::tenancy::resolve::resolve_realm;
use crate::tokens::verify::read_identity_hint;

/// The longest `state` a client gets back.
const STATE_MAX_BYTES: usize = 512;

/// What a client sent to the end-session endpoint.
#[derive(Clone, Copy, Debug, Default)]
pub struct LogoutParameters<'a> {
    pub id_token_hint: Option<&'a str>,
    pub post_logout_redirect_uri: Option<&'a str>,
    pub state: Option<&'a str>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Logout {
    /// The session, if there was one, is over. The browser goes back to the
    /// client when it named an address it had registered.
    SignedOut { location: Option<String> },
    /// Nothing proves the person asked for this: they are asked.
    ConfirmationRequired,
}

/// Handles a request to the end-session endpoint.
///
/// # Errors
///
/// Returns the failure of the realm resolution or of the storage.
pub async fn begin_logout(
    app: &App,
    realm: &str,
    parameters: LogoutParameters<'_>,
    ticket: Option<&SessionTicket>,
) -> Result<Logout, Failure> {
    let (realm_name, scope) = resolve_realm(app, realm).await?;
    let mut work = app.storage.begin(scope).await?;
    let session = match ticket {
        Some(ticket) => find_live_session(app, work.as_mut(), ticket).await?,
        None => None,
    };
    let issuer = name_issuer(&app.settings, &realm_name);
    let hint = match parameters.id_token_hint {
        Some(token) => read_identity_hint(app, work.as_mut(), &issuer, token).await?,
        None => None,
    };

    if let Some(session) = &session {
        if hint.as_ref().is_none_or(|hint| hint.session != session.id) {
            return Ok(Logout::ConfirmationRequired);
        }
        close_session(app, work.as_mut(), session).await?;
    }

    // Only the client an identity token of this realm names may send the
    // browser on, and only to an address it registered.
    let location = match (&hint, parameters.post_logout_redirect_uri) {
        (Some(hint), Some(asked)) => work
            .read_client(&hint.client_id)
            .await?
            .filter(|client| {
                client.enabled
                    && client
                        .post_logout_redirect_uris
                        .iter()
                        .any(|registered| registered == asked)
            })
            .map(|_| write_return_location(asked, parameters.state)),
        _ => None,
    };
    work.commit().await?;
    Ok(Logout::SignedOut { location })
}

fn write_return_location(registered: &str, state: Option<&str>) -> String {
    let mut location = registered.to_owned();
    if let Some(state) = state.filter(|state| state.len() <= STATE_MAX_BYTES) {
        location.push(if registered.contains('?') { '&' } else { '?' });
        location.push_str("state=");
        write_query_value(&mut location, state);
    }
    location
}

/// Ends the session of a person who confirmed, on the page of this realm,
/// that they sign out.
///
/// # Errors
///
/// Returns the failure of the realm resolution or of the storage. A ticket
/// that proves no live session is not an error: there is nothing to end.
pub async fn confirm_logout(app: &App, realm: &str, ticket: &SessionTicket) -> Result<(), Failure> {
    let (_, scope) = resolve_realm(app, realm).await?;
    let mut work = app.storage.begin(scope).await?;
    if let Some(session) = find_live_session(app, work.as_mut(), ticket).await? {
        close_session(app, work.as_mut(), &session).await?;
        work.commit().await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Logout, LogoutParameters, begin_logout, confirm_logout};
    use crate::login::session::{close_session, find_live_session};
    use crate::oidc::scenario::{GOODBYE, Scenario};
    use crate::testkit::drive::complete;

    fn hint<'a>(token: &'a str, uri: Option<&'a str>) -> LogoutParameters<'a> {
        LogoutParameters {
            id_token_hint: Some(token),
            post_logout_redirect_uri: uri,
            state: Some("s t"),
        }
    }

    fn is_signed_in(scenario: &Scenario, ticket: &crate::login::session::SessionTicket) -> bool {
        let mut work =
            complete(scenario.app.storage.begin(scenario.scope)).expect("a unit of work");
        complete(find_live_session(&scenario.app, work.as_mut(), ticket))
            .expect("a read")
            .is_some()
    }

    #[test]
    fn the_identity_token_of_the_session_ends_it_and_the_browser_returns_to_a_registered_address() {
        let scenario = Scenario::start();
        let signed_in = scenario.sign_in("openid");
        let identity = signed_in
            .tokens
            .id_token
            .clone()
            .expect("an identity token");
        let refresh = signed_in
            .tokens
            .refresh_token
            .clone()
            .expect("a refresh token");

        let outcome = complete(begin_logout(
            &scenario.app,
            "acme",
            hint(&identity, Some(GOODBYE)),
            Some(&signed_in.ticket),
        ));

        assert_eq!(
            outcome,
            Ok(Logout::SignedOut {
                location: Some(format!("{GOODBYE}?state=s%20t")),
            })
        );
        assert!(!is_signed_in(&scenario, &signed_in.ticket));
        let mut work =
            complete(scenario.app.storage.begin(scenario.scope)).expect("a unit of work");
        let digest = scenario.app.digester.sha256(refresh.as_bytes());
        let stored = complete(work.read_refresh_token(&digest))
            .expect("a read")
            .expect("the refresh token");
        assert!(
            stored.revoked_at.is_some(),
            "the refresh tokens of the session went with it"
        );
        assert_eq!(
            scenario.read_event_kinds().last().map(String::as_str),
            Some("session.ended")
        );
    }

    #[test]
    fn a_client_disabled_since_gets_no_browser_back() {
        let scenario = Scenario::start();
        let signed_in = scenario.sign_in("openid");
        let identity = signed_in
            .tokens
            .id_token
            .clone()
            .expect("an identity token");
        scenario.storage.disable_client("webapp");

        let outcome = complete(begin_logout(
            &scenario.app,
            "acme",
            hint(&identity, Some(GOODBYE)),
            Some(&signed_in.ticket),
        ));

        assert_eq!(outcome, Ok(Logout::SignedOut { location: None }));
        assert!(
            !is_signed_in(&scenario, &signed_in.ticket),
            "the session ends all the same"
        );
    }

    #[test]
    fn a_session_two_sign_outs_end_at_once_is_said_ended_once() {
        let scenario = Scenario::start();
        let signed_in = scenario.sign_in("openid");
        let read = || {
            let mut work =
                complete(scenario.app.storage.begin(scenario.scope)).expect("a unit of work");
            complete(work.read_session(signed_in.ticket.session))
                .expect("a read")
                .expect("the session")
                .session
        };
        // Both read it live, before either ended it.
        let (seen_first, seen_second) = (read(), read());

        for seen in [seen_first, seen_second] {
            let mut work =
                complete(scenario.app.storage.begin(scenario.scope)).expect("a unit of work");
            complete(close_session(&scenario.app, work.as_mut(), &seen)).expect("a sign-out");
            complete(work.commit()).expect("a commit");
        }

        let kinds = scenario.read_event_kinds();
        assert_eq!(
            kinds.iter().filter(|kind| *kind == "session.ended").count(),
            1,
            "{kinds:?}"
        );
    }

    #[test]
    fn an_address_the_client_did_not_register_is_never_returned_to() {
        let scenario = Scenario::start();
        let signed_in = scenario.sign_in("openid");
        let identity = signed_in
            .tokens
            .id_token
            .clone()
            .expect("an identity token");

        for asked in [
            Some("https://evil.example.org/goodbye"),
            Some("https://app.example.org/goodbye/"),
            None,
        ] {
            let outcome = complete(begin_logout(
                &scenario.app,
                "acme",
                hint(&identity, asked),
                None,
            ));
            assert_eq!(
                outcome,
                Ok(Logout::SignedOut { location: None }),
                "{asked:?}"
            );
        }
    }

    #[test]
    fn without_the_identity_token_of_this_very_session_the_person_is_asked() {
        let scenario = Scenario::start();
        let signed_in = scenario.sign_in("openid");
        let another_session = scenario.sign_in("openid");
        let of_another = another_session.tokens.id_token.expect("an identity token");
        let access = signed_in.tokens.access_token.clone();
        let asked = Ok(Logout::ConfirmationRequired);

        for parameters in [
            LogoutParameters::default(),
            hint("not.a.token", Some(GOODBYE)),
            hint(&of_another, Some(GOODBYE)),
            // An access token is not an identity token, whatever it says.
            hint(&access, Some(GOODBYE)),
        ] {
            let outcome = complete(begin_logout(
                &scenario.app,
                "acme",
                parameters,
                Some(&signed_in.ticket),
            ));
            assert_eq!(outcome, asked, "{parameters:?}");
        }
        assert!(is_signed_in(&scenario, &signed_in.ticket));

        complete(confirm_logout(&scenario.app, "acme", &signed_in.ticket)).expect("a sign-out");
        assert!(!is_signed_in(&scenario, &signed_in.ticket));
        assert!(
            is_signed_in(&scenario, &another_session.ticket),
            "one session ends, not the others of the person"
        );
        // Confirming again ends nothing and fails nothing.
        complete(confirm_logout(&scenario.app, "acme", &signed_in.ticket)).expect("nothing to end");
        let kinds = scenario.read_event_kinds();
        assert_eq!(
            kinds.iter().filter(|kind| *kind == "session.ended").count(),
            1,
            "{kinds:?}"
        );
    }
}
