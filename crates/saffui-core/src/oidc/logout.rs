//! Signing out (OpenID Connect RP-Initiated Logout), and the frames that
//! tell the clients a session served that it ended (OpenID Connect
//! Front-Channel Logout).
//!
//! A link is enough to send a browser here, so a request proves nothing by
//! arriving. The session ends at once only when the request carries an
//! identity token of that very session. Otherwise the person is asked.

use std::fmt::{self, Write as _};

use uuid::Uuid;

use super::authorize::write_query_value;
use super::discovery::name_issuer;
use super::response::write_frame_source;
use crate::app::App;
use crate::clients::{Client, neutralize_unshowable};
use crate::error::Failure;
use crate::login::session::{SessionTicket, close_session, find_live_session};
use crate::login::store::ServedClients;
use crate::tenancy::resolve::resolve_realm;
use crate::tokens::verify::read_identity_hint;

/// The longest `state` a client gets back.
const STATE_MAX_BYTES: usize = 512;

/// How many clients one page loads in frames: the browser fetches each, and
/// waits for them all, before it leaves. Ten of the longest origins a
/// registration takes, 268 bytes each with its space, stay under
/// [`MOST_FRAME_SOURCE_BYTES`].
const MOST_FRAMES: usize = 10;

/// How many bytes the origins a page frames may take in its policy, each
/// named once with the space before it: a proxy may refuse the headers of an
/// answer past 4 KiB, and the page would then reach nobody, nor take the
/// cookie back. Only an address no registration judged can reach it.
const MOST_FRAME_SOURCE_BYTES: usize = 3 * 1024;

/// How many characters of an address a client sent a page shows.
const SHOWN_ADDRESS_MAX_CHARS: usize = 200;

/// What a client sent to the end-session endpoint.
#[derive(Clone, Copy, Default)]
pub struct LogoutParameters<'a> {
    pub id_token_hint: Option<&'a str>,
    pub post_logout_redirect_uri: Option<&'a str>,
    pub state: Option<&'a str>,
    /// The client the request says it comes from. A hint issued to another
    /// proves nothing (RP-Initiated Logout 1.0, section 2).
    pub client_id: Option<&'a str>,
    /// Read for nothing: only carried on when a client posts its request.
    pub logout_hint: Option<&'a str>,
    /// Read for nothing: only carried on when a client posts its request.
    pub ui_locales: Option<&'a str>,
}

// Written by hand: an identity token hint says who the person is, and a
// logout hint may.
impl fmt::Debug for LogoutParameters<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LogoutParameters")
            .field("id_token_hint", &self.id_token_hint.map(|_| ".."))
            .field("post_logout_redirect_uri", &self.post_logout_redirect_uri)
            .field("state", &self.state)
            .field("client_id", &self.client_id)
            .field("logout_hint", &self.logout_hint.map(|_| ".."))
            .field("ui_locales", &self.ui_locales)
            .finish()
    }
}

/// What the browser loads in a frame for a client the session served: the
/// address it registered with `iss` and `sid` after it, and what the policy
/// of the page names it by in its `frame-src`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrontChannelLogout {
    pub url: String,
    pub source: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Logout {
    /// The session, if there was one, is over: the browser loads the frames
    /// of the clients it served, then goes back to the client when it named
    /// an address it had registered.
    SignedOut {
        location: Option<String>,
        frames: Vec<FrontChannelLogout>,
    },
    /// Nothing proves the person asked for this: they are asked.
    ConfirmationRequired(ConfirmationCause),
    /// The identity token of the session came with an address its client did
    /// not register: nothing ends, and the person is told, and asked. The
    /// address is written as a page shows it.
    ReturnUnregistered { address: String },
}

/// Why a person is asked whether they sign out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfirmationCause {
    /// The request carried no identity token.
    NoHint,
    /// It carried one that does not prove this session: unreadable, of
    /// another issuer or session, or not of the client the request names.
    HintNotOfSession,
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
    let parameters = leave_out_empty_values(parameters);
    let (realm_name, scope) = resolve_realm(app, realm).await?;
    let mut work = app.storage.begin(scope).await?;
    let session = match ticket {
        Some(ticket) => find_live_session(app, work.as_mut(), ticket).await?,
        None => None,
    };
    let issuer = name_issuer(&app.settings, &realm_name);
    let presented = parameters.id_token_hint;
    let hint = match presented {
        Some(token) => read_identity_hint(app, work.as_mut(), &issuer, token).await?,
        None => None,
    }
    .filter(|hint| {
        parameters
            .client_id
            .is_none_or(|named| named == hint.client_id)
    });
    let asked = parameters.post_logout_redirect_uri;
    let client = match (&hint, asked) {
        (Some(hint), Some(_)) => work.read_client(&hint.client_id).await?,
        _ => None,
    };
    let registered = |client: &Client| {
        asked.is_some_and(|asked| {
            client
                .post_logout_redirect_uris
                .iter()
                .any(|registered| registered == asked)
        })
    };

    let mut ended = None;
    let mut closed_named_session = false;
    if let Some(session) = &session {
        if hint.as_ref().is_none_or(|hint| hint.session != session.id) {
            let cause = match presented {
                None => ConfirmationCause::NoHint,
                Some(_) => ConfirmationCause::HintNotOfSession,
            };
            return Ok(Logout::ConfirmationRequired(cause));
        }
        // Decided before anything ends: an address its client never
        // registered is no place to go, nor a request to act on.
        if let Some(address) = asked
            && !client.as_ref().is_some_and(registered)
        {
            return Ok(Logout::ReturnUnregistered {
                address: write_shown_address(address),
            });
        }
        ended = close_session(app, work.as_mut(), session)
            .await?
            .map(|served| (session.id, served));
        closed_named_session = true;
    }

    // Only the client an identity token of this realm names may send the
    // browser on, and only to an address it registered. A client that
    // registered itself does so only when this request ended the session its
    // token names: a token kept from a session long over sends it nowhere.
    let returned_to = client
        .filter(|client| {
            client.enabled
                && (closed_named_session || !client.self_registered)
                && registered(client)
        })
        .and(asked);
    work.commit().await?;
    let frames = ended.map_or_else(Vec::new, |(session, served)| {
        write_frames(&issuer, session, &served)
    });
    // A page that loads frames leaves by a refresh, and the browser of the
    // conformance suite folds the target of a refresh to lower case.
    let spelling = if frames.is_empty() {
        StateSpelling::Plain
    } else {
        StateSpelling::Escaped
    };
    let location =
        returned_to.map(|asked| write_return_location(asked, parameters.state, spelling));
    Ok(Logout::SignedOut { location, frames })
}

/// The parameters of a request, each sent without a value left out: one
/// that was sent so was not sent (RFC 6749, section 3.1).
fn leave_out_empty_values<'a>(parameters: LogoutParameters<'a>) -> LogoutParameters<'a> {
    let valued = |value: Option<&'a str>| value.filter(|value| !value.is_empty());
    LogoutParameters {
        id_token_hint: valued(parameters.id_token_hint),
        post_logout_redirect_uri: valued(parameters.post_logout_redirect_uri),
        state: valued(parameters.state),
        client_id: valued(parameters.client_id),
        logout_hint: valued(parameters.logout_hint),
        ui_locales: valued(parameters.ui_locales),
    }
}

/// An address a client sent, as a page shows it: each character a page
/// cannot show as it is replaced, and cut past a bound, so that it neither
/// reorders nor fills the page it is named on.
fn write_shown_address(address: &str) -> String {
    let shown = neutralize_unshowable(address);
    match shown.char_indices().nth(SHOWN_ADDRESS_MAX_CHARS) {
        Some((cut, _)) => format!("{}\u{2026}", &shown[..cut]),
        None => shown,
    }
}

/// How a state is written on the address the browser goes back to.
/// `Escaped` goes against RFC 3986, section 2.3, which asks that a letter, a
/// digit or `-._~` be left as it is: the browser of the conformance suite
/// folds the case of a letter. An escaped byte reads as the byte (section
/// 6.2.2.2), in either case of its hexadecimal digits (section 2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StateSpelling {
    /// What RFC 3986 leaves unreserved as it is, every other byte escaped.
    Plain,
    /// Every byte escaped, on the page that loads frames alone.
    Escaped,
}

fn write_return_location(registered: &str, state: Option<&str>, spelling: StateSpelling) -> String {
    let mut location = registered.to_owned();
    if let Some(state) = state.filter(|state| state.len() <= STATE_MAX_BYTES) {
        location.push(if registered.contains('?') { '&' } else { '?' });
        location.push_str("state=");
        match spelling {
            StateSpelling::Plain => write_query_value(&mut location, state),
            StateSpelling::Escaped => {
                for byte in state.bytes() {
                    let _ = write!(location, "%{byte:02X}");
                }
            }
        }
    }
    location
}

/// The frames that tell the clients a session served that it ended, in the
/// order they were first served: one for each address registered, the
/// address with `iss` and `sid` after it and nothing else (Front-Channel
/// Logout 1.0, section 2), [`MOST_FRAMES`] at most, and the first that would
/// take their origins past [`MOST_FRAME_SOURCE_BYTES`] ends them.
fn write_frames(issuer: &str, session: Uuid, served: &ServedClients) -> Vec<FrontChannelLogout> {
    let session = session.to_string();
    let mut frames: Vec<FrontChannelLogout> = Vec::new();
    let mut source_bytes = 0;
    let addresses = served
        .first
        .iter()
        .filter_map(|client| client.frontchannel_logout_uri.as_deref());
    for address in addresses {
        if frames.len() == MOST_FRAMES {
            break;
        }
        let Some(source) = write_frame_source(address) else {
            continue;
        };
        let mut url = address.to_owned();
        url.push(if address.contains('?') { '&' } else { '?' });
        url.push_str("iss=");
        write_query_value(&mut url, issuer);
        url.push_str("&sid=");
        write_query_value(&mut url, &session);
        if frames.iter().any(|frame| frame.url == url) {
            continue;
        }
        if !frames.iter().any(|frame| frame.source == source) {
            source_bytes += source.len() + 1;
            if source_bytes > MOST_FRAME_SOURCE_BYTES {
                break;
            }
        }
        frames.push(FrontChannelLogout { url, source });
    }
    frames
}

/// The query that carries a request posted to the end-session endpoint on
/// to the endpoint itself, each parameter it named once, in one order.
#[must_use]
pub fn write_logout_query(parameters: &LogoutParameters<'_>) -> String {
    let mut query = String::new();
    for (name, value) in [
        ("id_token_hint", parameters.id_token_hint),
        (
            "post_logout_redirect_uri",
            parameters.post_logout_redirect_uri,
        ),
        ("state", parameters.state),
        ("client_id", parameters.client_id),
        ("logout_hint", parameters.logout_hint),
        ("ui_locales", parameters.ui_locales),
    ] {
        if let Some(value) = value {
            query.push(if query.is_empty() { '?' } else { '&' });
            query.push_str(name);
            query.push('=');
            write_query_value(&mut query, value);
        }
    }
    query
}

/// Ends the session of a person who confirmed, on the page of this realm,
/// that they sign out, and returns the frames that tell the clients it
/// served.
///
/// # Errors
///
/// Returns the failure of the realm resolution or of the storage. A ticket
/// that proves no live session is not an error: there is nothing to end.
pub async fn confirm_logout(
    app: &App,
    realm: &str,
    ticket: &SessionTicket,
) -> Result<Vec<FrontChannelLogout>, Failure> {
    let (realm_name, scope) = resolve_realm(app, realm).await?;
    let mut work = app.storage.begin(scope).await?;
    let Some(session) = find_live_session(app, work.as_mut(), ticket).await? else {
        return Ok(Vec::new());
    };
    let ended = close_session(app, work.as_mut(), &session).await?;
    work.commit().await?;
    let issuer = name_issuer(&app.settings, &realm_name);
    Ok(ended.map_or_else(Vec::new, |served| {
        write_frames(&issuer, session.id, &served)
    }))
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::{Value, json};
    use uuid::Uuid;

    use super::{
        ConfirmationCause, FrontChannelLogout, Logout, LogoutParameters, StateSpelling,
        begin_logout, confirm_logout, write_frames, write_logout_query, write_return_location,
    };
    use crate::login::session::{
        MOST_NAMED_SERVED_CLIENTS, SessionTicket, close_session, find_live_session,
    };
    use crate::login::store::{ServedClient, ServedClients};
    use crate::oidc::scenario::{GOODBYE, Scenario};
    use crate::testkit::drive::complete;

    /// The issuer of `acme`, as a frame carries it.
    const ISSUER: &str = "https%3A%2F%2Fid.example.test%2Frealms%2Facme";

    fn hint<'a>(token: &'a str, uri: Option<&'a str>) -> LogoutParameters<'a> {
        LogoutParameters {
            id_token_hint: Some(token),
            post_logout_redirect_uri: uri,
            state: Some("s t"),
            ..LogoutParameters::default()
        }
    }

    fn is_signed_in(scenario: &Scenario, ticket: &SessionTicket) -> bool {
        let mut work =
            complete(scenario.app.storage.begin(scenario.scope)).expect("a unit of work");
        complete(find_live_session(&scenario.app, work.as_mut(), ticket))
            .expect("a read")
            .is_some()
    }

    fn read_claims(token: &str) -> Value {
        let payload = token.split('.').nth(1).expect("a compact token");
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("base64url"))
            .expect("claims")
    }

    /// What the last `session.ended` of the realm says.
    fn read_last_ending(scenario: &Scenario) -> Value {
        scenario
            .storage
            .read_audit_envelopes(scenario.scope.realm())
            .into_iter()
            .rfind(|event| event["kind"] == "session.ended")
            .expect("an ending")["payload"]
            .clone()
    }

    /// Signs `ada` out of the session of `ticket` with `identity`, and
    /// returns the frames the page loads.
    fn sign_out(
        scenario: &Scenario,
        identity: &str,
        ticket: &SessionTicket,
    ) -> Vec<FrontChannelLogout> {
        let outcome = complete(begin_logout(
            &scenario.app,
            "acme",
            hint(identity, None),
            Some(ticket),
        ));
        let Ok(Logout::SignedOut {
            location: None,
            frames,
        }) = outcome
        else {
            panic!("the identity token of the session ends it: {outcome:?}");
        };
        frames
    }

    fn list_urls(frames: &[FrontChannelLogout]) -> Vec<&str> {
        frames.iter().map(|frame| frame.url.as_str()).collect()
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
                frames: Vec::new(),
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

        assert_eq!(
            outcome,
            Ok(Logout::SignedOut {
                location: None,
                frames: Vec::new(),
            })
        );
        assert!(
            !is_signed_in(&scenario, &signed_in.ticket),
            "the session ends all the same"
        );
    }

    #[test]
    fn a_session_two_sign_outs_end_at_once_is_said_ended_once() {
        let scenario = Scenario::start();
        scenario.register_framed("framed", Some("https://app.example.org/signed-out"));
        let signed_in = scenario.sign_in("openid");
        scenario.grant_in_session("framed", "openid", None, &signed_in.ticket);
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

        let mut told = Vec::new();
        for seen in [seen_first, seen_second] {
            let mut work =
                complete(scenario.app.storage.begin(scenario.scope)).expect("a unit of work");
            told.push(
                complete(close_session(&scenario.app, work.as_mut(), &seen))
                    .expect("a sign-out")
                    .map(|served| served.count),
            );
            complete(work.commit()).expect("a commit");
        }

        assert_eq!(
            told,
            [Some(2), None],
            "only the one that ended it tells the clients"
        );
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
                Ok(Logout::SignedOut {
                    location: None,
                    frames: Vec::new(),
                }),
                "{asked:?}"
            );
        }
    }

    #[test]
    fn an_address_the_client_did_not_register_ends_nothing_where_the_hint_proves_the_session() {
        let scenario = Scenario::start();
        let signed_in = scenario.sign_in("openid");
        let identity = signed_in
            .tokens
            .id_token
            .clone()
            .expect("an identity token");
        let with_more = format!("{GOODBYE}?foo=bar");

        for asked in ["https://evil.example.org/goodbye", &with_more] {
            let outcome = complete(begin_logout(
                &scenario.app,
                "acme",
                hint(&identity, Some(asked)),
                Some(&signed_in.ticket),
            ));
            assert_eq!(
                outcome,
                Ok(Logout::ReturnUnregistered {
                    address: asked.to_owned()
                }),
                "{asked}"
            );
            assert!(is_signed_in(&scenario, &signed_in.ticket), "{asked}");
        }
        assert!(
            !scenario
                .read_event_kinds()
                .contains(&"session.ended".to_owned())
        );

        // As a page shows it: nothing reorders it, and it ends.
        let long = format!("https://evil.example.org/{}", "a".repeat(10_000));
        let whole = format!("https://evil.example.org/{}", "a".repeat(175));
        for (asked, shown) in [
            (
                "https://evil.example.org/\u{202e}gro.elpmaxe",
                "https://evil.example.org/\u{fffd}gro.elpmaxe".to_owned(),
            ),
            (&long, format!("{whole}\u{2026}")),
            (&whole, whole.clone()),
        ] {
            let outcome = complete(begin_logout(
                &scenario.app,
                "acme",
                hint(&identity, Some(asked)),
                Some(&signed_in.ticket),
            ));
            assert_eq!(
                outcome,
                Ok(Logout::ReturnUnregistered { address: shown }),
                "{asked}"
            );
        }
        assert_eq!(whole.chars().count(), 200);

        // A client gone has registered no address.
        scenario.storage.remove_client("webapp");
        let outcome = complete(begin_logout(
            &scenario.app,
            "acme",
            hint(&identity, Some(GOODBYE)),
            Some(&signed_in.ticket),
        ));
        assert_eq!(
            outcome,
            Ok(Logout::ReturnUnregistered {
                address: GOODBYE.to_owned()
            })
        );
        assert!(is_signed_in(&scenario, &signed_in.ticket));
    }

    #[test]
    fn without_the_identity_token_of_this_very_session_the_person_is_asked() {
        let scenario = Scenario::start();
        let signed_in = scenario.sign_in("openid");
        let another_session = scenario.sign_in("openid");
        let of_another = another_session.tokens.id_token.expect("an identity token");
        let access = signed_in.tokens.access_token.clone();
        let identity = signed_in
            .tokens
            .id_token
            .clone()
            .expect("an identity token");
        let of_another_client = LogoutParameters {
            client_id: Some("billing"),
            ..hint(&identity, Some(GOODBYE))
        };

        for (parameters, cause) in [
            (LogoutParameters::default(), ConfirmationCause::NoHint),
            (hint("", Some(GOODBYE)), ConfirmationCause::NoHint),
            (
                hint("not.a.token", Some(GOODBYE)),
                ConfirmationCause::HintNotOfSession,
            ),
            (
                hint(&of_another, Some(GOODBYE)),
                ConfirmationCause::HintNotOfSession,
            ),
            // An access token is not an identity token, whatever it says.
            (
                hint(&access, Some(GOODBYE)),
                ConfirmationCause::HintNotOfSession,
            ),
            // A token proves nothing for a client it was not issued to.
            (of_another_client, ConfirmationCause::HintNotOfSession),
        ] {
            let outcome = complete(begin_logout(
                &scenario.app,
                "acme",
                parameters,
                Some(&signed_in.ticket),
            ));
            assert_eq!(
                outcome,
                Ok(Logout::ConfirmationRequired(cause)),
                "{parameters:?}"
            );
        }
        assert!(is_signed_in(&scenario, &signed_in.ticket));
        // Without the session, it sends the browser nowhere either.
        assert_eq!(
            complete(begin_logout(&scenario.app, "acme", of_another_client, None)),
            Ok(Logout::SignedOut {
                location: None,
                frames: Vec::new(),
            })
        );
        assert_eq!(
            complete(begin_logout(
                &scenario.app,
                "acme",
                LogoutParameters {
                    client_id: Some("webapp"),
                    ..hint(&identity, Some(GOODBYE))
                },
                None
            )),
            Ok(Logout::SignedOut {
                location: Some(format!("{GOODBYE}?state=s%20t")),
                frames: Vec::new(),
            }),
            "the client it was issued to is the one named"
        );

        assert_eq!(
            complete(confirm_logout(&scenario.app, "acme", &signed_in.ticket)),
            Ok(Vec::new())
        );
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

    #[test]
    fn a_parameter_sent_without_a_value_is_one_that_was_not_sent() {
        let scenario = Scenario::start();
        for empty in ["post_logout_redirect_uri", "client_id", "state"] {
            let signed_in = scenario.sign_in("openid");
            let identity = signed_in
                .tokens
                .id_token
                .clone()
                .expect("an identity token");
            let parameters = LogoutParameters {
                id_token_hint: Some(&identity),
                post_logout_redirect_uri: Some(if empty == "post_logout_redirect_uri" {
                    ""
                } else {
                    GOODBYE
                }),
                state: Some(""),
                client_id: Some(if empty == "client_id" { "" } else { "webapp" }),
                logout_hint: Some(""),
                ui_locales: Some(""),
            };

            let outcome = complete(begin_logout(
                &scenario.app,
                "acme",
                parameters,
                Some(&signed_in.ticket),
            ));

            let location = (empty != "post_logout_redirect_uri").then(|| GOODBYE.to_owned());
            assert_eq!(
                outcome,
                Ok(Logout::SignedOut {
                    location,
                    frames: Vec::new(),
                }),
                "{empty}"
            );
            assert!(!is_signed_in(&scenario, &signed_in.ticket), "{empty}");
        }
    }

    /// The state a query carries, as its reader decodes it.
    fn read_state(location: &str) -> Option<String> {
        let (_, written) = location.split_once("state=")?;
        let mut bytes = Vec::new();
        let mut rest = written.bytes();
        while let Some(byte) = rest.next() {
            if byte == b'%' {
                let digits = [rest.next()?, rest.next()?];
                bytes.push(u8::from_str_radix(std::str::from_utf8(&digits).ok()?, 16).ok()?);
            } else {
                bytes.push(byte);
            }
        }
        String::from_utf8(bytes).ok()
    }

    #[test]
    fn a_state_escaped_whole_reaches_its_client_through_a_browser_that_folds_the_case_of_its_target()
     {
        let state = "RbpoyN'(&`./-!$&|{$'#'/$?-@'>.{$)[=~ \u{e9}";

        let escaped = write_return_location(GOODBYE, Some(state), StateSpelling::Escaped);
        assert_eq!(
            read_state(&escaped.to_lowercase()).as_deref(),
            Some(state),
            "{escaped}"
        );

        let plain = write_return_location(GOODBYE, Some(state), StateSpelling::Plain);
        assert_eq!(read_state(&plain).as_deref(), Some(state), "{plain}");
        assert_ne!(
            read_state(&plain.to_lowercase()).as_deref(),
            Some(state),
            "the letters of a plain state do not survive the folding"
        );
    }

    #[test]
    fn a_sign_out_that_loads_frames_escapes_every_byte_of_the_state_it_returns() {
        let scenario = Scenario::start();
        scenario.register_framed("framed", Some("https://app.example.org/signed-out"));
        let signed_in = scenario.sign_in("openid");
        scenario.grant_in_session("framed", "openid", None, &signed_in.ticket);
        let identity = signed_in.tokens.id_token.expect("an identity token");

        let outcome = complete(begin_logout(
            &scenario.app,
            "acme",
            LogoutParameters {
                state: Some("AbC~"),
                ..hint(&identity, Some(GOODBYE))
            },
            Some(&signed_in.ticket),
        ));

        let Ok(Logout::SignedOut { location, frames }) = outcome else {
            panic!("the identity token of the session ends it: {outcome:?}");
        };
        assert_eq!(frames.len(), 1, "{frames:?}");
        assert_eq!(
            location,
            Some(format!("{GOODBYE}?state=%41%62%43%7E")),
            "each byte of the state escaped, in upper case"
        );
    }

    #[test]
    fn each_client_the_session_served_that_registered_an_address_is_told_with_iss_and_sid_alone() {
        let scenario = Scenario::start();
        scenario.register_framed(
            "framed",
            Some("https://app.example.org/signed-out?from=idp"),
        );
        let signed_in = scenario.sign_in("openid");
        let tokens = scenario.grant_in_session("framed", "openid", None, &signed_in.ticket);
        let identity = signed_in.tokens.id_token.expect("an identity token");

        let frames = sign_out(&scenario, &identity, &signed_in.ticket);

        let sid = read_claims(&tokens.id_token.expect("an identity token"))["sid"]
            .as_str()
            .expect("a session")
            .to_owned();
        assert_eq!(
            frames,
            [FrontChannelLogout {
                url: format!("https://app.example.org/signed-out?from=idp&iss={ISSUER}&sid={sid}"),
                source: "https://app.example.org".to_owned(),
            }],
            "the query it registered kept, then the two, and nothing else"
        );
        assert_eq!(sid, signed_in.ticket.session.to_string());
    }

    #[test]
    fn a_client_without_an_address_disabled_gone_or_of_another_session_is_told_nothing() {
        let scenario = Scenario::start();
        for client_id in ["told", "disabled", "gone", "elsewhere"] {
            let address = format!("https://app.example.org/{client_id}");
            scenario.register_framed(client_id, Some(&address));
        }
        let signed_in = scenario.sign_in("openid");
        for client_id in ["told", "disabled", "gone"] {
            scenario.grant_in_session(client_id, "openid", None, &signed_in.ticket);
        }
        let another = scenario.sign_in("openid");
        scenario.grant_in_session("elsewhere", "openid", None, &another.ticket);
        scenario.storage.disable_client("disabled");
        scenario.storage.remove_client("gone");
        let identity = signed_in.tokens.id_token.expect("an identity token");

        let frames = sign_out(&scenario, &identity, &signed_in.ticket);

        let sid = signed_in.ticket.session;
        assert_eq!(
            list_urls(&frames),
            [format!(
                "https://app.example.org/told?iss={ISSUER}&sid={sid}"
            )],
            "webapp registered no address"
        );
        assert_eq!(
            read_last_ending(&scenario)["clients_served"],
            json!(["told", "webapp"]),
            "served at one instant, in the order of their identifiers"
        );
    }

    #[test]
    fn two_clients_at_one_address_are_told_by_one_frame_in_the_order_they_were_first_served() {
        let scenario = Scenario::start();
        scenario.register_framed("later", Some("https://app.example.org/later"));
        for client_id in ["shared-b", "shared-a"] {
            scenario.register_framed(client_id, Some("https://app.example.org/shared"));
        }
        let signed_in = scenario.sign_in("openid");
        for client_id in ["shared-b", "later", "shared-a"] {
            scenario.clock.advance(std::time::Duration::from_secs(1));
            scenario.grant_in_session(client_id, "openid", None, &signed_in.ticket);
        }
        let identity = signed_in.tokens.id_token.expect("an identity token");

        let frames = sign_out(&scenario, &identity, &signed_in.ticket);

        let sid = signed_in.ticket.session;
        assert_eq!(
            list_urls(&frames),
            [
                format!("https://app.example.org/shared?iss={ISSUER}&sid={sid}"),
                format!("https://app.example.org/later?iss={ISSUER}&sid={sid}"),
            ]
        );
    }

    #[test]
    fn past_the_bound_no_more_frames_are_loaded_and_the_ending_counts_every_client() {
        let scenario = Scenario::start();
        let signed_in = scenario.sign_in("openid");
        let served: Vec<String> = (0..12).map(|at| format!("framed-{at:02}")).collect();
        for client_id in &served {
            let address = format!("https://app.example.org/{client_id}");
            scenario.register_framed(client_id, Some(&address));
            scenario.grant_in_session(client_id, "openid", None, &signed_in.ticket);
        }
        let identity = signed_in.tokens.id_token.expect("an identity token");

        let frames = sign_out(&scenario, &identity, &signed_in.ticket);

        assert_eq!(frames.len(), 10, "{frames:?}");
        assert!(frames[9].url.contains("/framed-09?"), "{frames:?}");
        let ending = read_last_ending(&scenario);
        assert_eq!(ending["clients_served_count"], 13);
        assert_eq!(
            ending["clients_served"].as_array().map(Vec::len),
            Some(13),
            "{ending}"
        );
    }

    /// What a session served, each client at its address, in this order.
    fn serve(addresses: &[&str]) -> ServedClients {
        let first: Vec<ServedClient> = addresses
            .iter()
            .enumerate()
            .map(|(at, address)| ServedClient {
                client_id: format!("served-{at}"),
                frontchannel_logout_uri: Some((*address).to_owned()),
            })
            .collect();
        let count = u64::try_from(first.len()).expect("a count");
        ServedClients { first, count }
    }

    fn write_paths(served: &ServedClients) -> Vec<String> {
        write_frames("https://id.example.test/realms/acme", Uuid::nil(), served)
            .into_iter()
            .map(|frame| {
                let (address, _) = frame.url.split_once('?').expect("a query");
                address.rsplit('/').next().unwrap_or_default().to_owned()
            })
            .collect()
    }

    #[test]
    fn frames_stop_before_their_origins_would_take_more_than_the_bound_in_bytes() {
        // Each origin takes 1,536 bytes with its space: two take 3 KiB.
        let (one, other) = ("a".repeat(1527), "b".repeat(1527));
        let at_the_bound = [
            format!("https://{one}/first"),
            format!("https://{one}/first"),
            format!("https://{one}/second"),
            format!("https://{other}/third"),
            "https://app.example.org/past".to_owned(),
            format!("https://{one}/after"),
        ];
        let at_the_bound: Vec<&str> = at_the_bound.iter().map(String::as_str).collect();

        assert_eq!(
            write_paths(&serve(&at_the_bound)),
            ["first", "second", "third"],
            "an origin named already takes nothing more, and the first past the bound ends them"
        );
        let past = format!("https://{other}b/past");
        assert_eq!(
            write_paths(&serve(&[at_the_bound[0], past.as_str()])),
            ["first"],
            "one byte past"
        );
    }

    #[test]
    fn an_address_no_policy_names_is_passed_over() {
        let served = serve(&["https://[::1]/unnamed", "https://app.example.org/named"]);

        assert_eq!(write_paths(&served), ["named"]);
    }

    #[test]
    fn the_ending_names_the_first_hundred_clients_the_session_served_and_counts_them_all() {
        let scenario = Scenario::start();
        let signed_in = scenario.sign_in("openid");
        for at in 0..MOST_NAMED_SERVED_CLIENTS {
            let client_id = format!("served-{at:03}");
            scenario.register_framed(&client_id, None);
            scenario.grant_in_session(&client_id, "openid", None, &signed_in.ticket);
        }

        complete(confirm_logout(&scenario.app, "acme", &signed_in.ticket)).expect("a sign-out");

        let ending = read_last_ending(&scenario);
        assert_eq!(ending["clients_served_count"], 101);
        let named = ending["clients_served"].as_array().expect("names");
        assert_eq!(named.len(), 100);
        assert_eq!(
            named[99], "served-099",
            "webapp, last by its name, is counted"
        );
    }

    #[test]
    fn a_confirmed_sign_out_tells_the_clients_the_session_served() {
        let scenario = Scenario::start();
        scenario.register_framed("framed", Some("https://app.example.org/signed-out"));
        let signed_in = scenario.sign_in("openid");
        scenario.grant_in_session("framed", "openid", None, &signed_in.ticket);

        let frames =
            complete(confirm_logout(&scenario.app, "acme", &signed_in.ticket)).expect("a sign-out");

        let sid = signed_in.ticket.session;
        assert_eq!(
            list_urls(&frames),
            [format!(
                "https://app.example.org/signed-out?iss={ISSUER}&sid={sid}"
            )]
        );
        assert_eq!(
            complete(confirm_logout(&scenario.app, "acme", &signed_in.ticket)),
            Ok(Vec::new()),
            "a session over tells nobody again"
        );
    }

    #[test]
    fn a_request_posted_is_carried_on_with_each_parameter_it_named_once() {
        let parameters = LogoutParameters {
            id_token_hint: Some("a.b.c"),
            post_logout_redirect_uri: Some("https://app.example.org/bye?x=1"),
            state: Some("s t&"),
            client_id: Some("webapp"),
            logout_hint: Some("ada@example.org"),
            ui_locales: Some("fr en"),
        };

        assert_eq!(
            write_logout_query(&parameters),
            "?id_token_hint=a.b.c\
             &post_logout_redirect_uri=https%3A%2F%2Fapp.example.org%2Fbye%3Fx%3D1\
             &state=s%20t%26&client_id=webapp&logout_hint=ada%40example.org&ui_locales=fr%20en"
        );
        assert_eq!(write_logout_query(&LogoutParameters::default()), "");
        assert_eq!(
            write_logout_query(&LogoutParameters {
                state: Some("s"),
                ..LogoutParameters::default()
            }),
            "?state=s"
        );
    }

    #[test]
    fn the_parameters_of_a_sign_out_print_no_identity_token_hint_nor_logout_hint() {
        let printed = format!(
            "{:?}",
            LogoutParameters {
                logout_hint: Some("ada@example.org"),
                ..hint("eyJhbGciOiJFUzI1NiJ9.e30.c2ln", Some(GOODBYE))
            }
        );

        assert!(!printed.contains("eyJ"), "{printed}");
        assert!(!printed.contains("ada@"), "{printed}");
        assert!(printed.contains("id_token_hint: Some"), "{printed}");
        assert!(printed.contains(GOODBYE), "{printed}");
    }
}
