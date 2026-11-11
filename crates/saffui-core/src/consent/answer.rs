//! The page on which a person allows a client what it asks, or refuses it.
//! Only the browser that started the request reaches it, signed in as the
//! person the request waits for.

use serde_json::json;
use time::Duration;
use uuid::Uuid;

use super::Consent;
use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::clients::{Client, neutralize_unshowable, read_named_client};
use crate::error::{ErrorCode, Failure};
use crate::login::session::{
    OFFLINE_SESSION_LIFETIME, Session, SessionTicket, find_answering_session,
};
use crate::oidc::authorize::{
    CodeGrant, issue_code, leave_out_offline_access, write_return_location,
};
use crate::oidc::code::PendingAuthorization;
use crate::oidc::discovery::name_issuer;
use crate::oidc::errors::OAuthError;
use crate::oidc::token::OFFLINE_ACCESS_SCOPE;
use crate::ports::storage::UnitOfWork;
use crate::secret::Secret;
use crate::tenancy::RealmName;
use crate::tenancy::resolve::resolve_realm;

/// What the page shows: who asks, and for what.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentPrompt {
    /// Written by whoever registered the client, with what a page cannot
    /// show as it is replaced. Text on the page, never markup.
    pub client_name: String,
    pub scopes: Vec<String>,
    /// How long the client may act while the person is away, when allowing
    /// grants it: past their sign-out, until they withdraw it from their account.
    pub offline_access: Option<Duration>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsentDecision {
    Allow,
    Deny,
}

fn expire() -> Failure {
    Failure::new(ErrorCode::AuthorizationRequestExpired)
}

/// What allowing a client on the page grants of the scopes asked: all of
/// them to a client that requires consent; to another, all but
/// `offline_access`, which would outlive any consent the person could
/// withdraw. It is left out in silence, as OpenID Connect Core 1.0, section
/// 11, allows.
fn grant_on_the_page(client: &Client, asked: &[String]) -> Vec<String> {
    if client.requires_consent {
        asked.to_vec()
    } else {
        leave_out_offline_access(asked)
    }
}

/// Checks that a request read or taken waits for a consent, from this
/// browser and in the session of this ticket, and returns that session.
/// Another browser, another session, or a request that waits for no consent
/// are answered alike.
async fn check_waiting_consent(
    app: &App,
    work: &mut dyn UnitOfWork,
    pending: Option<PendingAuthorization>,
    browser_secret: &Secret,
    ticket: &SessionTicket,
) -> Result<(PendingAuthorization, Session), Failure> {
    let presented = app.digester.sha256(browser_secret.expose());
    let expected = pending
        .as_ref()
        .map_or(&[0_u8; 32][..], |known| known.browser_digest.as_slice());
    let same_browser = app.digester.equal_in_constant_time(&presented, expected);
    let pending = pending.filter(|_| same_browser).ok_or_else(expire)?;
    let waiting_in = pending.consent_session.ok_or_else(expire)?;
    let session = find_answering_session(app, work, ticket)
        .await?
        .filter(|session| session.id == waiting_in)
        .ok_or_else(expire)?;
    Ok((pending, session))
}

/// Tells the page what the client asks.
///
/// # Errors
///
/// Returns [`ErrorCode::AuthorizationRequestExpired`] when no request waits
/// for this browser and this session, [`ErrorCode::ClientNotFound`] when
/// the client may no longer sign anyone in, or the storage failure.
pub async fn describe_consent(
    app: &App,
    realm: &str,
    request: Uuid,
    browser_secret: &Secret,
    ticket: Option<&SessionTicket>,
) -> Result<ConsentPrompt, Failure> {
    let ticket = ticket.ok_or_else(expire)?;
    let (_, scope) = resolve_realm(app, realm).await?;
    let mut work = app.storage.begin(scope).await?;
    let read = work.read_pending_authorization(request, app.now()).await?;
    let (pending, _) =
        check_waiting_consent(app, work.as_mut(), read, browser_secret, ticket).await?;
    let client = read_named_client(work.as_mut(), &pending.client_id)
        .await?
        .filter(|client| client.enabled && client.allows_authorization_code)
        .ok_or(Failure::new(ErrorCode::ClientNotFound))?;
    let granted = grant_on_the_page(&client, &pending.scopes);
    Ok(ConsentPrompt {
        client_name: neutralize_unshowable(&client.name),
        scopes: leave_out_offline_access(&granted),
        offline_access: granted
            .iter()
            .any(|scope| scope == OFFLINE_ACCESS_SCOPE)
            .then_some(OFFLINE_SESSION_LIFETIME),
    })
}

/// Takes the answer of the person, and returns where the browser goes: to
/// the client with a code, or with `access_denied`. Allowed, the scopes
/// join what the person allowed the client before.
///
/// # Errors
///
/// Returns [`ErrorCode::AuthorizationRequestExpired`] as
/// [`describe_consent`] does, and to the second of two answers,
/// [`ErrorCode::ClientNotFound`] when the client may no longer sign anyone
/// in, or the storage failure.
pub async fn answer_consent(
    app: &App,
    realm: &str,
    request: Uuid,
    browser_secret: &Secret,
    ticket: Option<&SessionTicket>,
    decision: ConsentDecision,
) -> Result<String, Failure> {
    let ticket = ticket.ok_or_else(expire)?;
    let (realm, scope) = resolve_realm(app, realm).await?;
    let mut work = app.storage.begin(scope).await?;
    // Taken before it is checked: of two answers to one page, one decides. A
    // refusal abandons the unit of work, and the request waits again.
    let taken = work.take_pending_authorization(request, app.now()).await?;
    let (pending, session) =
        check_waiting_consent(app, work.as_mut(), taken, browser_secret, ticket).await?;
    let location = match decision {
        ConsentDecision::Allow => {
            allow_client(app, work.as_mut(), &realm, &pending, &session).await?
        }
        ConsentDecision::Deny => write_return_location(
            &pending.redirect_uri,
            &name_issuer(&app.settings, &realm),
            pending.state.as_deref(),
            &[("error", OAuthError::AccessDenied.name())],
        ),
    };
    work.commit().await?;
    Ok(location)
}

/// Keeps what the person allowed, and gives the client its code.
async fn allow_client(
    app: &App,
    work: &mut dyn UnitOfWork,
    realm: &RealmName,
    pending: &PendingAuthorization,
    session: &Session,
) -> Result<String, Failure> {
    let client = read_named_client(work, &pending.client_id)
        .await?
        .filter(|client| client.enabled && client.allows_authorization_code)
        .ok_or(Failure::new(ErrorCode::ClientNotFound))?;
    // Kept only for a client that requires it: to another, `prompt=consent`
    // asks once, nothing stands to be withdrawn, and so nothing is granted
    // that outlives the browser session.
    let given = grant_on_the_page(&client, &pending.scopes);
    if client.requires_consent {
        work.add_consent(&Consent {
            person: session.person,
            client_id: client.client_id.clone(),
            scopes: given.clone(),
            granted_at: app.now(),
        })
        .await?;
    }
    let location = issue_code(
        app,
        work,
        CodeGrant {
            realm,
            client_id: &client.client_id,
            redirect_uri: &pending.redirect_uri,
            scopes: &given,
            state: pending.state.as_deref(),
            nonce: pending.nonce.as_deref(),
            code_challenge: &pending.code_challenge,
            person: session.person,
            session: session.id,
            authenticated_at: session.authenticated_at,
        },
    )
    .await?;
    // The event comes last: the head of the chain stays locked until the commit.
    let granted = json!({
        "client_id": client.client_id,
        "kept": client.requires_consent,
        "person_id": session.person.to_string(),
        "scopes": given,
        "session_id": session.id.to_string(),
    });
    record_event(app, work, EventKind::ConsentGranted, granted).await?;
    Ok(location)
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use uuid::Uuid;

    use super::{ConsentDecision, ConsentPrompt, answer_consent, describe_consent};
    use crate::authz::capability::Capability;
    use crate::clients::register::{NewClient, register_client};
    use crate::consent::Consent;
    use crate::consent::manage::{
        list_my_consents, list_person_consents, withdraw_my_consent, withdraw_person_consent,
    };
    use crate::error::ErrorCode;
    use crate::login::session::SessionTicket;
    use crate::oidc::authorize::{
        Authorization, AuthorizationParameters, AuthorizationRefusal, SignInAnswer, SignInStep,
        TypedSignIn, begin_authorization, finish_sign_in,
    };
    use crate::oidc::errors::OAuthError;
    use crate::oidc::scenario::{CALLBACK, PASSWORD, Scenario};
    use crate::oidc::token::{TokenRequest, TokenResponse, grant_token};
    use crate::secret::Secret;
    use crate::testkit::drive::complete;

    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    /// Registers `partner`, a public client that requires the consent of each
    /// person, named as whoever registered it chose.
    fn register_partner(scenario: &Scenario, name: &str) {
        let scopes = ["openid".to_owned(), "email".to_owned()];
        let redirect_uris = [CALLBACK.to_owned()];
        let mut work =
            complete(scenario.app.storage.begin(scenario.scope)).expect("a unit of work");
        complete(register_client(
            &scenario.app,
            work.as_mut(),
            NewClient {
                client_id: "partner",
                name,
                scopes: &scopes,
                capabilities: &[],
                redirect_uris: &redirect_uris,
                post_logout_redirect_uris: &[],
                public: true,
                requires_consent: true,
                created_by: None,
            },
        ))
        .expect("a client");
        complete(work.commit()).expect("a commit");
    }

    struct Asked<'a> {
        client_id: &'a str,
        scope: &'a str,
        prompt: Option<&'a str>,
        hint: Option<&'a str>,
    }

    fn ask(
        scenario: &Scenario,
        asked: &Asked<'_>,
        ticket: Option<&SessionTicket>,
    ) -> Result<Authorization, AuthorizationRefusal> {
        let challenge = URL_SAFE_NO_PAD.encode(scenario.app.digester.sha256(VERIFIER.as_bytes()));
        let parameters = AuthorizationParameters {
            response_type: Some("code"),
            client_id: Some(asked.client_id),
            redirect_uri: Some(CALLBACK),
            scope: Some(asked.scope),
            state: Some("s1"),
            code_challenge: Some(&challenge),
            code_challenge_method: Some("S256"),
            prompt: asked.prompt,
            id_token_hint: asked.hint,
            ..AuthorizationParameters::default()
        };
        complete(begin_authorization(
            &scenario.app,
            "acme",
            parameters,
            ticket,
        ))
    }

    fn ask_partner(
        scenario: &Scenario,
        scope: &str,
        ticket: Option<&SessionTicket>,
    ) -> Result<Authorization, AuthorizationRefusal> {
        let asked = Asked {
            client_id: "partner",
            scope,
            prompt: None,
            hint: None,
        };
        ask(scenario, &asked, ticket)
    }

    /// Names where an answer leaves the browser: back with a code, on the
    /// sign-in or the consent page, or back with the error the client is told.
    fn read_outcome(answer: Result<Authorization, AuthorizationRefusal>) -> String {
        match answer {
            Ok(Authorization::Granted { .. }) => "granted".to_owned(),
            Ok(Authorization::SignInRequired { .. }) => "sign in".to_owned(),
            Ok(Authorization::ConsentRequired { .. }) => "consent".to_owned(),
            Err(AuthorizationRefusal::Returned { location }) => location
                .split_once("error=")
                .and_then(|(_, rest)| rest.split('&').next())
                .expect("an error")
                .to_owned(),
            Err(AuthorizationRefusal::Shown(failure)) => panic!("shown: {failure:?}"),
        }
    }

    /// Signs `name` in for a request of `partner`, and returns the request
    /// that now waits for their consent, its browser secret and their ticket.
    fn sign_in_for_partner(
        scenario: &Scenario,
        name: &str,
        scope: &str,
    ) -> (Uuid, Secret, SessionTicket) {
        let Ok(Authorization::SignInRequired {
            request,
            browser_secret,
        }) = ask_partner(scenario, scope, None)
        else {
            panic!("a person without a session signs in first");
        };
        let step = complete(finish_sign_in(
            &scenario.app,
            "acme",
            request,
            &browser_secret,
            TypedSignIn {
                answer: SignInAnswer::Password {
                    name,
                    password: Secret::new(PASSWORD.as_bytes().to_vec()),
                },
                caller: None,
                known_browsers: &[],
            },
        ))
        .expect("a signed-in person");
        let SignInStep::ConsentRequired(signed_in) = step else {
            panic!("a client that requires consent asks it: {step:?}");
        };
        assert_eq!(signed_in.request, request);
        (request, browser_secret, signed_in.ticket)
    }

    fn answer(
        scenario: &Scenario,
        request: Uuid,
        browser_secret: &Secret,
        ticket: Option<&SessionTicket>,
        decision: ConsentDecision,
    ) -> Result<String, ErrorCode> {
        complete(answer_consent(
            &scenario.app,
            "acme",
            request,
            browser_secret,
            ticket,
            decision,
        ))
        .map_err(|failure| failure.code)
    }

    /// What the last `consent.granted` of the realm says.
    fn read_last_grant(scenario: &Scenario) -> serde_json::Value {
        scenario
            .storage
            .read_audit_envelopes(scenario.scope.realm())
            .into_iter()
            .rev()
            .find(|event| event["kind"] == "consent.granted")
            .expect("a consent granted")["payload"]
            .clone()
    }

    fn read_code(location: &str) -> Option<String> {
        location
            .split_once("code=")
            .and_then(|(_, rest)| rest.split('&').next())
            .map(str::to_owned)
    }

    fn try_exchange(scenario: &Scenario, code: &str) -> Result<TokenResponse, OAuthError> {
        let request = TokenRequest {
            grant_type: Some("authorization_code"),
            client_id: Some("partner"),
            code: Some(code),
            redirect_uri: Some(CALLBACK),
            code_verifier: Some(VERIFIER),
            ..TokenRequest::default()
        };
        complete(grant_token(&scenario.app, "acme", request)).map_err(|failure| failure.error)
    }

    fn exchange(scenario: &Scenario, code: &str) -> TokenResponse {
        try_exchange(scenario, code).expect("tokens for the code")
    }

    fn sign_in_again(
        scenario: &Scenario,
        request: Uuid,
        browser_secret: &Secret,
    ) -> Result<SignInStep, ErrorCode> {
        complete(finish_sign_in(
            &scenario.app,
            "acme",
            request,
            browser_secret,
            TypedSignIn {
                answer: SignInAnswer::Password {
                    name: "ada",
                    password: Secret::new(PASSWORD.as_bytes().to_vec()),
                },
                caller: None,
                known_browsers: &[],
            },
        ))
        .map_err(|failure| failure.code)
    }

    /// Signs `ada` in for `partner`, allows it `openid`, and exchanges the code.
    fn consent_once(scenario: &Scenario) -> (SessionTicket, TokenResponse) {
        let (request, browser_secret, ticket) = sign_in_for_partner(scenario, "ada", "openid");
        let location = answer(
            scenario,
            request,
            &browser_secret,
            Some(&ticket),
            ConsentDecision::Allow,
        )
        .expect("a code");
        let tokens = exchange(scenario, &read_code(&location).expect("a code"));
        (ticket, tokens)
    }

    #[test]
    fn a_client_that_requires_consent_asks_once_and_again_only_for_a_new_scope() {
        let scenario = Scenario::start();
        register_partner(&scenario, "Partner <b>Inc</b>");
        let (request, browser_secret, ticket) = sign_in_for_partner(&scenario, "ada", "openid");

        assert_eq!(
            complete(describe_consent(
                &scenario.app,
                "acme",
                request,
                &browser_secret,
                Some(&ticket)
            )),
            Ok(ConsentPrompt {
                client_name: "Partner <b>Inc</b>".to_owned(),
                scopes: vec!["openid".to_owned()],
                offline_access: None,
            }),
            "the name is given as it was written: the page writes it as text"
        );
        let location = answer(
            &scenario,
            request,
            &browser_secret,
            Some(&ticket),
            ConsentDecision::Allow,
        )
        .expect("a code");
        assert!(location.starts_with(CALLBACK), "{location}");
        assert!(location.contains("state=s1"), "{location}");
        let tokens = exchange(&scenario, &read_code(&location).expect("a code"));
        assert!(tokens.id_token.is_some());
        assert_eq!(read_last_grant(&scenario)["kept"], true);

        assert_eq!(
            read_outcome(ask_partner(&scenario, "openid", Some(&ticket))),
            "granted",
            "what was allowed is not asked again"
        );
        assert_eq!(
            read_outcome(ask_partner(&scenario, "openid email", Some(&ticket))),
            "consent",
            "a new scope is asked"
        );
    }

    #[test]
    fn a_client_that_requires_consent_gets_no_code_from_a_session_alone_whatever_the_request_says()
    {
        let scenario = Scenario::start();
        register_partner(&scenario, "Partner");
        let signed_in = scenario.sign_in("openid");
        let ask_with = |scope: &str, prompt, hint| {
            let asked = Asked {
                client_id: "partner",
                scope,
                prompt,
                hint,
            };
            read_outcome(ask(&scenario, &asked, Some(&signed_in.ticket)))
        };

        assert_eq!(ask_with("openid", None, None), "consent");
        assert_eq!(ask_with("openid", Some("none"), None), "consent_required");

        // Allowed `openid` once, the person is the one a hint of the client names.
        let (ticket, tokens) = consent_once(&scenario);
        let hint = tokens.id_token.expect("an identity token");
        let ask_hinted = |scope: &str, prompt| {
            let asked = Asked {
                client_id: "partner",
                scope,
                prompt,
                hint: Some(&hint),
            };
            read_outcome(ask(&scenario, &asked, Some(&ticket)))
        };
        assert_eq!(ask_hinted("openid", Some("none")), "granted");
        assert_eq!(
            ask_hinted("openid email", Some("none")),
            "consent_required",
            "a hint that names the person is no answer of theirs"
        );
        assert_eq!(ask_hinted("openid email", None), "consent");
        assert_eq!(ask_with("openid", Some("consent"), None), "consent");
    }

    #[test]
    fn a_request_left_waiting_for_a_consent_is_counted_as_a_sign_in_left_waiting() {
        use crate::login::throttle::MAX_PENDING_SIGN_INS_PER_ADDRESS;

        let scenario = Scenario::start();
        register_partner(&scenario, "Partner");
        let ticket = scenario.sign_in("openid").ticket;
        let challenge = URL_SAFE_NO_PAD.encode(scenario.app.digester.sha256(VERIFIER.as_bytes()));
        let ask_from = |address: &str| {
            let parameters = AuthorizationParameters {
                response_type: Some("code"),
                client_id: Some("partner"),
                redirect_uri: Some(CALLBACK),
                scope: Some("openid"),
                code_challenge: Some(&challenge),
                code_challenge_method: Some("S256"),
                caller: Some(address.parse().expect("an address")),
                ..AuthorizationParameters::default()
            };
            match complete(begin_authorization(
                &scenario.app,
                "acme",
                parameters,
                Some(&ticket),
            )) {
                Ok(Authorization::ConsentRequired { .. }) => Ok(()),
                Err(AuthorizationRefusal::Shown(failure)) => Err(failure.code),
                other => panic!("neither a consent nor a refusal shown: {other:?}"),
            }
        };

        for _ in 0..MAX_PENDING_SIGN_INS_PER_ADDRESS {
            assert_eq!(ask_from("203.0.113.7"), Ok(()));
        }
        assert_eq!(
            ask_from("203.0.113.7"),
            Err(ErrorCode::SignInRequestsTooFrequent),
            "each keeps a row for ten minutes"
        );
        assert_eq!(ask_from("198.51.100.7"), Ok(()), "another address");
    }

    #[test]
    fn a_refused_consent_sends_access_denied_keeps_nothing_and_answers_once() {
        let scenario = Scenario::start();
        register_partner(&scenario, "Partner");
        let (request, browser_secret, ticket) = sign_in_for_partner(&scenario, "ada", "openid");

        let location = answer(
            &scenario,
            request,
            &browser_secret,
            Some(&ticket),
            ConsentDecision::Deny,
        )
        .expect("a refusal sent back");

        assert!(location.starts_with(CALLBACK), "{location}");
        assert!(location.contains("error=access_denied"), "{location}");
        assert!(location.contains("state=s1"), "{location}");
        assert_eq!(read_code(&location), None);
        assert_eq!(
            answer(
                &scenario,
                request,
                &browser_secret,
                Some(&ticket),
                ConsentDecision::Allow
            ),
            Err(ErrorCode::AuthorizationRequestExpired),
            "a request is answered once"
        );
        assert_eq!(
            complete(list_my_consents(&scenario.app, "acme", Some(&ticket))).map(|held| held.len()),
            Ok(0)
        );
    }

    #[test]
    fn only_the_browser_and_the_session_the_request_waits_for_can_answer() {
        let scenario = Scenario::start();
        register_partner(&scenario, "Partner");
        let (request, browser_secret, ticket) = sign_in_for_partner(&scenario, "ada", "openid");
        let another_session_of_ada = scenario.sign_in("openid").ticket;
        let other_browser = Secret::new(vec![7; 32]);

        for (secret, held) in [
            (&other_browser, Some(&ticket)),
            (&browser_secret, None),
            (&browser_secret, Some(&another_session_of_ada)),
        ] {
            assert_eq!(
                answer(&scenario, request, secret, held, ConsentDecision::Allow),
                Err(ErrorCode::AuthorizationRequestExpired)
            );
            assert_eq!(
                complete(describe_consent(
                    &scenario.app,
                    "acme",
                    request,
                    secret,
                    held
                ))
                .map_err(|failure| failure.code),
                Err(ErrorCode::AuthorizationRequestExpired)
            );
        }
        assert!(
            answer(
                &scenario,
                request,
                &browser_secret,
                Some(&ticket),
                ConsentDecision::Allow
            )
            .is_ok(),
            "the request still waits for its own browser and session"
        );
    }

    #[test]
    fn a_request_that_waits_for_a_sign_in_is_no_consent_to_answer() {
        let scenario = Scenario::start();
        register_partner(&scenario, "Partner");
        let ticket = scenario.sign_in("openid").ticket;
        let Ok(Authorization::SignInRequired {
            request,
            browser_secret,
        }) = ask_partner(&scenario, "openid", None)
        else {
            panic!("a pending sign-in");
        };

        assert_eq!(
            answer(
                &scenario,
                request,
                &browser_secret,
                Some(&ticket),
                ConsentDecision::Allow
            ),
            Err(ErrorCode::AuthorizationRequestExpired)
        );
    }

    #[test]
    fn someone_else_than_the_person_a_hint_names_is_sent_back_and_asked_nothing() {
        let scenario = Scenario::start();
        register_partner(&scenario, "Partner");
        complete(crate::testkit::fixtures::create_person(
            &scenario.app,
            scenario.scope,
            "bob",
            PASSWORD,
        ));
        let (_, tokens) = consent_once(&scenario);
        let hint = tokens.id_token.expect("an identity token of ada");
        let asked = Asked {
            client_id: "partner",
            scope: "openid email",
            prompt: Some("login"),
            hint: Some(&hint),
        };
        let Ok(Authorization::SignInRequired {
            request,
            browser_secret,
        }) = ask(&scenario, &asked, None)
        else {
            panic!("a fresh sign-in is asked");
        };

        let step = complete(finish_sign_in(
            &scenario.app,
            "acme",
            request,
            &browser_secret,
            TypedSignIn {
                answer: SignInAnswer::Password {
                    name: "bob",
                    password: Secret::new(PASSWORD.as_bytes().to_vec()),
                },
                caller: None,
                known_browsers: &[],
            },
        ))
        .expect("bob signed in");

        let SignInStep::Finished(finished) = step else {
            panic!("bob is not asked to allow a client that waits for ada: {step:?}");
        };
        assert!(
            finished.location.contains("error=login_required"),
            "{}",
            finished.location
        );
    }

    #[test]
    fn a_name_the_page_cannot_show_as_it_is_is_shown_with_what_it_hides_replaced() {
        use crate::clients::Client;

        let scenario = Scenario::start();
        // Written behind the back of the product, which refuses such a name.
        let partner = Client {
            id: Uuid::from_u128(9),
            client_id: "partner".to_owned(),
            name: "Pay\u{202e}lapyap".to_owned(),
            secret_digest: None,
            allows_client_credentials: false,
            allows_authorization_code: true,
            redirect_uris: vec![CALLBACK.to_owned()],
            post_logout_redirect_uris: Vec::new(),
            requires_consent: true,
            scopes: vec!["openid".to_owned()],
            capabilities: Vec::new(),
            enabled: true,
            created_at: scenario.app.now(),
        };
        let mut work =
            complete(scenario.app.storage.begin(scenario.scope)).expect("a unit of work");
        complete(work.insert_client(&partner)).expect("a client");
        complete(work.commit()).expect("a commit");
        let (request, browser_secret, ticket) = sign_in_for_partner(&scenario, "ada", "openid");

        let prompt = complete(describe_consent(
            &scenario.app,
            "acme",
            request,
            &browser_secret,
            Some(&ticket),
        ))
        .expect("a prompt");
        assert_eq!(prompt.client_name, "Pay\u{fffd}lapyap");

        answer(
            &scenario,
            request,
            &browser_secret,
            Some(&ticket),
            ConsentDecision::Allow,
        )
        .expect("a code");
        let held =
            complete(list_my_consents(&scenario.app, "acme", Some(&ticket))).expect("a list");
        assert_eq!(held[0].client_name, "Pay\u{fffd}lapyap");
    }

    #[test]
    fn a_withdrawn_consent_ends_the_refresh_tokens_of_its_client_and_is_asked_again() {
        let scenario = Scenario::start();
        register_partner(&scenario, "Partner");
        let (ticket, tokens) = consent_once(&scenario);
        let refresh_token = tokens.refresh_token.expect("a refresh token");
        let of_webapp = scenario
            .sign_in("openid")
            .tokens
            .refresh_token
            .expect("a refresh token of another client");
        let held =
            complete(list_my_consents(&scenario.app, "acme", Some(&ticket))).expect("a list");
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].client_name, "Partner");
        assert_eq!(held[0].consent.scopes, ["openid"]);

        complete(withdraw_my_consent(
            &scenario.app,
            "acme",
            Some(&ticket),
            "partner",
        ))
        .expect("a withdrawal");

        assert_eq!(
            scenario.refresh_as("partner", &refresh_token, None).err(),
            Some(OAuthError::InvalidGrant)
        );
        assert!(
            scenario.refresh(&of_webapp).is_ok(),
            "another client keeps what it holds"
        );
        assert_eq!(
            read_outcome(ask_partner(&scenario, "openid", Some(&ticket))),
            "consent"
        );
        let events = scenario
            .storage
            .read_audit_envelopes(scenario.scope.realm());
        let withdrawn = &events
            .iter()
            .find(|event| event["kind"] == "consent.withdrawn")
            .expect("the withdrawal is told")["payload"];
        assert_eq!(withdrawn["client_id"], "partner", "{withdrawn}");
        assert_eq!(withdrawn["refresh_families_revoked"], 1, "{withdrawn}");
        assert_eq!(withdrawn["refresh_tokens_revoked"], 1, "{withdrawn}");
        assert_eq!(
            withdrawn["refresh_families"].as_array().map(Vec::len),
            Some(1)
        );
        assert_eq!(
            withdrawn["actor"]["person_id"],
            scenario.find_ada().to_string()
        );
        assert!(
            !scenario
                .read_event_kinds()
                .contains(&"token.revoked".to_owned()),
            "the families it ended are told in its own entry"
        );

        assert_eq!(
            complete(withdraw_my_consent(
                &scenario.app,
                "acme",
                Some(&ticket),
                "partner"
            ))
            .map_err(|failure| failure.code),
            Err(ErrorCode::ConsentNotFound)
        );
        assert_eq!(
            complete(withdraw_my_consent(&scenario.app, "acme", None, "partner"))
                .map_err(|failure| failure.code),
            Err(ErrorCode::SessionRequired)
        );
    }

    #[test]
    fn an_administrator_reads_and_withdraws_the_consents_of_a_person() {
        let scenario = Scenario::start();
        register_partner(&scenario, "Partner");
        let (_, tokens) = consent_once(&scenario);
        let refresh_token = tokens.refresh_token.expect("a refresh token");
        let reader = scenario.name_operator(&[Capability::UserRead, Capability::UserWrite]);
        let ada = scenario.find_ada();

        let consents = complete(list_person_consents(&scenario.app, &reader, ada)).expect("a list");
        assert_eq!(consents.len(), 1);
        assert_eq!(consents[0].consent.client_id, "partner");
        assert_eq!(
            complete(list_person_consents(
                &scenario.app,
                &reader,
                Uuid::from_u128(5)
            ))
            .map_err(|failure| failure.code),
            Err(ErrorCode::PersonNotFound)
        );
        complete(withdraw_person_consent(
            &scenario.app,
            &reader,
            ada,
            "partner",
        ))
        .expect("a withdrawal");
        assert_eq!(
            scenario.refresh_as("partner", &refresh_token, None).err(),
            Some(OAuthError::InvalidGrant)
        );
        // Written behind the back of the product, which names no client so.
        let planted = Consent {
            person: ada,
            client_id: "not a client!".to_owned(),
            scopes: vec!["openid".to_owned()],
            granted_at: scenario.app.now(),
        };
        let mut work =
            complete(scenario.app.storage.begin(scenario.scope)).expect("a unit of work");
        complete(work.add_consent(&planted)).expect("a consent");
        complete(work.commit()).expect("a commit");
        assert_eq!(
            complete(withdraw_person_consent(
                &scenario.app,
                &reader,
                ada,
                "not a client!"
            ))
            .map_err(|failure| failure.code),
            Err(ErrorCode::ConsentNotFound),
            "what is not a client identifier names no consent"
        );
        let mut work =
            complete(scenario.app.storage.begin(scenario.scope)).expect("a unit of work");
        assert_eq!(
            complete(work.read_consent(ada, "not a client!")),
            Ok(Some(planted)),
            "and nothing is removed under it"
        );
    }

    #[test]
    fn a_code_given_before_a_withdrawal_obtains_nothing_after_it() {
        let scenario = Scenario::start();
        register_partner(&scenario, "Partner");
        let (request, browser_secret, ticket) = sign_in_for_partner(&scenario, "ada", "openid");
        let from_the_page = answer(
            &scenario,
            request,
            &browser_secret,
            Some(&ticket),
            ConsentDecision::Allow,
        )
        .expect("a code");
        let Ok(Authorization::Granted {
            location: from_the_session,
        }) = ask_partner(&scenario, "openid", Some(&ticket))
        else {
            panic!("allowed once, the session answers alone");
        };

        complete(withdraw_my_consent(
            &scenario.app,
            "acme",
            Some(&ticket),
            "partner",
        ))
        .expect("a withdrawal");

        for kept in [&from_the_page, &from_the_session] {
            let code = read_code(kept).expect("a code");
            assert_eq!(
                try_exchange(&scenario, &code).err(),
                Some(OAuthError::InvalidGrant),
                "a code kept across the withdrawal: {kept}"
            );
        }
    }

    #[test]
    fn prompt_consent_on_a_client_that_requires_none_asks_once_and_keeps_nothing() {
        let scenario = Scenario::start();
        let ticket = scenario.sign_in("openid").ticket;
        let asked = Asked {
            client_id: "webapp",
            scope: "openid",
            prompt: Some("consent"),
            hint: None,
        };
        let Ok(Authorization::ConsentRequired {
            request,
            browser_secret,
        }) = ask(&scenario, &asked, Some(&ticket))
        else {
            panic!("prompt=consent asks the person on a page");
        };

        let location = answer(
            &scenario,
            request,
            &browser_secret,
            Some(&ticket),
            ConsentDecision::Allow,
        )
        .expect("a code");

        assert!(read_code(&location).is_some(), "{location}");
        assert_eq!(
            complete(list_my_consents(&scenario.app, "acme", Some(&ticket))).map(|held| held.len()),
            Ok(0),
            "nothing kept: nothing stands to be withdrawn"
        );
        assert_eq!(
            read_last_grant(&scenario)["kept"],
            false,
            "the chain says the answer was kept nowhere"
        );
    }

    #[test]
    fn a_session_reads_what_was_allowed_only_when_it_decides() {
        let scenario = Scenario::start();
        register_partner(&scenario, "Partner");
        let ticket = scenario.sign_in("openid").ticket;
        let ask_with = |client_id: &str, prompt| {
            let asked = Asked {
                client_id,
                scope: "openid",
                prompt,
                hint: None,
            };
            read_outcome(ask(&scenario, &asked, Some(&ticket)))
        };
        let read = || scenario.storage.count_consent_reads();
        let before = read();

        assert_eq!(ask_with("webapp", None), "granted");
        assert_eq!(read(), before, "a client that requires none");
        assert_eq!(ask_with("partner", Some("consent")), "consent");
        assert_eq!(read(), before, "asked again whatever was allowed");
        assert_eq!(ask_with("partner", None), "consent");
        assert_eq!(read(), before + 1, "what was allowed decides: read once");
    }

    #[test]
    fn prompt_consent_without_a_session_asks_after_the_sign_in_and_reads_nothing_to_know_it() {
        let scenario = Scenario::start();
        register_partner(&scenario, "Partner");
        consent_once(&scenario);

        for client_id in ["webapp", "partner"] {
            let asked = Asked {
                client_id,
                scope: "openid",
                prompt: Some("consent"),
                hint: None,
            };
            let Ok(Authorization::SignInRequired {
                request,
                browser_secret,
            }) = ask(&scenario, &asked, None)
            else {
                panic!("a person without a session signs in first");
            };
            let before = scenario.storage.count_consent_reads();

            let step = sign_in_again(&scenario, request, &browser_secret);

            assert!(
                matches!(step, Ok(SignInStep::ConsentRequired(_))),
                "{client_id}, even allowed before: {step:?}"
            );
            assert_eq!(
                scenario.storage.count_consent_reads(),
                before,
                "{client_id}"
            );
        }
    }

    #[test]
    fn an_answer_takes_its_request_without_reading_it_first() {
        let scenario = Scenario::start();
        register_partner(&scenario, "Partner");
        let (request, browser_secret, ticket) = sign_in_for_partner(&scenario, "ada", "openid");
        let before = scenario.storage.count_pending_reads();

        answer(
            &scenario,
            request,
            &browser_secret,
            Some(&ticket),
            ConsentDecision::Deny,
        )
        .expect("a refusal sent back");

        assert_eq!(scenario.storage.count_pending_reads(), before);
    }

    #[test]
    fn a_page_without_a_session_opens_no_unit_of_work() {
        let scenario = Scenario::start();
        register_partner(&scenario, "Partner");
        let (request, browser_secret, _) = sign_in_for_partner(&scenario, "ada", "openid");
        let opened = scenario.storage.count_units_of_work();
        let code =
            |outcome: Result<(), crate::error::Failure>| outcome.map_err(|failure| failure.code);

        assert_eq!(
            code(complete(list_my_consents(&scenario.app, "acme", None)).map(|_| ())),
            Err(ErrorCode::SessionRequired)
        );
        assert_eq!(
            code(complete(withdraw_my_consent(
                &scenario.app,
                "acme",
                None,
                "partner"
            ))),
            Err(ErrorCode::SessionRequired)
        );
        assert_eq!(
            code(
                complete(describe_consent(
                    &scenario.app,
                    "acme",
                    request,
                    &browser_secret,
                    None
                ))
                .map(|_| ())
            ),
            Err(ErrorCode::AuthorizationRequestExpired)
        );
        assert_eq!(
            answer(
                &scenario,
                request,
                &browser_secret,
                None,
                ConsentDecision::Allow
            ),
            Err(ErrorCode::AuthorizationRequestExpired)
        );
        assert_eq!(scenario.storage.count_units_of_work(), opened);
    }

    #[test]
    fn a_session_of_the_password_alone_lists_and_withdraws_nothing_once_its_person_holds_a_factor()
    {
        let scenario = Scenario::start();
        register_partner(&scenario, "Partner");
        let (ticket, _) = consent_once(&scenario);
        let typed_secret = scenario.enroll_authenticator(&ticket);

        assert_eq!(
            complete(list_my_consents(&scenario.app, "acme", Some(&ticket)))
                .map(|held| held.len())
                .map_err(|failure| failure.code),
            Err(ErrorCode::SessionRequired)
        );
        assert_eq!(
            complete(withdraw_my_consent(
                &scenario.app,
                "acme",
                Some(&ticket),
                "partner"
            ))
            .map_err(|failure| failure.code),
            Err(ErrorCode::SessionRequired)
        );
        let proven = scenario.sign_in_with_code(&typed_secret);
        assert_eq!(
            complete(list_my_consents(&scenario.app, "acme", Some(&proven))).map(|held| held.len()),
            Ok(1),
            "nothing was withdrawn"
        );
    }

    #[test]
    fn a_person_disabled_since_they_signed_in_lists_and_withdraws_nothing() {
        let scenario = Scenario::start();
        register_partner(&scenario, "Partner");
        let (ticket, _) = consent_once(&scenario);
        scenario.storage.disable_person("ada");

        assert_eq!(
            complete(list_my_consents(&scenario.app, "acme", Some(&ticket)))
                .map(|held| held.len())
                .map_err(|failure| failure.code),
            Err(ErrorCode::SessionRequired)
        );
        assert_eq!(
            complete(withdraw_my_consent(
                &scenario.app,
                "acme",
                Some(&ticket),
                "partner"
            ))
            .map_err(|failure| failure.code),
            Err(ErrorCode::SessionRequired)
        );
    }

    #[test]
    fn a_client_disabled_while_its_request_waits_gets_no_page_and_no_code() {
        let scenario = Scenario::start();
        register_partner(&scenario, "Partner");
        let (request, browser_secret, ticket) = sign_in_for_partner(&scenario, "ada", "openid");
        scenario.storage.disable_client("partner");

        assert_eq!(
            complete(describe_consent(
                &scenario.app,
                "acme",
                request,
                &browser_secret,
                Some(&ticket)
            ))
            .map_err(|failure| failure.code),
            Err(ErrorCode::ClientNotFound)
        );
        assert_eq!(
            answer(
                &scenario,
                request,
                &browser_secret,
                Some(&ticket),
                ConsentDecision::Allow
            ),
            Err(ErrorCode::ClientNotFound)
        );
    }

    #[test]
    fn a_second_sign_in_for_a_request_that_waits_for_a_consent_ends_its_own_session() {
        use crate::login::session::SessionState;

        let scenario = Scenario::start();
        register_partner(&scenario, "Partner");
        let (request, browser_secret, first) = sign_in_for_partner(&scenario, "ada", "openid");

        assert_eq!(
            sign_in_again(&scenario, request, &browser_secret).map(|_| ()),
            Err(ErrorCode::AuthorizationRequestExpired)
        );

        let events = scenario
            .storage
            .read_audit_envelopes(scenario.scope.realm());
        let ended = events
            .iter()
            .rev()
            .find(|event| event["kind"] == "session.ended")
            .and_then(|event| event["payload"]["session_id"].as_str())
            .and_then(|id| Uuid::parse_str(id).ok())
            .expect("the session of the second sign-in is ended");
        assert_ne!(ended, first.session);
        let mut work =
            complete(scenario.app.storage.begin(scenario.scope)).expect("a unit of work");
        let read = complete(work.read_session(ended))
            .expect("a read")
            .expect("the session");
        assert_eq!(
            read.session.state,
            SessionState::Ended,
            "its ticket proves nothing"
        );
        drop(work);
        assert!(
            answer(
                &scenario,
                request,
                &browser_secret,
                Some(&first),
                ConsentDecision::Allow
            )
            .is_ok(),
            "the request still waits for the first"
        );
    }

    #[test]
    fn a_client_removed_while_its_request_waits_is_asked_for_and_its_page_says_it_is_gone() {
        let scenario = Scenario::start();
        let asked = Asked {
            client_id: "webapp",
            scope: "openid",
            prompt: None,
            hint: None,
        };
        let Ok(Authorization::SignInRequired {
            request,
            browser_secret,
        }) = ask(&scenario, &asked, None)
        else {
            panic!("a person without a session signs in first");
        };
        scenario.storage.remove_client("webapp");

        let step = sign_in_again(&scenario, request, &browser_secret);

        let Ok(SignInStep::ConsentRequired(signed_in)) = step else {
            panic!("no code for a client gone: {step:?}");
        };
        assert_eq!(
            complete(describe_consent(
                &scenario.app,
                "acme",
                request,
                &browser_secret,
                Some(&signed_in.ticket)
            ))
            .map_err(|failure| failure.code),
            Err(ErrorCode::ClientNotFound)
        );
    }

    #[test]
    fn a_code_asked_for_more_than_what_was_allowed_again_obtains_nothing() {
        let scenario = Scenario::start();
        register_partner(&scenario, "Partner");
        let (request, browser_secret, ticket) =
            sign_in_for_partner(&scenario, "ada", "openid email");
        let wider = answer(
            &scenario,
            request,
            &browser_secret,
            Some(&ticket),
            ConsentDecision::Allow,
        )
        .expect("a code for openid and email");
        complete(withdraw_my_consent(
            &scenario.app,
            "acme",
            Some(&ticket),
            "partner",
        ))
        .expect("a withdrawal");
        let Ok(Authorization::ConsentRequired {
            request,
            browser_secret,
        }) = ask_partner(&scenario, "openid", Some(&ticket))
        else {
            panic!("withdrawn, the consent is asked again");
        };
        answer(
            &scenario,
            request,
            &browser_secret,
            Some(&ticket),
            ConsentDecision::Allow,
        )
        .expect("openid allowed again, and nothing more");

        assert_eq!(
            try_exchange(&scenario, &read_code(&wider).expect("a code")).err(),
            Some(OAuthError::InvalidGrant),
            "email is no longer allowed"
        );
    }

    #[test]
    fn a_page_without_a_session_is_refused_before_its_realm_is_looked_for() {
        let scenario = Scenario::start();
        let code =
            |outcome: Result<(), crate::error::Failure>| outcome.map_err(|failure| failure.code);
        let request = Uuid::from_u128(1);
        let browser_secret = Secret::new(vec![1; 32]);

        assert_eq!(
            code(complete(list_my_consents(&scenario.app, "nowhere", None)).map(|_| ())),
            Err(ErrorCode::SessionRequired)
        );
        assert_eq!(
            code(complete(withdraw_my_consent(
                &scenario.app,
                "nowhere",
                None,
                "partner"
            ))),
            Err(ErrorCode::SessionRequired)
        );
        assert_eq!(
            code(
                complete(describe_consent(
                    &scenario.app,
                    "nowhere",
                    request,
                    &browser_secret,
                    None
                ))
                .map(|_| ())
            ),
            Err(ErrorCode::AuthorizationRequestExpired)
        );
        assert_eq!(
            code(
                complete(answer_consent(
                    &scenario.app,
                    "nowhere",
                    request,
                    &browser_secret,
                    None,
                    ConsentDecision::Allow
                ))
                .map(|_| ())
            ),
            Err(ErrorCode::AuthorizationRequestExpired)
        );
    }

    #[test]
    fn a_sign_in_reads_the_flag_of_the_client_and_its_consent_in_one_statement() {
        let scenario = Scenario::start();
        let asked = Asked {
            client_id: "webapp",
            scope: "openid",
            prompt: None,
            hint: None,
        };
        let Ok(Authorization::SignInRequired {
            request,
            browser_secret,
        }) = ask(&scenario, &asked, None)
        else {
            panic!("a person without a session signs in first");
        };
        let clients = scenario.storage.count_client_reads();
        let consents = scenario.storage.count_consent_reads();

        let step = sign_in_again(&scenario, request, &browser_secret);

        assert!(matches!(step, Ok(SignInStep::Finished(_))), "{step:?}");
        assert_eq!(
            scenario.storage.count_client_reads(),
            clients,
            "no client read alone"
        );
        assert_eq!(scenario.storage.count_consent_reads(), consents + 1);
    }

    #[test]
    fn a_client_not_allowed_offline_access_is_refused_it_and_never_gets_it() {
        let scenario = Scenario::start();
        register_partner(&scenario, "Partner");

        assert_eq!(
            read_outcome(ask_partner(&scenario, "openid offline_access", None)),
            "invalid_scope"
        );
    }

    /// Asks `client_id` to have `ada` consent again to `scope`, and signs her
    /// in: the request then waits on the page.
    fn sign_in_asked_again(
        scenario: &Scenario,
        client_id: &str,
        scope: &str,
    ) -> (Uuid, Secret, SessionTicket) {
        let asked = Asked {
            client_id,
            scope,
            prompt: Some("consent"),
            hint: None,
        };
        let Ok(Authorization::SignInRequired {
            request,
            browser_secret,
        }) = ask(scenario, &asked, None)
        else {
            panic!("a person without a session signs in first");
        };
        let step = sign_in_again(scenario, request, &browser_secret).expect("a signed-in person");
        let SignInStep::ConsentRequired(signed_in) = step else {
            panic!("asked again, the person answers on the page: {step:?}");
        };
        (request, browser_secret, signed_in.ticket)
    }

    #[test]
    fn a_client_that_requires_no_consent_is_given_nothing_offline_even_allowed_on_the_page() {
        let scenario = Scenario::start();
        let (request, browser_secret, ticket) =
            sign_in_asked_again(&scenario, "webapp", "openid offline_access");

        let prompt = complete(describe_consent(
            &scenario.app,
            "acme",
            request,
            &browser_secret,
            Some(&ticket),
        ))
        .expect("the page");
        assert_eq!(
            prompt.scopes,
            ["openid"],
            "nothing is offered it would not give"
        );
        assert_eq!(prompt.offline_access, None);
        let location = answer(
            &scenario,
            request,
            &browser_secret,
            Some(&ticket),
            ConsentDecision::Allow,
        )
        .expect("an allowed client");
        let tokens = scenario.exchange_as("webapp", &read_code(&location).expect("a code"));

        assert_eq!(
            tokens.scope, "openid",
            "nobody could withdraw a grant offline from this client"
        );
        let issued = scenario
            .storage
            .read_audit_envelopes(scenario.scope.realm())
            .into_iter()
            .rev()
            .find(|event| event["kind"] == "token.issued")
            .expect("the exchange");
        assert_eq!(issued["payload"]["session_kind"], "browser", "{issued}");
        assert_eq!(
            issued["payload"]["session_id"],
            ticket.session.to_string(),
            "the grant lives in the browser session: {issued}"
        );
    }

    #[test]
    fn the_page_says_how_long_a_client_that_requires_consent_may_act_offline() {
        use crate::login::session::OFFLINE_SESSION_LIFETIME;

        let scenario = Scenario::start();
        scenario.register_partner();
        let (request, browser_secret, ticket) =
            sign_in_asked_again(&scenario, "partner", "openid offline_access");

        assert_eq!(
            complete(describe_consent(
                &scenario.app,
                "acme",
                request,
                &browser_secret,
                Some(&ticket),
            )),
            Ok(ConsentPrompt {
                client_name: "partner".to_owned(),
                scopes: vec!["openid".to_owned()],
                offline_access: Some(OFFLINE_SESSION_LIFETIME),
            }),
            "said in words, not as a scope"
        );
    }
}
