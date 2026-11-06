//! The page on which a person allows a client what it asks, or refuses it.
//! Only the browser that started the request reaches it, signed in as the
//! person the request waits for.

use serde_json::json;
use uuid::Uuid;

use super::Consent;
use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::clients::{neutralize_unshowable, read_named_client};
use crate::error::{ErrorCode, Failure};
use crate::login::session::{Session, SessionTicket, find_answering_session};
use crate::oidc::authorize::{CodeGrant, issue_code, write_return_location};
use crate::oidc::code::PendingAuthorization;
use crate::oidc::discovery::name_issuer;
use crate::oidc::errors::OAuthError;
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsentDecision {
    Allow,
    Deny,
}

fn expire() -> Failure {
    Failure::new(ErrorCode::AuthorizationRequestExpired)
}

/// Finds the request that waits for a consent, and the session it waits in.
/// Another browser, another session, or a request that waits for no consent
/// are answered alike.
async fn find_waiting_consent(
    app: &App,
    work: &mut dyn UnitOfWork,
    request: Uuid,
    browser_secret: &Secret,
    ticket: Option<&SessionTicket>,
) -> Result<(PendingAuthorization, Session), Failure> {
    let pending = work.read_pending_authorization(request, app.now()).await?;
    let presented = app.digester.sha256(browser_secret.expose());
    let expected = pending
        .as_ref()
        .map_or(&[0_u8; 32][..], |known| known.browser_digest.as_slice());
    let same_browser = app.digester.equal_in_constant_time(&presented, expected);
    let pending = pending.filter(|_| same_browser).ok_or_else(expire)?;
    let waiting_in = pending.consent_session.ok_or_else(expire)?;
    let session = match ticket {
        Some(ticket) => find_answering_session(app, work, ticket).await?,
        None => None,
    }
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
    let (_, scope) = resolve_realm(app, realm).await?;
    let mut work = app.storage.begin(scope).await?;
    let (pending, _) =
        find_waiting_consent(app, work.as_mut(), request, browser_secret, ticket).await?;
    let client = read_named_client(work.as_mut(), &pending.client_id)
        .await?
        .filter(|client| client.enabled && client.allows_authorization_code)
        .ok_or(Failure::new(ErrorCode::ClientNotFound))?;
    Ok(ConsentPrompt {
        client_name: neutralize_unshowable(&client.name),
        scopes: pending.scopes,
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
    let (realm, scope) = resolve_realm(app, realm).await?;
    let mut work = app.storage.begin(scope).await?;
    let (_, session) =
        find_waiting_consent(app, work.as_mut(), request, browser_secret, ticket).await?;
    // Taken, not read: of two answers to one page, one decides.
    let pending = work
        .take_pending_authorization(request, app.now())
        .await?
        .ok_or_else(expire)?;
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
    work.add_consent(&Consent {
        person: session.person,
        client_id: client.client_id.clone(),
        scopes: pending.scopes.clone(),
        granted_at: app.now(),
    })
    .await?;
    let location = issue_code(
        app,
        work,
        CodeGrant {
            realm,
            client_id: &client.client_id,
            redirect_uri: &pending.redirect_uri,
            scopes: &pending.scopes,
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
        "person_id": session.person.to_string(),
        "scopes": pending.scopes,
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

    fn read_code(location: &str) -> Option<String> {
        location
            .split_once("code=")
            .and_then(|(_, rest)| rest.split('&').next())
            .map(str::to_owned)
    }

    fn exchange(scenario: &Scenario, code: &str) -> TokenResponse {
        let request = TokenRequest {
            grant_type: Some("authorization_code"),
            client_id: Some("partner"),
            code: Some(code),
            redirect_uri: Some(CALLBACK),
            code_verifier: Some(VERIFIER),
            ..TokenRequest::default()
        };
        complete(grant_token(&scenario.app, "acme", request)).expect("tokens for the code")
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
        assert!(
            scenario
                .read_event_kinds()
                .contains(&"consent.granted".to_owned())
        );

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
        let someone_else = scenario.sign_in("openid").ticket;
        let other_browser = Secret::new(vec![7; 32]);

        for (secret, held) in [
            (&other_browser, Some(&ticket)),
            (&browser_secret, None),
            (&browser_secret, Some(&someone_else)),
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
        let kinds: Vec<&str> = events
            .iter()
            .filter_map(|event| event["kind"].as_str())
            .collect();
        let withdrawn = kinds
            .iter()
            .position(|kind| *kind == "consent.withdrawn")
            .expect("the withdrawal is told");
        assert_eq!(kinds.get(withdrawn + 1), Some(&"token.revoked"));
        let revoked = &events[withdrawn + 1]["payload"];
        assert_eq!(revoked["reason"], "consent_withdrawn", "{revoked}");
        assert_eq!(revoked["client_id"], "partner", "{revoked}");
        assert_eq!(revoked["tokens"], 1, "{revoked}");
        assert_eq!(
            events[withdrawn]["payload"]["actor"]["person_id"],
            scenario.find_ada().to_string()
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
    }
}
