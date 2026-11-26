//! What the authorization endpoint signs itself, in the implicit and the
//! hybrid flows (OpenID Connect Core 1.0, sections 3.2 and 3.3).
//!
//! The access token signed here is the one a code obtains at the token
//! endpoint, under the same consent and never beside a refresh token; the
//! identity token says what the scopes and mappers name only when nothing
//! else is handed back (OpenID Connect Core 1.0, section 5.4). Nothing
//! proves here which client reads the answer, so nothing outlives it.

use serde_json::{Value, json};
use uuid::Uuid;

use super::authorize::leave_out_offline_access;
use super::response::ResponseType;
use super::token::{HeldConsent, PersonTokens, Signed, hold_consent_for, sign_for_person};
use crate::app::App;
use crate::claims::request::ClaimsRequest;
use crate::claims::rules::NamedClaims;
use crate::clients::{Client, read_named_client};
use crate::consent::Allowance;
use crate::error::{ErrorCode, Failure};
use crate::login::session::{Session, read_live_subject};
use crate::ports::storage::UnitOfWork;
use crate::tokens::DEFAULT_ALGORITHM;

/// Whom an answer is for, as its caller holds them in the unit of work
/// that answers.
#[derive(Clone, Copy)]
pub(crate) enum AnswerSubject<'a> {
    /// Read in this unit: the client enabled, the session answering, and
    /// the consent the client requires held, or written, until the commit.
    Read {
        client: &'a Client,
        session: &'a Session,
        /// What the person allowed a client that asks them, as it was held
        /// or written; `None` for a client that asks nobody.
        allowed: Option<&'a Allowance>,
    },
    /// Named by a request read in other units: each is read again here.
    Named {
        client_id: &'a str,
        session: Uuid,
        person: Uuid,
    },
}

impl AnswerSubject<'_> {
    pub(crate) fn client_id(&self) -> &str {
        match self {
            Self::Read { client, .. } => &client.client_id,
            Self::Named { client_id, .. } => client_id,
        }
    }

    pub(crate) fn person(&self) -> Uuid {
        match self {
            Self::Read { session, .. } => session.person,
            Self::Named { person, .. } => *person,
        }
    }

    pub(crate) fn session(&self) -> Uuid {
        match self {
            Self::Read { session, .. } => session.id,
            Self::Named { session, .. } => *session,
        }
    }
}

/// What a request answered at the authorization endpoint signed in.
pub(crate) struct AuthorizationSigning<'a> {
    pub(crate) issuer: &'a str,
    pub(crate) subject: AnswerSubject<'a>,
    pub(crate) scopes: &'a [String],
    pub(crate) nonce: Option<&'a str>,
    pub(crate) response_type: ResponseType,
    /// The code the answer carries too, which the identity token binds.
    pub(crate) code: Option<&'a str>,
    pub(crate) claims: Option<&'a ClaimsRequest>,
}

/// What was signed, as the answer carries it, and what the chain is to say
/// of it once nothing else is left to do.
pub(crate) struct SignedAnswer {
    pub(crate) parameters: Vec<(&'static str, String)>,
    pub(crate) told: Value,
}

/// Signs what `response_type` asks of the authorization endpoint itself.
///
/// # Errors
///
/// Returns [`ErrorCode::ClientNotFound`] for a client that may no longer
/// sign anyone in, [`ErrorCode::SessionRequired`] for a session that ended
/// or a person disabled meanwhile, [`ErrorCode::ConsentNotFound`] for a
/// consent withdrawn meanwhile, or what signing fails with.
pub(crate) async fn sign_at_authorization(
    app: &App,
    work: &mut dyn UnitOfWork,
    signing: AuthorizationSigning<'_>,
) -> Result<SignedAnswer, Failure> {
    let signed = match signing.response_type {
        ResponseType::IdToken => Signed::Identity,
        ResponseType::CodeIdToken => Signed::BoundIdentity,
        ResponseType::IdTokenToken | ResponseType::CodeIdTokenToken => {
            Signed::AccessAndBoundIdentity
        }
        ResponseType::CodeToken => Signed::Access,
        ResponseType::Code => return Err(Failure::new(ErrorCode::Internal)),
    };
    // Nothing refreshes what is signed here: no grant outlives the session.
    let scopes = leave_out_offline_access(signing.scopes);
    let named;
    let held;
    let (client, session, person, allowed) = match signing.subject {
        AnswerSubject::Read {
            client,
            session,
            allowed,
        } => {
            let person = work
                .read_person(session.person)
                .await?
                .filter(|person| person.enabled)
                .ok_or(Failure::new(ErrorCode::SessionRequired))?;
            (client, session, person, allowed)
        }
        // Read where it is signed for: a client disabled, a session ended or
        // a consent withdrawn since the request was read gets nothing.
        AnswerSubject::Named {
            client_id,
            session,
            person,
        } => {
            let client = read_named_client(work, client_id)
                .await?
                .filter(|client| client.enabled && client.allows_authorization_code)
                .ok_or(Failure::new(ErrorCode::ClientNotFound))?;
            let (session, person) = read_live_subject(app, work, session)
                .await?
                .filter(|(_, read)| read.id == person)
                .ok_or(Failure::new(ErrorCode::SessionRequired))?;
            held = match hold_consent_for(work, &client, person.id, &scopes).await? {
                HeldConsent::NotRequired => None,
                HeldConsent::Allowed(allowance) => Some(allowance),
                HeldConsent::Short => return Err(Failure::new(ErrorCode::ConsentNotFound)),
            };
            named = (client, session);
            (&named.0, &named.1, person, held.as_ref())
        }
    };
    let named_claims = signing.claims.map(|request| NamedClaims {
        request,
        entitled: &client.scopes,
        allowed,
    });
    let tokens = sign_for_person(
        app,
        work,
        PersonTokens {
            issuer: signing.issuer,
            client_id: &client.client_id,
            session,
            person: &person,
            scopes: &scopes,
            nonce: signing.nonce,
            id_token_algorithm: client
                .id_token_signed_response_alg
                .unwrap_or(DEFAULT_ALGORITHM),
            signed,
            code: signing.code,
            named: named_claims,
            // No family is opened here: the access token names none, and
            // userinfo tells it what its scopes say, nothing by name.
            family: None,
        },
    )
    .await?;
    let mut parameters = Vec::new();
    if let Some(identity) = tokens.identity {
        parameters.push(("id_token", identity));
    }
    if let Some(access) = tokens.access {
        parameters.push(("access_token", access.token));
        parameters.push(("token_type", "Bearer".to_owned()));
        parameters.push(("expires_in", access.expires_in.to_string()));
        parameters.push(("scope", access.scope));
    }
    let told = json!({
        "client_id": client.client_id,
        "grant": "implicit",
        "person_id": person.id.to_string(),
        "response_type": signing.response_type.name(),
        "scope": scopes.join(" "),
        "session_id": session.id.to_string(),
        "session_kind": session.kind.name(),
    });
    Ok(SignedAnswer { parameters, told })
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::Value;

    use crate::audit::EventKind;
    use crate::authz::capability::Capability;
    use crate::claims::ClaimTarget;
    use crate::claims::manage::create_mapper;
    use crate::claims::{MapperKind, NewMapper};
    use crate::clients::register::NewClient;
    use crate::consent::answer::{ConsentDecision, answer_consent, describe_consent};
    use crate::error::ErrorCode;
    use crate::keys::rotate::rotate_signing_key_as_operator;
    use crate::login::session::SessionTicket;
    use crate::oidc::authorize::{
        Authorization, AuthorizationParameters, AuthorizationRefusal, SignInAnswer, SignInStep,
        TypedSignIn, begin_authorization, finish_sign_in,
    };
    use crate::oidc::response::{AuthorizationResponse, ResponseMode, ResponseType};
    use crate::oidc::scenario::{CALLBACK, PASSWORD, Scenario, VERIFIER};
    use crate::oidc::token::{TokenRequest, grant_token};
    use crate::oidc::userinfo::read_user_info;
    use crate::ports::crypto::SignatureAlgorithm;
    use crate::secret::Secret;
    use crate::testkit::drive::complete;
    use crate::testkit::fixtures::check_and_register_client;
    use crate::tokens::mint::write_half_hash;

    const NONCE: &str = "n-0S6_WzA2Mj";

    /// Registers the public application `client_id`, sent back to the
    /// callback, handed back what `response_types` declares.
    fn register(
        scenario: &Scenario,
        client_id: &str,
        response_types: &[ResponseType],
        requires_consent: bool,
        algorithm: Option<SignatureAlgorithm>,
    ) {
        let scopes = ["openid", "profile", "email", "roles", "offline_access"].map(str::to_owned);
        let callbacks = [CALLBACK.to_owned()];
        let mut work = complete(scenario.app.storage.begin(scenario.scope)).expect("a unit");
        complete(check_and_register_client(
            &scenario.app,
            work.as_mut(),
            NewClient {
                client_id,
                name: client_id,
                scopes: &scopes,
                capabilities: &[],
                redirect_uris: &callbacks,
                post_logout_redirect_uris: &[],
                frontchannel_logout_uri: None,
                response_types,
                public: true,
                requires_consent,
                id_token_signed_response_alg: algorithm,
                auth_method: None,
                jwks: None,
                jwks_uri: None,
                auth_signing_alg: None,
                request_object_signing_alg: None,
                require_signed_request_object: false,
                created_by: None,
            },
        ))
        .expect("an application");
        complete(work.commit()).expect("a commit");
    }

    /// `spa`, handed back each of the six.
    fn start() -> (Scenario, String) {
        let scenario = Scenario::start();
        register(&scenario, "spa", &ResponseType::ALL, false, None);
        let challenge = URL_SAFE_NO_PAD.encode(scenario.app.digester.sha256(VERIFIER.as_bytes()));
        (scenario, challenge)
    }

    fn ask<'a>(
        client_id: &'a str,
        response_type: &'a str,
        challenge: &'a str,
    ) -> AuthorizationParameters<'a> {
        AuthorizationParameters {
            response_type: Some(response_type),
            client_id: Some(client_id),
            redirect_uri: Some(CALLBACK),
            scope: Some("openid profile email"),
            state: Some("st&te"),
            nonce: Some(NONCE),
            code_challenge: Some(challenge),
            code_challenge_method: Some("S256"),
            ..AuthorizationParameters::default()
        }
    }

    /// Signs `ada` in for the request, and returns what the client is
    /// handed back, and her ticket.
    #[expect(
        clippy::large_types_passed_by_value,
        reason = "handed on as the endpoint hands it on"
    )]
    fn sign_in(
        scenario: &Scenario,
        parameters: AuthorizationParameters<'_>,
    ) -> (AuthorizationResponse, SessionTicket) {
        let begun = complete(begin_authorization(&scenario.app, "acme", parameters, None));
        let Ok(Authorization::SignInRequired {
            request,
            browser_secret,
        }) = begun
        else {
            panic!("a person without a session signs in: {begun:?}");
        };
        let step = complete(finish_sign_in(
            &scenario.app,
            "acme",
            request,
            &browser_secret,
            TypedSignIn {
                answer: SignInAnswer::Password {
                    name: "ada",
                    password: Secret::new(PASSWORD.as_bytes().to_vec()),
                },
                caller: None,
                known_browsers: &[],
            },
        ))
        .expect("a signed-in person");
        let SignInStep::Finished(finished) = step else {
            panic!("a person who owes nothing more is sent back: {step:?}");
        };
        (finished.response, finished.ticket)
    }

    /// What the client is told when the request is refused at once.
    #[expect(
        clippy::large_types_passed_by_value,
        reason = "handed on as the endpoint hands it on"
    )]
    fn refuse(
        scenario: &Scenario,
        parameters: AuthorizationParameters<'_>,
    ) -> AuthorizationResponse {
        match complete(begin_authorization(&scenario.app, "acme", parameters, None)) {
            Err(AuthorizationRefusal::Returned { response }) => response,
            other => panic!("returned to the client: {other:?}"),
        }
    }

    fn read_part(token: &str, part: usize) -> Value {
        let encoded = token.split('.').nth(part).expect("a compact token");
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).expect("base64url")).expect("JSON")
    }

    fn read_token(answer: &AuthorizationResponse, name: &str) -> Value {
        read_part(answer.read_parameter(name).expect("the token"), 1)
    }

    fn name_parameters(answer: &AuthorizationResponse) -> Vec<&'static str> {
        answer.parameters().iter().map(|(name, _)| *name).collect()
    }

    #[test]
    fn an_identity_token_beside_a_code_or_an_access_token_says_what_was_named_for_it() {
        let (scenario, challenge) = start();
        scenario.write_ada_attributes(&serde_json::json!({ "given_name": "Ada" }));
        let named = r#"{"id_token": {"email": null, "given_name": null}}"#;

        for asked in ["id_token code", "code id_token token", "id_token token"] {
            let (plain, _) = sign_in(&scenario, ask("spa", asked, &challenge));
            let identity = read_token(&plain, "id_token");
            for unsaid in ["email", "given_name"] {
                assert!(
                    identity.get(unsaid).is_none(),
                    "{asked}: the scopes say nothing there"
                );
            }
            let naming = AuthorizationParameters {
                claims: Some(named),
                ..ask("spa", asked, &challenge)
            };
            let (answer, _) = sign_in(&scenario, naming);
            let identity = read_token(&answer, "id_token");
            assert_eq!(identity["email"], "ada@example.org", "{asked}");
            assert_eq!(identity["given_name"], "Ada", "{asked}");
            assert!(identity.get("preferred_username").is_none(), "{asked}");
        }
    }

    #[test]
    fn an_access_token_signed_at_the_authorization_endpoint_is_told_nothing_by_name() {
        use crate::tokens::FAMILY_CLAIM;

        let (scenario, challenge) = start();
        let named = r#"{"userinfo": {"email": null}}"#;
        let told = |token: &str| {
            complete(read_user_info(&scenario.app, "acme", token))
                .expect("claims")
                .get("email")
                .cloned()
        };
        let in_session = |response_type, claims, ticket| {
            let parameters = AuthorizationParameters {
                scope: Some("openid"),
                claims,
                ..ask("spa", response_type, &challenge)
            };
            match complete(begin_authorization(
                &scenario.app,
                "acme",
                parameters,
                Some(ticket),
            )) {
                Ok(Authorization::Granted { response }) => response,
                other => panic!("the session answers: {other:?}"),
            }
        };
        let code_grant = AuthorizationParameters {
            scope: Some("openid"),
            claims: Some(named),
            ..ask("spa", "code", &challenge)
        };
        let (answer, ticket) = sign_in(&scenario, code_grant);
        let tokens = scenario.exchange_as("spa", answer.read_parameter("code").expect("a code"));
        assert_eq!(
            told(&tokens.access_token),
            Some(serde_json::json!("ada@example.org"))
        );

        let implicit = in_session("id_token token", None, &ticket);
        let access = implicit.read_parameter("access_token").expect("a token");
        assert_eq!(
            told(access),
            None,
            "a grant of the session names nothing for it"
        );
        assert!(read_part(access, 1).get(FAMILY_CLAIM).is_none());

        let hybrid = in_session("code token", Some(named), &ticket);
        let up_front = hybrid.read_parameter("access_token").expect("a token");
        assert_eq!(told(up_front), None, "no family is opened at the endpoint");
        assert!(read_part(up_front, 1).get(FAMILY_CLAIM).is_none());
        let exchanged = scenario.exchange_as("spa", hybrid.read_parameter("code").expect("a code"));
        assert_eq!(
            told(&exchanged.access_token),
            Some(serde_json::json!("ada@example.org"))
        );
    }

    #[test]
    fn each_response_type_hands_back_what_it_names_and_a_token_after_the_hash() {
        let (scenario, challenge) = start();
        let issued = ["state", "iss"];
        let access = ["access_token", "token_type", "expires_in", "scope"];
        for (asked, mode, named) in [
            ("code", ResponseMode::Query, vec!["code"]),
            ("id_token", ResponseMode::Fragment, vec!["id_token"]),
            (
                "token id_token",
                ResponseMode::Fragment,
                [&["id_token"][..], &access].concat(),
            ),
            (
                "id_token code",
                ResponseMode::Fragment,
                vec!["code", "id_token"],
            ),
            (
                "code token",
                ResponseMode::Fragment,
                [&["code"][..], &access].concat(),
            ),
            (
                "code id_token token",
                ResponseMode::Fragment,
                [&["code", "id_token"][..], &access].concat(),
            ),
        ] {
            let (answer, _) = sign_in(&scenario, ask("spa", asked, &challenge));

            assert_eq!(answer.mode(), mode, "{asked}");
            assert_eq!(
                name_parameters(&answer),
                [&named[..], &issued].concat(),
                "{asked}"
            );
            assert_eq!(answer.read_parameter("state"), Some("st&te"), "{asked}");
        }
    }

    #[test]
    fn an_implicit_request_asks_no_verifier_and_leaves_no_code_behind() {
        let (scenario, _) = start();
        let parameters = AuthorizationParameters {
            code_challenge: None,
            code_challenge_method: None,
            ..ask("spa", "id_token token", "")
        };

        let (answer, _) = sign_in(&scenario, parameters);

        assert!(answer.read_parameter("access_token").is_some());
        assert_eq!(answer.read_parameter("code"), None);
        let hybrid = AuthorizationParameters {
            code_challenge: None,
            ..ask("spa", "code id_token", "")
        };
        assert_eq!(
            refuse(&scenario, hybrid).read_parameter("error"),
            Some("invalid_request"),
            "a code is spent with its verifier, whatever comes with it"
        );
    }

    #[test]
    fn an_identity_token_signed_here_binds_by_their_hashes_the_token_and_the_code_beside_it() {
        let (scenario, challenge) = start();
        let half = |value: &str| {
            write_half_hash(
                scenario.app.digester.as_ref(),
                SignatureAlgorithm::Es256,
                value,
            )
            .expect("a hash")
        };
        for (asked, at_hash, c_hash) in [
            ("code id_token token", true, true),
            ("id_token token", true, false),
            ("code id_token", false, true),
            ("id_token", false, false),
        ] {
            let (answer, _) = sign_in(&scenario, ask("spa", asked, &challenge));
            let identity = read_token(&answer, "id_token");

            assert_eq!(identity["nonce"], NONCE, "{asked}");
            assert_eq!(identity["aud"], "spa", "{asked}");
            let expected_at_hash = answer
                .read_parameter("access_token")
                .filter(|_| at_hash)
                .map(half);
            assert_eq!(
                identity
                    .get("at_hash")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                expected_at_hash,
                "{asked}"
            );
            let expected_c_hash = answer.read_parameter("code").filter(|_| c_hash).map(half);
            assert_eq!(
                identity
                    .get("c_hash")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                expected_c_hash,
                "{asked}"
            );
        }
    }

    #[test]
    fn the_hashes_are_taken_in_the_algorithm_the_identity_token_is_signed_in() {
        let (scenario, challenge) = start();
        complete(rotate_signing_key_as_operator(
            &scenario.app,
            "acme",
            SignatureAlgorithm::Es384,
        ))
        .expect("a key of ES384");
        register(
            &scenario,
            "spa384",
            &[ResponseType::CodeIdTokenToken, ResponseType::IdToken],
            false,
            Some(SignatureAlgorithm::Es384),
        );

        let (answer, _) = sign_in(&scenario, ask("spa384", "code id_token token", &challenge));

        let id_token = answer
            .read_parameter("id_token")
            .expect("an identity token");
        assert_eq!(read_part(id_token, 0)["alg"], "ES384");
        let identity = read_part(id_token, 1);
        let half = |value: &str| {
            write_half_hash(
                scenario.app.digester.as_ref(),
                SignatureAlgorithm::Es384,
                value,
            )
            .expect("a hash")
        };
        let access_token = answer.read_parameter("access_token").expect("a token");
        assert_eq!(identity["at_hash"], half(access_token));
        assert_eq!(
            identity["c_hash"],
            half(answer.read_parameter("code").expect("a code"))
        );
        assert_eq!(
            read_part(access_token, 0)["alg"],
            "ES256",
            "an access token is signed as at the token endpoint"
        );
        let (alone, _) = sign_in(&scenario, ask("spa384", "id_token", &challenge));
        let id_token = alone.read_parameter("id_token").expect("an identity token");
        assert_eq!(read_part(id_token, 0)["alg"], "ES384", "alone too");
    }

    #[test]
    fn what_is_signed_here_says_what_the_token_endpoint_says_and_lives_as_long() {
        let (scenario, challenge) = start();
        let operator = scenario.name_operator(&[Capability::ClientWrite]);
        complete(create_mapper(
            &scenario.app,
            &operator,
            "spa",
            NewMapper {
                name: "api",
                kind: MapperKind::Audience {
                    audience: "https://api.example.org".to_owned(),
                },
                claim: None,
                targets: &[ClaimTarget::AccessToken],
                scope: None,
            },
        ))
        .expect("a mapper");
        let parameters = AuthorizationParameters {
            scope: Some("openid email roles"),
            ..ask("spa", "code id_token token", &challenge)
        };

        let (answer, _) = sign_in(&scenario, parameters);
        let exchanged = complete(grant_token(
            &scenario.app,
            "acme",
            TokenRequest {
                grant_type: Some("authorization_code"),
                client_id: Some("spa"),
                code: answer.read_parameter("code"),
                redirect_uri: Some(CALLBACK),
                code_verifier: Some(VERIFIER),
                ..TokenRequest::default()
            },
        ))
        .expect("the code of a hybrid flow is spent at the token endpoint");

        let here = read_token(&answer, "access_token");
        let there = read_part(&exchanged.access_token, 1);
        let names = |claims: &Value| {
            let mut names: Vec<String> = claims
                .as_object()
                .expect("claims")
                .keys()
                .cloned()
                .collect();
            names.sort();
            names
        };
        assert_eq!(names(&here), names(&there));
        for same in [
            "iss",
            "sub",
            "aud",
            "client_id",
            "scope",
            "sid",
            "acr",
            "realm_access",
        ] {
            assert_eq!(here[same], there[same], "{same}");
        }
        assert_eq!(
            here["exp"]
                .as_i64()
                .zip(here["iat"].as_i64())
                .map(|(exp, iat)| exp - iat),
            Some(300)
        );
        assert_eq!(answer.read_parameter("expires_in"), Some("300"));
        let identity = read_token(&answer, "id_token");
        let exchanged_identity = read_part(exchanged.id_token.as_deref().expect("one"), 1);
        assert_eq!(identity["sid"], here["sid"]);
        for same in ["iss", "sub", "aud", "sid", "acr", "amr", "auth_time"] {
            assert_eq!(identity[same], exchanged_identity[same], "{same}");
        }
        assert_eq!(answer.read_parameter("refresh_token"), None);
    }

    #[test]
    fn an_identity_token_alone_says_what_the_scopes_name() {
        let (scenario, challenge) = start();

        let (answer, _) = sign_in(&scenario, ask("spa", "id_token", &challenge));

        let identity = read_token(&answer, "id_token");
        assert_eq!(identity["preferred_username"], "ada", "{identity}");
        assert_eq!(identity["email"], "ada@example.org", "{identity}");
        assert_eq!(identity["email_verified"], false, "{identity}");
    }

    #[test]
    fn an_identity_token_beside_a_code_or_a_token_says_who_signed_in_and_nothing_more() {
        let (scenario, challenge) = start();
        let operator = scenario.name_operator(&[Capability::ClientWrite, Capability::UserRead]);
        complete(create_mapper(
            &scenario.app,
            &operator,
            "spa",
            NewMapper {
                name: "email-again",
                kind: MapperKind::Property {
                    property: crate::claims::PersonProperty::Email,
                },
                claim: Some("mail"),
                targets: &[ClaimTarget::IdToken],
                scope: Some("email"),
            },
        ))
        .expect("a mapper");
        let protocol = [
            "iss",
            "sub",
            "aud",
            "exp",
            "iat",
            "auth_time",
            "nonce",
            "acr",
            "amr",
            "azp",
            "sid",
            "at_hash",
            "c_hash",
        ];

        for asked in ["id_token token", "code id_token", "code id_token token"] {
            let (answer, _) = sign_in(&scenario, ask("spa", asked, &challenge));

            let identity = read_token(&answer, "id_token");
            let said: Vec<&String> = identity
                .as_object()
                .expect("claims")
                .keys()
                .filter(|name| !protocol.contains(&name.as_str()))
                .collect();
            assert!(said.is_empty(), "{asked}: {identity}");
            if let Some(code) = answer.read_parameter("code") {
                let exchanged = complete(grant_token(
                    &scenario.app,
                    "acme",
                    TokenRequest {
                        grant_type: Some("authorization_code"),
                        client_id: Some("spa"),
                        code: Some(code),
                        redirect_uri: Some(CALLBACK),
                        code_verifier: Some(VERIFIER),
                        ..TokenRequest::default()
                    },
                ))
                .expect("tokens for the code");
                let exchanged = read_part(exchanged.id_token.as_deref().expect("one"), 1);
                assert_eq!(exchanged["email"], "ada@example.org", "{asked}");
                assert_eq!(exchanged["mail"], "ada@example.org", "{asked}");
            }
        }
        let (alone, _) = sign_in(&scenario, ask("spa", "id_token", &challenge));
        assert_eq!(
            read_token(&alone, "id_token")["mail"],
            "ada@example.org",
            "what a mapper says goes in an identity token alone"
        );
    }

    #[test]
    fn a_token_signed_here_is_recorded_as_issued_and_carries_no_grant_offline() {
        let (scenario, challenge) = start();
        let parameters = AuthorizationParameters {
            scope: Some("openid offline_access"),
            ..ask("spa", "id_token token", &challenge)
        };

        let (answer, ticket) = sign_in(&scenario, parameters);

        assert_eq!(answer.read_parameter("scope"), Some("openid"));
        assert_eq!(read_token(&answer, "access_token")["scope"], "openid");
        let issued = scenario
            .storage
            .read_audit_envelopes(scenario.scope.realm())
            .into_iter()
            .rev()
            .find(|event| event["kind"] == "token.issued")
            .expect("the issue");
        assert_eq!(
            issued["payload"],
            serde_json::json!({
                "client_id": "spa",
                "grant": "implicit",
                "person_id": scenario.find_ada().to_string(),
                "response_type": "id_token token",
                "scope": "openid",
                "session_id": ticket.session.to_string(),
                "session_kind": "browser",
            })
        );
    }

    #[test]
    fn a_session_answers_an_implicit_request_at_once_and_says_so_in_the_chain() {
        let (scenario, challenge) = start();
        let (_, ticket) = sign_in(&scenario, ask("spa", "code", &challenge));
        let before = scenario.read_event_kinds().len();

        let answered = complete(begin_authorization(
            &scenario.app,
            "acme",
            ask("spa", "id_token token", &challenge),
            Some(&ticket),
        ));

        let Ok(Authorization::Granted { response }) = answered else {
            panic!("a session answers at once: {answered:?}");
        };
        assert_eq!(response.mode(), ResponseMode::Fragment);
        assert_eq!(
            read_token(&response, "access_token")["sid"],
            ticket.session.to_string()
        );
        assert_eq!(
            scenario.read_event_kinds()[before..],
            ["token.issued".to_owned()]
        );
    }

    #[test]
    fn an_access_token_signed_here_is_refused_once_its_client_is_disabled() {
        let (scenario, challenge) = start();
        let (answer, _) = sign_in(&scenario, ask("spa", "id_token token", &challenge));
        let token = answer.read_parameter("access_token").expect("a token");
        assert!(complete(read_user_info(&scenario.app, "acme", token)).is_ok());
        assert!(scenario.is_token_active(token));

        scenario.storage.disable_client("spa");

        assert_eq!(
            complete(read_user_info(&scenario.app, "acme", token)).map_err(|failure| failure.code),
            Err(ErrorCode::TokenInvalid)
        );
        assert!(!scenario.is_token_active(token));
    }

    #[test]
    fn a_type_the_client_did_not_declare_is_refused_where_its_answer_would_have_gone() {
        let (scenario, challenge) = start();

        for asked in ["id_token", "id_token token", "code id_token", "code token"] {
            let refused = refuse(&scenario, ask("webapp", asked, &challenge));

            assert_eq!(
                refused.read_parameter("error"),
                Some("unauthorized_client"),
                "{asked}"
            );
            assert_eq!(refused.mode(), ResponseMode::Fragment, "{asked}");
        }
        assert!(matches!(
            complete(begin_authorization(
                &scenario.app,
                "acme",
                ask("webapp", "code", &challenge),
                None
            )),
            Ok(Authorization::SignInRequired { .. })
        ));
    }

    #[test]
    fn a_type_or_a_mode_this_realm_does_not_serve_is_refused_and_told_where_the_client_reads() {
        let (scenario, challenge) = start();
        let with_mode = |response_type, response_mode| AuthorizationParameters {
            response_mode,
            ..ask("spa", response_type, &challenge)
        };

        for (parameters, error, mode) in [
            (
                with_mode("token", None),
                "unsupported_response_type",
                ResponseMode::Query,
            ),
            (
                with_mode("token", Some("fragment")),
                "unsupported_response_type",
                ResponseMode::Fragment,
            ),
            (
                with_mode("code none", None),
                "unsupported_response_type",
                ResponseMode::Query,
            ),
            (
                with_mode("id_token token", Some("query")),
                "unsupported_response_mode",
                ResponseMode::Fragment,
            ),
            (
                with_mode("code", Some("web_message")),
                "unsupported_response_mode",
                ResponseMode::Query,
            ),
            (
                with_mode("id_token", Some("jwt")),
                "unsupported_response_mode",
                ResponseMode::Fragment,
            ),
        ] {
            let refused = refuse(&scenario, parameters);

            assert_eq!(refused.read_parameter("error"), Some(error), "{error}");
            assert_eq!(refused.mode(), mode, "{error}");
            assert_eq!(refused.read_parameter("state"), Some("st&te"));
        }
    }

    #[test]
    fn a_client_that_declared_a_code_alone_is_never_answered_after_the_hash() {
        let (scenario, challenge) = start();
        let with_mode = |response_mode| AuthorizationParameters {
            response_mode: Some(response_mode),
            ..ask("webapp", "code", &challenge)
        };

        let refused = refuse(&scenario, with_mode("fragment"));

        assert_eq!(
            refused.read_parameter("error"),
            Some("unsupported_response_mode")
        );
        assert_eq!(refused.mode(), ResponseMode::Query, "told where it reads");
        let (posted, _) = sign_in(&scenario, with_mode("form_post"));
        assert_eq!(posted.mode(), ResponseMode::FormPost);
        assert!(posted.read_parameter("code").is_some());
    }

    #[test]
    fn a_refusal_travels_in_the_mode_the_request_named() {
        let (scenario, challenge) = start();

        for (response_type, response_mode, mode) in [
            ("code", Some("form_post"), ResponseMode::FormPost),
            ("code", Some("fragment"), ResponseMode::Fragment),
            ("id_token", None, ResponseMode::Fragment),
            ("id_token token", Some("form_post"), ResponseMode::FormPost),
        ] {
            let parameters = AuthorizationParameters {
                response_mode,
                scope: Some("openid payments"),
                ..ask("spa", response_type, &challenge)
            };

            let refused = refuse(&scenario, parameters);

            assert_eq!(refused.read_parameter("error"), Some("invalid_scope"));
            assert_eq!(refused.mode(), mode, "{response_type} {response_mode:?}");
        }
    }

    #[test]
    fn an_answer_goes_in_the_mode_the_request_named() {
        let (scenario, challenge) = start();
        for (response_type, response_mode, mode) in [
            ("code", Some("form_post"), ResponseMode::FormPost),
            ("code", Some("fragment"), ResponseMode::Fragment),
            ("code", Some("query"), ResponseMode::Query),
            ("code id_token", Some("form_post"), ResponseMode::FormPost),
            ("id_token token", Some("fragment"), ResponseMode::Fragment),
        ] {
            let parameters = AuthorizationParameters {
                response_mode,
                ..ask("spa", response_type, &challenge)
            };

            let (answer, _) = sign_in(&scenario, parameters);

            assert_eq!(answer.mode(), mode, "{response_type} {response_mode:?}");
        }
    }

    #[test]
    fn an_identity_token_signed_here_asks_a_nonce_and_the_openid_scope() {
        let (scenario, challenge) = start();
        for asked in [
            "id_token",
            "id_token token",
            "code id_token",
            "code id_token token",
        ] {
            for nonce in [None, Some("")] {
                let parameters = AuthorizationParameters {
                    nonce,
                    ..ask("spa", asked, &challenge)
                };

                let refused = refuse(&scenario, parameters);

                assert_eq!(
                    refused.read_parameter("error"),
                    Some("invalid_request"),
                    "{asked} {nonce:?}"
                );
                assert_eq!(refused.mode(), ResponseMode::Fragment, "{asked}");
            }
            let without_openid = AuthorizationParameters {
                scope: Some("profile"),
                ..ask("spa", asked, &challenge)
            };
            assert_eq!(
                refuse(&scenario, without_openid).read_parameter("error"),
                Some("invalid_request"),
                "{asked}"
            );
        }
        for asked in ["code", "code token"] {
            let parameters = AuthorizationParameters {
                nonce: None,
                ..ask("spa", asked, &challenge)
            };
            let (answer, _) = sign_in(&scenario, parameters);
            assert!(answer.read_parameter("code").is_some(), "{asked}");
        }
    }

    #[test]
    fn a_client_that_asks_each_person_asks_them_in_the_implicit_flow_too() {
        let (scenario, challenge) = start();
        register(
            &scenario,
            "partner-spa",
            &[ResponseType::IdTokenToken],
            true,
            None,
        );
        let begun = complete(begin_authorization(
            &scenario.app,
            "acme",
            ask("partner-spa", "id_token token", &challenge),
            None,
        ));
        let Ok(Authorization::SignInRequired {
            request,
            browser_secret,
        }) = begun
        else {
            panic!("a sign-in first: {begun:?}");
        };
        let step = complete(finish_sign_in(
            &scenario.app,
            "acme",
            request,
            &browser_secret,
            TypedSignIn {
                answer: SignInAnswer::Password {
                    name: "ada",
                    password: Secret::new(PASSWORD.as_bytes().to_vec()),
                },
                caller: None,
                known_browsers: &[],
            },
        ))
        .expect("a signed-in person");
        let SignInStep::ConsentRequired(signed_in) = step else {
            panic!("she is asked before anything is signed for the client: {step:?}");
        };
        assert!(
            !scenario
                .read_event_kinds()
                .contains(&"token.issued".to_owned()),
            "nothing is signed before she answers"
        );
        let silent = complete(begin_authorization(
            &scenario.app,
            "acme",
            AuthorizationParameters {
                prompt: Some("none"),
                ..ask("partner-spa", "id_token token", &challenge)
            },
            Some(&signed_in.ticket),
        ));
        let Err(AuthorizationRefusal::Returned { response }) = silent else {
            panic!("without a page, the client is told: {silent:?}");
        };
        assert_eq!(response.read_parameter("error"), Some("consent_required"));
        assert_eq!(response.mode(), ResponseMode::Fragment);

        let shown = complete(describe_consent(
            &scenario.app,
            "acme",
            request,
            &browser_secret,
            Some(&signed_in.ticket),
        ))
        .expect("the page")
        .shown;
        let allowed = complete(answer_consent(
            &scenario.app,
            "acme",
            request,
            &browser_secret,
            Some(&signed_in.ticket),
            ConsentDecision::Allow { shown },
        ))
        .expect("an allowed client");

        assert_eq!(allowed.mode(), ResponseMode::Fragment);
        assert!(allowed.read_parameter("access_token").is_some());
        assert_eq!(read_token(&allowed, "id_token")["nonce"], NONCE);
        let kinds = scenario.read_event_kinds();
        assert_eq!(
            kinds[kinds.len() - 2..],
            ["consent.granted".to_owned(), "token.issued".to_owned()]
        );
    }

    #[test]
    fn a_refused_consent_is_told_where_the_answer_would_have_gone() {
        let (scenario, challenge) = start();
        register(
            &scenario,
            "partner-spa",
            &[ResponseType::IdToken],
            true,
            None,
        );
        let parameters = AuthorizationParameters {
            response_mode: Some("form_post"),
            ..ask("partner-spa", "id_token", &challenge)
        };
        let Ok(Authorization::SignInRequired {
            request,
            browser_secret,
        }) = complete(begin_authorization(&scenario.app, "acme", parameters, None))
        else {
            panic!("a sign-in first");
        };
        let step = complete(finish_sign_in(
            &scenario.app,
            "acme",
            request,
            &browser_secret,
            TypedSignIn {
                answer: SignInAnswer::Password {
                    name: "ada",
                    password: Secret::new(PASSWORD.as_bytes().to_vec()),
                },
                caller: None,
                known_browsers: &[],
            },
        ))
        .expect("a signed-in person");
        let SignInStep::ConsentRequired(signed_in) = step else {
            panic!("asked first: {step:?}");
        };

        let denied = complete(answer_consent(
            &scenario.app,
            "acme",
            request,
            &browser_secret,
            Some(&signed_in.ticket),
            ConsentDecision::Deny,
        ))
        .expect("a refusal told to the client");

        assert_eq!(denied.mode(), ResponseMode::FormPost);
        assert_eq!(denied.read_parameter("error"), Some("access_denied"));
    }

    #[test]
    fn an_identity_token_signed_after_the_page_says_a_claim_a_scope_allowed_before_covers() {
        let (scenario, challenge) = start();
        register(
            &scenario,
            "partner-spa",
            &[ResponseType::IdToken],
            true,
            None,
        );
        let asking = |scope, prompt, claims| AuthorizationParameters {
            scope: Some(scope),
            prompt,
            claims,
            ..ask("partner-spa", "id_token", &challenge)
        };
        let (request, browser_secret, ticket) =
            sign_in_to_consent(&scenario, asking("openid email", None, None));
        let describe = |request, browser_secret: &Secret| {
            complete(describe_consent(
                &scenario.app,
                "acme",
                request,
                browser_secret,
                Some(&ticket),
            ))
            .expect("the page")
        };
        let allow = |request, browser_secret: &Secret, shown| {
            complete(answer_consent(
                &scenario.app,
                "acme",
                request,
                browser_secret,
                Some(&ticket),
                ConsentDecision::Allow { shown },
            ))
        };
        let shown = describe(request, &browser_secret).shown;
        allow(request, &browser_secret, shown).expect("an allowed client");
        let named = r#"{"id_token": {"email": null}}"#;
        let again = asking("openid", Some("consent"), Some(named));
        let begun = complete(begin_authorization(
            &scenario.app,
            "acme",
            again,
            Some(&ticket),
        ));
        let Ok(Authorization::ConsentRequired {
            request,
            browser_secret,
        }) = begun
        else {
            panic!("asked again, she answers on the page: {begun:?}");
        };

        let prompt = describe(request, &browser_secret);
        let allowed = allow(request, &browser_secret, prompt.shown);

        assert!(prompt.claims.is_empty(), "{:?}", prompt.claims);
        let identity = read_token(&allowed.expect("the page she saw"), "id_token");
        assert_eq!(identity["email"], "ada@example.org", "{identity}");
        assert_eq!(identity["email_verified"], false);
    }

    /// Signs `ada` in for a request of a client that asks her first, and
    /// returns the request, its browser secret and her ticket.
    #[expect(
        clippy::large_types_passed_by_value,
        reason = "handed on as the endpoint hands it on"
    )]
    fn sign_in_to_consent(
        scenario: &Scenario,
        parameters: AuthorizationParameters<'_>,
    ) -> (uuid::Uuid, Secret, SessionTicket) {
        let begun = complete(begin_authorization(&scenario.app, "acme", parameters, None));
        let Ok(Authorization::SignInRequired {
            request,
            browser_secret,
        }) = begun
        else {
            panic!("a sign-in first: {begun:?}");
        };
        let step = complete(finish_sign_in(
            &scenario.app,
            "acme",
            request,
            &browser_secret,
            TypedSignIn {
                answer: SignInAnswer::Password {
                    name: "ada",
                    password: Secret::new(PASSWORD.as_bytes().to_vec()),
                },
                caller: None,
                known_browsers: &[],
            },
        ))
        .expect("a signed-in person");
        let SignInStep::ConsentRequired(signed_in) = step else {
            panic!("she is asked first: {step:?}");
        };
        (request, browser_secret, signed_in.ticket)
    }

    #[test]
    fn every_answer_records_its_client_on_the_session_whatever_the_response_type() {
        let (scenario, challenge) = start();
        register(&scenario, "spa-again", &ResponseType::ALL, false, None);
        register(&scenario, "partner-spa", &ResponseType::ALL, true, None);
        for kind in ResponseType::ALL {
            let asked = kind.name();
            // After a sign-in.
            let (_, ticket) = sign_in(&scenario, ask("spa", asked, &challenge));
            // By the session, twice: one line.
            for _ in 0..2 {
                let answered = complete(begin_authorization(
                    &scenario.app,
                    "acme",
                    ask("spa-again", asked, &challenge),
                    Some(&ticket),
                ));
                assert!(
                    matches!(answered, Ok(Authorization::Granted { .. })),
                    "{asked}: {answered:?}"
                );
            }
            assert_eq!(
                scenario.list_served(&ticket),
                ["spa", "spa-again"],
                "{asked}"
            );
            // On the page of consent.
            let asked_again = AuthorizationParameters {
                prompt: Some("consent"),
                ..ask("partner-spa", asked, &challenge)
            };
            let (request, browser_secret, ticket) = sign_in_to_consent(&scenario, asked_again);
            let shown = complete(describe_consent(
                &scenario.app,
                "acme",
                request,
                &browser_secret,
                Some(&ticket),
            ))
            .expect("the page")
            .shown;
            complete(answer_consent(
                &scenario.app,
                "acme",
                request,
                &browser_secret,
                Some(&ticket),
                ConsentDecision::Allow { shown },
            ))
            .expect("an allowed client");
            assert_eq!(scenario.list_served(&ticket), ["partner-spa"], "{asked}");
        }
    }

    #[test]
    fn an_answer_for_a_session_that_ended_records_nothing_and_issues_nothing() {
        use super::AnswerSubject;
        use crate::oidc::authorize::{AnswerGrant, issue_answer};
        use crate::tenancy::RealmName;

        let (scenario, challenge) = start();
        let (_, ticket) = sign_in(&scenario, ask("spa", "code", &challenge));
        register(&scenario, "spa-again", &[ResponseType::Code], false, None);
        scenario.end_session(&ticket);
        let realm = RealmName::parse("acme").expect("a realm name");
        let scopes = ["openid".to_owned()];
        let mut work =
            complete(scenario.app.storage.begin(scenario.scope)).expect("a unit of work");

        let issued = complete(issue_answer(
            &scenario.app,
            work.as_mut(),
            AnswerGrant {
                realm: &realm,
                subject: AnswerSubject::Named {
                    client_id: "spa-again",
                    session: ticket.session,
                    person: scenario.find_ada(),
                },
                redirect_uri: CALLBACK,
                scopes: &scopes,
                state: None,
                nonce: None,
                response_type: ResponseType::Code,
                response_mode: ResponseMode::Query,
                code_challenge: Some(&challenge),
                authenticated_at: scenario.app.now(),
                claims: None,
            },
        ));

        assert_eq!(
            issued.map(|_| ()).map_err(|failure| failure.code),
            Err(ErrorCode::SessionRequired),
            "not even a code"
        );
        drop(work);
        assert_eq!(scenario.list_served(&ticket), ["spa"]);
    }

    #[test]
    fn a_grant_offline_comes_with_a_code_and_never_with_what_is_signed_here() {
        let (scenario, challenge) = start();
        let declared = [ResponseType::IdTokenToken, ResponseType::CodeIdTokenToken];
        register(&scenario, "partner-spa", &declared, true, None);
        let offline = |response_type| AuthorizationParameters {
            scope: Some("openid offline_access"),
            ..ask("partner-spa", response_type, &challenge)
        };
        let describe = |request, browser_secret: &Secret, ticket: &SessionTicket| {
            complete(describe_consent(
                &scenario.app,
                "acme",
                request,
                browser_secret,
                Some(ticket),
            ))
            .expect("the page")
        };

        let (request, browser_secret, ticket) =
            sign_in_to_consent(&scenario, offline("id_token token"));
        let without_code = describe(request, &browser_secret, &ticket);
        assert_eq!(without_code.scopes, ["openid"]);
        assert_eq!(
            without_code.offline_access, None,
            "nothing is ever refreshed without a code: the page does not say otherwise"
        );

        let (request, browser_secret, ticket) =
            sign_in_to_consent(&scenario, offline("code id_token token"));
        let with_code = describe(request, &browser_secret, &ticket);
        assert!(with_code.offline_access.is_some());
        let allowed = complete(answer_consent(
            &scenario.app,
            "acme",
            request,
            &browser_secret,
            Some(&ticket),
            ConsentDecision::Allow {
                shown: with_code.shown,
            },
        ))
        .expect("an allowed client");
        assert_eq!(allowed.read_parameter("scope"), Some("openid"));
        assert_eq!(read_token(&allowed, "access_token")["scope"], "openid");
        let exchanged = complete(grant_token(
            &scenario.app,
            "acme",
            TokenRequest {
                grant_type: Some("authorization_code"),
                client_id: Some("partner-spa"),
                code: allowed.read_parameter("code"),
                redirect_uri: Some(CALLBACK),
                code_verifier: Some(VERIFIER),
                ..TokenRequest::default()
            },
        ))
        .expect("tokens for the code");
        assert_eq!(exchanged.scope, "openid offline_access");
        assert!(exchanged.refresh_token.is_some());
    }

    #[test]
    fn a_client_disabled_while_its_person_signs_in_is_handed_nothing() {
        let (scenario, challenge) = start();
        let begun = complete(begin_authorization(
            &scenario.app,
            "acme",
            ask("spa", "id_token token", &challenge),
            None,
        ));
        let Ok(Authorization::SignInRequired {
            request,
            browser_secret,
        }) = begun
        else {
            panic!("a sign-in first: {begun:?}");
        };
        scenario.storage.disable_client("spa");

        let finished = complete(finish_sign_in(
            &scenario.app,
            "acme",
            request,
            &browser_secret,
            TypedSignIn {
                answer: SignInAnswer::Password {
                    name: "ada",
                    password: Secret::new(PASSWORD.as_bytes().to_vec()),
                },
                caller: None,
                known_browsers: &[],
            },
        ));

        assert_eq!(
            finished.map(|_| ()).map_err(|failure| failure.code),
            Err(ErrorCode::ClientNotFound)
        );
        assert!(
            !scenario
                .read_event_kinds()
                .contains(&"token.issued".to_owned())
        );
        assert_eq!(
            scenario.storage.count_active_sessions(scenario.find_ada()),
            0,
            "the session she opened for nothing ends"
        );
    }

    /// Leaves a request of `spa` for `id_token token` waiting, then signs
    /// `ada` in for it once `meanwhile` ran.
    fn sign_in_after(
        scenario: &Scenario,
        challenge: &str,
        meanwhile: impl FnOnce(),
    ) -> Result<SignInStep, ErrorCode> {
        let begun = complete(begin_authorization(
            &scenario.app,
            "acme",
            ask("spa", "id_token token", challenge),
            None,
        ));
        let Ok(Authorization::SignInRequired {
            request,
            browser_secret,
        }) = begun
        else {
            panic!("a sign-in first: {begun:?}");
        };
        meanwhile();
        complete(finish_sign_in(
            &scenario.app,
            "acme",
            request,
            &browser_secret,
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

    #[test]
    fn a_session_opened_for_an_answer_whose_commit_fails_ends_and_the_failure_is_told() {
        let (scenario, challenge) = start();
        scenario
            .storage
            .refuse_commits_recording(EventKind::TokenIssued);

        let finished = sign_in_after(&scenario, &challenge, || {});

        assert_eq!(finished.map(|_| ()), Err(ErrorCode::StorageUnavailable));
        assert!(
            !scenario
                .read_event_kinds()
                .contains(&"token.issued".to_owned()),
            "nothing of the answer is kept"
        );
        assert_eq!(
            scenario.storage.count_active_sessions(scenario.find_ada()),
            0,
            "the session she opened for nothing ends"
        );
    }

    #[test]
    fn a_session_that_cannot_be_ended_leaves_the_refusal_as_it_was() {
        let (scenario, challenge) = start();
        scenario
            .storage
            .refuse_commits_recording(EventKind::SessionEnded);

        let finished = sign_in_after(&scenario, &challenge, || {
            scenario.storage.disable_client("spa");
        });

        assert_eq!(
            finished.map(|_| ()),
            Err(ErrorCode::ClientNotFound),
            "the refusal of the answer, not the failure of the ending"
        );
        assert_eq!(
            scenario.storage.count_active_sessions(scenario.find_ada()),
            1,
            "the ending failed: the session waits for its expiry"
        );
    }

    #[test]
    fn a_session_answer_reads_its_client_its_session_and_the_consent_once() {
        let (scenario, challenge) = start();
        register(
            &scenario,
            "partner-spa",
            &[ResponseType::IdTokenToken],
            true,
            None,
        );
        let storage = &scenario.storage;
        let count_reads = || {
            [
                storage.count_client_reads(),
                storage.count_session_reads(),
                storage.count_consent_reads(),
            ]
        };
        let parameters = || ask("partner-spa", "id_token token", &challenge);
        let (request, browser_secret, ticket) = sign_in_to_consent(&scenario, parameters());
        let shown = complete(describe_consent(
            &scenario.app,
            "acme",
            request,
            &browser_secret,
            Some(&ticket),
        ))
        .expect("the page")
        .shown;
        let before = count_reads();

        let allowed = complete(answer_consent(
            &scenario.app,
            "acme",
            request,
            &browser_secret,
            Some(&ticket),
            ConsentDecision::Allow { shown },
        ))
        .expect("an allowed client");

        assert!(allowed.read_parameter("access_token").is_some());
        let after = count_reads();
        assert_eq!(
            [0, 1, 2].map(|at| after[at] - before[at]),
            [1, 1, 0],
            "the consent it just wrote is not read again"
        );
        let before = count_reads();
        let answered = complete(begin_authorization(
            &scenario.app,
            "acme",
            parameters(),
            Some(&ticket),
        ));
        let Ok(Authorization::Granted { response }) = answered else {
            panic!("her session answers: {answered:?}");
        };
        assert!(response.read_parameter("access_token").is_some());
        let after = count_reads();
        assert_eq!([0, 1, 2].map(|at| after[at] - before[at]), [1, 1, 1]);
    }

    #[test]
    fn nothing_is_signed_for_another_person_than_that_of_the_session_or_without_a_consent_held() {
        use super::{AnswerSubject, AuthorizationSigning, sign_at_authorization};

        let (scenario, challenge) = start();
        register(
            &scenario,
            "partner-spa",
            &[ResponseType::IdToken],
            true,
            None,
        );
        let (_, ticket) = sign_in(&scenario, ask("spa", "code", &challenge));
        let scopes = ["openid".to_owned()];
        let sign = |client_id, person| {
            let mut work = complete(scenario.app.storage.begin(scenario.scope)).expect("a unit");
            complete(sign_at_authorization(
                &scenario.app,
                work.as_mut(),
                AuthorizationSigning {
                    issuer: "https://id.example.test/realms/acme",
                    subject: AnswerSubject::Named {
                        client_id,
                        session: ticket.session,
                        person,
                    },
                    scopes: &scopes,
                    nonce: Some(NONCE),
                    response_type: ResponseType::IdToken,
                    code: None,
                    claims: None,
                },
            ))
            .map(|signed| signed.parameters.len())
            .map_err(|failure| failure.code)
        };
        let ada = scenario.find_ada();

        assert_eq!(sign("spa", ada), Ok(1));
        assert_eq!(
            sign("spa", uuid::Uuid::from_u128(7)),
            Err(ErrorCode::SessionRequired)
        );
        assert_eq!(
            sign("partner-spa", ada),
            Err(ErrorCode::ConsentNotFound),
            "a client that asks each person signs nothing she did not allow"
        );
    }
}
