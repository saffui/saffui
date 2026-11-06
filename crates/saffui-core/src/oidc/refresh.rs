//! The refresh grant: a refresh token is spent for new tokens and for the
//! refresh token that follows it.

use serde_json::{Value, json};
use uuid::Uuid;

use super::discovery::name_issuer;
use super::errors::OAuthFailure;
use super::token::{Granted, TokenRequest, TokenResponse, answer_for_person, narrow_scopes};
use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::clients::authenticate::identify_client;
use crate::error::{ErrorCode, Failure};
use crate::instant::write_instant;
use crate::login::session::read_live_subject;
use crate::tenancy::{RealmName, RealmScope};
use crate::tokens::mint::RefreshGrant;
use crate::tokens::store::EndedFamily;

/// The event of a family taken back. It names the session, and keeps what
/// the tokens told: they go with their session, and a theft is traced later.
pub(super) fn describe_family_end(
    client_id: &str,
    family: Uuid,
    person: Uuid,
    session: Uuid,
    reason: &str,
    ended: &EndedFamily,
) -> Value {
    json!({
        "client_id": client_id,
        "family": family.to_string(),
        "last_issued_at": write_instant(ended.last_issued_at),
        "last_used_at": ended.last_used_at.map(write_instant),
        "person_id": person.to_string(),
        "reason": reason,
        "session_id": session.to_string(),
        "tokens": ended.tokens,
    })
}

pub(super) async fn rotate_refresh_token(
    app: &App,
    realm_name: &RealmName,
    scope: RealmScope,
    request: TokenRequest<'_>,
) -> Result<TokenResponse, OAuthFailure> {
    let client_id = request
        .client_id
        .ok_or(ErrorCode::ClientAuthenticationFailed)?;
    let presented = request.refresh_token.ok_or(ErrorCode::RequestInvalid)?;
    let invalid = || OAuthFailure::from(ErrorCode::GrantInvalid);
    let now = app.now();

    // One unit of work spends the token and writes the next: a failure in
    // between leaves the client the token it had.
    let mut work = app.storage.begin(scope).await.map_err(Failure::from)?;
    let client = identify_client(app, work.as_mut(), client_id, request.client_secret).await?;
    if !client.allows_authorization_code {
        return Err(ErrorCode::GrantNotAllowed.into());
    }
    let digest = app.digester.sha256(presented.as_bytes());
    let spent = work
        .spend_refresh_token(&digest, &client.client_id, now)
        .await
        .map_err(Failure::from)?;
    let Some(spent) = spent else {
        // A token presented after it was used is a token someone copied.
        // Which of the two holders is the thief cannot be told: neither keeps
        // what descends from it. A family revoked already is written no more,
        // however often its tokens come back.
        let replayed = work
            .read_refresh_token(&digest)
            .await
            .map_err(Failure::from)?
            .filter(|known| {
                known.used_at.is_some()
                    && known.revoked_at.is_none()
                    && known.token.client_id == client.client_id
            });
        if let Some(replayed) = replayed {
            let token = &replayed.token;
            let ended = work
                .revoke_refresh_family(token.family, now)
                .await
                .map_err(Failure::from)?;
            if let Some(ended) = ended {
                let told = describe_family_end(
                    &client.client_id,
                    token.family,
                    token.person,
                    token.session,
                    "replayed",
                    &ended,
                );
                record_event(app, work.as_mut(), EventKind::TokenRevoked, told).await?;
            }
            work.commit().await.map_err(Failure::from)?;
        }
        return Err(invalid());
    };

    let (session, person) = read_live_subject(app, work.as_mut(), spent.session)
        .await?
        .filter(|(_, person)| person.id == spent.person)
        .ok_or_else(invalid)?;
    let scopes = narrow_scopes(request.scope, &spent.scopes)?;

    let issuer = name_issuer(&app.settings, realm_name);
    let granted = Granted {
        issuer: &issuer,
        client_id: &client.client_id,
        session: &session,
        person: &person,
        scopes: &scopes,
        // A nonce answers one authorization request: it is not said again.
        nonce: None,
        family: RefreshGrant {
            family: spent.family,
            client_id: &client.client_id,
            session: &session,
            scopes: &spent.scopes,
        },
    };
    // No event: a rotation only carries on what the chain already says was
    // issued, and one would queue every rotation of the realm on its head.
    let response = answer_for_person(app, work.as_mut(), granted).await?;
    work.commit().await.map_err(Failure::from)?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::Value;
    use uuid::Uuid;

    use crate::instant::write_instant;
    use crate::oidc::errors::OAuthError;
    use crate::oidc::scenario::Scenario;
    use crate::ports::crypto::{CryptoFailure, SealPlace, Sealer, WrappedDataKey};
    use crate::secret::Secret;
    use crate::testkit::crypto::TransparentSealer;
    use crate::testkit::drive::complete;
    use crate::testkit::fixtures::create_application;

    fn read_claims(token: &str) -> Value {
        let payload = token.split('.').nth(1).expect("a compact token");
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("base64url"))
            .expect("claims")
    }

    #[test]
    fn a_refresh_token_is_spent_for_new_tokens_and_the_next_refresh_token() {
        let scenario = Scenario::start();
        let first = scenario.sign_in("openid profile email").tokens;
        let presented = first.refresh_token.expect("a refresh token");

        let second = scenario.refresh(&presented).expect("new tokens");

        let next = second
            .refresh_token
            .clone()
            .expect("the next refresh token");
        assert_ne!(next, presented);
        assert_eq!(second.scope, "openid profile email");
        let access = read_claims(&second.access_token);
        let before = read_claims(&first.access_token);
        assert_eq!(access["sub"], before["sub"]);
        assert_eq!(access["sid"], before["sid"]);
        assert_ne!(access["jti"], before["jti"]);
        let identity = read_claims(&second.id_token.expect("an identity token"));
        assert_eq!(identity["preferred_username"], "ada");
        assert_eq!(
            identity["auth_time"],
            read_claims(&first.id_token.expect("an identity token"))["auth_time"],
            "refreshing does not move the time the person signed in"
        );
        assert!(
            identity.get("nonce").is_none(),
            "a nonce answers one authorization request: {identity}"
        );
    }

    #[test]
    fn a_rotation_writes_nothing_in_the_chain_of_the_realm() {
        let scenario = Scenario::start();
        let presented = scenario
            .sign_in("openid")
            .tokens
            .refresh_token
            .expect("a refresh token");
        let before = scenario.read_event_kinds();
        assert_eq!(
            before.last().map(String::as_str),
            Some("token.issued"),
            "the exchange of the code is said"
        );

        let next = scenario
            .refresh(&presented)
            .expect("new tokens")
            .refresh_token
            .expect("the next refresh token");
        scenario.refresh(&next).expect("new tokens again");

        assert_eq!(
            scenario.read_event_kinds(),
            before,
            "two rotations add nothing to the chain"
        );
    }

    /// A sealer that counts how often a sealed value is opened.
    #[derive(Default)]
    struct CountingSealer(AtomicUsize);

    impl Sealer for CountingSealer {
        fn make_data_key(
            &self,
            tenant: Uuid,
            realm: Uuid,
            generation: u32,
        ) -> Result<WrappedDataKey, CryptoFailure> {
            TransparentSealer.make_data_key(tenant, realm, generation)
        }

        fn seal(
            &self,
            data_key: &WrappedDataKey,
            place: &SealPlace,
            plaintext: &Secret,
        ) -> Result<Vec<u8>, CryptoFailure> {
            TransparentSealer.seal(data_key, place, plaintext)
        }

        fn open(
            &self,
            data_key: &WrappedDataKey,
            place: &SealPlace,
            sealed: &[u8],
        ) -> Result<Secret, CryptoFailure> {
            self.0.fetch_add(1, Ordering::Relaxed);
            TransparentSealer.open(data_key, place, sealed)
        }

        fn digest_typed_name(
            &self,
            tenant: Uuid,
            realm: Uuid,
            typed: &[u8],
        ) -> Result<Vec<u8>, CryptoFailure> {
            TransparentSealer.digest_typed_name(tenant, realm, typed)
        }
    }

    #[test]
    fn an_answer_opens_the_key_of_the_realm_once_for_all_its_tokens() {
        let mut scenario = Scenario::start();
        let sealer = Arc::new(CountingSealer::default());
        scenario.app.sealer = sealer.clone();
        let presented = scenario
            .sign_in("openid")
            .tokens
            .refresh_token
            .expect("a refresh token");
        let opened_before = sealer.0.load(Ordering::Relaxed);

        let answer = scenario.refresh(&presented).expect("new tokens");

        assert!(answer.id_token.is_some(), "an access and an identity token");
        assert_eq!(
            sealer.0.load(Ordering::Relaxed) - opened_before,
            1,
            "the key of the realm is opened once for every token of the answer"
        );
    }

    #[test]
    fn a_narrower_request_narrows_the_answer_and_not_what_the_next_one_may_ask() {
        let scenario = Scenario::start();
        let presented = scenario
            .sign_in("openid profile email")
            .tokens
            .refresh_token
            .expect("a refresh token");

        let narrowed = scenario
            .refresh_as("webapp", &presented, Some("openid"))
            .expect("narrowed tokens");
        let next = narrowed.refresh_token.expect("the next refresh token");

        assert_eq!(narrowed.scope, "openid");
        assert_eq!(
            scenario
                .refresh_as("webapp", &next, Some("openid invoices:read"))
                .map(|tokens| tokens.scope),
            Err(OAuthError::InvalidScope),
            "nothing that was not granted at first is ever given"
        );
        assert_eq!(
            scenario
                .refresh_as("webapp", &next, Some("openid email"))
                .map(|tokens| tokens.scope),
            Ok("openid email".to_owned()),
            "a refused request leaves the token to its client"
        );
    }

    #[test]
    fn a_refresh_token_presented_twice_takes_everything_that_descends_from_it() {
        let scenario = Scenario::start();
        let signed_in = scenario.sign_in("openid");
        let first = signed_in.tokens.refresh_token.expect("a refresh token");
        scenario.clock.advance(Duration::from_mins(1));
        let second = scenario
            .refresh(&first)
            .expect("new tokens")
            .refresh_token
            .expect("the next refresh token");
        scenario.clock.advance(Duration::from_mins(1));
        let last_rotation = scenario.app.now();
        let third = scenario
            .refresh(&second)
            .expect("new tokens again")
            .refresh_token
            .expect("the third refresh token");
        scenario.clock.advance(Duration::from_mins(1));

        let replayed = scenario.refresh(&first).map(|tokens| tokens.scope);

        assert_eq!(replayed, Err(OAuthError::InvalidGrant));
        assert_eq!(
            scenario.refresh(&third).map(|tokens| tokens.scope),
            Err(OAuthError::InvalidGrant),
            "the token that descends from the replayed one is gone too"
        );
        let kinds = scenario.read_event_kinds();
        assert_eq!(
            kinds.iter().filter(|kind| *kind == "token.revoked").count(),
            1,
            "the family is revoked once: {kinds:?}"
        );
        let revoked = scenario
            .storage
            .read_audit_envelopes(scenario.scope.realm())
            .into_iter()
            .find(|event| event["kind"] == "token.revoked")
            .expect("the revocation");
        // What the rows of the family knew, kept once they are gone.
        let told = &revoked["payload"];
        assert_eq!(told["reason"], "replayed", "{revoked}");
        assert_eq!(
            told["session_id"],
            signed_in.ticket.session.to_string(),
            "{revoked}"
        );
        assert_eq!(told["tokens"], 3, "{revoked}");
        let last = write_instant(last_rotation);
        assert_eq!(told["last_issued_at"], last.as_str(), "{revoked}");
        assert_eq!(told["last_used_at"], last.as_str(), "{revoked}");
    }

    #[test]
    fn a_used_token_another_client_presents_takes_nothing_back_from_its_owner() {
        let scenario = Scenario::start();
        complete(create_application(
            &scenario.app,
            scenario.scope,
            "other",
            "https://other.example.org/callback",
            true,
        ));
        let first = scenario
            .sign_in("openid")
            .tokens
            .refresh_token
            .expect("a refresh token");
        let next = scenario
            .refresh(&first)
            .expect("new tokens")
            .refresh_token
            .expect("the next refresh token");

        assert_eq!(
            scenario
                .refresh_as("other", &first, None)
                .map(|tokens| tokens.scope),
            Err(OAuthError::InvalidGrant)
        );
        assert!(
            scenario.refresh(&next).is_ok(),
            "a client cannot revoke the family of another by replaying its token"
        );
        assert!(
            !scenario
                .read_event_kinds()
                .contains(&"token.revoked".to_owned())
        );
    }

    #[test]
    fn a_refresh_token_is_worth_nothing_to_another_client_and_survives_the_attempt() {
        let scenario = Scenario::start();
        complete(create_application(
            &scenario.app,
            scenario.scope,
            "other",
            "https://other.example.org/callback",
            true,
        ));
        let presented = scenario
            .sign_in("openid")
            .tokens
            .refresh_token
            .expect("a refresh token");

        assert_eq!(
            scenario
                .refresh_as("other", &presented, None)
                .map(|tokens| tokens.scope),
            Err(OAuthError::InvalidGrant)
        );
        assert_eq!(
            scenario
                .refresh_as("ghost", &presented, None)
                .map(|tokens| tokens.scope),
            Err(OAuthError::InvalidClient)
        );
        assert_eq!(
            scenario
                .refresh_as("billing", &presented, None)
                .map(|tokens| tokens.scope),
            Err(OAuthError::InvalidClient),
            "a confidential client that presents no secret is not identified"
        );
        assert!(scenario.refresh(&presented).is_ok());
    }

    #[test]
    fn a_refresh_token_dies_with_its_session_and_with_its_person() {
        let scenario = Scenario::start();
        let presented = scenario
            .sign_in("openid")
            .tokens
            .refresh_token
            .expect("a refresh token");
        let invalid = Err(OAuthError::InvalidGrant);

        scenario.storage.disable_person("ada");
        assert_eq!(
            scenario.refresh(&presented).map(|tokens| tokens.scope),
            invalid
        );

        let scenario = Scenario::start();
        let presented = scenario
            .sign_in("openid")
            .tokens
            .refresh_token
            .expect("a refresh token");
        scenario.clock.advance(Duration::from_hours(12));
        assert_eq!(
            scenario.refresh(&presented).map(|tokens| tokens.scope),
            invalid,
            "a refresh token never outlives its session"
        );
        assert_eq!(
            scenario.refresh("not-a-token").map(|tokens| tokens.scope),
            invalid
        );
    }
}
