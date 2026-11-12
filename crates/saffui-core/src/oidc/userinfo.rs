//! The userinfo endpoint: what an access token allows to be said of the
//! person it was issued for.

use serde_json::Value;

use super::discovery::name_issuer;
use crate::app::App;
use crate::claims::ClaimTarget;
use crate::claims::gather::gather_claim_inputs;
use crate::claims::rules::{ClaimGrant, write_claims};
use crate::error::{ErrorCode, Failure};
use crate::login::session::read_live_subject;
use crate::tenancy::resolve::resolve_realm;
use crate::tokens::verify::verify_access_token;

/// Tells who an access token was issued for, as far as its scopes allow.
///
/// # Errors
///
/// Returns [`ErrorCode::TokenInvalid`] for a token that does not verify,
/// that is not for this realm, that was issued to a client for itself, or
/// whose session ended or whose person was disabled. Returns
/// [`ErrorCode::TokenScopeInsufficient`] for a token without the `openid`
/// scope, [`ErrorCode::HeldTooMany`] for a person whose roles a mapper says
/// and who holds them by more ways than are read,
/// [`ErrorCode::ClaimsTooLarge`], or the storage failure.
pub async fn read_user_info(app: &App, realm: &str, token: &str) -> Result<Value, Failure> {
    let invalid = || Failure::new(ErrorCode::TokenInvalid);
    // An unknown realm issued no token: the one presented is invalid.
    let (realm_name, scope) = resolve_realm(app, realm).await.map_err(|failure| {
        if failure.code == ErrorCode::RealmNotFound {
            invalid()
        } else {
            failure
        }
    })?;
    let mut work = app.storage.begin(scope).await?;
    let issuer = name_issuer(&app.settings, &realm_name);
    let claims = verify_access_token(app, work.as_mut(), &issuer, token).await?;
    if !claims.audiences.contains(&issuer) {
        return Err(invalid());
    }

    let session = claims.session.ok_or_else(invalid)?;
    let (_, person) = read_live_subject(app, work.as_mut(), session)
        .await?
        .filter(|(_, person)| person.id.to_string() == claims.subject)
        .ok_or_else(invalid)?;
    if !claims.scopes.iter().any(|granted| granted == "openid") {
        return Err(Failure::new(ErrorCode::TokenScopeInsufficient));
    }

    // Read now, as for a token made now: the three never disagree.
    let grant = ClaimGrant {
        person: Some(&person),
        client_id: &claims.client_id,
        scopes: &claims.scopes,
    };
    let targets = [ClaimTarget::Userinfo];
    let inputs = gather_claim_inputs(work.as_mut(), &grant, &targets, app.now()).await?;
    let mut told = write_claims(ClaimTarget::Userinfo, &grant, &inputs)?.claims;
    told.insert("sub".to_owned(), Value::String(claims.subject));
    Ok(Value::Object(told))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::read_user_info;
    use crate::error::ErrorCode;
    use crate::oidc::scenario::Scenario;
    use crate::oidc::token::{TokenRequest, grant_token};
    use crate::testkit::drive::complete;

    fn ask(scenario: &Scenario, realm: &str, token: &str) -> Result<serde_json::Value, ErrorCode> {
        complete(read_user_info(&scenario.app, realm, token)).map_err(|failure| failure.code)
    }

    #[test]
    fn a_token_says_of_its_person_what_its_scopes_allow_and_nothing_more() {
        let scenario = Scenario::start();
        let with_email = scenario.sign_in("openid email").tokens;
        let with_profile = scenario.sign_in("openid profile").tokens;
        let subject =
            ask(&scenario, "acme", &with_email.access_token).expect("claims")["sub"].clone();

        assert_eq!(
            ask(&scenario, "acme", &with_email.access_token),
            Ok(json!({ "sub": subject, "email": "ada@example.org", "email_verified": false }))
        );
        assert_eq!(
            ask(&scenario, "acme", &with_profile.access_token),
            Ok(json!({
                "sub": subject,
                "preferred_username": "ada",
                "name": "A person under test",
            }))
        );
    }

    #[test]
    fn a_token_without_openid_of_a_service_or_of_another_kind_tells_nothing() {
        let scenario = Scenario::start();
        let without_openid = scenario.sign_in("profile").tokens;
        let signed_in = scenario.sign_in("openid").tokens;
        let service = TokenRequest {
            grant_type: Some("client_credentials"),
            client_id: Some("billing"),
            client_secret: Some(scenario.copy_service_secret()),
            ..TokenRequest::default()
        };
        let of_a_service = complete(grant_token(&scenario.app, "acme", service)).expect("a token");

        assert_eq!(
            ask(&scenario, "acme", &without_openid.access_token),
            Err(ErrorCode::TokenScopeInsufficient)
        );
        for token in [
            of_a_service.access_token.as_str(),
            signed_in.id_token.as_deref().expect("an identity token"),
            signed_in.refresh_token.as_deref().expect("a refresh token"),
            "not.a.token",
        ] {
            assert_eq!(ask(&scenario, "acme", token), Err(ErrorCode::TokenInvalid));
        }
        assert_eq!(
            ask(&scenario, "nowhere", &signed_in.access_token),
            Err(ErrorCode::TokenInvalid)
        );
    }

    #[test]
    fn a_token_that_is_not_for_the_realm_tells_nothing() {
        use crate::keys::jwks::open_signing_key;
        use crate::ports::crypto::SignatureAlgorithm;
        use crate::tokens::ACCESS_TOKEN_TYPE;
        use crate::tokens::jws::sign_compact;

        const ISSUER: &str = "https://id.example.test/realms/acme";
        let scenario = Scenario::start();
        let signed_in = scenario.sign_in("openid");
        let ada = scenario.find_ada();
        let now = scenario.app.now().unix_timestamp();
        let mut work =
            complete(scenario.app.storage.begin(scenario.scope)).expect("a unit of work");
        let (key, private_key) = complete(open_signing_key(
            &scenario.app,
            work.as_mut(),
            SignatureAlgorithm::Es256,
        ))
        .expect("the key of the realm");
        drop(work);
        let sign = |audience: serde_json::Value| {
            let claims = json!({
                "iss": ISSUER,
                "sub": ada.to_string(),
                "aud": audience,
                "client_id": "webapp",
                "scope": "openid",
                "iat": now,
                "exp": now + 300,
                "jti": "a-token-made-elsewhere",
                "sid": signed_in.ticket.session.to_string(),
            });
            sign_compact(
                scenario.app.signer.as_ref(),
                &key,
                &private_key,
                ACCESS_TOKEN_TYPE,
                &claims,
            )
            .expect("a token")
        };

        assert_eq!(
            ask(&scenario, "acme", &sign(json!("https://api.example.org"))),
            Err(ErrorCode::TokenInvalid),
            "a token for a resource server alone"
        );
        assert!(
            ask(
                &scenario,
                "acme",
                &sign(json!([ISSUER, "https://api.example.org"]))
            )
            .is_ok()
        );
    }

    #[test]
    fn a_token_tells_nothing_once_its_session_ended_or_its_person_was_disabled() {
        let scenario = Scenario::start();
        let signed_in = scenario.sign_in("openid");
        let other = scenario.sign_in("openid");
        assert!(ask(&scenario, "acme", &signed_in.tokens.access_token).is_ok());

        scenario.end_session(&signed_in.ticket);

        assert_eq!(
            ask(&scenario, "acme", &signed_in.tokens.access_token),
            Err(ErrorCode::TokenInvalid)
        );
        assert!(ask(&scenario, "acme", &other.tokens.access_token).is_ok());
        scenario.storage.disable_person("ada");
        assert_eq!(
            ask(&scenario, "acme", &other.tokens.access_token),
            Err(ErrorCode::TokenInvalid)
        );
    }
}
