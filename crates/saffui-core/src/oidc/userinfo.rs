//! The userinfo endpoint: what an access token allows to be said of the
//! person it was issued for.

use serde_json::Value;

use super::discovery::name_issuer;
use crate::app::App;
use crate::claims::ClaimTarget;
use crate::claims::gather::gather_claim_inputs;
use crate::claims::rules::{ClaimGrant, NamedClaims, write_claims};
use crate::clients::{is_client_enabled, read_named_client};
use crate::consent::read_allowance;
use crate::error::{ErrorCode, Failure};
use crate::login::session::read_live_subject;
use crate::tenancy::resolve::resolve_realm;
use crate::tokens::verify::verify_access_token;

/// Tells who an access token was issued for, as far as its scopes allow.
///
/// # Errors
///
/// Returns [`ErrorCode::TokenInvalid`] for a token that does not verify,
/// that is not for this realm, that was issued to a client for itself or to
/// a client disabled since, or whose session ended or whose person was
/// disabled. Returns
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
    // A token of a grant that named claims is told them within the scopes
    // of its client, read whole; any other only asks that it be enabled.
    let client = match claims.family {
        Some(_) => Some(
            read_named_client(work.as_mut(), &claims.client_id)
                .await?
                .filter(|client| client.enabled)
                .ok_or_else(invalid)?,
        ),
        None if is_client_enabled(work.as_mut(), &claims.client_id).await? => None,
        None => return Err(invalid()),
    };

    let session = claims.session.ok_or_else(invalid)?;
    let (_, person) = read_live_subject(app, work.as_mut(), session)
        .await?
        .filter(|(_, person)| person.id.to_string() == claims.subject)
        .ok_or_else(invalid)?;
    if !claims.scopes.iter().any(|granted| granted == "openid") {
        return Err(Failure::new(ErrorCode::TokenScopeInsufficient));
    }

    // The claims the grant of the token named, read by the family it names,
    // in its session and for its client, and bound as when its tokens are
    // made: by the scopes of the client and what the person allows now. A
    // token that names no family, as one signed at the authorization
    // endpoint, is told what its scopes say and nothing by name.
    let asked = match (claims.family, &client) {
        (Some(family), Some(client)) => {
            work.read_family_claims(family, session, &client.client_id)
                .await?
        }
        _ => None,
    };
    let allowed = match (&asked, &client) {
        (Some(_), Some(client)) => read_allowance(work.as_mut(), client, person.id).await?,
        _ => None,
    };
    let named = asked
        .as_ref()
        .zip(client.as_ref())
        .map(|(request, client)| NamedClaims {
            request,
            entitled: &client.scopes,
            allowed: allowed.as_ref(),
        });

    // Read now, as for a token made now: the three never disagree.
    let grant = ClaimGrant {
        person: Some(&person),
        client_id: &claims.client_id,
        scopes: &claims.scopes,
        named,
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
            client_secret: Some(crate::clients::authenticate::PresentedSecret::Basic(
                scenario.copy_service_secret(),
            )),
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

    /// The claims of a compact token.
    fn read_token(token: &str) -> serde_json::Value {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let payload = token.split('.').nth(1).expect("a compact token");
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("base64url"))
            .expect("claims")
    }

    #[test]
    fn claims_named_are_told_within_the_scopes_of_the_client_and_the_targets_of_its_mappers() {
        use crate::claims::ClaimTarget;

        let scenario = Scenario::start();
        scenario.register_lean();
        scenario.map_attribute(
            "lean",
            "department",
            "dept",
            &[ClaimTarget::Userinfo],
            "profile",
        );
        scenario.write_ada_attributes(&json!({
            "given_name": "Ada",
            "locale": "en",
            "department": "research",
        }));
        let named = r#"{
            "id_token": {"given_name": null, "email": null, "dept": null,
                         "nickname": {"essential": true}, "locale": {"value": "fr"}},
            "userinfo": {"given_name": null, "dept": null, "email": {"essential": true},
                         "locale": {"values": ["de", "en"]}}
        }"#;

        let signed_in = scenario.sign_in_naming("lean", "openid", named);

        let identity = read_token(
            signed_in
                .tokens
                .id_token
                .as_deref()
                .expect("an identity token"),
        );
        assert_eq!(
            identity["given_name"], "Ada",
            "named, of a scope the client may be given"
        );
        for absent in ["email", "dept", "nickname", "locale", "preferred_username"] {
            assert!(identity.get(absent).is_none(), "{absent}: {identity}");
        }
        let told = ask(&scenario, "acme", &signed_in.tokens.access_token).expect("claims");
        assert_eq!(told["given_name"], "Ada");
        assert_eq!(told["dept"], "research", "its mapper writes it in userinfo");
        assert_eq!(told["locale"], "en", "one of the values the client takes");
        for absent in ["email", "nickname", "preferred_username", "name"] {
            assert!(told.get(absent).is_none(), "{absent}: {told}");
        }

        let unnamed = scenario.sign_in_naming("lean", "openid", "{}");
        let identity = read_token(
            unnamed
                .tokens
                .id_token
                .as_deref()
                .expect("an identity token"),
        );
        assert!(identity.get("given_name").is_none(), "{identity}");
        let told = ask(&scenario, "acme", &unnamed.tokens.access_token).expect("claims");
        assert_eq!(
            told.as_object().map(serde_json::Map::len),
            Some(1),
            "openid alone says who, and nothing of them: {told}"
        );
    }

    #[test]
    fn claims_named_are_read_from_the_person_again_at_each_renewal_and_the_sign_in_stays_as_it_was()
    {
        let scenario = Scenario::start();
        scenario.register_lean();
        scenario.write_ada_attributes(&json!({ "given_name": "Ada" }));
        let named = r#"{"id_token": {"given_name": null}, "userinfo": {"given_name": null}}"#;
        let first = scenario.sign_in_naming("lean", "openid", named);
        let before = read_token(first.tokens.id_token.as_deref().expect("an identity token"));

        scenario.write_ada_attributes(&json!({ "given_name": "Augusta" }));
        scenario.clock.advance(std::time::Duration::from_secs(90));
        let renewed = scenario
            .refresh_as(
                "lean",
                first
                    .tokens
                    .refresh_token
                    .as_deref()
                    .expect("a refresh token"),
                None,
            )
            .expect("tokens");

        let after = read_token(renewed.id_token.as_deref().expect("an identity token"));
        assert_eq!(after["given_name"], "Augusta", "what she holds now");
        assert_eq!(after["acr"], before["acr"]);
        assert_eq!(after["auth_time"], before["auth_time"]);
        assert_ne!(after["iat"], before["iat"]);
        let told = ask(&scenario, "acme", &renewed.access_token).expect("claims");
        assert_eq!(told["given_name"], "Augusta");
        let again = scenario
            .refresh_as(
                "lean",
                renewed.refresh_token.as_deref().expect("a refresh token"),
                None,
            )
            .expect("tokens");
        let after = read_token(again.id_token.as_deref().expect("an identity token"));
        assert_eq!(
            after["given_name"], "Augusta",
            "the next token of the family names it too"
        );
    }

    #[test]
    fn each_grant_of_one_client_in_one_session_is_told_what_it_named_and_no_other() {
        use crate::tokens::FAMILY_CLAIM;

        let scenario = Scenario::start();
        scenario.register_lean();
        scenario.write_ada_attributes(&json!({ "given_name": "Ada" }));
        let named = r#"{"userinfo": {"given_name": null}}"#;
        let first = scenario.sign_in_naming("lean", "openid", named);
        let ticket = &first.ticket;

        let plain = scenario.grant_in_session("lean", "openid", None, ticket);
        let again = scenario.grant_in_session("lean", "openid", Some(named), ticket);
        let for_identity = r#"{"id_token": {"given_name": null}}"#;
        let identity = scenario.grant_in_session("lean", "openid", Some(for_identity), ticket);

        let granted = [
            (&first.tokens, true),
            (&plain, false),
            (&again, true),
            (&identity, false),
        ];
        for (tokens, told) in granted {
            let given =
                ask(&scenario, "acme", &tokens.access_token).expect("claims")["given_name"].clone();
            assert_eq!(given == "Ada", told, "{given}");
        }
        for (tokens, unnamed) in [(&plain, "nothing"), (&identity, "nothing for userinfo")] {
            assert!(
                read_token(&tokens.access_token).get(FAMILY_CLAIM).is_none(),
                "a grant that named {unnamed} has its tokens said as before"
            );
        }
        assert_ne!(
            read_token(&first.tokens.access_token)[FAMILY_CLAIM],
            read_token(&again.access_token)[FAMILY_CLAIM],
            "each grant its family"
        );
    }

    #[test]
    fn whether_an_address_was_verified_goes_with_it_and_a_value_takes_both_away() {
        let scenario = Scenario::start();
        let verified_only = r#"{"userinfo": {"email_verified": {"value": true}},
                                "id_token": {"email_verified": {"value": true}}}"#;

        let asked = scenario.sign_in_naming("webapp", "openid email", verified_only);

        let identity = read_token(asked.tokens.id_token.as_deref().expect("an identity token"));
        let told = ask(&scenario, "acme", &asked.tokens.access_token).expect("claims");
        for said in [&identity, &told] {
            for claim in ["email", "email_verified"] {
                assert!(
                    said.get(claim).is_none(),
                    "her address was not verified: {said}"
                );
            }
        }

        let named = scenario.sign_in_naming("webapp", "openid", r#"{"userinfo": {"email": null}}"#);
        let told = ask(&scenario, "acme", &named.tokens.access_token).expect("claims");
        assert_eq!(told["email"], "ada@example.org");
        assert_eq!(told["email_verified"], false, "said with the address");
    }
}
