//! Token revocation (RFC 7009).

use super::discovery::name_issuer;
use super::errors::OAuthFailure;
use super::refresh::describe_family_end;
use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::clients::authenticate::identify_client;
use crate::error::{ErrorCode, Failure};
use crate::secret::Secret;
use crate::tenancy::resolve::resolve_realm;
use crate::tokens::verify::verify_access_token;

/// Revokes a refresh token of the calling client, and with it everything
/// that descends from the same grant. A token the client does not own, or
/// that nobody knows, is answered like a revoked one: the caller learns
/// nothing from asking.
///
/// # Errors
///
/// Returns [`ErrorCode::ClientAuthenticationFailed`] for a caller that is
/// not identified, [`ErrorCode::RequestInvalid`] when no token is presented,
/// [`ErrorCode::TokenTypeUnsupported`] for an access token of this realm,
/// which is kept nowhere and cannot be taken back, or the storage failure.
pub async fn revoke_token(
    app: &App,
    realm: &str,
    client_id: Option<&str>,
    client_secret: Option<Secret>,
    token: Option<&str>,
) -> Result<(), OAuthFailure> {
    let (realm_name, scope) = resolve_realm(app, realm).await?;
    let client_id = client_id.ok_or(ErrorCode::ClientAuthenticationFailed)?;
    let mut work = app.storage.begin(scope).await.map_err(Failure::from)?;
    let client = identify_client(app, work.as_mut(), client_id, client_secret).await?;
    let token = token.ok_or(ErrorCode::RequestInvalid)?;

    let digest = app.digester.sha256(token.as_bytes());
    let owned = work
        .read_refresh_token(&digest)
        .await
        .map_err(Failure::from)?
        .filter(|stored| stored.token.client_id == client.client_id);
    if let Some(stored) = owned {
        // Revoked already: asking again writes nothing.
        if stored.revoked_at.is_some() {
            return Ok(());
        }
        let token = &stored.token;
        let ended = work
            .revoke_refresh_family(token.family, app.now())
            .await
            .map_err(Failure::from)?;
        if let Some(ended) = ended {
            let told = describe_family_end(
                &client.client_id,
                token.family,
                token.person,
                token.session,
                "asked",
                &ended,
            );
            record_event(app, work.as_mut(), EventKind::TokenRevoked, told).await?;
        }
        work.commit().await.map_err(Failure::from)?;
        return Ok(());
    }

    // Saying yes to an access token would be a lie: it stands until it expires.
    let issuer = name_issuer(&app.settings, &realm_name);
    if verify_access_token(app, work.as_mut(), &issuer, token)
        .await
        .is_ok()
    {
        return Err(ErrorCode::TokenTypeUnsupported.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::revoke_token;
    use crate::oidc::errors::OAuthError;
    use crate::oidc::scenario::Scenario;
    use crate::testkit::drive::complete;

    fn revoke(scenario: &Scenario, client_id: &str, token: &str) -> Result<(), OAuthError> {
        let secret = (client_id == "billing").then(|| scenario.copy_service_secret());
        complete(revoke_token(
            &scenario.app,
            "acme",
            Some(client_id),
            secret,
            Some(token),
        ))
        .map_err(|failure| failure.error)
    }

    #[test]
    fn a_revoked_refresh_token_is_gone_with_everything_that_descends_from_the_same_grant() {
        let scenario = Scenario::start();
        let signed_in = scenario.sign_in("openid");
        let first = signed_in.tokens.refresh_token.expect("a refresh token");
        let second = scenario
            .refresh(&first)
            .expect("new tokens")
            .refresh_token
            .expect("the next refresh token");

        // The older token of the grant is enough to name it.
        assert_eq!(revoke(&scenario, "webapp", &first), Ok(()));

        assert_eq!(
            scenario.refresh(&second).map(|tokens| tokens.scope),
            Err(OAuthError::InvalidGrant)
        );
        let envelopes = scenario
            .storage
            .read_audit_envelopes(scenario.scope.realm());
        let revoked = envelopes.last().expect("an event");
        assert_eq!(revoked["kind"], "token.revoked");
        let told = &revoked["payload"];
        assert_eq!(told["reason"], "asked", "{revoked}");
        assert_eq!(
            told["session_id"],
            signed_in.ticket.session.to_string(),
            "{revoked}"
        );
        assert_eq!(told["tokens"], 2, "the grant and its rotation: {revoked}");
        assert_eq!(
            revoke(&scenario, "webapp", &first),
            Ok(()),
            "revoking twice is not an error"
        );
        assert_eq!(
            scenario
                .read_event_kinds()
                .iter()
                .filter(|kind| *kind == "token.revoked")
                .count(),
            1,
            "the family is said revoked once"
        );
    }

    #[test]
    fn a_token_of_another_client_or_of_nobody_is_answered_alike_and_left_alone() {
        let scenario = Scenario::start();
        let refresh = scenario
            .sign_in("openid")
            .tokens
            .refresh_token
            .expect("a refresh token");

        assert_eq!(revoke(&scenario, "billing", &refresh), Ok(()));
        assert_eq!(revoke(&scenario, "webapp", "not-a-token"), Ok(()));

        assert!(
            scenario.refresh(&refresh).is_ok(),
            "another client revokes nothing"
        );
        assert_eq!(
            revoke(&scenario, "ghost", &refresh),
            Err(OAuthError::InvalidClient)
        );
    }

    #[test]
    fn an_access_token_cannot_be_taken_back_and_the_answer_says_so() {
        let scenario = Scenario::start();
        let access = scenario.sign_in("openid").tokens.access_token;

        assert_eq!(
            revoke(&scenario, "webapp", &access),
            Err(OAuthError::UnsupportedTokenType)
        );
    }
}
