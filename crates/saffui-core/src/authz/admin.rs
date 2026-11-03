//! The guard of the administration plane. In order: authenticate the token,
//! confine it to the realm that minted it, then check the capability. Each
//! step refuses by default.

use super::capability::Capability;
use crate::app::App;
use crate::clients::Client;
use crate::error::{ErrorCode, Failure};
use crate::oidc::discovery::name_issuer;
use crate::tenancy::resolve::resolve_realm;
use crate::tenancy::{RealmName, RealmScope};
use crate::tokens::verify::verify_access_token;

/// The scope a token must carry to reach the administration plane at all.
pub const ADMIN_SCOPE: &str = "admin";

/// Who is calling the administration plane, once the guard let it through.
#[derive(Clone, Debug)]
pub struct AdminCaller {
    pub realm: RealmName,
    pub scope: RealmScope,
    pub client: Client,
}

/// Lets a call through, or refuses it.
///
/// The realm of the path is not looked up to be compared: the token must
/// name the issuer of that very realm, and be signed by its keys. A token
/// minted by one realm therefore reaches no other, whatever it claims.
///
/// # Errors
///
/// Returns [`ErrorCode::AdminAuthenticationFailed`] when there is no token,
/// when the realm does not exist, or when the token is not a valid access
/// token of this realm carrying the `admin` scope: all answer alike. Returns
/// [`ErrorCode::CapabilityMissing`] when the authenticated client is not
/// granted the capability. Returns the storage failure otherwise.
pub async fn authorize_admin_call(
    app: &App,
    realm: &str,
    bearer_token: Option<&str>,
    required: Capability,
) -> Result<AdminCaller, Failure> {
    let unauthenticated = || Failure::new(ErrorCode::AdminAuthenticationFailed);
    let token = bearer_token.ok_or_else(unauthenticated)?;
    let (realm_name, scope) =
        resolve_realm(app, realm)
            .await
            .map_err(|failure| match failure.code {
                ErrorCode::RealmNotFound => unauthenticated(),
                _ => failure,
            })?;

    let mut work = app.storage.begin(scope).await?;
    let issuer = name_issuer(&app.settings, &realm_name);
    let claims = verify_access_token(app, work.as_mut(), &issuer, token)
        .await
        .map_err(|failure| match failure.code {
            ErrorCode::TokenInvalid => unauthenticated(),
            _ => failure,
        })?;
    if !claims.scopes.iter().any(|scope| scope == ADMIN_SCOPE) {
        return Err(unauthenticated());
    }

    // The grants are read now, from the storage, and not from the token: a
    // capability taken away stops working at once, not when the token expires.
    let client = work
        .read_client(&claims.client_id)
        .await?
        .filter(|client| client.enabled)
        .ok_or_else(unauthenticated)?;
    if !client.capabilities.contains(&required) {
        return Err(Failure::new(ErrorCode::CapabilityMissing));
    }
    Ok(AdminCaller {
        realm: realm_name,
        scope,
        client,
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::authorize_admin_call;
    use crate::app::App;
    use crate::authz::capability::Capability;
    use crate::clients::register::{NewServiceClient, register_service_client};
    use crate::error::ErrorCode;
    use crate::oidc::token::{TokenRequest, grant_token};
    use crate::secret::Secret;
    use crate::tenancy::RealmScope;
    use crate::testkit::drive::complete;
    use crate::testkit::fixtures::create_realm;
    use crate::testkit::memory::MemoryStorage;

    fn register(
        app: &App,
        scope: RealmScope,
        client_id: &str,
        scopes: &[&str],
        capabilities: &[Capability],
    ) -> Secret {
        let scopes: Vec<String> = scopes.iter().map(|scope| (*scope).to_owned()).collect();
        let mut work = complete(app.storage.begin(scope)).expect("a unit of work");
        let wanted = NewServiceClient {
            client_id,
            name: "An operator",
            scopes: &scopes,
            capabilities,
        };
        let (_client, secret) =
            complete(register_service_client(app, work.as_mut(), wanted)).expect("a client");
        complete(work.commit()).expect("a commit");
        secret
    }

    fn get_token(app: &App, realm: &str, client_id: &str, secret: &Secret) -> String {
        let request = TokenRequest {
            grant_type: Some("client_credentials"),
            scope: None,
            client_id: Some(client_id),
            client_secret: Some(Secret::new(secret.expose().to_vec())),
        };
        complete(grant_token(app, realm, request))
            .expect("a token")
            .access_token
    }

    fn decide(
        app: &App,
        realm: &str,
        token: Option<&str>,
        required: Capability,
    ) -> Result<String, ErrorCode> {
        complete(authorize_admin_call(app, realm, token, required))
            .map(|caller| caller.client.client_id)
            .map_err(|failure| failure.code)
    }

    #[test]
    fn a_client_granted_a_capability_is_let_through_for_it_and_for_no_other() {
        let (app, _storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        let secret = register(
            &app,
            scope,
            "operator",
            &["admin"],
            &[Capability::ClientRead],
        );
        let token = get_token(&app, "acme", "operator", &secret);

        assert_eq!(
            decide(&app, "acme", Some(&token), Capability::ClientRead),
            Ok("operator".to_owned())
        );
        assert_eq!(
            decide(&app, "acme", Some(&token), Capability::ClientWrite),
            Err(ErrorCode::CapabilityMissing)
        );
    }

    #[test]
    fn a_token_of_one_realm_reaches_no_other_realm() {
        let (app, _storage) = MemoryStorage::wire();
        let acme = complete(create_realm(&app, "acme"));
        let globex = complete(create_realm(&app, "globex"));
        let secret = register(&app, acme, "operator", &["admin"], &Capability::ALL);
        // The same identifier exists over there, with every capability.
        register(&app, globex, "operator", &["admin"], &Capability::ALL);
        let token = get_token(&app, "acme", "operator", &secret);

        assert_eq!(
            decide(&app, "globex", Some(&token), Capability::RealmRead),
            Err(ErrorCode::AdminAuthenticationFailed)
        );
    }

    #[test]
    fn no_token_a_broken_token_an_unknown_realm_and_a_token_without_the_admin_scope_answer_alike() {
        let (app, _storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        let secret = register(&app, scope, "operator", &["admin"], &Capability::ALL);
        let plain = register(&app, scope, "billing", &["invoices:read"], &Capability::ALL);
        let token = get_token(&app, "acme", "operator", &secret);
        let without_admin = get_token(&app, "acme", "billing", &plain);
        let refused = Err(ErrorCode::AdminAuthenticationFailed);

        assert_eq!(decide(&app, "acme", None, Capability::RealmRead), refused);
        assert_eq!(
            decide(&app, "acme", Some("not.a.token"), Capability::RealmRead),
            refused
        );
        assert_eq!(
            decide(&app, "nowhere", Some(&token), Capability::RealmRead),
            refused
        );
        assert_eq!(
            decide(&app, "acme", Some(&without_admin), Capability::RealmRead),
            refused,
            "capabilities without the admin scope open nothing"
        );
    }

    #[test]
    fn a_client_disabled_after_its_token_was_minted_is_refused_at_once() {
        let (app, storage, clock) = MemoryStorage::wire_with_clock();
        let scope = complete(create_realm(&app, "acme"));
        let secret = register(&app, scope, "operator", &["admin"], &Capability::ALL);
        let token = get_token(&app, "acme", "operator", &secret);
        assert!(decide(&app, "acme", Some(&token), Capability::RealmRead).is_ok());

        storage.disable_client("operator");
        assert_eq!(
            decide(&app, "acme", Some(&token), Capability::RealmRead),
            Err(ErrorCode::AdminAuthenticationFailed),
            "the token has not expired, and it opens nothing"
        );

        clock.advance(Duration::from_secs(301));
        assert_eq!(
            decide(&app, "acme", Some(&token), Capability::RealmRead),
            Err(ErrorCode::AdminAuthenticationFailed)
        );
    }
}
