//! What a realm needs before anybody can administer it.
//!
//! The admin plane refuses a token whose `scope` claim lacks the one it was
//! configured with, and `/authorize` drops a scope no client is attached to.
//! Between the two there is no client registration endpoint and no realm
//! creation handler, so nothing ever created the scope or the client that holds
//! it: the only token that reached `/admin` was one a test built by hand.
//!
//! This is the provisioning that closes it. Not a migration: a migration runs
//! against a schema, and both halves of this are rows in a realm that does not
//! exist yet when it runs, addressed to a client id the deployment names in its
//! own configuration.

use deadpool_postgres::Transaction;
use models::auditable::AuditableModel;
use models::entities::client::{ClientCreateModel, ClientScopeModel, Protocol};
use models::entities::realm::RealmModel;
use store::error::StoreResult;
use store::providers::{client_scopes, clients, realms};

/// What the admin plane requires on a token unless a deployment renames it.
///
/// The same default `SAFFUI_ADMIN_SCOPE` falls back to. Two spellings of one
/// string would let a deployment provision a scope its own plane refuses.
pub const ADMIN_SCOPE: &str = "admin";

/// The console a realm is administered from.
///
/// The client id is both halves of what the plane matches on. An access token
/// is minted for the client that asked for it and nothing adds a second
/// audience, so this one string is what `SAFFUI_ADMIN_PARTIES` and
/// `SAFFUI_ADMIN_AUDIENCES` both have to name.
#[derive(Debug, Clone)]
pub struct AdminConsole<'a> {
    /// What `azp` and `aud` will carry on every token this console obtains.
    pub client_id: &'a str,
    /// The scope the plane requires, passed in rather than read off the
    /// constant, so a deployment that renamed it provisions the name it asks for.
    pub scope: &'a str,
    /// Where the console is served. The operator's, because nothing else knows
    /// it, and a login is only sent back to a value written down here.
    pub redirect_uris: Vec<String>,
}

/// The scopes OIDC Core §5.4 defines, and what a fresh realm needs to honour
/// them.
///
/// Without these rows a realm entitles nobody to anything: `/authorize`
/// intersects the request with what a client is attached to, so a request for
/// `profile` is dropped and `/userinfo` releases a subject and nothing else.
///
/// `profile` and `email` are defaults, which is what every client gets without
/// asking. `phone` is not: §5.4 gates a number behind a scope a client has to
/// name, and a default would hand it out to every registration.
const STANDARD_SCOPES: [(&str, bool, &str); 3] = [
    ("profile", true, "Basic profile claims"),
    ("email", true, "Email address and whether it is verified"),
    ("phone", false, "Phone number and whether it is verified"),
];

/// Create a realm and everything it cannot work without.
///
/// One transaction, because a realm whose scopes failed to seed is not a
/// half-provisioned realm: it is one whose clients are entitled to nothing and
/// whose tokens carry a subject and no claims, and nothing about it says so.
///
/// Idempotent throughout, so a deployment that renames its console or adds a
/// redirect can run it again.
pub async fn provision_realm(
    transaction: &Transaction<'_>,
    realm: &RealmModel,
    console: &AdminConsole<'_>,
) -> StoreResult<()> {
    let tenant = &realm.metadata.tenant;
    if realms::load(transaction, &realm.realm_id).await?.is_none() {
        realms::create(transaction, realm).await?;
    }
    provision_standard_scopes(transaction, tenant, &realm.realm_id).await?;
    provision_admin_console(transaction, tenant, &realm.realm_id, console).await
}

/// The scopes a client can be attached to, and nothing attached yet.
///
/// Which clients hold which is a registration decision. This only makes the
/// decision possible: a scope that does not exist cannot be granted, so a realm
/// without these rows silently answers every request with less than was asked.
pub async fn provision_standard_scopes(
    transaction: &Transaction<'_>,
    tenant: &str,
    realm_id: &str,
) -> StoreResult<()> {
    let metadata = AuditableModel::from_creator(tenant.to_owned(), "system".to_owned());

    for (name, default, description) in STANDARD_SCOPES {
        if client_scopes::load_scope(transaction, name)
            .await?
            .is_some()
        {
            continue;
        }
        client_scopes::create_scope(
            transaction,
            &ClientScopeModel {
                client_scope_id: name.to_owned(),
                realm_id: realm_id.to_owned(),
                name: name.to_owned(),
                description: description.to_owned(),
                protocol: Protocol::OpenId,
                default_scope: Some(default),
                configs: None,
                metadata: metadata.clone(),
            },
        )
        .await?;
    }
    Ok(())
}

/// Give a realm its admin scope and a console entitled to it./// Give a realm its admin scope and a console entitled to it.
///
/// Idempotent, and idempotent in the direction that matters: what already
/// exists is left as it stands. An operator who pointed the console at a
/// different address or made it confidential keeps that, and only the
/// attachment is re-asserted, which is the one thing this is here to guarantee.
///
/// The attachment is not optional, so the console carries the scope without
/// asking for it. That is what lets the plane require the scope by default
/// rather than every admin UI having to remember to ask.
pub async fn provision_admin_console(
    transaction: &Transaction<'_>,
    tenant: &str,
    realm_id: &str,
    console: &AdminConsole<'_>,
) -> StoreResult<()> {
    let metadata = AuditableModel::from_creator(tenant.to_owned(), "system".to_owned());

    if client_scopes::load_scope(transaction, console.scope)
        .await?
        .is_none()
    {
        client_scopes::create_scope(
            transaction,
            &ClientScopeModel {
                client_scope_id: console.scope.to_owned(),
                realm_id: realm_id.to_owned(),
                name: console.scope.to_owned(),
                description: "Administration plane access".to_owned(),
                protocol: Protocol::OpenId,
                // Not a realm default. A default is offered to every client
                // registered afterwards, and a scope that opens the admin plane
                // is the last one to hand out by registration.
                default_scope: Some(false),
                configs: None,
                metadata: metadata.clone(),
            },
        )
        .await?;
    }

    if clients::load(transaction, console.client_id)
        .await?
        .is_none()
    {
        let mut client = ClientCreateModel {
            name: console.client_id.to_owned(),
            display_name: "Admin Console".to_owned(),
            description: "The console this realm is administered from".to_owned(),
            enabled: Some(true),
        }
        .into_model(
            console.client_id.to_owned(),
            realm_id.to_owned(),
            metadata.clone(),
        );
        client.protocol = Some(Protocol::OpenId);
        // A browser application, so there is nowhere to keep a secret and the
        // code is bound to the browser that started the login instead. Being
        // public is what makes `/authorize` insist on a challenge.
        client.public_client = Some(true);
        client.standard_flow_enabled = Some(true);
        // A console acts for the administrator using it and never for itself, so
        // it gets no service account and no direct grant.
        client.service_account_enabled = Some(false);
        client.direct_access_grants_enabled = Some(false);
        client.implicit_flow_enabled = Some(false);
        client.redirect_uris = Some(console.redirect_uris.clone());

        clients::create(transaction, &client).await?;
        // Twice, because the insert writes the identifying columns and the rest
        // are an update. Everything above that decides what this client may do
        // lives in the second half.
        clients::update(transaction, &client).await?;
    }

    client_scopes::attach_scope(transaction, console.client_id, console.scope, false).await
}
