//! Establishing the client behind a request, the way the token endpoint does.
//!
//! Introspection and revocation authenticate exactly as the token endpoint
//! does, RFC 7662 §2.1 and RFC 7009 §2.1, so one sequence serves all three.

use actix_web::{HttpRequest, HttpResponse};
use chrono::{DateTime, Utc};
use deadpool_postgres::{Object, Transaction};
use models::entities::client::ClientModel;
use secrecy::SecretBox;
use services::client;
use store::tenancy::{Tenancy, TenantContext};

use config::serving::{Egress, PublicOrigin};

use crate::api::config::Sealing;
use crate::api::rest::endpoints::protocol::basic;
use crate::api::rest::endpoints::protocol::dto::Denied;
use crate::api::rest::endpoints::protocol::token::refused;

/// The client, authenticated, and the transaction it was read in.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one request"
)]
pub async fn establish<'a>(
    request: &HttpRequest,
    form_client_id: Option<&str>,
    form_secret: Option<String>,
    signed: Option<client::Signed<'_>>,
    connection: &'a mut Object,
    tenancy: &Tenancy,
    sealing: &Sealing,
    origin: &PublicOrigin,
    egress: Egress,
    context: &TenantContext,
    now: DateTime<Utc>,
) -> Result<(Transaction<'a>, ClientModel), HttpResponse> {
    let presented = client::read_presented(
        basic::credentials(request),
        form_client_id,
        form_secret.map(|secret| SecretBox::new(Box::new(secret))),
        signed,
    )
    .map_err(refused)?;

    // An assertion is spent as it is checked, and that spending has to survive
    // whatever the request then does: rolled back with a refused grant, the
    // assertion would be presentable again.
    let client = if matches!(presented, client::Presented::Assertion { .. }) {
        let held = {
            let transaction = scoped(connection, tenancy, context).await?;
            super::hosted::refresh_client_keys(&transaction, presented.client_id(), egress, now)
                .await;
            let client = checked(&transaction, sealing, origin, context, &presented, now).await?;
            transaction.commit().await.map_err(|why| {
                tracing::warn!(why = %why, "the assertion could not be spent");
                Denied::InvalidRequest.answer("the assertion could not be spent")
            })?;
            client
        };
        Some(held)
    } else {
        None
    };

    let transaction = scoped(connection, tenancy, context).await?;
    let client = match client {
        Some(client) => client,
        None => checked(&transaction, sealing, origin, context, &presented, now).await?,
    };
    Ok((transaction, client))
}

async fn scoped<'a>(
    connection: &'a mut Object,
    tenancy: &Tenancy,
    context: &TenantContext,
) -> Result<Transaction<'a>, HttpResponse> {
    tenancy
        .transaction(connection, context)
        .await
        .map_err(|_| Denied::InvalidRequest.answer("the realm could not be read"))
}

async fn checked(
    transaction: &Transaction<'_>,
    sealing: &Sealing,
    origin: &PublicOrigin,
    context: &TenantContext,
    presented: &client::Presented,
    now: DateTime<Utc>,
) -> Result<ClientModel, HttpResponse> {
    let realm = services::realm::named(transaction, &context.realm_id)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| Denied::InvalidRequest.answer("the realm could not be read"))?;
    let cost = realm
        .password_policy
        .as_ref()
        .map(|policy| policy.hashing)
        .unwrap_or_default();

    // Opened only where a client keeps a secret this deployment must read
    // back, which is one method out of five.
    let ring = match presented {
        client::Presented::Assertion { .. } => store::keyring::load(
            transaction,
            &sealing.envelope,
            &context.tenant,
            &context.realm_id,
        )
        .await
        .ok(),
        _ => None,
    };
    client::authenticate(
        transaction,
        &client::Establishing {
            provider: sealing.provider.as_ref(),
            cost,
            tenant: context,
            audiences: &audiences(origin, &context.realm_id),
            sealing: ring.as_ref().map(|ring| (ring, sealing.envelope.as_ref())),
        },
        presented,
        now,
    )
    .await
    .map_err(refused)
}

/// The names an assertion may be addressed to: RFC 7523 §3 says the token
/// endpoint, OIDC Core §9 says the issuer, and a client picking either has
/// addressed this server and no other.
pub fn audiences(origin: &PublicOrigin, realm_id: &str) -> Vec<String> {
    let issuer = origin.issuer(realm_id);
    let protocol = format!("{issuer}/protocol/openid-connect");
    vec![
        format!("{protocol}/token"),
        format!("{protocol}/par"),
        issuer,
    ]
}
