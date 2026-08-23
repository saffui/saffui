//! Establishing the client behind a request, the way the token endpoint does.
//!
//! Introspection and revocation authenticate exactly as the token endpoint
//! does, RFC 7662 §2.1 and RFC 7009 §2.1, so one sequence serves all three.

use actix_web::{HttpRequest, HttpResponse};
use chrono::{DateTime, Utc};
use crypto::provider::CryptoProvider;
use deadpool_postgres::{Object, Transaction};
use models::entities::client::ClientModel;
use secrecy::SecretBox;
use services::client;
use store::tenancy::{Tenancy, TenantContext};

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
    connection: &'a mut Object,
    tenancy: &Tenancy,
    provider: &dyn CryptoProvider,
    context: &TenantContext,
    now: DateTime<Utc>,
) -> Result<(Transaction<'a>, ClientModel), HttpResponse> {
    let presented = client::read_presented(
        basic::credentials(request),
        form_client_id,
        form_secret.map(|secret| SecretBox::new(Box::new(secret))),
    )
    .map_err(refused)?;

    let transaction = tenancy
        .transaction(connection, context)
        .await
        .map_err(|_| Denied::InvalidRequest.answer("the realm could not be read"))?;
    let realm = services::realm::named(&transaction, &context.realm_id)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| Denied::InvalidRequest.answer("the realm could not be read"))?;
    let cost = realm
        .password_policy
        .as_ref()
        .map(|policy| policy.hashing)
        .unwrap_or_default();

    let client = client::authenticate(&transaction, provider, cost, &presented, now)
        .await
        .map_err(refused)?;
    Ok((transaction, client))
}
