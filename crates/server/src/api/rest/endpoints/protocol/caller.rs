use actix_web::{HttpRequest, HttpResponse};
use chrono::{DateTime, Utc};
use models::entities::client::ClientModel;
use secrecy::SecretBox;
use services::client;
use store::error::StoreError;
use store::tenancy::{Tenancy, TenantContext, UnitOfWork};

use config::serving::{Egress, PublicOrigin};

use crate::api::rest::endpoints::protocol::basic;
use crate::api::rest::endpoints::protocol::dto::{Denied, answer_unavailable};
use crate::api::rest::endpoints::protocol::token::refused;
use outbound::Sealing;

/// The client, authenticated, and the transaction it was read in.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one request"
)]
pub async fn establish(
    request: &HttpRequest,
    form_client_id: Option<&str>,
    form_secret: Option<String>,
    signed: Option<client::Signed<'_>>,
    tenancy: &Tenancy,
    sealing: &Sealing,
    origin: &PublicOrigin,
    egress: Egress,
    context: &TenantContext,
    now: DateTime<Utc>,
) -> Result<(UnitOfWork, ClientModel), HttpResponse> {
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
        outbound::egress::refresh_client_keys(tenancy, context, presented.client_id(), egress, now)
            .await;
        let held = {
            let transaction = scoped(tenancy, context).await?;
            let client = checked(
                request,
                &transaction,
                sealing,
                origin,
                context,
                &presented,
                now,
            )
            .await?;
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

    let transaction = scoped(tenancy, context).await?;
    let client = match client {
        Some(client) => client,
        None => {
            checked(
                request,
                &transaction,
                sealing,
                origin,
                context,
                &presented,
                now,
            )
            .await?
        }
    };
    Ok((transaction, client))
}

/// The transaction to go on in, and the client read again from it, once the
/// keys the client publishes have been read afresh, when they were due.
///
/// Not due, which is every request but one a keeping, nothing changes. Due,
/// the transaction in hand is committed, the keys read on none, and a fresh one
/// opened: no pooled connection waits on the client's host.
pub async fn with_client_keys_read(
    tenancy: &Tenancy,
    context: &TenantContext,
    transaction: UnitOfWork,
    client: ClientModel,
    egress: Egress,
    now: DateTime<Utc>,
) -> Result<(UnitOfWork, ClientModel), StoreError> {
    if client.jwks_uri.is_none()
        || client::keys_due(&transaction, &client.client_id, now)
            .await
            .is_none()
    {
        return Ok((transaction, client));
    }
    transaction.commit().await?;
    outbound::egress::refresh_client_keys(tenancy, context, &client.client_id, egress, now).await;
    let transaction = tenancy.begin(context).await?;
    let client = client::read_client(&transaction, &client.client_id)
        .await
        .ok()
        .flatten()
        .unwrap_or(client);
    Ok((transaction, client))
}

async fn scoped(tenancy: &Tenancy, context: &TenantContext) -> Result<UnitOfWork, HttpResponse> {
    tenancy.begin(context).await.map_err(|why| match why {
        StoreError::Unavailable => answer_unavailable(),
        _ => Denied::InvalidRequest.answer("the realm could not be read"),
    })
}

async fn checked(
    request: &HttpRequest,
    transaction: &UnitOfWork,
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
            certificate: certificate_names(request),
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
/// The names off the certificate a trusted proxy forwarded, read with the
/// discipline every mTLS read here has: the operator-named header, from the
/// operator-named peers, and from nobody else.
fn certificate_names(request: &HttpRequest) -> Option<client::CertificateNames> {
    let proxying = request
        .app_data::<actix_web::web::Data<config::proxying::Proxying>>()
        .map_or_else(config::proxying::Proxying::none, |held| (***held).clone());
    let named =
        actix_web::http::header::HeaderName::from_bytes(proxying.certificate_header()?.as_bytes())
            .ok()?;
    let carried = request.headers().get(named)?.to_str().ok()?;
    let peer = request.peer_addr().map(|address| address.ip().to_string());
    let carried = proxying.client_certificate(peer.as_deref(), Some(carried))?;
    Some(client::CertificateNames {
        dns: services::client::mtls::san_dns(carried).unwrap_or_default(),
        uris: services::client::mtls::san_uris(carried).unwrap_or_default(),
        subject: services::client::mtls::subject_dn(carried).ok(),
    })
}

pub fn audiences(origin: &PublicOrigin, realm_id: &str) -> Vec<String> {
    let issuer = origin.issuer(realm_id);
    let protocol = format!("{issuer}/protocol/openid-connect");
    vec![
        format!("{protocol}/token"),
        format!("{protocol}/par"),
        issuer,
    ]
}
