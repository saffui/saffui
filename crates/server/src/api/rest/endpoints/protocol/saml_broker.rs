use actix_web::http::StatusCode;
use actix_web::{HttpResponse, HttpResponseBuilder, web};
use config::serving::PublicOrigin;
use deadpool_postgres::Pool;
use services::saml_brokering::{self, SamlUpstream};
use store::tenancy::{Tenancy, resolve};

use crate::api::config::Sealing;
use crate::api::rest::endpoints::protocol::login::told;

/// The realm as one SAML provider's service provider, for that provider to import.
///
/// Public like a key set: certificates and addresses, nothing secret, and a
/// provider that cannot fetch it cannot be configured. A provider that is not
/// SAML, or is switched off, has none.
pub async fn metadata(
    path: web::Path<(String, String)>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    origin: web::Data<PublicOrigin>,
) -> HttpResponse {
    let (realm, alias) = path.into_inner();
    let Ok(mut connection) = pool.get().await else {
        return told(StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
    };
    let Ok(context) = resolve::realm_by_name(&connection, &realm).await else {
        return told(StatusCode::NOT_FOUND, "no-such-provider");
    };
    let Ok(transaction) = tenancy.transaction(&mut connection, &context).await else {
        return told(StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
    };

    let Ok(Some(provider)) =
        store::providers::brokering::provider_by_alias(&transaction, &alias).await
    else {
        return told(StatusCode::NOT_FOUND, "no-such-provider");
    };
    if provider.enabled == Some(false) || !saml_brokering::is_saml(&provider) {
        return told(StatusCode::NOT_FOUND, "no-such-provider");
    }
    let Ok(upstream) = SamlUpstream::parse(&provider) else {
        tracing::warn!(alias, "a SAML provider is stored that cannot be used");
        return told(StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
    };

    let Ok(ring) = store::keyring::load(
        &transaction,
        &sealing.envelope,
        &context.tenant,
        &context.realm_id,
    )
    .await
    else {
        return told(StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
    };
    let signing = services::grant::Signing {
        provider: sealing.provider.as_ref(),
        ring: &ring,
        envelope: &sealing.envelope,
    };
    let described = match saml_brokering::load_published_keys(&transaction, &signing).await {
        Ok((signing_key, encryption_key)) => saml_brokering::describe_realm(
            &upstream,
            &origin.issuer(&context.realm_id),
            &alias,
            &context.realm_id,
            &signing_key,
            encryption_key.as_ref(),
        ),
        Err(refused) => Err(refused),
    };
    match described {
        // Cacheable like a key set: a rotation leaves the old key published beside
        // the new one, so a copy a few minutes old still verifies.
        Ok(document) => HttpResponseBuilder::new(StatusCode::OK)
            .insert_header(("content-type", "application/samlmetadata+xml"))
            .insert_header(("Cache-Control", "public, max-age=300"))
            .body(document),
        Err(why) => {
            tracing::warn!(alias, %why, "a realm could not describe itself to a SAML provider");
            told(StatusCode::INTERNAL_SERVER_ERROR, "unavailable")
        }
    }
}
