use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, HttpResponseBuilder, web};
use chrono::Utc;
use config::serving::PublicOrigin;
use deadpool_postgres::Pool;
use serde::Deserialize;
use services::saml_brokering::{self, SamlUpstream, Untaken};
use store::tenancy::{Tenancy, resolve};

use crate::api::config::Sealing;
use crate::api::provenance::read_provenance;
use crate::api::rest::endpoints::protocol::answering::posted_page;
use crate::api::rest::endpoints::protocol::binding;
use crate::api::rest::endpoints::protocol::broker::{admit_arrival, answer_admitted, link_arrival};
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

/// What a SAML provider posts back through the browser, and whether this origin has
/// already posted it once more.
#[derive(Deserialize)]
pub struct Posted {
    #[serde(rename = "SAMLResponse")]
    pub saml_response: Option<String>,
    pub bounced: Option<String>,
}

/// Where a SAML provider's answer comes back: the realm's assertion consumer for
/// that provider.
///
/// Everything here is attacker supplied, and every refusal answers the same way,
/// with the reason kept for the operator log. The provider posts from its own site,
/// and a browser keeps a Lax cookie off a post from another site: an answer posted
/// without the login's cookie is posted once more from this origin, where the
/// cookie travels, and nothing is read or spent before it comes back. Posted once
/// more and still without the cookie, it is refused.
pub async fn consume_assertion(
    request: HttpRequest,
    path: web::Path<(String, String)>,
    posted: web::Form<Posted>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    origin: web::Data<PublicOrigin>,
) -> HttpResponse {
    let (realm, alias) = path.into_inner();
    let now = Utc::now();
    let refused = || told(StatusCode::BAD_REQUEST, "refused");
    let Some(answer) = posted.saml_response.as_deref() else {
        return refused();
    };
    let Ok(mut connection) = pool.get().await else {
        return told(StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
    };
    let Ok(context) = resolve::realm_by_name(&connection, &realm).await else {
        return told(StatusCode::NOT_FOUND, "no-such-login");
    };
    let Ok(transaction) = tenancy.transaction(&mut connection, &context).await else {
        return told(StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
    };
    let Ok(Some(provider)) =
        store::providers::brokering::provider_by_alias(&transaction, &alias).await
    else {
        return refused();
    };
    if provider.enabled == Some(false) || !saml_brokering::is_saml(&provider) {
        return refused();
    }
    let issuer = origin.issuer(&context.realm_id);

    let Some(auth_session) = binding::read(&request, binding::AUTH_SESSION) else {
        if posted.bounced.is_some() {
            tracing::warn!(
                alias,
                "a SAML answer came back to a browser with no login open"
            );
            return refused();
        }
        let consumer = format!(
            "{}/acs",
            saml_brokering::compose_saml_address(&issuer, &alias)
        );
        return posted_page(
            &mut HttpResponseBuilder::new(StatusCode::OK),
            &consumer,
            &[
                ("SAMLResponse".to_owned(), answer.to_owned()),
                ("bounced".to_owned(), "1".to_owned()),
            ],
        );
    };

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
    let taken = match saml_brokering::take_answer(
        &transaction,
        &signing,
        &upstream,
        &issuer,
        &alias,
        answer,
        &auth_session,
        now,
    )
    .await
    {
        Ok(taken) => taken,
        Err(Untaken::Backend) => return told(StatusCode::INTERNAL_SERVER_ERROR, "unavailable"),
        Err(why) => {
            tracing::warn!(alias, ?why, "a SAML provider's answer was not taken");
            return refused();
        }
    };

    let user_id = match link_arrival(
        &transaction,
        &sealing,
        &context,
        &provider,
        &alias,
        &taken.arrival,
        now,
    )
    .await
    {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    let (admitted, landed) = match admit_arrival(
        &transaction,
        &sealing,
        &origin,
        &context,
        Some(&signing),
        &read_provenance(&request),
        &taken.request.auth_session,
        &alias,
        &user_id,
        &taken.arrival.external_user_id,
        now,
    )
    .await
    {
        Ok(admission) => admission,
        Err(response) => return response,
    };
    if saml_brokering::record_named_session(
        &transaction,
        &alias,
        &admitted.session_id,
        &taken.accepted,
    )
    .await
    .is_err()
        || transaction.commit().await.is_err()
    {
        return told(StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
    }
    answer_admitted(&origin, &context.realm_id, &alias, &admitted, &landed)
}
