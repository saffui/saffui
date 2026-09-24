use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, HttpResponseBuilder, web};
use chrono::Utc;
use config::serving::{LoginUi, PublicOrigin};
use serde::Deserialize;
use services::federation::brokering;
use services::federation::saml_brokering::{
    self, SamlLogoutMessage, SamlUpstream, TakenLogout, Unheeded, Untaken,
};
use store::error::StoreError;
use store::tenancy::{RealmNamed, Tenancy};

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
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    origin: web::Data<PublicOrigin>,
) -> HttpResponse {
    let (realm, alias) = path.into_inner();
    let context = match tenancy.resolve(RealmNamed::ByName(&realm)).await {
        Ok(context) => context,
        Err(StoreError::Unavailable) => {
            return told(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
        }
        Err(_) => {
            return told(StatusCode::NOT_FOUND, "no-such-provider");
        }
    };
    let transaction = match tenancy.begin(&context).await {
        Ok(transaction) => transaction,
        Err(StoreError::Unavailable) => {
            return told(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
        }
        Err(_) => return told(StatusCode::INTERNAL_SERVER_ERROR, "unavailable"),
    };

    let Ok(Some(provider)) = brokering::read_provider(&transaction, &alias).await else {
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
    let signing = services::oidc::grant::Signing {
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
/// Everything here is attacker supplied, and every failed check answers the same way,
/// with the reason kept for the operator log. The provider posts from its own site,
/// and a browser keeps a Lax cookie off a post from another site: an answer posted
/// without the login's cookie is posted once more from this origin, where the
/// cookie travels, and nothing is read or spent before it comes back. Posted once
/// more and still without the cookie, it is refused.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a piece of app state the consumer reads"
)]
pub async fn consume_assertion(
    request: HttpRequest,
    path: web::Path<(String, String)>,
    posted: web::Form<Posted>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    origin: web::Data<PublicOrigin>,
    login_ui: web::Data<LoginUi>,
) -> HttpResponse {
    let (realm, alias) = path.into_inner();
    let now = Utc::now();
    let refused = || told(StatusCode::BAD_REQUEST, "refused");
    let Some(answer) = posted.saml_response.as_deref() else {
        return refused();
    };
    let context = match tenancy.resolve(RealmNamed::ByName(&realm)).await {
        Ok(context) => context,
        Err(StoreError::Unavailable) => {
            return told(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
        }
        Err(_) => {
            return told(StatusCode::NOT_FOUND, "no-such-login");
        }
    };
    let transaction = match tenancy.begin(&context).await {
        Ok(transaction) => transaction,
        Err(StoreError::Unavailable) => {
            return told(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
        }
        Err(_) => return told(StatusCode::INTERNAL_SERVER_ERROR, "unavailable"),
    };
    let Ok(Some(provider)) = brokering::read_provider(&transaction, &alias).await else {
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
    let signing = services::oidc::grant::Signing {
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

    let sign_in_page = login_ui
        .answering()
        .map(str::to_owned)
        .unwrap_or_else(|| super::page::location(&origin, &realm));
    let user_id = match link_arrival(
        &transaction,
        &sealing,
        &context,
        &provider,
        &alias,
        &taken.arrival,
        &sign_in_page,
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

/// What a SAML provider posts to the realm's logout address: its own logout request,
/// or its answer to one the realm sent.
#[derive(Deserialize)]
pub struct PostedLogout {
    #[serde(rename = "SAMLRequest")]
    pub saml_request: Option<String>,
    #[serde(rename = "SAMLResponse")]
    pub saml_response: Option<String>,
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
}

/// A SAML logout message on a Redirect, read from the query exactly as it arrived.
pub async fn take_redirected_logout(
    request: HttpRequest,
    path: web::Path<(String, String)>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    origin: web::Data<PublicOrigin>,
    egress: web::Data<config::serving::Egress>,
) -> HttpResponse {
    let (realm, alias) = path.into_inner();
    answer_logout_message(
        &realm,
        &alias,
        SamlLogoutMessage::Redirected(request.query_string()),
        &tenancy,
        &sealing,
        &origin,
        **egress,
    )
    .await
}

/// A SAML logout message posted through the browser: a request or an answer, never
/// both.
pub async fn take_posted_logout(
    path: web::Path<(String, String)>,
    posted: web::Form<PostedLogout>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    origin: web::Data<PublicOrigin>,
    egress: web::Data<config::serving::Egress>,
) -> HttpResponse {
    let (realm, alias) = path.into_inner();
    let message = match (
        posted.saml_request.as_deref(),
        posted.saml_response.as_deref(),
    ) {
        (Some(request), None) => SamlLogoutMessage::PostedRequest {
            request,
            relay_state: posted.relay_state.as_deref(),
        },
        (None, Some(answer)) => SamlLogoutMessage::PostedAnswer(answer),
        _ => return told(StatusCode::BAD_REQUEST, "refused"),
    };
    answer_logout_message(
        &realm, &alias, message, &tenancy, &sealing, &origin, **egress,
    )
    .await
}

/// Take a SAML logout message and answer the browser.
///
/// Everything here is attacker supplied until the message verifies, and every
/// refusal answers the same way, with the reason kept for the operator log. A
/// provider's own logout request ends the logins it names with their clients told,
/// as when an OpenID Connect provider logs somebody out, and the browser carries the
/// signed answer back to the provider. The provider's answer to a logout the realm
/// started sends the browser on to where that logout was going.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one message"
)]
async fn answer_logout_message(
    realm: &str,
    alias: &str,
    message: SamlLogoutMessage<'_>,
    tenancy: &Tenancy,
    sealing: &Sealing,
    origin: &PublicOrigin,
    egress: config::serving::Egress,
) -> HttpResponse {
    let now = Utc::now();
    let refused = || told(StatusCode::BAD_REQUEST, "refused");
    let context = match tenancy.resolve(RealmNamed::ByName(realm)).await {
        Ok(context) => context,
        Err(StoreError::Unavailable) => {
            return told(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
        }
        Err(_) => {
            return refused();
        }
    };
    let transaction = match tenancy.begin(&context).await {
        Ok(transaction) => transaction,
        Err(StoreError::Unavailable) => {
            return told(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
        }
        Err(_) => return told(StatusCode::INTERNAL_SERVER_ERROR, "unavailable"),
    };
    let Ok(Some(provider)) = brokering::read_provider(&transaction, alias).await else {
        return refused();
    };
    if provider.enabled == Some(false) || !saml_brokering::is_saml(&provider) {
        return refused();
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
    let signing = services::oidc::grant::Signing {
        provider: sealing.provider.as_ref(),
        ring: &ring,
        envelope: &sealing.envelope,
    };
    let Ok(signing_key) = saml_brokering::load_signing_key(&transaction, &signing).await else {
        tracing::warn!(
            alias,
            "the realm holds no RSA key to answer a SAML logout with"
        );
        return told(StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
    };
    let issuer = origin.issuer(&context.realm_id);
    let taken = match saml_brokering::take_logout_message(
        &transaction,
        sealing.provider.as_ref(),
        &upstream,
        &issuer,
        alias,
        &signing_key,
        message,
        now,
    )
    .await
    {
        Ok(taken) => taken,
        Err(Unheeded::Backend) => return told(StatusCode::INTERNAL_SERVER_ERROR, "unavailable"),
        Err(why) => {
            tracing::warn!(alias, ?why, "a SAML logout message was not taken");
            return refused();
        }
    };
    let heeded = match taken {
        TakenLogout::Requested(heeded) => heeded,
        TakenLogout::Answered(request) => {
            if transaction.commit().await.is_err() {
                return told(StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
            }
            tracing::info!(alias, "a SAML provider answered the realm's logout");
            return match request.resume_to {
                Some(resume_to) => HttpResponseBuilder::new(StatusCode::SEE_OTHER)
                    .insert_header(("location", resume_to))
                    .insert_header(("cache-control", "no-store"))
                    .finish(),
                None => told(StatusCode::OK, "logged-out"),
            };
        }
    };

    let notices = services::oidc::logout::end_brokered_sessions(
        &transaction,
        Some(&signing),
        &issuer,
        &heeded.sessions,
        now,
    )
    .await;
    if transaction.commit().await.is_err() {
        return told(StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
    }
    tracing::info!(
        alias,
        closed = heeded.sessions.len(),
        "a SAML provider's logout landed"
    );
    crate::api::rest::endpoints::protocol::backchannel::deliver(notices, egress).await;
    match heeded.answer {
        Some(location) => HttpResponseBuilder::new(StatusCode::SEE_OTHER)
            .insert_header(("location", location))
            .insert_header(("cache-control", "no-store"))
            .finish(),
        None => told(StatusCode::OK, "logged-out"),
    }
}
