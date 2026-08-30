use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, HttpResponseBuilder, web};
use chrono::Utc;
use config::serving::Egress;
use data_encoding::BASE64;
use deadpool_postgres::Pool;
use serde::Deserialize;
use serde_json::Value;
use services::brokering::{self, Upstream};
use store::tenancy::{Tenancy, resolve};
use ureq::unversioned::resolver::DefaultResolver;

use config::serving::PublicOrigin;

use crate::api::config::Sealing;
use crate::api::provenance::read_provenance;
use crate::api::rest::endpoints::protocol::binding;
use crate::api::rest::endpoints::protocol::hosted::{Outward, PATIENCE, fetch};
use crate::api::rest::endpoints::protocol::login::{
    SSO_LIFESPAN, Spoken, hand_over, told, told_landing,
};

/// Send the browser to the upstream provider.
///
/// Only an open login may leave: brokering is a way to answer this realm's
/// own sign-in, not a freestanding door, so the request must carry the
/// login's cookie the way an answer would.
pub async fn begin(
    request: HttpRequest,
    path: web::Path<(String, String)>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    origin: web::Data<PublicOrigin>,
) -> HttpResponse {
    let (realm, alias) = path.into_inner();
    let now = Utc::now();
    let Some(auth_session) = binding::read(&request, binding::AUTH_SESSION) else {
        return told(StatusCode::NOT_FOUND, "no-such-login");
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
        return told(StatusCode::NOT_FOUND, "no-such-provider");
    };
    if provider.enabled == Some(false) {
        return told(StatusCode::NOT_FOUND, "no-such-provider");
    }
    let Ok(upstream) = Upstream::parse(&provider) else {
        tracing::warn!(alias, "a provider is stored that cannot be used");
        return told(StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
    };

    let landing = callback_of(&origin, &context.realm_id, &alias);
    let Ok(departure) = brokering::depart(
        sealing.provider.as_ref(),
        &upstream,
        &alias,
        &auth_session,
        &landing,
        now,
    ) else {
        return told(StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
    };
    if store::providers::brokering::open_state(&transaction, &departure.state)
        .await
        .is_err()
        || transaction.commit().await.is_err()
    {
        return told(StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
    }

    HttpResponseBuilder::new(StatusCode::SEE_OTHER)
        .insert_header(("location", departure.location))
        .finish()
}

/// What the upstream sends back through the browser.
#[derive(Deserialize)]
pub struct CameBack {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

/// Where the browser comes back. The security boundary of the whole slice:
/// everything here is attacker supplied, and every failure answers the same
/// way, with the reason kept for the operator log.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a piece of app state the callback reads"
)]
pub async fn conclude(
    request: HttpRequest,
    path: web::Path<(String, String)>,
    came: web::Query<CameBack>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    origin: web::Data<PublicOrigin>,
    egress: web::Data<Egress>,
) -> HttpResponse {
    let (realm, alias) = path.into_inner();
    let now = Utc::now();
    let refused = || told(StatusCode::BAD_REQUEST, "refused");

    let (Some(code), Some(state)) = (came.code.clone(), came.state.clone()) else {
        tracing::warn!(alias, error = ?came.error, "a brokered login came back without a grant");
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
    let Ok(upstream) = Upstream::parse(&provider) else {
        return told(StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
    };

    // 1. Spend the state: keyed on its hash and this provider, once.
    let Ok(spent) =
        brokering::returned(&transaction, sealing.provider.as_ref(), &alias, &state, now).await
    else {
        tracing::warn!(alias, "a brokered login presented a state nothing opened");
        return refused();
    };

    // 2. Redeem the code with the verifier from that row, never the request.
    let secret = opened_secret(&transaction, &sealing, &context, &provider).await;
    let landing = callback_of(&origin, &context.realm_id, &alias);
    let mut form = vec![
        ("grant_type".to_owned(), "authorization_code".to_owned()),
        ("code".to_owned(), code),
        ("redirect_uri".to_owned(), landing),
        ("code_verifier".to_owned(), spent.code_verifier.clone()),
    ];
    if secret.is_none() {
        form.push(("client_id".to_owned(), upstream.client_id.clone()));
    }
    let basic = secret.map(|held| (upstream.client_id.clone(), held));
    let Some(answered) = post_form(upstream.token_endpoint.clone(), **egress, form, basic).await
    else {
        tracing::warn!(alias, "the upstream refused the code exchange");
        return refused();
    };
    let Ok(answered) = serde_json::from_str::<Value>(&answered) else {
        return refused();
    };
    let Some(id_token) = answered.get("id_token").and_then(Value::as_str) else {
        tracing::warn!(alias, "the upstream answered without an identity token");
        return refused();
    };

    // 3. Verify the token against the upstream's published keys, bounded by
    //    configuration, and 4. against this departure's own nonce.
    let Some(keys) = fetch(upstream.jwks_uri.clone(), **egress).await else {
        tracing::warn!(alias, "the upstream's keys could not be read");
        return refused();
    };
    let Ok(keys) = serde_json::from_str::<Value>(&keys) else {
        return refused();
    };
    let Ok(arrival) = brokering::arrived(&upstream, &keys, id_token, &spent, now) else {
        tracing::warn!(alias, "the upstream's identity token did not verify");
        return refused();
    };

    // Who that is here, decided by policy; then the login they left open is
    // admitted the same way an answered one is.
    let Ok((user_id, first_login)) = brokering::decide_link(
        &transaction,
        &context.tenant,
        &context.realm_id,
        &provider,
        &arrival,
        now,
    )
    .await
    else {
        tracing::warn!(alias, "no local account could be decided for the arrival");
        return refused();
    };
    // The provider's rules run on every arrival; each rule says whether it
    // writes once or every time. After the link, so a rule reads who the
    // person is here; before the admission, so what it wrote is what the
    // tokens are minted from.
    if brokering::apply_mappers(&transaction, &provider, &user_id, &arrival, first_login)
        .await
        .is_err()
    {
        return told(StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
    }
    // The upstream's own signed assertion, kept as this person's aggregated
    // claim source: what it says travels as its word, never restated as
    // this realm's.
    if brokering::keep_assertions(&transaction, &provider, &user_id, id_token, &arrival)
        .await
        .is_err()
    {
        return told(StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
    }
    let Ok(Some(person)) = store::providers::users::load(&transaction, &user_id).await else {
        return told(StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
    };

    let seen = read_provenance(&request);
    let step = match auth::login::browser::admit_federated(
        &transaction,
        sealing.provider.as_ref(),
        &context,
        &spent.auth_session,
        &person.user_id,
        &person.user_name,
        &alias,
        &arrival.external_user_id,
        &seen,
        now,
    )
    .await
    {
        Ok(step) => step,
        Err(_) => {
            tracing::warn!(alias, "the login the broker was answering is gone");
            return refused();
        }
    };

    let ring = store::keyring::load(
        &transaction,
        &sealing.envelope,
        &context.tenant,
        &context.realm_id,
    )
    .await
    .ok();
    let signing = ring.as_ref().map(|ring| store::keyring::Signing {
        provider: sealing.provider.as_ref(),
        ring,
        envelope: &sealing.envelope,
    });
    let auth::login::browser::Step::Admitted(admitted) = step else {
        return refused();
    };
    let Ok(landed) = services::minting::landed(
        &transaction,
        sealing.provider.as_ref(),
        &context,
        &admitted,
        signing.as_ref(),
        &origin.issuer(&context.realm_id),
        now,
    )
    .await
    else {
        return told(StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
    };
    if transaction.commit().await.is_err() {
        return told(StatusCode::INTERNAL_SERVER_ERROR, "unavailable");
    }

    tracing::info!(session = %admitted.session_id, alias, "brokered login admitted");
    let mut response = HttpResponseBuilder::new(StatusCode::SEE_OTHER);
    binding::clear(&mut response, binding::AUTH_SESSION, &context.realm_id);
    binding::set(
        &mut response,
        binding::SSO_SESSION,
        &admitted.session_id,
        &context.realm_id,
        SSO_LIFESPAN,
    );
    if let Some(state) = &admitted.browser_state {
        binding::set_browser_state(&mut response, state, &context.realm_id);
    }
    hand_over(&mut response, &context.realm_id, None);
    told_landing(
        &mut response,
        Spoken::Form,
        "admitted",
        &landed,
        &origin,
        &context.realm_id,
    )
}

/// Where the upstream sends the browser back for this provider.
fn callback_of(origin: &PublicOrigin, realm_id: &str, alias: &str) -> String {
    format!(
        "{}/protocol/openid-connect/broker/{alias}/endpoint",
        origin.issuer(realm_id)
    )
}

/// The sealed upstream secret, opened for this exchange, or nothing when
/// the provider keeps none.
async fn opened_secret(
    transaction: &deadpool_postgres::Transaction<'_>,
    sealing: &Sealing,
    context: &store::tenancy::TenantContext,
    provider: &models::entities::authz::IdentityProviderModel,
) -> Option<String> {
    let sealed = provider
        .configs
        .as_ref()?
        .get(services::admin::idps::SEALED_SECRET)?
        .as_str()?;
    let sealed = BASE64.decode(sealed.as_bytes()).ok()?;
    let ring = store::keyring::load(
        transaction,
        &sealing.envelope,
        &context.tenant,
        &context.realm_id,
    )
    .await
    .ok()?;
    let opened = ring
        .open(
            &sealing.envelope,
            "identity-provider-secret",
            &provider.internal_id,
            &sealed,
        )
        .await
        .ok()?;
    String::from_utf8(crypto::secrecy::ExposeSecret::expose_secret(&opened).clone()).ok()
}

/// Dial the upstream's token endpoint. Same guardrails as every outbound
/// call: the egress policy decides what may be dialled, and the resolver
/// refuses addresses inside the deployment.
async fn post_form(
    uri: String,
    egress: Egress,
    form: Vec<(String, String)>,
    basic: Option<(String, String)>,
) -> Option<String> {
    let secure =
        uri.starts_with("https://") || (egress == Egress::Anywhere && uri.starts_with("http://"));
    if !secure {
        return None;
    }
    tokio::task::spawn_blocking(move || {
        let agent = ureq::Agent::with_parts(
            ureq::Agent::config_builder()
                .timeout_global(Some(PATIENCE))
                .max_redirects(0)
                .tls_config(
                    ureq::tls::TlsConfig::builder()
                        .provider(ureq::tls::TlsProvider::NativeTls)
                        .root_certs(ureq::tls::RootCerts::PlatformVerifier)
                        .build(),
                )
                .build(),
            ureq::unversioned::transport::DefaultConnector::new(),
            Outward(DefaultResolver::default(), egress),
        );
        let pairs: Vec<(&str, &str)> = form
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        let mut request = agent.post(&uri);
        if let Some((user, secret)) = &basic {
            let encoded = BASE64.encode(format!("{user}:{secret}").as_bytes());
            request = request.header("authorization", &format!("Basic {encoded}"));
        }
        let mut response = request.send_form(pairs).ok()?;
        if response.status() != 200 {
            return None;
        }
        response
            .body_mut()
            .with_config()
            .limit(64 * 1024)
            .read_to_string()
            .ok()
    })
    .await
    .ok()
    .flatten()
}
