use actix_web::http::StatusCode;
use actix_web::{HttpResponse, HttpResponseBuilder, web};
use config::serving::PublicOrigin;
use store::error::StoreError;
use store::tenancy::{RealmNamed, Tenancy};

use crate::api::rest::endpoints::protocol::dto::{answer_unavailable, uncached};

/// The realm's DID document, where a wallet finds the key that signs the
/// realm's presentation requests.
///
/// A realm that does not run the verifier, or holds no Ed25519 key to sign a
/// request with, has none, and answers as a realm this server does not hold.
pub async fn did_document(
    realm: web::Path<String>,
    tenancy: web::Data<Tenancy>,
    origin: web::Data<PublicOrigin>,
) -> HttpResponse {
    let context = match tenancy.resolve(RealmNamed::ByName(&realm)).await {
        Ok(context) => context,
        Err(StoreError::Unavailable) => return answer_unavailable(),
        Err(_) => return refused(StatusCode::NOT_FOUND),
    };
    let transaction = match tenancy.begin(&context).await {
        Ok(transaction) => transaction,
        Err(StoreError::Unavailable) => return answer_unavailable(),
        Err(_) => return refused(StatusCode::INTERNAL_SERVER_ERROR),
    };
    if !crate::api::feature::runs_for_realm(&transaction, commons::feature::Feature::WalletVerifier)
        .await
    {
        return refused(StatusCode::NOT_FOUND);
    }
    let Ok(keys) = services::realm::published_keys(&transaction).await else {
        return refused(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let Some(did) = services::verifier::did::realm_did(&origin.issuer(&realm)) else {
        return refused(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let issuer = origin.issuer(&realm);
    let Some(document) = services::verifier::did::realm_did_document(
        &did,
        &keys,
        &services::verifier::presentation::response_uri(&issuer),
    ) else {
        return refused(StatusCode::NOT_FOUND);
    };

    // Cacheable like the key set, and for the same reason: a rotation leaves
    // the retreating key listed, so a stale copy still verifies.
    HttpResponseBuilder::new(StatusCode::OK)
        .insert_header(("Cache-Control", "public, max-age=300"))
        .content_type("application/did+json")
        .body(document.to_string())
}

fn refused(status: StatusCode) -> HttpResponse {
    uncached(&mut HttpResponseBuilder::new(status)).finish()
}

/// One presentation request, as the wallet that holds its address fetches it:
/// signed, while it waits for an answer.
pub async fn request_object(
    path: web::Path<(String, String)>,
    tenancy: web::Data<Tenancy>,
) -> HttpResponse {
    let (realm, request_id) = path.into_inner();
    let context = match tenancy.resolve(RealmNamed::ByName(&realm)).await {
        Ok(context) => context,
        Err(StoreError::Unavailable) => return answer_unavailable(),
        Err(_) => return refused(StatusCode::NOT_FOUND),
    };
    let transaction = match tenancy.begin(&context).await {
        Ok(transaction) => transaction,
        Err(StoreError::Unavailable) => return answer_unavailable(),
        Err(_) => return refused(StatusCode::INTERNAL_SERVER_ERROR),
    };
    if !crate::api::feature::runs_for_realm(&transaction, commons::feature::Feature::WalletVerifier)
        .await
    {
        return refused(StatusCode::NOT_FOUND);
    }
    match services::verifier::presentation::read_request_object(
        &transaction,
        &request_id,
        chrono::Utc::now(),
    )
    .await
    {
        Ok(Some(signed)) => uncached(&mut HttpResponseBuilder::new(StatusCode::OK))
            .content_type("application/oauth-authz-req+jwt")
            .body(signed),
        Ok(None) => refused(StatusCode::NOT_FOUND),
        Err(_) => refused(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// What a wallet posts to the realm's one response address: an encrypted
/// answer, or a refusal in the clear.
#[derive(Debug, serde::Deserialize)]
pub struct PostedAnswer {
    response: Option<String>,
    error: Option<String>,
    state: Option<String>,
}

/// Where every answer to the realm's presentation requests arrives. The answer
/// settles its request, once; what it came to is the asker's to read, and the
/// wallet is told only whether it was taken.
pub async fn response(
    realm: web::Path<String>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<outbound::Sealing>,
    origin: web::Data<PublicOrigin>,
    posted: web::Form<PostedAnswer>,
) -> HttpResponse {
    use services::verifier::presentation::{Answer, Settled, Unanswerable, settle_answer};
    let realm = realm.into_inner();
    let context = match tenancy.resolve(RealmNamed::ByName(&realm)).await {
        Ok(context) => context,
        Err(StoreError::Unavailable) => return answer_unavailable(),
        Err(_) => return refused(StatusCode::NOT_FOUND),
    };
    let transaction = match tenancy.begin(&context).await {
        Ok(transaction) => transaction,
        Err(StoreError::Unavailable) => return answer_unavailable(),
        Err(_) => return refused(StatusCode::INTERNAL_SERVER_ERROR),
    };
    if !crate::api::feature::runs_for_realm(&transaction, commons::feature::Feature::WalletVerifier)
        .await
    {
        return refused(StatusCode::NOT_FOUND);
    }
    let posted = posted.into_inner();
    let answer = match (&posted.response, &posted.error, &posted.state) {
        (Some(response), None, _) => Answer::Encrypted(response),
        (None, Some(error), Some(state)) => Answer::Refused { error, state },
        _ => {
            return wallet_error("the answer is an encrypted response, or an error with its state");
        }
    };
    let Ok(ring) = store::keyring::load(
        &transaction,
        &sealing.envelope,
        &context.tenant,
        &context.realm_id,
    )
    .await
    else {
        return refused(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let signing = store::keyring::Signing {
        provider: sealing.provider.as_ref(),
        ring: &ring,
        envelope: &sealing.envelope,
    };
    let settled = settle_answer(
        &transaction,
        &signing,
        &origin.issuer(&realm),
        answer,
        chrono::Utc::now(),
    )
    .await;
    match settled {
        Ok(settled) => {
            if transaction.commit().await.is_err() {
                return refused(StatusCode::INTERNAL_SERVER_ERROR);
            }
            match settled {
                Settled::Verified | Settled::Refused => {
                    uncached(&mut HttpResponseBuilder::new(StatusCode::OK))
                        .json(serde_json::json!({}))
                }
                Settled::Failed(why) => wallet_error(why),
            }
        }
        Err(Unanswerable::Unknown) => wallet_error("no request is waiting for this answer"),
        Err(Unanswerable::Unreadable) => wallet_error("the answer could not be read"),
        Err(Unanswerable::Unwritable) => refused(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

fn wallet_error(why: &str) -> HttpResponse {
    uncached(&mut HttpResponseBuilder::new(StatusCode::BAD_REQUEST)).json(serde_json::json!({
        "error": "invalid_request",
        "error_description": why,
    }))
}
