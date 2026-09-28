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
    let Some(document) = services::verifier::did::realm_did_document(&did, &keys) else {
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
