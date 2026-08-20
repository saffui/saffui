//! What a relying party verifies with.
//!
//! Unauthenticated, because a key set is public: it holds public halves and
//! nothing else. Active and passive both, since a token signed just before a
//! rotation must still verify against the key that signed it.

use actix_web::http::StatusCode;
use actix_web::{HttpResponse, HttpResponseBuilder, web};
use deadpool_postgres::Pool;
use models::entities::keys::KeyUse;
use serde_json::{Value, json};
use store::providers::realm_keys;
use store::tenancy::{Tenancy, resolve};

use crate::api::rest::endpoints::protocol::dto::uncached;

/// The realm's key set.
pub async fn published(
    realm: web::Path<String>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
) -> HttpResponse {
    let Ok(mut connection) = pool.get().await else {
        return refused(StatusCode::INTERNAL_SERVER_ERROR);
    };
    // A realm's existence is not what this hides. Which clients it holds and
    // which users are, and neither is answerable here.
    let Ok(context) = resolve::realm_by_name(&connection, &realm).await else {
        return refused(StatusCode::NOT_FOUND);
    };
    let Ok(transaction) = tenancy.transaction(&mut connection, &context).await else {
        return refused(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let Ok(keys) = realm_keys::published(&transaction, KeyUse::Sig).await else {
        return refused(StatusCode::INTERNAL_SERVER_ERROR);
    };

    // Cacheable, unlike everything else on this plane. A key set is read on
    // every verification a relying party performs, and the rotation that
    // changes it leaves the old key in place, so a stale copy verifies rather
    // than failing.
    HttpResponseBuilder::new(StatusCode::OK)
        .insert_header(("Cache-Control", "public, max-age=300"))
        .json(json!({ "keys": keys.iter().map(advertised).collect::<Vec<_>>() }))
}

/// One key, as RFC 7517 §4 spells it.
///
/// `use` and `alg` are added rather than assumed from the stored JWK: a
/// verifier that has to guess which key is for signatures picks one, and the
/// one it picks is not always the one that signed.
fn advertised(key: &models::entities::keys::RealmSigningKeyView) -> Value {
    let mut jwk = key.public_jwk.clone();
    if let Some(named) = jwk.as_object_mut() {
        named.insert("kid".into(), Value::String(key.kid.clone()));
        named.insert("use".into(), Value::String("sig".into()));
        if let Ok(Value::String(alg)) = serde_json::to_value(key.algorithm) {
            named.insert("alg".into(), Value::String(alg));
        }
    }
    jwk
}

fn refused(status: StatusCode) -> HttpResponse {
    uncached(&mut HttpResponseBuilder::new(status)).json(json!({ "keys": [] }))
}
