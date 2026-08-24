use actix_web::http::{StatusCode, header};
use actix_web::{HttpRequest, HttpResponse, web};
use chrono::Utc;
use deadpool_postgres::Pool;
use models::entities::client::ClientModel;
use serde_json::{Value, json};
use services::registration::{self, Metadata, Refused};
use store::providers::realms;
use store::tenancy::{Tenancy, resolve};

use crate::api::config::Sealing;
use crate::api::rest::endpoints::protocol::dto::uncached;
use crate::api::rest::endpoints::protocol::hosted;
use config::serving::PublicOrigin;

/// RFC 7591 §3.1: the caller may carry an initial access token, and RFC 7592
/// §2 a registration access token. Both arrive the same way.
fn bearer(request: &HttpRequest) -> Option<String> {
    request
        .headers()
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::to_owned)
}

/// §3.2.2 of RFC 7591 and §3.3 of the registration spec.
fn refused(why: &Refused) -> HttpResponse {
    let (status, error) = match why {
        Refused::Closed => (StatusCode::NOT_FOUND, "invalid_request"),
        Refused::Unknown => (StatusCode::NOT_FOUND, "invalid_client_metadata"),
        Refused::Unauthorized => (StatusCode::UNAUTHORIZED, "invalid_token"),
        Refused::Invalid(_) => (StatusCode::BAD_REQUEST, "invalid_client_metadata"),
        Refused::Unwritable => (StatusCode::INTERNAL_SERVER_ERROR, "invalid_request"),
    };
    let mut building = HttpResponse::build(status);
    let answer = uncached(&mut building);
    if status == StatusCode::UNAUTHORIZED {
        answer.insert_header((header::WWW_AUTHENTICATE, "Bearer error=\"invalid_token\""));
    }
    answer.json(json!({ "error": error, "error_description": why.to_string() }))
}

/// Where this client's own registration is managed, §3.2.1.
fn managed_at(origin: &PublicOrigin, realm: &str, client_id: &str) -> String {
    format!(
        "{}/realms/{realm}/protocol/openid-connect/register/{client_id}",
        origin.as_str().trim_end_matches('/')
    )
}

fn answered(document: Value, status: StatusCode) -> HttpResponse {
    uncached(&mut HttpResponse::build(status)).json(document)
}

#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one registration"
)]
pub async fn create(
    request: HttpRequest,
    realm: web::Path<String>,
    body: Option<web::Json<Metadata>>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    origin: web::Data<PublicOrigin>,
    egress: web::Data<config::serving::Egress>,
) -> HttpResponse {
    let now = Utc::now();
    let Some(body) = body else {
        return refused(&Refused::Invalid("the body could not be read as json"));
    };
    let Ok(mut connection) = pool.get().await else {
        return refused(&Refused::Unwritable);
    };
    let Ok(context) = resolve::realm_by_name(&connection, &realm).await else {
        return refused(&Refused::Closed);
    };
    let Ok(transaction) = tenancy.transaction(&mut connection, &context).await else {
        return refused(&Refused::Unwritable);
    };
    let Ok(Some(held)) = realms::load(&transaction, &context.realm_id).await else {
        return refused(&Refused::Closed);
    };
    if let Err(why) = registration::admits(
        &held,
        sealing.provider.as_ref(),
        bearer(&request).as_deref(),
    ) {
        return refused(&why);
    }

    // Only opened where the registration asks for a method that keeps a
    // readable secret; the rest of them store nothing this could open.
    let ring = store::keyring::load(
        &transaction,
        &sealing.envelope,
        &context.tenant,
        &context.realm_id,
    )
    .await
    .ok();
    // §5: fetched here, because reaching the network is the transport's, and
    // read by the service, which is what decides.
    let sector = match body.sector_identifier_uri.as_deref() {
        Some(named) => match hosted::fetch(named.to_owned(), **egress).await {
            Some(document) => serde_json::from_str::<Vec<String>>(&document).ok(),
            None => None,
        },
        None => None,
    };
    let registered = match registration::register(
        &transaction,
        sealing.provider.as_ref(),
        ring.as_ref().map(|ring| (ring, sealing.envelope.as_ref())),
        &context.tenant,
        &context.realm_id,
        &body,
        sector.as_deref(),
        now,
    )
    .await
    {
        Ok(registered) => registered,
        Err(why) => return refused(&why),
    };
    if transaction.commit().await.is_err() {
        return refused(&Refused::Unwritable);
    }

    let mut document = registration::as_document(&registered.client, now.timestamp());
    let named = document.as_object_mut().expect("a json object");
    if let Some(secret) = registered.secret {
        named.insert("client_secret".to_owned(), Value::from(secret));
        // Zero is never, §3.2.1. A secret with no end is said to have none
        // rather than left for the client to assume.
        named.insert("client_secret_expires_at".to_owned(), Value::from(0));
    }
    named.insert(
        "registration_access_token".to_owned(),
        Value::from(registered.access_token),
    );
    named.insert(
        "registration_client_uri".to_owned(),
        Value::from(managed_at(&origin, &realm, &registered.client.client_id)),
    );
    answered(document, StatusCode::CREATED)
}

pub async fn read(
    request: HttpRequest,
    path: web::Path<(String, String)>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    origin: web::Data<PublicOrigin>,
) -> HttpResponse {
    let now = Utc::now();
    let (realm, client_id) = path.into_inner();
    let held = match held_client(&request, &realm, &client_id, &pool, &tenancy, &sealing).await {
        Ok(client) => client,
        Err(why) => return refused(&why),
    };
    let issued = held
        .registered_at
        .or(held.metadata.created_at)
        .unwrap_or(now);
    let mut document = registration::as_document(&held, issued.timestamp());
    document.as_object_mut().expect("a json object").insert(
        "registration_client_uri".to_owned(),
        Value::from(managed_at(&origin, &realm, &client_id)),
    );
    answered(document, StatusCode::OK)
}

pub async fn replace(
    request: HttpRequest,
    path: web::Path<(String, String)>,
    body: Option<web::Json<Metadata>>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    origin: web::Data<PublicOrigin>,
) -> HttpResponse {
    let now = Utc::now();
    let (realm, client_id) = path.into_inner();
    let Some(body) = body else {
        return refused(&Refused::Invalid("the body could not be read as json"));
    };
    let mut connection = match pool.get().await {
        Ok(connection) => connection,
        Err(_) => return refused(&Refused::Unwritable),
    };
    let Ok(context) = resolve::realm_by_name(&connection, &realm).await else {
        return refused(&Refused::Closed);
    };
    let Ok(transaction) = tenancy.transaction(&mut connection, &context).await else {
        return refused(&Refused::Unwritable);
    };
    let held = match registration::holder_of(
        &transaction,
        sealing.provider.as_ref(),
        &client_id,
        bearer(&request).as_deref(),
    )
    .await
    {
        Ok(client) => client,
        Err(why) => return refused(&why),
    };
    // §2.2: a request naming a different client is not an amendment of this one.
    if body
        .client_id
        .as_deref()
        .is_some_and(|named| named != client_id)
    {
        return refused(&Refused::Invalid("the body names another client"));
    }
    let amended = match registration::amend(&transaction, &held, &body).await {
        Ok(amended) => amended,
        Err(why) => return refused(&why),
    };
    if transaction.commit().await.is_err() {
        return refused(&Refused::Unwritable);
    }
    let issued = amended
        .registered_at
        .or(amended.metadata.created_at)
        .unwrap_or(now);
    let mut document = registration::as_document(&amended, issued.timestamp());
    document.as_object_mut().expect("a json object").insert(
        "registration_client_uri".to_owned(),
        Value::from(managed_at(&origin, &realm, &client_id)),
    );
    answered(document, StatusCode::OK)
}

pub async fn withdraw(
    request: HttpRequest,
    path: web::Path<(String, String)>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
) -> HttpResponse {
    let (realm, client_id) = path.into_inner();
    let mut connection = match pool.get().await {
        Ok(connection) => connection,
        Err(_) => return refused(&Refused::Unwritable),
    };
    let Ok(context) = resolve::realm_by_name(&connection, &realm).await else {
        return refused(&Refused::Closed);
    };
    let Ok(transaction) = tenancy.transaction(&mut connection, &context).await else {
        return refused(&Refused::Unwritable);
    };
    if let Err(why) = registration::holder_of(
        &transaction,
        sealing.provider.as_ref(),
        &client_id,
        bearer(&request).as_deref(),
    )
    .await
    {
        return refused(&why);
    }
    if let Err(why) = registration::withdraw(&transaction, &client_id).await {
        return refused(&why);
    }
    if transaction.commit().await.is_err() {
        return refused(&Refused::Unwritable);
    }
    uncached(&mut HttpResponse::build(StatusCode::NO_CONTENT)).finish()
}

/// The client this caller's registration access token stands for.
async fn held_client(
    request: &HttpRequest,
    realm: &str,
    client_id: &str,
    pool: &Pool,
    tenancy: &Tenancy,
    sealing: &Sealing,
) -> Result<ClientModel, Refused> {
    let mut connection = pool.get().await.map_err(|_| Refused::Unwritable)?;
    let context = resolve::realm_by_name(&connection, realm)
        .await
        .map_err(|_| Refused::Closed)?;
    let transaction = tenancy
        .transaction(&mut connection, &context)
        .await
        .map_err(|_| Refused::Unwritable)?;
    registration::holder_of(
        &transaction,
        sealing.provider.as_ref(),
        client_id,
        bearer(request).as_deref(),
    )
    .await
}
