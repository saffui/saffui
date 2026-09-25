use crate::api::rest::endpoints::within;
use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use models::entities::client::ProtocolMapperMutationModel;
use services::admin::protocol_mappers::{self, Unwritable};
use store::tenancy::Tenancy;

use config::serving::PublicOrigin;

use crate::error::refuse_unopened_work;
use crate::middleware::admin_guard::Admin;
use outbound::Sealing;

pub async fn list(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let transaction = tenancy
        .begin(&within(&admin, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    let listed = protocol_mappers::mappers(&transaction)
        .await
        .map_err(refused)?;
    Ok(HttpResponse::Ok().json(listed))
}

/// The keys a rule reads as a switch, each with what its absence means, so a
/// screen can render a toggle already sitting where the rule would read it.
fn switches(keys: &[(&str, bool)]) -> Vec<serde_json::Value> {
    keys.iter()
        .map(|(key, resting)| serde_json::json!({ "key": key, "resting": resting }))
        .collect()
}

/// What each rule reads, so a console can offer a rule's own fields rather
/// than a free-text box and a hope.
///
/// Metadata: no realm is read. The path names one because every admin route
/// is realm scoped, and because what a build runs could one day differ by
/// realm without every caller having to learn a new address.
pub async fn kinds() -> Result<HttpResponse, ApiError> {
    let described: Vec<serde_json::Value> = services::oidc::mappers::KNOWN_TYPES
        .iter()
        .filter_map(|kind| {
            services::oidc::mappers::keys_of(kind).map(|keys| {
                serde_json::json!({
                    "mapper_type": kind,
                    "allowed": keys.allowed,
                    "required": keys.required,
                    "one_of": keys.one_of,
                    "booleans": switches(keys.booleans),
                })
            })
        })
        .collect();
    let flags: Vec<(&str, bool)> = services::oidc::mappers::TARGET_FLAGS
        .iter()
        .map(|flag| (*flag, services::oidc::mappers::FLAG_RESTING))
        .collect();
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "kinds": described,
        "target_flags": switches(&flags),
    })))
}

/// What the mappers would write for one grant, claim by claim with its
/// author. Mints nothing; the evaluation is issuance's own.
#[derive(serde::Deserialize)]
pub struct PreviewAsk {
    pub user_id: String,
    pub client_id: String,
    #[serde(default)]
    pub scope: Option<String>,
}

pub async fn preview(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    origin: web::Data<PublicOrigin>,
    path: web::Path<String>,
    body: web::Json<PreviewAsk>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let asked = body.into_inner();
    let transaction = tenancy
        .begin(&within(&admin, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    let scope = asked.scope.unwrap_or_else(|| "openid".to_owned());
    let user = services::admin::users::identified(&transaction, &asked.user_id)
        .await
        .map_err(|why| match why {
            services::admin::users::Uncreatable::NotFound => ApiError::new(ErrorCode::UserNotFound),
            _ => internal(),
        })?;
    let realm = services::realm::named(&transaction, &realm_id)
        .await
        .map_err(|_| internal())?
        .ok_or_else(|| ApiError::new(ErrorCode::RealmNotFound))?;

    // The realm's own keys, opened to name the one that would sign. Opened and
    // not used to sign: nothing here reaches a signer.
    let ring = store::keyring::load(
        &transaction,
        &sealing.envelope,
        &admin.context.tenant.tenant,
        &realm_id,
    )
    .await
    .map_err(|_| internal())?;
    let signing = services::oidc::grant::Signing {
        provider: sealing.provider.as_ref(),
        ring: &ring,
        envelope: &sealing.envelope,
    };

    let foreseen = services::token::preview::foresee(
        &transaction,
        &signing,
        &realm,
        &origin.issuer(&realm_id),
        &asked.client_id,
        &user.user_id,
        &scope,
    )
    .await
    .map_err(unforeseeable)?;

    let shown = |held: services::token::preview::Shown| serde_json::json!({ "header": held.header, "body": held.body });
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "scope": scope,
        "access": shown(foreseen.access),
        "identity": foreseen.identity.map(shown),
        "authors": foreseen.authors,
        "drawn_at_issuance": services::token::preview::DRAWN_AT_ISSUANCE,
    })))
}

/// Nothing foreseen, in the words the admin plane answers with.
fn unforeseeable(why: services::token::preview::Unforeseeable) -> ApiError {
    use services::token::preview::Unforeseeable;
    match why {
        Unforeseeable::NoSuchClient => ApiError::new(ErrorCode::ClientNotFound),
        Unforeseeable::NoKey | Unforeseeable::Unreadable => internal(),
    }
}

pub async fn create(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    path: web::Path<String>,
    body: web::Json<ProtocolMapperMutationModel>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let transaction = tenancy
        .begin(&within(&admin, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    let made = protocol_mappers::create_mapper(
        &transaction,
        sealing.provider.as_ref(),
        &admin.context.tenant.tenant,
        &realm_id,
        admin.context.principal.id(),
        body.into_inner(),
    )
    .await
    .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Created().json(made))
}

pub async fn get(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, mapper_id) = path.into_inner();
    let transaction = tenancy
        .begin(&within(&admin, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    let found = protocol_mappers::get_mapper(&transaction, &mapper_id)
        .await
        .map_err(refused)?;
    Ok(HttpResponse::Ok().json(found))
}

pub async fn update(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
    body: web::Json<ProtocolMapperMutationModel>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, mapper_id) = path.into_inner();
    let transaction = tenancy
        .begin(&within(&admin, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    let rewritten = protocol_mappers::update_mapper(
        &transaction,
        &mapper_id,
        admin.context.principal.id(),
        body.into_inner(),
    )
    .await
    .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(rewritten))
}

pub async fn delete(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, mapper_id) = path.into_inner();
    let transaction = tenancy
        .begin(&within(&admin, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    protocol_mappers::delete_mapper(&transaction, &mapper_id)
        .await
        .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

/// The four owner-side handlers share one shape: two ids off the path, one
/// manager call, an empty answer.
macro_rules! carrying {
    ($list:ident, $attach:ident, $detach:ident, $list_call:ident, $attach_call:ident, $detach_call:ident) => {
        pub async fn $list(
            admin: web::ReqData<Admin>,
            tenancy: web::Data<Tenancy>,
            path: web::Path<(String, String)>,
        ) -> Result<HttpResponse, ApiError> {
            let (realm_id, owner) = path.into_inner();
            let transaction = tenancy
                .begin(&within(&admin, &realm_id))
                .await
                .map_err(refuse_unopened_work)?;
            let listed = protocol_mappers::$list_call(&transaction, &owner)
                .await
                .map_err(refused)?;
            Ok(HttpResponse::Ok().json(listed))
        }

        pub async fn $attach(
            admin: web::ReqData<Admin>,
            tenancy: web::Data<Tenancy>,
            path: web::Path<(String, String, String)>,
        ) -> Result<HttpResponse, ApiError> {
            let (realm_id, owner, mapper_id) = path.into_inner();
            let transaction = tenancy
                .begin(&within(&admin, &realm_id))
                .await
                .map_err(refuse_unopened_work)?;
            protocol_mappers::$attach_call(&transaction, &owner, &mapper_id)
                .await
                .map_err(refused)?;
            transaction.commit().await.map_err(|_| internal())?;
            Ok(HttpResponse::NoContent().finish())
        }

        pub async fn $detach(
            admin: web::ReqData<Admin>,
            tenancy: web::Data<Tenancy>,
            path: web::Path<(String, String, String)>,
        ) -> Result<HttpResponse, ApiError> {
            let (realm_id, owner, mapper_id) = path.into_inner();
            let transaction = tenancy
                .begin(&within(&admin, &realm_id))
                .await
                .map_err(refuse_unopened_work)?;
            protocol_mappers::$detach_call(&transaction, &owner, &mapper_id)
                .await
                .map_err(refused)?;
            transaction.commit().await.map_err(|_| internal())?;
            Ok(HttpResponse::NoContent().finish())
        }
    };
}

carrying!(
    of_scope,
    attach_to_scope,
    detach_from_scope,
    mappers_of_scope,
    attach_to_scope,
    detach_from_scope
);
carrying!(
    of_client,
    attach_to_client,
    detach_from_client,
    mappers_of_client,
    attach_to_client,
    detach_from_client
);

fn refused(why: Unwritable) -> ApiError {
    match why {
        Unwritable::NotFound => ApiError::new(ErrorCode::ProtocolMapperNotFound),
        Unwritable::NoSuchScope => ApiError::new(ErrorCode::ClientScopeNotFound),
        Unwritable::NoSuchClient => ApiError::new(ErrorCode::ClientNotFound),
        Unwritable::UnknownRule(known) => ApiError::with_detail(
            ErrorCode::ValidationError,
            format!("no rule of this name runs here; one of: {known}"),
        ),
        Unwritable::BadRule(why) => {
            ApiError::with_detail(ErrorCode::ValidationError, why.to_string())
        }
        Unwritable::StillHeld => ApiError::new(ErrorCode::StillGranted),
        Unwritable::Backend => internal(),
    }
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}
