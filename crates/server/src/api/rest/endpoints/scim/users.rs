use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, web};
use config::serving::PublicOrigin;
use crypto::password::storage::StoredPassword;
use crypto::provider::Argon2Params;
use crypto::secrecy::SecretBox;
use deadpool_postgres::{Pool, Transaction};
use models::entities::attributes::AttributeValue;
use models::entities::authz::GroupModel;
use models::entities::credentials::{CredentialModel, CredentialSecret, CredentialType};
use models::entities::user::{UserModel, profile};
use serde_json::Value;
use services::scim::{self, AssertedUser, Matched, Refusal, UserPatch, list_response, shown_user};
use store::providers::{credentials, roles, users};
use store::query::list_query::ListQuery;
use store::tenancy::{Tenancy, TenantContext};

use super::{answered, base_of, filter_of, refused, unavailable, window};
use crate::api::config::Sealing;
use crate::middleware::admin_guard::Admin;

fn within(admin: &Admin, realm_id: &str) -> TenantContext {
    TenantContext::new(&admin.context.tenant.tenant, realm_id)
}

async fn groups_of(
    transaction: &Transaction<'_>,
    person: &UserModel,
) -> Result<Vec<GroupModel>, ()> {
    let mut held = Vec::new();
    for group_id in users::groups_of(transaction, &person.user_id)
        .await
        .map_err(|_| ())?
    {
        if let Some(group) = roles::load_group(transaction, &group_id)
            .await
            .map_err(|_| ())?
        {
            held.push(group);
        }
    }
    Ok(held)
}

async fn shown(transaction: &Transaction<'_>, base: &str, person: &UserModel) -> Result<Value, ()> {
    let groups = groups_of(transaction, person).await?;
    Ok(shown_user(base, person, &groups))
}

pub async fn list(
    request: HttpRequest,
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    origin: web::Data<PublicOrigin>,
    path: web::Path<String>,
) -> HttpResponse {
    let realm_id = path.into_inner();
    let base = base_of(&request, &origin, &realm_id);
    let Ok(mut connection) = pool.get().await else {
        return unavailable();
    };
    let Ok(transaction) = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
    else {
        return unavailable();
    };

    let query = request.query_string();
    let (start_index, page) = window(query);

    let found: Vec<UserModel> = match filter_of(query) {
        Some(filter) => {
            let matched = match scim::folded_filter(&filter, false) {
                Ok(matched) => matched,
                Err(refusal) => return refused(&refusal),
            };
            let one = match matched {
                Matched::UserName(name) => users::load_by_name(&transaction, &name).await,
                Matched::Email(address) => users::load_by_email(&transaction, &address).await,
                Matched::ExternalId(external) => {
                    users::load_by_attribute(&transaction, scim::EXTERNAL_ID, &external).await
                }
                Matched::GroupName(_) => {
                    return refused(&Refusal::invalid_filter(
                        "displayName filters groups, not users",
                    ));
                }
            };
            match one {
                Ok(held) => held.into_iter().collect(),
                Err(_) => return unavailable(),
            }
        }
        None => match users::list(&transaction, &ListQuery::new(page), true).await {
            Ok(held) => held.items,
            Err(_) => return unavailable(),
        },
    };

    let total = found.len() as i64;
    let mut resources = Vec::with_capacity(found.len());
    for person in &found {
        match shown(&transaction, &base, person).await {
            Ok(body) => resources.push(body),
            Err(()) => return unavailable(),
        }
    }
    answered(StatusCode::OK, list_response(start_index, total, resources))
}

pub async fn get(
    request: HttpRequest,
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    origin: web::Data<PublicOrigin>,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    let (realm_id, user_id) = path.into_inner();
    let base = base_of(&request, &origin, &realm_id);
    let Ok(mut connection) = pool.get().await else {
        return unavailable();
    };
    let Ok(transaction) = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
    else {
        return unavailable();
    };
    match users::load(&transaction, &user_id).await {
        Ok(Some(person)) => match shown(&transaction, &base, &person).await {
            Ok(body) => answered(StatusCode::OK, body),
            Err(()) => unavailable(),
        },
        Ok(None) => refused(&Refusal::not_found()),
        Err(_) => unavailable(),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one request"
)]
pub async fn create(
    request: HttpRequest,
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    origin: web::Data<PublicOrigin>,
    path: web::Path<String>,
    body: web::Json<Value>,
) -> HttpResponse {
    let realm_id = path.into_inner();
    let base = base_of(&request, &origin, &realm_id);
    let asserted = match AssertedUser::read(&body) {
        Ok(asserted) => asserted,
        Err(refusal) => return refused(&refusal),
    };
    let Some(user_name) = asserted.user_name.clone() else {
        return refused(&Refusal::invalid("userName is required"));
    };

    let Ok(mut connection) = pool.get().await else {
        return unavailable();
    };
    let context = within(&admin, &realm_id);
    let Ok(transaction) = tenancy.transaction(&mut connection, &context).await else {
        return unavailable();
    };

    match users::load_by_name(&transaction, &user_name).await {
        Ok(Some(_)) => {
            return refused(&Refusal::uniqueness(format!(
                "userName {user_name} is already taken"
            )));
        }
        Ok(None) => {}
        Err(_) => return unavailable(),
    }
    if let Some(external) = &asserted.external_id {
        match users::load_by_attribute(&transaction, scim::EXTERNAL_ID, external).await {
            Ok(Some(_)) => {
                return refused(&Refusal::uniqueness(format!(
                    "externalId {external} is already taken"
                )));
            }
            Ok(None) => {}
            Err(_) => return unavailable(),
        }
    }

    let mut metadata = models::auditable::AuditableModel::from_creator(
        context.tenant.clone(),
        admin.context.principal.id().to_owned(),
    );
    metadata.created_at = Some(chrono::Utc::now());
    let mut person = UserModel {
        user_id: user_name.clone(),
        realm_id: realm_id.clone(),
        user_name,
        enabled: asserted.active.unwrap_or(true),
        email: asserted.email.clone().unwrap_or_default(),
        // A provisioner asserts an address; verifying it stays this realm's
        // own act, the same rule federation follows.
        email_verified: Some(false),
        phone_number: None,
        phone_number_verified: None,
        required_actions: None,
        not_before: None,
        user_storage: None,
        attributes: None,
        is_service_account: None,
        service_account_client_link: None,
        metadata,
    };
    asserted.apply(&mut person);

    if users::create(&transaction, &person).await.is_err() {
        return unavailable();
    }
    if let Some(password) = &asserted.password
        && planted_password(
            &transaction,
            &sealing,
            &admin.context.tenant.tenant,
            &realm_id,
            &person.user_id,
            password,
        )
        .await
        .is_err()
    {
        return refused(&Refusal::invalid("the password could not be kept"));
    }

    let body = match shown(&transaction, &base, &person).await {
        Ok(body) => body,
        Err(()) => return unavailable(),
    };
    if transaction.commit().await.is_err() {
        return unavailable();
    }
    answered(StatusCode::CREATED, body)
}

#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one request"
)]
pub async fn replace(
    request: HttpRequest,
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    origin: web::Data<PublicOrigin>,
    path: web::Path<(String, String)>,
    body: web::Json<Value>,
) -> HttpResponse {
    let (realm_id, user_id) = path.into_inner();
    let base = base_of(&request, &origin, &realm_id);
    let asserted = match AssertedUser::read(&body) {
        Ok(asserted) => asserted,
        Err(refusal) => return refused(&refusal),
    };

    let Ok(mut connection) = pool.get().await else {
        return unavailable();
    };
    let Ok(transaction) = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
    else {
        return unavailable();
    };
    let mut person = match users::load(&transaction, &user_id).await {
        Ok(Some(person)) => person,
        Ok(None) => return refused(&Refusal::not_found()),
        Err(_) => return unavailable(),
    };
    if let Some(renamed) = &asserted.user_name
        && renamed != &person.user_name
    {
        return refused(&Refusal {
            status: 400,
            scim_type: Some("mutability"),
            detail: "userName does not change here".into(),
        });
    }

    asserted.apply(&mut person);
    if users::update(&transaction, &person).await.is_err() {
        return unavailable();
    }
    if let Some(password) = &asserted.password
        && planted_password(
            &transaction,
            &sealing,
            &admin.context.tenant.tenant,
            &realm_id,
            &person.user_id,
            password,
        )
        .await
        .is_err()
    {
        return refused(&Refusal::invalid("the password could not be kept"));
    }
    let shown = match users::load(&transaction, &user_id).await {
        Ok(Some(fresh)) => match shown(&transaction, &base, &fresh).await {
            Ok(body) => body,
            Err(()) => return unavailable(),
        },
        _ => return unavailable(),
    };
    if transaction.commit().await.is_err() {
        return unavailable();
    }
    answered(StatusCode::OK, shown)
}

#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one request"
)]
pub async fn patch(
    request: HttpRequest,
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    origin: web::Data<PublicOrigin>,
    path: web::Path<(String, String)>,
    body: web::Json<Value>,
) -> HttpResponse {
    let (realm_id, user_id) = path.into_inner();
    let base = base_of(&request, &origin, &realm_id);
    let folded = match scim::folded_user_patch(&body) {
        Ok(folded) => folded,
        Err(refusal) => return refused(&refusal),
    };

    let Ok(mut connection) = pool.get().await else {
        return unavailable();
    };
    let Ok(transaction) = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
    else {
        return unavailable();
    };
    let mut person = match users::load(&transaction, &user_id).await {
        Ok(Some(person)) => person,
        Ok(None) => return refused(&Refusal::not_found()),
        Err(_) => return unavailable(),
    };

    let mut password = None;
    for change in folded {
        let bag = person.attributes.get_or_insert_with(Default::default);
        match change {
            UserPatch::Active(active) => person.enabled = active,
            UserPatch::GivenName(held) => {
                match held {
                    Some(value) => {
                        bag.insert(profile::FIRST_NAME.to_owned(), AttributeValue::Str(value));
                    }
                    None => {
                        bag.remove(profile::FIRST_NAME);
                    }
                };
            }
            UserPatch::FamilyName(held) => {
                match held {
                    Some(value) => {
                        bag.insert(profile::LAST_NAME.to_owned(), AttributeValue::Str(value));
                    }
                    None => {
                        bag.remove(profile::LAST_NAME);
                    }
                };
            }
            UserPatch::ExternalId(value) => {
                bag.insert(scim::EXTERNAL_ID.to_owned(), AttributeValue::Str(value));
            }
            UserPatch::Password(value) => password = Some(value),
            UserPatch::Email(value) => {
                if person.email != value {
                    person.email = value;
                    person.email_verified = Some(false);
                }
            }
        }
    }

    if users::update(&transaction, &person).await.is_err() {
        return unavailable();
    }
    if let Some(password) = &password
        && planted_password(
            &transaction,
            &sealing,
            &admin.context.tenant.tenant,
            &realm_id,
            &person.user_id,
            password,
        )
        .await
        .is_err()
    {
        return refused(&Refusal::invalid("the password could not be kept"));
    }
    let shown = match users::load(&transaction, &user_id).await {
        Ok(Some(fresh)) => match shown(&transaction, &base, &fresh).await {
            Ok(body) => body,
            Err(()) => return unavailable(),
        },
        _ => return unavailable(),
    };
    if transaction.commit().await.is_err() {
        return unavailable();
    }
    answered(StatusCode::OK, shown)
}

pub async fn delete(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    let (realm_id, user_id) = path.into_inner();
    let Ok(mut connection) = pool.get().await else {
        return unavailable();
    };
    let Ok(transaction) = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
    else {
        return unavailable();
    };
    match users::delete(&transaction, &user_id).await {
        Ok(true) => {
            if transaction.commit().await.is_err() {
                return unavailable();
            }
            HttpResponse::NoContent().finish()
        }
        Ok(false) => refused(&Refusal::not_found()),
        Err(_) => unavailable(),
    }
}

/// The same argon2 the login checks, replacing whatever password stood.
async fn planted_password(
    transaction: &Transaction<'_>,
    sealing: &Sealing,
    tenant: &str,
    realm_id: &str,
    user_id: &str,
    password: &str,
) -> Result<(), ()> {
    let StoredPassword::Argon2id { encoded } = StoredPassword::hash_argon2id(
        sealing.provider.as_ref(),
        Argon2Params::default(),
        &SecretBox::new(Box::new(password.to_owned())),
    )
    .map_err(|_| ())?
    else {
        return Err(());
    };
    let standing =
        credentials::load_for_user_of_type(transaction, user_id, CredentialType::Password)
            .await
            .map_err(|_| ())?;
    for held in &standing {
        credentials::delete(transaction, &held.credential_id)
            .await
            .map_err(|_| ())?;
    }
    credentials::create(
        transaction,
        &CredentialModel {
            credential_id: format!("scim-{user_id}"),
            realm_id: realm_id.to_owned(),
            user_id: user_id.to_owned(),
            credential_type: CredentialType::Password,
            secret: CredentialSecret::new(encoded),
            user_label: Some("provisioned".to_owned()),
            otp: None,
            priority: 0,
            metadata: models::auditable::AuditableModel::from_creator(
                tenant.to_owned(),
                "scim".to_owned(),
            ),
        },
    )
    .await
    .map_err(|_| ())
}
