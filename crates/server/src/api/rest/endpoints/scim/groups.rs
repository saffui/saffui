use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, web};
use config::serving::PublicOrigin;
use deadpool_postgres::{Pool, Transaction};
use models::entities::authz::GroupModel;
use models::entities::user::UserModel;
use serde_json::Value;
use services::scim::{self, GroupPatch, Refusal, list_response, shown_group};
use store::providers::{roles, users};
use store::query::list_query::ListQuery;
use store::tenancy::{Tenancy, TenantContext};

use super::{answered, base_of, filter_of, refused, unavailable, window};
use crate::middleware::admin_guard::Admin;

fn within(admin: &Admin, realm_id: &str) -> TenantContext {
    TenantContext::new(&admin.context.tenant.tenant, realm_id)
}

async fn members_of(
    transaction: &Transaction<'_>,
    group: &GroupModel,
) -> Result<Vec<UserModel>, ()> {
    let (people, _) = roles::group_membership(transaction, &group.group_id)
        .await
        .map_err(|_| ())?;
    let mut held = Vec::new();
    for user_id in people {
        if let Some(person) = users::load(transaction, &user_id).await.map_err(|_| ())? {
            held.push(person);
        }
    }
    Ok(held)
}

async fn shown(transaction: &Transaction<'_>, base: &str, group: &GroupModel) -> Result<Value, ()> {
    let members = members_of(transaction, group).await?;
    Ok(shown_group(base, group, &members))
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
    let found: Vec<GroupModel> = match filter_of(query) {
        Some(filter) => match scim::folded_filter(&filter, true) {
            Ok(scim::Matched::GroupName(name)) => {
                match roles::load_group_by_name(&transaction, &name).await {
                    Ok(held) => held.into_iter().collect(),
                    Err(_) => return unavailable(),
                }
            }
            Ok(_) => return refused(&Refusal::invalid_filter("groups filter by displayName")),
            Err(refusal) => return refused(&refusal),
        },
        None => match roles::list_groups(&transaction, &ListQuery::new(page), false).await {
            Ok(held) => held.items,
            Err(_) => return unavailable(),
        },
    };

    let total = found.len() as i64;
    let mut resources = Vec::with_capacity(found.len());
    for group in &found {
        match shown(&transaction, &base, group).await {
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
    let (realm_id, group_id) = path.into_inner();
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
    match roles::load_group(&transaction, &group_id).await {
        Ok(Some(group)) => match shown(&transaction, &base, &group).await {
            Ok(body) => answered(StatusCode::OK, body),
            Err(()) => unavailable(),
        },
        Ok(None) => refused(&Refusal::not_found()),
        Err(_) => unavailable(),
    }
}

pub async fn create(
    request: HttpRequest,
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    origin: web::Data<PublicOrigin>,
    path: web::Path<String>,
    body: web::Json<Value>,
) -> HttpResponse {
    let realm_id = path.into_inner();
    let base = base_of(&request, &origin, &realm_id);
    let Some(name) = body["displayName"]
        .as_str()
        .map(str::trim)
        .filter(|it| !it.is_empty())
    else {
        return refused(&Refusal::invalid("displayName is required"));
    };

    let Ok(mut connection) = pool.get().await else {
        return unavailable();
    };
    let context = within(&admin, &realm_id);
    let Ok(transaction) = tenancy.transaction(&mut connection, &context).await else {
        return unavailable();
    };
    match roles::load_group_by_name(&transaction, name).await {
        Ok(Some(_)) => {
            return refused(&Refusal::uniqueness(format!("{name} is already a group")));
        }
        Ok(None) => {}
        Err(_) => return unavailable(),
    }

    let mut metadata = models::auditable::AuditableModel::from_creator(
        context.tenant.clone(),
        admin.context.principal.id().to_owned(),
    );
    metadata.created_at = Some(chrono::Utc::now());
    let group = GroupModel {
        group_id: name.to_owned(),
        realm_id: realm_id.clone(),
        name: name.to_owned(),
        display_name: name.to_owned(),
        description: String::new(),
        is_default: false,
        metadata,
    };
    if roles::create_group(&transaction, &group).await.is_err() {
        return unavailable();
    }
    for member in body["members"].as_array().unwrap_or(&Vec::new()) {
        let Some(user_id) = member["value"].as_str().filter(|it| !it.is_empty()) else {
            return refused(&Refusal::invalid("a member names its value"));
        };
        if roles::add_to_group(&transaction, user_id, &group.group_id)
            .await
            .is_err()
        {
            return unavailable();
        }
    }

    let body = match shown(&transaction, &base, &group).await {
        Ok(body) => body,
        Err(()) => return unavailable(),
    };
    if transaction.commit().await.is_err() {
        return unavailable();
    }
    answered(StatusCode::CREATED, body)
}

pub async fn patch(
    request: HttpRequest,
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    origin: web::Data<PublicOrigin>,
    path: web::Path<(String, String)>,
    body: web::Json<Value>,
) -> HttpResponse {
    let (realm_id, group_id) = path.into_inner();
    let base = base_of(&request, &origin, &realm_id);
    let folded = match scim::folded_group_patch(&body) {
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
    let mut group = match roles::load_group(&transaction, &group_id).await {
        Ok(Some(group)) => group,
        Ok(None) => return refused(&Refusal::not_found()),
        Err(_) => return unavailable(),
    };

    for change in folded {
        let landed = match change {
            GroupPatch::Rename(name) => {
                group.name = name.clone();
                group.display_name = name;
                roles::update_group(&transaction, &group).await.map(|_| ())
            }
            GroupPatch::AddMembers(people) => {
                let mut outcome = Ok(());
                for user_id in people {
                    if let Err(why) = roles::add_to_group(&transaction, &user_id, &group_id).await {
                        outcome = Err(why);
                        break;
                    }
                }
                outcome
            }
            GroupPatch::RemoveMembers(people) => {
                let mut outcome = Ok(());
                for user_id in people {
                    if let Err(why) =
                        roles::remove_from_group(&transaction, &user_id, &group_id).await
                    {
                        outcome = Err(why);
                        break;
                    }
                    // A remove of somebody not in the group is the state
                    // asked for, not an error.
                }
                outcome.map(|_| ())
            }
            GroupPatch::ReplaceMembers(people) => {
                let mut outcome = roles::group_membership(&transaction, &group_id)
                    .await
                    .map(|(standing, _)| standing);
                if let Ok(standing) = &outcome {
                    for user_id in standing {
                        if roles::remove_from_group(&transaction, user_id, &group_id)
                            .await
                            .is_err()
                        {
                            outcome = Err(store::error::StoreError::Backend);
                            break;
                        }
                    }
                }
                match outcome {
                    Ok(_) => {
                        let mut landed = Ok(());
                        for user_id in people {
                            if let Err(why) =
                                roles::add_to_group(&transaction, &user_id, &group_id).await
                            {
                                landed = Err(why);
                                break;
                            }
                        }
                        landed
                    }
                    Err(why) => Err(why),
                }
            }
        };
        if landed.is_err() {
            return unavailable();
        }
    }

    let shown = match roles::load_group(&transaction, &group_id).await {
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

pub async fn replace(
    request: HttpRequest,
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    origin: web::Data<PublicOrigin>,
    path: web::Path<(String, String)>,
    body: web::Json<Value>,
) -> HttpResponse {
    let (realm_id, group_id) = path.into_inner();
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
    let mut group = match roles::load_group(&transaction, &group_id).await {
        Ok(Some(group)) => group,
        Ok(None) => return refused(&Refusal::not_found()),
        Err(_) => return unavailable(),
    };
    if let Some(name) = body["displayName"].as_str().filter(|it| !it.is_empty()) {
        group.name = name.to_owned();
        group.display_name = name.to_owned();
        if roles::update_group(&transaction, &group).await.is_err() {
            return unavailable();
        }
    }
    if let Some(members) = body.get("members") {
        let wanted: Vec<String> = match members
            .as_array()
            .map(|entries| {
                entries
                    .iter()
                    .map(|entry| {
                        entry["value"]
                            .as_str()
                            .filter(|it| !it.is_empty())
                            .map(str::to_owned)
                    })
                    .collect::<Option<Vec<_>>>()
            })
            .unwrap_or(None)
        {
            Some(wanted) => wanted,
            None => return refused(&Refusal::invalid("members is an array of values")),
        };
        let Ok((standing, _)) = roles::group_membership(&transaction, &group_id).await else {
            return unavailable();
        };
        for user_id in &standing {
            if roles::remove_from_group(&transaction, user_id, &group_id)
                .await
                .is_err()
            {
                return unavailable();
            }
        }
        for user_id in &wanted {
            if roles::add_to_group(&transaction, user_id, &group_id)
                .await
                .is_err()
            {
                return unavailable();
            }
        }
    }

    let shown = match roles::load_group(&transaction, &group_id).await {
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
    let (realm_id, group_id) = path.into_inner();
    let Ok(mut connection) = pool.get().await else {
        return unavailable();
    };
    let Ok(transaction) = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
    else {
        return unavailable();
    };
    match roles::delete_group(&transaction, &group_id).await {
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
