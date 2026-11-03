use actix_web::{HttpResponse, get, post, web};
use api::NewUser;
use saffui_core::app::App as Product;
use saffui_core::authz::capability::Capability;
use saffui_core::directory::create::{NewPerson, create_person};
use saffui_core::directory::list::list_persons;
use saffui_core::error::Failure;
use saffui_core::secret::Secret;

use super::listing::{ListParameters, answer_page};
use super::views::show_user;
use crate::error::render_failure;
use crate::extract::admin::Caller;
use crate::middleware::admin_guard::RequireCapability;

#[get(
    "/admin/v1/realms/{realm}/users",
    wrap = "RequireCapability(Capability::UserRead)"
)]
pub async fn list_users(
    caller: Caller,
    product: web::Data<Product>,
    parameters: web::Query<ListParameters>,
) -> HttpResponse {
    let listed = async {
        let (window, cut) = parameters.bound()?;
        let (persons, total) =
            list_persons(&product, caller.scope, window, parameters.is_counted()).await?;
        Ok::<_, Failure>((window, cut, persons, total))
    }
    .await;
    match listed {
        Ok((window, cut, persons, total)) => {
            answer_page(window, cut, persons.iter().map(show_user).collect(), total)
        }
        Err(failure) => render_failure(&failure),
    }
}

#[post(
    "/admin/v1/realms/{realm}/users",
    wrap = "RequireCapability(Capability::UserWrite)"
)]
pub async fn create_user(
    caller: Caller,
    product: web::Data<Product>,
    wanted: web::Json<NewUser>,
) -> HttpResponse {
    let wanted = wanted.into_inner();
    let person = NewPerson {
        username: &wanted.username,
        email: wanted.email.as_deref(),
        display_name: wanted.display_name.as_deref(),
        password: wanted
            .password
            .map(|password| Secret::new(password.into_bytes())),
        created_by: Some(&caller.client.client_id),
    };
    match create_person(&product, caller.scope, person).await {
        Ok(person) => HttpResponse::Created().json(show_user(&person)),
        Err(failure) => render_failure(&failure),
    }
}
