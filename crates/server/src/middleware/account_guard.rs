use std::future::{Ready, ready};
use std::rc::Rc;
use store::error::StoreError;
use store::tenancy::{RealmNamed, Tenancy};

use actix_web::body::{BoxBody, EitherBody};
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::StatusCode;
use actix_web::{Error, HttpMessage, HttpResponse, HttpResponseBuilder, ResponseError};
use chrono::Utc;
use commons::error::ErrorCode;
use commons::http::ApiError;
use config::serving::PublicOrigin;
use services::account_api::{
    ACCOUNT_SCOPE, AccountCaller, NotAdmitted, StepUp, establish_account_caller,
};
use services::token::{Binding, Proofs};

use crate::api::rest::endpoints::protocol::dto::uncached;
use crate::middleware::bearer::{bearer, unverified_issuer};

/// Why the account API turned a request away.
#[derive(Debug)]
pub enum AccountRefusal {
    /// No token, or one that does not reach the account API.
    InvalidToken,
    /// A token the account console obtained without the account scope.
    InsufficientScope,
    /// A login too old or too weak for the change asked for.
    StepUp(StepUp),
    /// A request the account refuses for a reason of its own, in the catalogue's words.
    Refused(ApiError),
    /// No connection to the database could be had, which trying again may mend.
    Unavailable,
    Failed,
}

impl AccountRefusal {
    pub fn for_unopened_work(why: StoreError) -> Self {
        match why {
            StoreError::Unavailable => Self::Unavailable,
            _ => Self::Failed,
        }
    }
}

impl std::fmt::Display for AccountRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidToken => formatter.write_str("the token does not reach the account API"),
            Self::InsufficientScope => {
                formatter.write_str("the token does not carry the account scope")
            }
            Self::StepUp(_) => formatter.write_str("the login has to be proven again first"),
            Self::Refused(error) => write!(formatter, "{error}"),
            Self::Unavailable => {
                formatter.write_str("the account API cannot answer for the moment")
            }
            Self::Failed => formatter.write_str("the account API could not answer"),
        }
    }
}

impl ResponseError for AccountRefusal {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidToken | Self::StepUp(_) => StatusCode::UNAUTHORIZED,
            Self::InsufficientScope => StatusCode::FORBIDDEN,
            Self::Refused(error) => error.status_code(),
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Failed => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// RFC 6750 §3 and RFC 9470 §3: a refused credential is answered with a
    /// challenge saying what to present instead, and nothing here is cached.
    fn error_response(&self) -> HttpResponse<BoxBody> {
        let (body, challenge) = match self {
            Self::InvalidToken => (
                ApiError::new(ErrorCode::Unauthorized).body(),
                Some(r#"Bearer error="invalid_token""#.to_owned()),
            ),
            Self::InsufficientScope => (
                ApiError::new(ErrorCode::AccessDenied).body(),
                Some(format!(
                    r#"Bearer error="insufficient_scope", scope="{ACCOUNT_SCOPE}""#
                )),
            ),
            Self::StepUp(step_up) => (
                ApiError::new(ErrorCode::AccountStepUpRequired).body(),
                Some(write_step_up_challenge(step_up)),
            ),
            Self::Refused(error) => (error.body(), None),
            Self::Unavailable => (ApiError::new(ErrorCode::ServiceUnavailable).body(), None),
            Self::Failed => (ApiError::new(ErrorCode::InternalError).body(), None),
        };
        let mut response = HttpResponseBuilder::new(self.status_code());
        if let Some(challenge) = challenge {
            response.insert_header(("WWW-Authenticate", challenge));
        }
        uncached(&mut response).json(body)
    }
}

/// The step-up challenge, its values quoted so that a level whose name holds a
/// quote cannot close one parameter and open another.
fn write_step_up_challenge(step_up: &StepUp) -> String {
    let quoted = |value: &str| value.replace('\\', "\\\\").replace('"', "\\\"");
    let mut challenge = String::from(
        r#"Bearer error="insufficient_user_authentication", error_description="sign in again, recently and as strongly as this account allows""#,
    );
    if let Some(acr_values) = &step_up.acr_values {
        challenge.push_str(&format!(r#", acr_values="{}""#, quoted(acr_values)));
    }
    challenge.push_str(&format!(r#", max_age="{}""#, step_up.max_age));
    challenge
}

/// The account API's guard, and what it needs to establish the caller.
#[derive(Clone)]
pub struct AccountGuard {
    pub tenancy: Tenancy,
    /// What this deployment answers from, which every issuer it accepts is
    /// built out of.
    pub origin: PublicOrigin,
}

impl<S, B> Transform<S, ServiceRequest> for AccountGuard
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = AccountGuardService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AccountGuardService {
            service: Rc::new(service),
            guard: self.clone(),
        }))
    }
}

pub struct AccountGuardService<S> {
    service: Rc<S>,
    guard: AccountGuard,
}

impl<S, B> Service<ServiceRequest> for AccountGuardService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = std::pin::Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    actix_web::dev::forward_ready!(service);

    fn call(&self, request: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);
        let guard = self.guard.clone();

        Box::pin(async move {
            match establish(&guard, &request).await {
                Ok(caller) => {
                    request.extensions_mut().insert(caller);
                    service
                        .call(request)
                        .await
                        .map(ServiceResponse::map_into_left_body)
                }
                Err(refusal) => {
                    let (request, _) = request.into_parts();
                    Ok(ServiceResponse::new(request, refusal.error_response())
                        .map_into_right_body())
                }
            }
        })
    }
}

/// Establish who a request comes from, once, for every route beneath the guard.
///
/// Every failure before the token verifies answers the way a missing token does,
/// so this door cannot be asked which realms exist.
async fn establish(
    guard: &AccountGuard,
    request: &ServiceRequest,
) -> Result<AccountCaller, AccountRefusal> {
    let now = Utc::now();
    let bearer = bearer(request).ok_or(AccountRefusal::InvalidToken)?;
    let issuer = unverified_issuer(&bearer).ok_or(AccountRefusal::InvalidToken)?;
    let named = guard
        .origin
        .realm_of(&issuer)
        .ok_or(AccountRefusal::InvalidToken)?;
    // The realm the path names has to be the one that minted the token, compared
    // as two strings before anything is looked up.
    if request.match_info().get("realm") != Some(named) {
        return Err(AccountRefusal::InvalidToken);
    }

    let context = match guard.tenancy.resolve(RealmNamed::ById(named)).await {
        Ok(context) => context,
        Err(StoreError::Unavailable) => return Err(AccountRefusal::Unavailable),
        Err(_) => return Err(AccountRefusal::InvalidToken),
    };
    let transaction = guard
        .tenancy
        .begin(&context)
        .await
        .map_err(AccountRefusal::for_unopened_work)?;
    let keys = services::realm::published_keys(&transaction)
        .await
        .map_err(|_| AccountRefusal::Failed)?;
    // A token bound to a key or a certificate is refused, as on the admin plane:
    // the console proves neither.
    let verified = services::token::verify_presented(
        &transaction,
        &keys,
        &bearer,
        Binding::Presented(Proofs::none()),
        now,
    )
    .await
    .map_err(|_| AccountRefusal::InvalidToken)?;

    establish_account_caller(&transaction, context, &verified, now)
        .await
        .map_err(|why| {
            tracing::warn!(reason = %why, "an account API request was refused");
            match why {
                NotAdmitted::MissingScope => AccountRefusal::InsufficientScope,
                NotAdmitted::Backend => AccountRefusal::Failed,
                NotAdmitted::NotForAccountConsole
                | NotAdmitted::LoggedOut
                | NotAdmitted::Withdrawn => AccountRefusal::InvalidToken,
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_missing_connection_is_worth_retrying() {
        assert_eq!(
            AccountRefusal::for_unopened_work(StoreError::Unavailable).status_code(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            AccountRefusal::for_unopened_work(StoreError::Backend).status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
