use std::future::{Ready, ready};
use std::rc::Rc;

use actix_web::body::EitherBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::{Error, HttpMessage, ResponseError};
use chrono::Utc;
use config::serving::PublicOrigin;
use deadpool_postgres::Pool;
use deadpool_postgres::Transaction;
use models::entities::authz::AdminAction;
use services::context::{self, Acting, Context};
use store::tenancy::{Tenancy, resolve};

use crate::api::routes;
use crate::error::{refused, unauthenticated};
use crate::middleware::admin_policy::{AdminPolicy, Refusal, decide};
use crate::middleware::bearer::{bearer, unverified_issuer};

/// What the guard established, for the handler that follows.
///
/// One value and not two lists of overlapping fields. What the token said and
/// what the realm says about it are different questions, so they are different
/// values, and neither is rebuilt from the other further down.
#[derive(Debug, Clone)]
pub struct Admin {
    /// Who is asking, resolved against the realm: the subject, whether the
    /// realm still stands behind it, and which organization it acts within.
    pub context: Context,
    /// What the route required, already checked.
    pub allowed: AdminAction,
}

/// The guard, and what it needs to do its work.
#[derive(Clone)]
pub struct Guard {
    pub pool: Pool,
    pub tenancy: Tenancy,
    pub policy: AdminPolicy,
    /// What this deployment answers from. A token states an issuer built out of
    /// it, and one built out of anything else is not this deployment's.
    pub origin: PublicOrigin,
}

impl<S, B> Transform<S, ServiceRequest> for Guard
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = GuardService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(GuardService {
            service: Rc::new(service),
            guard: self.clone(),
        }))
    }
}

pub struct GuardService<S> {
    service: Rc<S>,
    guard: Guard,
}

impl<S, B> Service<ServiceRequest> for GuardService<S>
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
                Ok(admin) => {
                    request.extensions_mut().insert(admin);
                    service
                        .call(request)
                        .await
                        .map(ServiceResponse::map_into_left_body)
                }
                Err(error) => {
                    let (request, _) = request.into_parts();
                    Ok(ServiceResponse::new(request, error.error_response()).map_into_right_body())
                }
            }
        })
    }
}

/// The realm the path names, read off the pattern that matched it.
///
/// The resolved parameters are not there to read: a middleware wrapping the
/// scope runs before the resource fills them in, and `match_info` answers
/// nothing. The pattern is available though, and it says which segment is
/// the realm, so the two are walked together and the segment is taken by
/// position rather than by counting slashes and hoping.
///
/// The path is compared as it arrived, undecoded. A caller that percent-
/// encodes its own realm is refused rather than served, which is the safe
/// direction: the decoded form can only ever be the one the handler would
/// have used, so nothing that differs here becomes equal down there.
fn named_realm<'a>(pattern: Option<&str>, path: &'a str) -> Option<&'a str> {
    pattern?
        .split('/')
        .zip(path.split('/'))
        .find(|(held, _)| *held == "{realm}")
        .map(|(_, named)| named)
}

/// Establish the caller, then decide.
///
/// Every failure before the decision answers the same way a missing token does.
/// A caller that could tell "your token did not verify" from "no such realm"
/// would have a probe for which realms exist.
async fn establish(
    guard: &Guard,
    request: &ServiceRequest,
) -> Result<Admin, commons::http::ApiError> {
    // Read once, so everything this request decides shares an instant.
    let now = Utc::now();
    let bearer = bearer(request).ok_or_else(unauthenticated)?;

    // The issuer names the realm, and nothing is trusted until the signature
    // checks out: this only decides which keys to fetch. What it does settle is
    // that the issuer is one this deployment mints, so a token naming somebody
    // else's cannot reach a realm here by having a familiar tail.
    let issuer = unverified_issuer(&bearer).ok_or_else(unauthenticated)?;
    let named = guard.origin.realm_of(&issuer).ok_or_else(unauthenticated)?;

    let mut connection = guard.pool.get().await.map_err(|_| unauthenticated())?;
    let context = resolve::realm_by_id(&connection, named)
        .await
        .map_err(|_| unauthenticated())?;

    let transaction = guard
        .tenancy
        .transaction(&mut connection, &context)
        .await
        .map_err(|_| unauthenticated())?;

    let keys = services::realm::published_keys(&transaction)
        .await
        .map_err(|_| unauthenticated())?;

    // One gate, and it is not this crate's. Signature, the window the token
    // states, and whether it was withdrawn: a second caller is about to ask the
    // same question, and a check left beside the verifier is one that caller
    // inherits by omission. The instant is stated rather than read in there, so
    // this decision and a replay of it read the same clock.
    let verified = services::token::verify_presented(
        &transaction,
        &keys,
        &bearer,
        services::token::Binding::Presented(services::token::Proofs::none()),
        now,
    )
    .await
    .map_err(|_| unauthenticated())?;

    // What the realm says about the token, which the token cannot say about
    // itself: whether the subject is still one this realm holds, whether it has
    // been switched off, and whether it belongs where it claims to be acting.
    let established = context::establish(&transaction, context, &verified, now)
        .await
        .map_err(|_| unauthenticated())?;

    // The path names a realm on every route but the handful that speak for
    // the deployment. It has to be the one that minted the token: an
    // administrator is a user of the realm it administers, and nothing here
    // grants across that line.
    //
    // Two strings, and the path's is never looked up. A realm that exists
    // and one that does not are refused identically, so this door cannot be
    // asked which realms the deployment holds.
    if let Some(named) = named_realm(request.match_pattern().as_deref(), request.path())
        && named != established.tenant.realm_id
    {
        return Err(refused(Refusal::WrongRealm));
    }

    let held = capabilities(&transaction, &established).await?;

    let required = request
        .match_pattern()
        .and_then(|pattern| routes::required(request.method(), &pattern));

    let allowed = decide(required, &verified, &held, &guard.policy).map_err(refused)?;

    // A capability the realm has closed refuses every route that belongs to
    // it, here rather than in each handler. Twelve SCIM doors are twelve
    // chances to forget one, and a capability that is off on eleven of them
    // is not off.
    if !action_still_runs(&transaction, allowed).await {
        return Err(refused(Refusal::ClosedHere));
    }

    Ok(Admin {
        context: established,
        allowed,
    })
}

/// Whether the realm still runs whatever the action belongs to.
///
/// Actions with no capability behind them are always open, which is every one
/// of them but the few a realm may close.
async fn action_still_runs(transaction: &Transaction<'_>, action: AdminAction) -> bool {
    let behind = match action {
        AdminAction::ScimRead | AdminAction::ScimWrite => commons::feature::Feature::Scim,
        _ => return true,
    };
    crate::api::feature::runs_for_realm(transaction, behind).await
}

/// What this caller may do, where it is acting.
///
/// A caller acting across the realm holds what the realm granted it. One acting
/// within an organization holds that, and what the organization granted it
/// there as well. The two are read separately and only ever added together
/// under an organization the caller was confirmed to belong to: folded into the
/// realm wide set, a grant made inside one organization would answer for every
/// other one and for the realm itself.
async fn capabilities(
    transaction: &Transaction<'_>,
    established: &Context,
) -> Result<Vec<AdminAction>, commons::http::ApiError> {
    let within = match &established.acting {
        Acting::In { org_id } => Some(org_id.as_str()),
        _ => None,
    };
    services::authorization::admin_actions(transaction, established.principal.id(), within)
        .await
        .map_err(|_| unauthenticated())
}

#[cfg(test)]
mod tests {
    use super::named_realm;

    /// The segment is taken by position on the pattern, so a realm named
    /// like a later segment cannot be mistaken for it.
    #[test]
    fn the_pattern_says_which_segment_is_the_realm() {
        assert_eq!(
            named_realm(
                Some("/admin/realms/{realm}/users"),
                "/admin/realms/main/users"
            ),
            Some("main")
        );
        assert_eq!(
            named_realm(
                Some("/realms/{realm}/scim/v2/Users/{id}"),
                "/realms/other/scim/v2/Users/7"
            ),
            Some("other")
        );
        assert_eq!(
            named_realm(
                Some("/admin/realms/{realm}/groups/{group}"),
                "/admin/realms/users/groups/users"
            ),
            Some("users"),
            "a realm called like a later segment is still read at its own position"
        );
    }

    /// A route that names no realm speaks for the deployment, and this
    /// check has nothing to say about it.
    #[test]
    fn a_pattern_without_a_realm_names_none() {
        assert_eq!(named_realm(Some("/admin/realms"), "/admin/realms"), None);
        assert_eq!(
            named_realm(Some("/admin/features"), "/admin/features"),
            None
        );
        assert_eq!(named_realm(None, "/admin/realms/main/users"), None);
    }

    /// A path shorter than its pattern cannot happen through routing, and
    /// answers nothing rather than an index out of a shorter list.
    #[test]
    fn a_path_that_stops_early_names_no_realm() {
        assert_eq!(
            named_realm(Some("/admin/realms/{realm}/users"), "/admin"),
            None
        );
    }
}
