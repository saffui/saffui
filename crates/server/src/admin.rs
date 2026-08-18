//! Establishing who is asking, and deciding before the handler runs.
//!
//! This is a middleware and not an extractor on purpose. An extractor is
//! something a handler can be written without, and a handler written without it
//! is an unguarded route that looks exactly like a guarded one. Wrapping the
//! scope means every route under it is guarded by construction, and the only
//! way to add an unguarded one is to put it somewhere else.

use std::future::{Ready, ready};
use std::rc::Rc;

use actix_web::body::EitherBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::{Error, HttpMessage, ResponseError};
use crypto::jose::jwk::Jwk;
use crypto::jose::jws::{ES256, ES384, ES512, EdDSA, PS256, PS384, PS512, RS256, RS384, RS512};
use crypto::jose::jwt;
use crypto::provider::SignAlg;
use data_encoding::BASE64URL_NOPAD;
use deadpool_postgres::Pool;
use models::entities::authz::AdminAction;
use store::providers::{realm_keys, roles};
use store::tenancy::{Tenancy, TenantContext, resolve};

use crate::error::{refused, unauthenticated};
use crate::guard::{AdminPolicy, Presented, decide};
use crate::routes;

/// What the guard established, for the handler that follows.
#[derive(Debug, Clone)]
pub struct Admin {
    pub presented: Presented,
    /// The realm the token was issued by, and the tenant it belongs to.
    pub context: TenantContext,
    /// What the route required, already checked.
    pub allowed: AdminAction,
}

/// The guard, and what it needs to do its work.
#[derive(Clone)]
pub struct Guard {
    pub pool: Pool,
    pub tenancy: Tenancy,
    pub policy: AdminPolicy,
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

/// Establish the caller, then decide.
///
/// Every failure before the decision answers the same way a missing token does.
/// A caller that could tell "your token did not verify" from "no such realm"
/// would have a probe for which realms exist.
async fn establish(
    guard: &Guard,
    request: &ServiceRequest,
) -> Result<Admin, commons::http::ApiError> {
    let bearer = bearer(request).ok_or_else(unauthenticated)?;

    // The issuer names the realm, and nothing is trusted until the signature
    // checks out: this only decides which keys to fetch.
    let issuer = unverified_issuer(&bearer).ok_or_else(unauthenticated)?;

    let mut connection = guard.pool.get().await.map_err(|_| unauthenticated())?;
    let context = resolve::realm_by_id(&connection, &issuer)
        .await
        .map_err(|_| unauthenticated())?;

    let transaction = guard
        .tenancy
        .transaction(&mut connection, &context)
        .await
        .map_err(|_| unauthenticated())?;

    let keys = realm_keys::published(&transaction, models::entities::keys::KeyUse::Sig)
        .await
        .map_err(|_| unauthenticated())?;
    let presented = verify(&bearer, &keys).ok_or_else(unauthenticated)?;

    let held: Vec<AdminAction> = roles::effective_roles(&transaction, &presented.subject)
        .await
        .map_err(|_| unauthenticated())?
        .into_iter()
        .filter_map(|role| role.admin_actions)
        .flatten()
        .collect();

    let required = request
        .match_pattern()
        .and_then(|pattern| routes::required(request.method(), &pattern));

    let allowed = decide(required, &presented, &held, &guard.policy).map_err(refused)?;

    Ok(Admin {
        presented,
        context,
        allowed,
    })
}

fn bearer(request: &ServiceRequest) -> Option<String> {
    let header = request.headers().get("authorization")?.to_str().ok()?;
    header
        .strip_prefix("Bearer ")
        .map(|token| token.trim().to_owned())
        .filter(|token| !token.is_empty())
}

/// The issuer, read without verifying anything.
///
/// Reading an unverified payload to find the key is unavoidable: something has
/// to say which realm's keys to fetch, and which realm that is, is written in
/// the token. Nothing else is taken from it, and nothing read here survives
/// into the decision: the payload is read again, from scratch, once the
/// signature has checked out.
///
/// The segment is decoded here rather than through the JOSE layer because that
/// layer has no way to read a payload without checking it. Decoding as an
/// unsecured token refuses anything whose header is not `alg: none`, which is
/// every real token; asking it for no verifier is an error rather than a
/// permission to skip the check. So this reads the one field it needs and
/// treats the rest as what it is, unproven text.
fn unverified_issuer(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let decoded = BASE64URL_NOPAD.decode(payload.as_bytes()).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    claims.get("iss")?.as_str().map(str::to_owned)
}

/// Verify against the one key the token names.
///
/// The header names a key and only that key is tried. Trying each published key
/// in turn would let a token be verified by whichever one happens to accept it,
/// which is how a retired key keeps signing long after it stopped being active.
///
/// The algorithm comes from the key and never from the token's header, which is
/// what stops a token choosing a weaker one than the key was published for.
fn verify(
    token: &str,
    published: &[models::entities::keys::RealmSigningKeyView],
) -> Option<Presented> {
    let header = jwt::decode_header(token).ok()?;
    let kid = header.claim("kid")?.as_str()?.to_owned();
    let key = published.iter().find(|key| key.kid == kid)?;

    let jwk = Jwk::from_map(key.public_jwk.as_object()?.clone()).ok()?;
    let verifier = verifier_for(key.algorithm, &jwk)?;
    let payload = jwt::decode_with_verifier(token, &*verifier).ok()?.0;

    Some(Presented {
        subject: payload.subject()?.to_owned(),
        audiences: payload
            .audience()
            .map(|audiences| audiences.iter().map(|a| (*a).to_owned()).collect())
            .unwrap_or_default(),
        scope: payload
            .claim("scope")
            .and_then(|scope| scope.as_str())
            .unwrap_or_default()
            .to_owned(),
    })
}

/// The verifier the published algorithm names.
///
/// Exhaustive over the catalogue rather than a lookup with a fallback: an
/// algorithm this build does not implement must fail to compile here, not fail
/// to verify at runtime and read as a bad token.
fn verifier_for(algorithm: SignAlg, jwk: &Jwk) -> Option<Box<dyn crypto::jose::jws::JwsVerifier>> {
    let verifier =
        match algorithm {
            SignAlg::Rs256 => Box::new(RS256.verifier_from_jwk(jwk).ok()?)
                as Box<dyn crypto::jose::jws::JwsVerifier>,
            SignAlg::Rs384 => Box::new(RS384.verifier_from_jwk(jwk).ok()?)
                as Box<dyn crypto::jose::jws::JwsVerifier>,
            SignAlg::Rs512 => Box::new(RS512.verifier_from_jwk(jwk).ok()?)
                as Box<dyn crypto::jose::jws::JwsVerifier>,
            SignAlg::Ps256 => Box::new(PS256.verifier_from_jwk(jwk).ok()?)
                as Box<dyn crypto::jose::jws::JwsVerifier>,
            SignAlg::Ps384 => Box::new(PS384.verifier_from_jwk(jwk).ok()?)
                as Box<dyn crypto::jose::jws::JwsVerifier>,
            SignAlg::Ps512 => Box::new(PS512.verifier_from_jwk(jwk).ok()?)
                as Box<dyn crypto::jose::jws::JwsVerifier>,
            SignAlg::Es256 => Box::new(ES256.verifier_from_jwk(jwk).ok()?)
                as Box<dyn crypto::jose::jws::JwsVerifier>,
            SignAlg::Es384 => Box::new(ES384.verifier_from_jwk(jwk).ok()?)
                as Box<dyn crypto::jose::jws::JwsVerifier>,
            SignAlg::Es512 => Box::new(ES512.verifier_from_jwk(jwk).ok()?)
                as Box<dyn crypto::jose::jws::JwsVerifier>,
            SignAlg::EdDsa => Box::new(EdDSA.verifier_from_jwk(jwk).ok()?)
                as Box<dyn crypto::jose::jws::JwsVerifier>,
        };
    Some(verifier)
}
