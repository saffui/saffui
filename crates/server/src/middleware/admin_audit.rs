use std::future::{Future, Ready, ready};
use std::pin::Pin;
use std::rc::Rc;

use actix_web::Error;
use actix_web::HttpMessage;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use chrono::Utc;
use crypto::provider::CryptoProvider;
use deadpool_postgres::Pool;
use std::sync::Arc;
use store::tenancy::{Tenancy, TenantContext};

use crate::middleware::admin_guard::Admin;

/// Writes every authenticated admin write into the realm's audit chain.
///
/// Wrapped outside the guard, so it sees the answer as it leaves and the
/// identity the guard established. Reads only what the request line says:
/// no body ever lands in the journal, because bodies carry secrets and an
/// audit that stores them becomes the leak it was meant to catch.
///
/// Best effort by design: a journal entry that cannot be written warns and
/// the response still goes out. The chain's own verification says whether
/// the record is whole; refusing admin work because the journal hiccupped
/// would turn the audit into a denial lever.
#[derive(Clone)]
pub struct Journal {
    pub pool: Pool,
    pub tenancy: Tenancy,
    /// For the genesis digest, when a realm's chain starts on first write.
    pub provider: Arc<dyn CryptoProvider>,
}

impl<S, B> Transform<S, ServiceRequest> for Journal
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = JournalScribe<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(JournalScribe {
            service: Rc::new(service),
            pool: self.pool.clone(),
            tenancy: self.tenancy.clone(),
            provider: Arc::clone(&self.provider),
        }))
    }
}

pub struct JournalScribe<S> {
    service: Rc<S>,
    pool: Pool,
    tenancy: Tenancy,
    provider: Arc<dyn CryptoProvider>,
}

impl<S, B> Service<ServiceRequest> for JournalScribe<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    actix_web::dev::forward_ready!(service);

    fn call(&self, request: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);
        let pool = self.pool.clone();
        let tenancy = self.tenancy.clone();
        let provider = Arc::clone(&self.provider);
        Box::pin(async move {
            let mutates = matches!(
                request.method().as_str(),
                "POST" | "PUT" | "PATCH" | "DELETE"
            );
            let answered = service.call(request).await?;
            // Writes are journalled unconditionally: that is the design. A
            // read lands in the chain only where the realm switched its
            // admin_events_enabled on, the forensic mode.
            if !mutates && !reads_are_journalled(&pool, &tenancy, answered.request()).await {
                return Ok(answered);
            }
            // The identity the guard established. Absent means the request
            // never got past authentication, and an anonymous knock is not an
            // admin write. The borrow ends before the response moves on.
            let entry: Option<(TenantContext, serde_json::Value)> = {
                let request = answered.request();
                let held = request.extensions();
                held.get::<Admin>().and_then(|admin| {
                    let path = request.path().to_owned();
                    // The realm the chain belongs to is the one in the path; a
                    // route outside a realm has no chain to write.
                    let realm = realm_of(&path)?;
                    let context = TenantContext::new(&admin.context.tenant.tenant, &realm);
                    let envelope = serde_json::json!({
                        "kind": if mutates { "admin.write" } else { "admin.read" },
                        "occurred_at": Utc::now().timestamp() as f64,
                        "actor": admin.context.principal.id(),
                        "party": admin.context.presenter,
                        "method": request.method().as_str(),
                        "pattern": request.match_pattern(),
                        "path": path,
                        "status": answered.status().as_u16(),
                    });
                    Some((context, envelope))
                })
            };
            if let Some((context, envelope)) = entry {
                record_or_warn(&pool, &tenancy, provider.as_ref(), &context, &envelope).await;
            }
            Ok(answered)
        })
    }
}

/// Whether this realm journals its reads too. One indexed load per admin
/// GET when consulted; false on any failure, because a read that cannot be
/// checked is treated the way every realm treats reads by default.
async fn reads_are_journalled(
    pool: &Pool,
    tenancy: &Tenancy,
    request: &actix_web::HttpRequest,
) -> bool {
    let Some(admin) = request
        .extensions()
        .get::<Admin>()
        .map(|held| held.context.tenant.tenant.clone())
    else {
        return false;
    };
    let Some(realm) = realm_of(request.path()) else {
        return false;
    };
    let Ok(mut connection) = pool.get().await else {
        return false;
    };
    let context = TenantContext::new(&admin, &realm);
    let Ok(transaction) = tenancy.transaction(&mut connection, &context).await else {
        return false;
    };
    matches!(
        store::providers::realms::load(&transaction, &realm).await,
        Ok(Some(held)) if held.admin_events_enabled == Some(true)
    )
}

/// The realm segment of an admin path: `/admin/realms/{realm}/...`, already
/// percent-decoded by the router.
fn realm_of(path: &str) -> Option<String> {
    let rest = path.strip_prefix("/admin/realms/")?;
    let realm = rest.split('/').next().filter(|held| !held.is_empty())?;
    Some(realm.to_owned())
}

/// Append, starting the realm's chain on the way when nothing has yet.
///
/// Two passes on two transactions, never one: a failed append poisons its
/// transaction, and the start that follows would only ever see the abort.
/// The start is idempotent, so two first writers race harmlessly.
async fn record_or_warn(
    pool: &Pool,
    tenancy: &Tenancy,
    provider: &dyn CryptoProvider,
    context: &TenantContext,
    envelope: &serde_json::Value,
) {
    let written = async {
        {
            let mut connection = pool.get().await.ok()?;
            let transaction = tenancy.transaction(&mut connection, context).await.ok()?;
            if store::audit::append(&transaction, envelope).await.is_ok() {
                return transaction.commit().await.ok();
            }
        }
        let mut connection = pool.get().await.ok()?;
        let transaction = tenancy.transaction(&mut connection, context).await.ok()?;
        store::audit::start(
            &transaction,
            provider.digest(),
            &context.tenant,
            &context.realm_id,
        )
        .await
        .ok()?;
        store::audit::append(&transaction, envelope).await.ok()?;
        transaction.commit().await.ok()
    }
    .await;
    if written.is_none() {
        tracing::warn!(
            realm = %context.realm_id,
            "an admin write could not be journalled"
        );
    }
}
