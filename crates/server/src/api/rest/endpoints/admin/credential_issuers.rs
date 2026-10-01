use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use config::serving::Egress;
use models::entities::credential_issuers::{CredentialIssuer, IssuerTrust};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use services::admin::credential_issuers::{ReadKeys, Unnamable};
use services::verifier::issuers::{self, KeySource, Published, Unreadable};
use store::tenancy::{Tenancy, TenantContext};

use crate::error::refuse_unopened_work;
use crate::middleware::admin_guard::Admin;
use outbound::Sealing;

/// One named issuer, as a caller may see it. Its keys are public, and handed
/// back whole so they can be checked against the ones meant.
#[derive(Debug, Serialize)]
pub struct IssuerBrief {
    pub id: String,
    pub name: String,
    pub issuer: String,
    /// `metadata` or `certificate`: how the realm trusts the issuer.
    pub trusted_by: &'static str,
    /// What its metadata published, read when and where; none by certificate.
    pub keys: Vec<Value>,
    pub read_from: Option<String>,
    pub read_at: Option<chrono::DateTime<chrono::Utc>>,
    /// The trust anchors it is trusted through, and the types it issues, when
    /// trusted by certificate.
    pub anchors: Vec<String>,
    pub credential_types: Vec<String>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl From<CredentialIssuer> for IssuerBrief {
    fn from(named: CredentialIssuer) -> Self {
        let (trusted_by, keys, read_from, read_at, anchors, credential_types) = match named.trust {
            IssuerTrust::Metadata {
                keys,
                read_from,
                read_at,
            } => (
                "metadata",
                keys,
                Some(read_from),
                Some(read_at),
                Vec::new(),
                Vec::new(),
            ),
            IssuerTrust::Certificate {
                anchors,
                credential_types,
            } => (
                "certificate",
                Vec::new(),
                None,
                None,
                anchors,
                credential_types,
            ),
        };
        Self {
            id: named.issuer_id,
            name: named.name,
            issuer: named.issuer,
            trusted_by,
            keys,
            read_from,
            read_at,
            anchors,
            credential_types,
            created_by: named.created_by,
            created_at: named.created_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct IssuerWrite {
    pub name: String,
    /// An https address or a `did:web`, as the issuer's credentials name it.
    pub issuer: String,
}

/// The issuers the realm names, and whether the verifier that reads them runs:
/// experimental, they do nothing until the process runs it.
pub async fn list(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let transaction = tenancy
        .begin(&TenantContext::new(&admin.context.tenant.tenant, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    let named = services::admin::credential_issuers::list(&transaction)
        .await
        .map_err(refused)?;
    let running = crate::api::feature::runs_for_realm(
        &transaction,
        commons::feature::Feature::WalletVerifier,
    )
    .await;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "running": running,
        "items": named.into_iter().map(IssuerBrief::from).collect::<Vec<_>>(),
    })))
}

/// Name an issuer, reading its keys first: before any transaction opens, so
/// no database session waits on somebody else's server.
pub async fn name(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    egress: web::Data<Egress>,
    path: web::Path<String>,
    asked: web::Json<IssuerWrite>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let asked = asked.into_inner();
    let read = read_issuer_keys(&asked.issuer, **egress).await?;
    let transaction = tenancy
        .begin(&TenantContext::new(&admin.context.tenant.tenant, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    let named = services::admin::credential_issuers::name(
        &transaction,
        sealing.provider.as_ref(),
        &asked.name,
        &asked.issuer,
        read,
        admin.context.principal.id(),
        chrono::Utc::now(),
    )
    .await
    .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Created().json(IssuerBrief::from(named)))
}

/// Read an issuer's keys again, where they were first read from.
pub async fn read_again(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    egress: web::Data<Egress>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, issuer_id) = path.into_inner();
    let within = TenantContext::new(&admin.context.tenant.tenant, &realm_id);
    let issuer = {
        let transaction = tenancy.begin(&within).await.map_err(refuse_unopened_work)?;
        services::admin::credential_issuers::named(&transaction, &issuer_id)
            .await
            .map_err(refused)?
            .issuer
    };
    let read = read_issuer_keys(&issuer, **egress).await?;
    let transaction = tenancy.begin(&within).await.map_err(refuse_unopened_work)?;
    let named = services::admin::credential_issuers::read_again(
        &transaction,
        &issuer_id,
        read,
        chrono::Utc::now(),
    )
    .await
    .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(IssuerBrief::from(named)))
}

pub async fn forget(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, issuer_id) = path.into_inner();
    let transaction = tenancy
        .begin(&TenantContext::new(&admin.context.tenant.tenant, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    services::admin::credential_issuers::forget(&transaction, &issuer_id)
        .await
        .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

/// An issuer's keys, read where its kind publishes them, under the egress
/// policy. An https issuer's metadata may point at a key set elsewhere, which
/// is read the same way.
async fn read_issuer_keys(issuer: &str, egress: Egress) -> Result<ReadKeys, ApiError> {
    match issuers::locate_issuer_keys(issuer).map_err(unread)? {
        KeySource::DidDocument(address) => {
            let document = fetched(&address, egress).await?;
            Ok(ReadKeys {
                keys: issuers::read_did_document(issuer, &document).map_err(unread)?,
                read_from: address,
            })
        }
        KeySource::Metadata(address) => {
            let document = fetched(&address, egress).await?;
            match issuers::read_issuer_metadata(issuer, &document).map_err(unread)? {
                Published::Keys(keys) => Ok(ReadKeys {
                    keys,
                    read_from: address,
                }),
                Published::At(set) => {
                    let document = fetched(&set, egress).await?;
                    Ok(ReadKeys {
                        keys: issuers::read_key_set(&document).map_err(unread)?,
                        read_from: set,
                    })
                }
            }
        }
    }
}

async fn fetched(address: &str, egress: Egress) -> Result<String, ApiError> {
    outbound::egress::fetch(address.to_owned(), egress)
        .await
        .ok_or_else(|| {
            ApiError::with_detail(
                ErrorCode::ValidationError,
                format!("nothing could be read at {address}"),
            )
        })
}

fn unread(why: Unreadable) -> ApiError {
    ApiError::with_detail(ErrorCode::ValidationError, why.to_string())
}

fn refused(why: Unnamable) -> ApiError {
    match why {
        Unnamable::NotFound => ApiError::new(ErrorCode::CredentialIssuerNotFound),
        Unnamable::AlreadyNamed => ApiError::new(ErrorCode::CredentialIssuerAlreadyNamed),
        Unnamable::Unwritable => internal(),
        spoken => ApiError::with_detail(ErrorCode::ValidationError, spoken.to_string()),
    }
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}
