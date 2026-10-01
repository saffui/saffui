use actix_web::{HttpResponse, web};
use chrono::{DateTime, Utc};
use commons::error::ErrorCode;
use commons::http::ApiError;
use models::entities::verifier::{
    VerifierCertificate, VerifierIdentity, VerifierKeyState, VerifierKeyView, VerifierSubject,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use services::admin::verifier::{Unsettable, Verifier, WantedSettings};
use store::keyring;
use store::tenancy::{Tenancy, TenantContext};

use crate::error::refuse_unopened_work;
use crate::middleware::admin_guard::Admin;
use outbound::Sealing;

/// How the realm presents itself to the wallets it asks, and the keys it
/// holds to present itself by a certificate.
#[derive(Debug, Serialize)]
pub struct VerifierBrief {
    pub identity: VerifierIdentity,
    pub registrar_dataset: Option<Value>,
    pub registration_certificate: Option<String>,
    pub updated_by: Option<String>,
    pub updated_at: Option<DateTime<Utc>>,
    pub keys: Vec<VerifierKeyBrief>,
    /// Whether the verifier these say how to present runs for the realm.
    pub running: bool,
}

/// A key the realm signs its requests with under a certificate, never its
/// private half.
#[derive(Debug, Serialize)]
pub struct VerifierKeyBrief {
    pub kid: String,
    pub state: VerifierKeyState,
    pub subject: VerifierSubject,
    /// The PKCS#10 request an authority certifies the key from, PEM.
    pub request: String,
    pub public_jwk: Value,
    pub certificate: Option<CertificateBrief>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
}

/// The certificate an authority issued for a key.
#[derive(Debug, Serialize)]
pub struct CertificateBrief {
    /// What the realm's requests are asked under while it serves.
    pub client_id: String,
    /// The subject of each certificate of the chain, leaf first.
    pub subjects: Vec<String>,
    /// The chain, DER, base64, leaf first, the anchor left out.
    pub chain: Vec<String>,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub certified_at: DateTime<Utc>,
}

impl From<VerifierKeyView> for VerifierKeyBrief {
    fn from(key: VerifierKeyView) -> Self {
        Self {
            kid: key.kid,
            state: key.state,
            subject: key.subject,
            request: key.request_pem,
            public_jwk: key.public_jwk,
            certificate: key.certificate.map(CertificateBrief::from),
            created_by: key.created_by,
            created_at: key.created_at,
        }
    }
}

impl From<VerifierCertificate> for CertificateBrief {
    fn from(certificate: VerifierCertificate) -> Self {
        Self {
            client_id: services::verifier::presentation::certified_client_id(
                &certificate.leaf_hash,
            ),
            subjects: certificate
                .chain
                .iter()
                .map(|der| crypto::x509::subject_dn(der).unwrap_or_default())
                .collect(),
            chain: certificate
                .chain
                .iter()
                .map(|der| data_encoding::BASE64.encode(der))
                .collect(),
            not_before: certificate.not_before,
            not_after: certificate.not_after,
            certified_at: certificate.certified_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct VerifierWrite {
    pub identity: VerifierIdentity,
    #[serde(default)]
    pub registrar_dataset: Option<Value>,
    /// A JWT in compact serialization.
    #[serde(default)]
    pub registration_certificate: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ChainWrite {
    /// The certificate and the authorities that issued it, PEM encoded.
    pub chain: String,
}

pub async fn read(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let transaction = tenancy
        .begin(&TenantContext::new(
            &admin.context.tenant.tenant,
            path.as_str(),
        ))
        .await
        .map_err(refuse_unopened_work)?;
    let held = services::admin::verifier::read(&transaction)
        .await
        .map_err(refused)?;
    Ok(HttpResponse::Ok().json(describe_verifier(&transaction, held).await))
}

/// Say how the realm presents itself: by its did:web, or by its certificate
/// while it holds one valid now, with what its registrar holds of it.
pub async fn write_settings(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
    asked: web::Json<VerifierWrite>,
) -> Result<HttpResponse, ApiError> {
    let asked = asked.into_inner();
    let transaction = tenancy
        .begin(&TenantContext::new(
            &admin.context.tenant.tenant,
            path.as_str(),
        ))
        .await
        .map_err(refuse_unopened_work)?;
    services::admin::verifier::write_settings(
        &transaction,
        WantedSettings {
            identity: asked.identity,
            registrar_dataset: asked.registrar_dataset,
            registration_certificate: asked.registration_certificate,
        },
        admin.context.principal.id(),
        Utc::now(),
    )
    .await
    .map_err(refused)?;
    let held = services::admin::verifier::read(&transaction)
        .await
        .map_err(refused)?;
    let described = describe_verifier(&transaction, held).await;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(described))
}

/// Draw a key and the request an authority certifies it from.
pub async fn request_certificate(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    path: web::Path<String>,
    asked: web::Json<VerifierSubject>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.as_str();
    let tenant = admin.context.tenant.tenant.clone();
    let transaction = tenancy
        .begin(&TenantContext::new(&tenant, realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    keyring::provision(&transaction, &sealing.envelope, &tenant, realm_id)
        .await
        .map_err(|_| internal())?;
    let ring = keyring::load(&transaction, &sealing.envelope, &tenant, realm_id)
        .await
        .map_err(|_| internal())?;
    let drawn = services::admin::verifier::request_certificate(
        &transaction,
        &keyring::Signing {
            provider: sealing.provider.as_ref(),
            ring: &ring,
            envelope: &sealing.envelope,
        },
        asked.into_inner(),
        admin.context.principal.id(),
        Utc::now(),
    )
    .await
    .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Created().json(VerifierKeyBrief::from(drawn)))
}

/// Take the chain an authority issued for the key awaiting its certificate.
pub async fn take_certificate(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    path: web::Path<String>,
    asked: web::Json<ChainWrite>,
) -> Result<HttpResponse, ApiError> {
    let transaction = tenancy
        .begin(&TenantContext::new(
            &admin.context.tenant.tenant,
            path.as_str(),
        ))
        .await
        .map_err(refuse_unopened_work)?;
    let certified = services::admin::verifier::take_certificate(
        &transaction,
        sealing.provider.as_ref(),
        &asked.chain,
        Utc::now(),
    )
    .await
    .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(VerifierKeyBrief::from(certified)))
}

pub async fn withdraw_key(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, kid) = path.into_inner();
    let transaction = tenancy
        .begin(&TenantContext::new(&admin.context.tenant.tenant, &realm_id))
        .await
        .map_err(refuse_unopened_work)?;
    services::admin::verifier::withdraw_key(&transaction, &kid)
        .await
        .map_err(refused)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

async fn describe_verifier(
    transaction: &store::tenancy::UnitOfWork,
    held: Verifier,
) -> VerifierBrief {
    let running =
        crate::api::feature::runs_for_realm(transaction, commons::feature::Feature::WalletVerifier)
            .await;
    let settings = held.settings;
    VerifierBrief {
        identity: settings
            .as_ref()
            .map_or(VerifierIdentity::DidWeb, |kept| kept.identity),
        registrar_dataset: settings
            .as_ref()
            .and_then(|kept| kept.registrar_dataset.clone()),
        registration_certificate: settings
            .as_ref()
            .and_then(|kept| kept.registration_certificate.clone()),
        updated_by: settings.as_ref().map(|kept| kept.updated_by.clone()),
        updated_at: settings.as_ref().map(|kept| kept.updated_at),
        keys: held.keys.into_iter().map(VerifierKeyBrief::from).collect(),
        running,
    }
}

/// A refusal in the words of what was wrong, since the operator is the one
/// who can fix it.
fn refused(why: Unsettable) -> ApiError {
    match why {
        Unsettable::NotFound => ApiError::new(ErrorCode::VerifierKeyNotFound),
        Unsettable::Unwritable => internal(),
        spoken => ApiError::with_detail(ErrorCode::ValidationError, spoken.to_string()),
    }
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}
