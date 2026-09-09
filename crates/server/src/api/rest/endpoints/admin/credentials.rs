use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use deadpool_postgres::Pool;
use models::entities::credentials::{CredentialModel, CredentialType, OtpParameters};
use store::tenancy::Tenancy;

use super::users::named_user;
use crate::api::rest::endpoints::within;
use crate::middleware::admin_guard::Admin;

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}

/// Everything this account can answer with, and nothing it answers.
///
/// The secrets never leave: what each row carries is the kind, the name the
/// person gave it, the parameters that describe it, and when it was made. A
/// superseded password is left out, since it is not a way in, only what the
/// reuse rule compares against.
pub async fn list(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, user_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let user_id = named_user(&transaction, &user_id).await?;

    let held = store::providers::credentials::load_for_user(&transaction, &user_id)
        .await
        .map_err(|_| internal())?;
    let unused = store::providers::credentials::count_recovery_codes(&transaction, &user_id)
        .await
        .unwrap_or(0);

    let shown: Vec<_> = held
        .iter()
        .filter(|row| row.credential_type != CredentialType::PasswordHistory)
        .map(|row| {
            serde_json::json!({
                // Named where a door takes it away. A password is replaced
                // through its own, and the superseded ones are not a way in,
                // so neither offers the action.
                "id": matches!(
                    row.credential_type,
                    CredentialType::Totp | CredentialType::Hotp | CredentialType::RecoveryCode
                )
                .then(|| row.credential_id.clone()),
                "kind": row.credential_type.to_string(),
                "label": row.user_label,
                "detail": describe(row, unused),
                "created_at": row.metadata.created_at,
            })
        })
        .collect();

    // Keys are enrolled into their own store rather than beside the rest, so
    // a listing that read one table would miss the credential most likely to
    // be taken away. Theirs is the one identifier here, because theirs is the
    // one door.
    let keys = services::admin::keys::of_user(&transaction, &user_id)
        .await
        .map_err(|_| internal())?;
    let mut shown = shown;
    shown.extend(keys.into_iter().map(|key| {
        serde_json::json!({
            "id": data_encoding::BASE64URL_NOPAD.encode(&key.credential_id),
            "kind": "webauthn",
            "label": key.label,
            "detail": key.last_used_at.map(|at| at.to_rfc3339()),
            "created_at": key.enrolled_at,
        })
    }));
    Ok(HttpResponse::Ok().json(serde_json::json!({ "items": shown })))
}

/// What a credential is, in its own terms.
///
/// Read off the parameters a credential stores rather than off its secret. A
/// password's cost is in the encoded prefix, which every reader of a PHC
/// string already sees, and the rest is the shape an authenticator enrolled.
fn describe(row: &CredentialModel, unused: i64) -> Option<String> {
    match row.credential_type {
        CredentialType::Password | CredentialType::Secret => row
            .secret
            .expose()
            .split('$')
            .nth(1)
            .map(|named| named.to_owned()),
        CredentialType::Totp | CredentialType::Hotp => row.otp.as_ref().map(|otp| {
            let algorithm = otp.algorithm.to_string();
            match otp.parameters {
                OtpParameters::Totp { digits, period } => {
                    format!("{algorithm} · {digits} digits · {period} s")
                }
                OtpParameters::Hotp { digits, counter } => {
                    format!("{algorithm} · {digits} digits · counter {counter}")
                }
            }
        }),
        CredentialType::RecoveryCode => Some(format!("{unused} still unused")),
        CredentialType::PasswordHistory => None,
    }
}

/// Take away one of this account's second factors.
///
/// The person who lost their phone is otherwise locked out for good, and a
/// deployment with no way back pushes people off the second factor rather
/// than onto it. What it costs is stated plainly: an administrator holding
/// `user:write` can strip the factor and then set a password, which is the
/// whole of an account takeover from one compromised console account. The
/// entry lands in the realm's chain like every other write, which is what
/// makes it a decision somebody has to answer for rather than an invisible
/// one.
///
/// Second factors only. A password is replaced through its own door, and the
/// superseded ones are what the reuse rule compares against rather than a way
/// in, so neither is removable here.
pub async fn revoke(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, user_id, credential_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let user_id = named_user(&transaction, &user_id).await?;

    let held = store::providers::credentials::load(&transaction, &credential_id)
        .await
        .map_err(|_| internal())?
        .filter(|row| row.user_id == user_id)
        .ok_or_else(|| ApiError::new(ErrorCode::CredentialNotFound))?;
    if !matches!(
        held.credential_type,
        CredentialType::Totp | CredentialType::Hotp | CredentialType::RecoveryCode
    ) {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            "a password is replaced rather than taken away",
        ));
    }
    store::providers::credentials::delete(&transaction, &credential_id)
        .await
        .map_err(|_| internal())?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}
