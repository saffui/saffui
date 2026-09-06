use crypto::provider::CryptoProvider;
use data_encoding::HEXLOWER;
use deadpool_postgres::Transaction;
use models::compliance::subject_request::{DsarKind, DsarLodgement, DsarRequest, Jurisdiction};
use store::providers::{compliance, users};

/// Why the register could not do what was asked.
#[derive(Debug, thiserror::Error)]
pub enum Unactionable {
    #[error("no such request")]
    NotFound,
    #[error("{0}")]
    Invalid(String),
    #[error("the store could not be written")]
    Backend,
}

/// What an operator lodges: the subject's own words, plus the clock's terms.
pub struct Lodging<'a> {
    pub subject_identifier: &'a str,
    pub kind: DsarKind,
    pub jurisdiction: Jurisdiction,
    /// An absolute due instant, required where the jurisdiction fixes no
    /// window and welcome where the controller's policy is tighter.
    pub due_at: Option<i64>,
}

/// Lodge a request in the register.
///
/// The identifier is looked up as a username and then as a sole address, and
/// whatever that found is only written into the row: the answer is the same
/// whether an account matched or not, so the register is not a way to ask
/// which addresses hold accounts.
pub async fn lodge(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    tenant: &str,
    realm_id: &str,
    asked: Lodging<'_>,
    now: i64,
) -> Result<DsarRequest, Unactionable> {
    let mut drawn = [0u8; 16];
    provider
        .rand()
        .fill(&mut drawn)
        .map_err(|_| Unactionable::Backend)?;
    let mut request = DsarRequest::lodge(
        DsarLodgement {
            request_id: HEXLOWER.encode(&drawn),
            tenant: tenant.to_owned(),
            realm_id: realm_id.to_owned(),
            subject_identifier: asked.subject_identifier.to_owned(),
            kind: asked.kind,
            jurisdiction: asked.jurisdiction,
            due_override: asked.due_at,
        },
        now,
    )
    .map_err(|why| Unactionable::Invalid(why.to_string()))?;

    request.user_id = resolved_subject(transaction, asked.subject_identifier).await?;
    compliance::lodge(transaction, &request)
        .await
        .map_err(|_| Unactionable::Backend)?;
    Ok(request)
}

pub async fn list(transaction: &Transaction<'_>) -> Result<Vec<DsarRequest>, Unactionable> {
    compliance::list(transaction)
        .await
        .map_err(|_| Unactionable::Backend)
}

pub async fn get(
    transaction: &Transaction<'_>,
    request_id: &str,
) -> Result<DsarRequest, Unactionable> {
    compliance::load(transaction, request_id)
        .await
        .map_err(|_| Unactionable::Backend)?
        .ok_or(Unactionable::NotFound)
}

/// Record that the subject proved who they are. The lifecycle is the
/// model's: whatever it refuses is answered in its own words.
pub async fn verify(
    transaction: &Transaction<'_>,
    request_id: &str,
    now: i64,
) -> Result<DsarRequest, Unactionable> {
    let mut request = get(transaction, request_id).await?;
    request
        .verify(now)
        .map_err(|why| Unactionable::Invalid(why.to_string()))?;
    saved(transaction, request).await
}

/// Close a request as refused, with the reason the subject is owed.
pub async fn refuse(
    transaction: &Transaction<'_>,
    request_id: &str,
    reason: &str,
    now: i64,
) -> Result<DsarRequest, Unactionable> {
    let mut request = get(transaction, request_id).await?;
    request
        .refuse(reason, now)
        .map_err(|why| Unactionable::Invalid(why.to_string()))?;
    saved(transaction, request).await
}

async fn saved(
    transaction: &Transaction<'_>,
    request: DsarRequest,
) -> Result<DsarRequest, Unactionable> {
    if !compliance::save(transaction, &request)
        .await
        .map_err(|_| Unactionable::Backend)?
    {
        return Err(Unactionable::NotFound);
    }
    Ok(request)
}

async fn resolved_subject(
    transaction: &Transaction<'_>,
    identifier: &str,
) -> Result<Option<String>, Unactionable> {
    if let Some(person) = users::load_by_name(transaction, identifier)
        .await
        .map_err(|_| Unactionable::Backend)?
    {
        return Ok(Some(person.user_id));
    }
    Ok(users::sole_by_email(transaction, identifier)
        .await
        .map_err(|_| Unactionable::Backend)?
        .map(|person| person.user_id))
}
