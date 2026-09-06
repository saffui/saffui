use chrono::{DateTime, Duration, Utc};
use config::serving::PublicOrigin;
use crypto::provider::CryptoProvider;
use data_encoding::BASE64URL_NOPAD;
use deadpool_postgres::Transaction;
use models::compliance::subject_request::{DsarKind, DsarRequest};
use models::entities::mail::MailSettings;
use models::entities::realm::RealmModel;
use models::entities::user::UserModel;
use store::providers::{one_time_tokens, users};

use auth::messaging::{Message, Outgoing};

use crate::admin::compliance::{self, Lodging, Unactionable};

/// How long a mailed confirmation lasts, and how soon another may be asked
/// for.
const CONFIRM_LIFESPAN: i64 = 900;
const CONFIRM_COOLDOWN: i64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Undoored {
    #[error("this realm does not take subject requests")]
    NotOffered,
    #[error("the link is unknown, spent or expired")]
    NoSuchLink,
    #[error("the store could not be read")]
    Unreadable,
}

/// The purpose a confirmation token is minted under: one per kind, so an
/// outstanding erasure link does not spend as an access one, and asking for
/// one kind does not throttle asking for another.
pub fn confirmation_purpose(kind: DsarKind) -> String {
    format!("dsar-{}", kind.as_str())
}

/// Mail a link that confirms a subject request, and say nothing about
/// whether anybody was found.
///
/// The answer is the same for a name nobody holds, and nothing is lodged
/// yet: a register that grew a row for every address a form was fed would
/// answer the question this endpoint refuses to.
#[allow(clippy::too_many_arguments, reason = "each is a distinct fact")]
pub async fn offer_link(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    realm: &RealmModel,
    origin: &PublicOrigin,
    settings: Option<&MailSettings>,
    named: &str,
    kind: DsarKind,
    now: DateTime<Utc>,
) -> Result<Option<Outgoing>, Undoored> {
    if realm.dsar_jurisdiction.is_none() {
        return Err(Undoored::NotOffered);
    }
    let Some(settings) = settings else {
        return Ok(None);
    };
    let Some(subject) = found(transaction, named).await? else {
        return Ok(None);
    };
    if subject.email.is_empty() || !subject.enabled {
        return Ok(None);
    }

    let purpose = confirmation_purpose(kind);
    let recent = one_time_tokens::minted_at(transaction, &subject.user_id, &purpose, now)
        .await
        .map_err(|_| Undoored::Unreadable)?;
    if recent.is_some_and(|sent| now - sent < Duration::seconds(CONFIRM_COOLDOWN)) {
        return Ok(None);
    }

    let mut drawn = [0u8; 32];
    provider
        .rand()
        .fill(&mut drawn)
        .map_err(|_| Undoored::Unreadable)?;
    let token = BASE64URL_NOPAD.encode(&drawn);
    // Bound to nothing: the person asking may hold no session at all, and
    // the link proves the mailbox rather than a browser. What it buys is a
    // row in the register, never an admission.
    one_time_tokens::mint(
        transaction,
        provider.digest(),
        one_time_tokens::Owner {
            tenant: &subject.metadata.tenant,
            realm_id: &subject.realm_id,
            user_id: &subject.user_id,
            purpose: &purpose,
        },
        &token,
        None,
        now + Duration::seconds(CONFIRM_LIFESPAN),
        now,
    )
    .await
    .map_err(|_| Undoored::Unreadable)?;

    let link = format!(
        "{}/realms/{}/protocol/openid-connect/privacy-confirm?token={token}&user={}&kind={}",
        origin.as_str(),
        realm.name,
        subject.user_id,
        kind.as_str(),
    );
    let default_body = format!(
        "Somebody asked us to act on the personal data of this account \
         ({}). If it was you, follow the link to confirm the request. If \
         not, nothing happens without it.\n\n{{{{link}}}}\n",
        kind.as_str()
    );
    let (worded_subject, worded_body) = auth::messaging::worded(
        realm,
        "subject_request",
        &link,
        "Confirm your privacy request",
        &default_body,
    );
    Ok(Some(Outgoing {
        settings: settings.duplicate(),
        message: Message {
            to: subject.email.clone(),
            subject: worded_subject,
            body: worded_body,
        },
        about: auth::messaging::About {
            user_id: subject.user_id.clone(),
            purpose,
        },
    }))
}

/// Spend the link and lodge the request, verified in the same breath: the
/// mail round-trip is the identity proof, made by the one person who could
/// have followed it.
pub async fn lodge_from_link(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    realm: &RealmModel,
    user_id: &str,
    kind: DsarKind,
    token: &str,
    now: DateTime<Utc>,
) -> Result<DsarRequest, Undoored> {
    let Some(jurisdiction) = realm.dsar_jurisdiction else {
        return Err(Undoored::NotOffered);
    };
    let subject = users::load(transaction, user_id)
        .await
        .map_err(|_| Undoored::Unreadable)?
        .filter(|held| held.enabled)
        .ok_or(Undoored::NoSuchLink)?;

    let spent = one_time_tokens::spend(
        transaction,
        provider.digest(),
        user_id,
        &confirmation_purpose(kind),
        token,
        None,
        now,
    )
    .await
    .map_err(|_| Undoored::Unreadable)?;
    if spent != one_time_tokens::Spent::Yes {
        return Err(Undoored::NoSuchLink);
    }

    let lodged = compliance::lodge(
        transaction,
        provider,
        &subject.metadata.tenant,
        &subject.realm_id,
        Lodging {
            subject_identifier: &subject.user_name,
            kind,
            jurisdiction,
            due_at: realm
                .dsar_response_days
                .map(|days| now.timestamp() + i64::from(days) * 86_400),
        },
        now.timestamp(),
    )
    .await
    .map_err(from_register)?;
    compliance::verify(transaction, &lodged.request_id, now.timestamp())
        .await
        .map_err(from_register)
}

/// Whatever the register refused, this door has no better word for: the
/// realm's terms were checked when they were written, and the row is one
/// this same transaction lodged.
fn from_register(_: Unactionable) -> Undoored {
    Undoored::Unreadable
}

/// By username, or by address where the realm lets a person sign in with
/// one: the same two ways the login form finds them.
async fn found(transaction: &Transaction<'_>, named: &str) -> Result<Option<UserModel>, Undoored> {
    if let Some(held) = users::load_by_name(transaction, named)
        .await
        .map_err(|_| Undoored::Unreadable)?
    {
        return Ok(Some(held));
    }
    users::load_by_email(transaction, named)
        .await
        .map_err(|_| Undoored::Unreadable)
}
