use chrono::{DateTime, Duration, Utc};
use config::serving::PublicOrigin;
use crypto::provider::CryptoProvider;
use data_encoding::BASE64URL_NOPAD;
use deadpool_postgres::Transaction;
use models::entities::mail::MailSettings;
use models::entities::realm::{About, RealmModel};
use models::entities::user::{RequiredAction, UserModel};
use secrecy::SecretBox;
use store::providers::{one_time_tokens, sessions, users};

use crate::messaging::{Message, Outgoing};

pub const RESET_PASSWORD: &str = "reset-password";

/// How long a mailed reset link lasts, and how soon another may be asked for.
const RESET_LIFESPAN: i64 = 900;
const RESET_COOLDOWN: i64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unrecoverable {
    #[error("this realm does not reset passwords")]
    NotOffered,
    #[error("the link is unknown, spent or expired")]
    NoSuchLink,
    #[error("{0}")]
    Refused(&'static str),
    #[error("the store could not be read")]
    Unreadable,
}

/// Ask for a link, and say nothing about whether anybody was found.
///
/// The answer is the same for a name nobody holds. Anything else here is a way
/// to read a realm's list of people off how the server replies.
pub async fn offer_link(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    realm: &RealmModel,
    origin: &PublicOrigin,
    settings: Option<&MailSettings>,
    named: &str,
    now: DateTime<Utc>,
) -> Result<Option<Outgoing>, Unrecoverable> {
    if realm.reset_password_allowed != Some(true) {
        return Err(Unrecoverable::NotOffered);
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

    // The same window the other mailed links have. Without it a caller loops
    // this endpoint and the server floods a mailbox on somebody's behalf.
    let recent = one_time_tokens::minted_at(transaction, &subject.user_id, RESET_PASSWORD, now)
        .await
        .map_err(|_| Unrecoverable::Unreadable)?;
    if recent.is_some_and(|sent| now - sent < Duration::seconds(RESET_COOLDOWN)) {
        return Ok(None);
    }

    let mut drawn = [0u8; 32];
    provider
        .rand()
        .fill(&mut drawn)
        .map_err(|_| Unrecoverable::Unreadable)?;
    let token = BASE64URL_NOPAD.encode(&drawn);
    // Bound to nothing, deliberately. Somebody who cannot sign in is often on
    // another device than the one they will finish on, and a link that only
    // works in the browser that asked is a link they cannot use. What stands
    // in for that binding is that the link proves the mailbox and nothing
    // else: it sets a password and admits nobody.
    one_time_tokens::mint(
        transaction,
        provider.digest(),
        one_time_tokens::Owner {
            tenant: &subject.metadata.tenant,
            realm_id: &subject.realm_id,
            user_id: &subject.user_id,
            purpose: RESET_PASSWORD,
        },
        &token,
        None,
        now + Duration::seconds(RESET_LIFESPAN),
        now,
    )
    .await
    .map_err(|_| Unrecoverable::Unreadable)?;

    let link = format!(
        "{}/realms/{}/protocol/openid-connect/reset-password?token={token}&user={}",
        origin.as_str(),
        realm.name,
        subject.user_id,
    );
    Ok(Some(Outgoing {
        settings: settings.duplicate(),
        message: Message {
            to: subject.email.clone(),
            subject: "Set a new password".to_owned(),
            body: format!(
                "Somebody asked to set a new password for this account. If it was not \
                 you, nothing has changed and you can ignore this.\n\n{link}\n"
            ),
        },
        about: crate::messaging::About {
            user_id: subject.user_id.clone(),
            purpose: RESET_PASSWORD.to_owned(),
        },
    }))
}

/// Spend the link and set the password.
pub async fn set_from_link(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    realm: &RealmModel,
    user_id: &str,
    token: &str,
    password: &SecretBox<String>,
    now: DateTime<Utc>,
) -> Result<(), Unrecoverable> {
    if realm.reset_password_allowed != Some(true) {
        return Err(Unrecoverable::NotOffered);
    }
    let subject = users::load(transaction, user_id)
        .await
        .map_err(|_| Unrecoverable::Unreadable)?
        .filter(|held| held.enabled)
        .ok_or(Unrecoverable::NoSuchLink)?;

    // Before the link is spent. What actually keeps a refused password from
    // costing somebody their link is that this returns without committing and
    // the transaction rolls the spend back; a mutation run proved the order
    // alone is not what saves it. The order stays because the guarantee then
    // does not depend on every future caller remembering not to commit.
    if let Some(policy) = realm.password_policy.as_ref()
        && let Some(why) = policy.refuses(
            secrecy::ExposeSecret::expose_secret(password),
            About {
                username: Some(&subject.user_name),
                email: Some(&subject.email),
                birthdate: None,
            },
        )
    {
        return Err(Unrecoverable::Refused(refused_as(why)));
    }

    let spent = one_time_tokens::spend(
        transaction,
        provider.digest(),
        user_id,
        RESET_PASSWORD,
        token,
        None,
        now,
    )
    .await
    .map_err(|_| Unrecoverable::Unreadable)?;
    if spent != one_time_tokens::Spent::Yes {
        return Err(Unrecoverable::NoSuchLink);
    }

    let cost = realm
        .password_policy
        .as_ref()
        .map_or_else(Default::default, |policy| policy.hashing);
    crate::admin::users::keep_password(
        transaction,
        provider,
        cost,
        &subject.metadata.tenant,
        &subject.realm_id,
        RESET_PASSWORD,
        user_id,
        password,
    )
    .await
    .map_err(|_| Unrecoverable::Unreadable)?;

    // Somebody resetting a password is often somebody whose old one is known
    // to another person. Leaving that person's sessions open would leave them
    // signed in through the very reset meant to shut them out.
    sessions::end_all_of_user(transaction, user_id)
        .await
        .map_err(|_| Unrecoverable::Unreadable)?;

    for action in [
        RequiredAction::ResetPassword,
        RequiredAction::UpdatePassword,
    ] {
        users::clear_required_action(transaction, user_id, action)
            .await
            .map_err(|_| Unrecoverable::Unreadable)?;
    }
    Ok(())
}

/// What the caller is told. The reason is the policy's, never the password's.
fn refused_as(why: models::entities::realm::PasswordRefused) -> &'static str {
    match why {
        models::entities::realm::PasswordRefused::TooShort => "the password is too short",
        models::entities::realm::PasswordRefused::TooLong => "the password is too long",
        models::entities::realm::PasswordRefused::Digits => "the password needs more digits",
        models::entities::realm::PasswordRefused::UpperCase => "the password needs more capitals",
        models::entities::realm::PasswordRefused::LowerCase => {
            "the password needs more small letters"
        }
        models::entities::realm::PasswordRefused::SpecialChars => {
            "the password needs more punctuation"
        }
        models::entities::realm::PasswordRefused::AboutYou => "the password is something about you",
        models::entities::realm::PasswordRefused::Blacklisted => {
            "the password is one this realm refuses"
        }
        models::entities::realm::PasswordRefused::Shape => {
            "the password does not match the shape this realm requires"
        }
    }
}

/// By username, or by address where the realm lets a person sign in with one.
async fn found(
    transaction: &Transaction<'_>,
    named: &str,
) -> Result<Option<UserModel>, Unrecoverable> {
    if let Some(held) = users::load_by_name(transaction, named)
        .await
        .map_err(|_| Unrecoverable::Unreadable)?
    {
        return Ok(Some(held));
    }
    users::load_by_email(transaction, named)
        .await
        .map_err(|_| Unrecoverable::Unreadable)
}
