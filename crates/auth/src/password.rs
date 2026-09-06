//! Writing a password, wherever one is written.
//!
//! One implementation under every door: the admin plane, SCIM, self-service
//! signup, the mailed reset, and the login-time change all funnel here. The
//! realm's policy, the history it asks to be remembered, and the bookkeeping
//! rows that make the history mean something are one copy each; the second
//! copies that used to exist were found drifting and deleted one by one.

use crypto::password::storage::StoredPassword;
use crypto::provider::{Argon2Params, CryptoProvider};
use data_encoding::HEXLOWER;
use deadpool_postgres::Transaction;
use models::entities::credentials::{CredentialModel, CredentialSecret, CredentialType};
use models::entities::realm::{About, PasswordPolicy, PasswordRefused};
use secrecy::SecretBox;
use store::providers::{credentials, realms, users};

/// Why a password was not kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unkept {
    /// The realm's policy said no, in words the person is meant to read.
    #[error("{0}")]
    Refused(PasswordRefused),
    #[error("no such person")]
    NoSuchPerson,
    #[error("the store could not be written")]
    Unwritable,
}

/// Refuse a password the realm's policy will not have, in the realm's words.
///
/// The person is loaded because the policy asks about them: a rule that refuses
/// a password containing the username cannot fire without the username, and the
/// one about a birth date could never fire at all until the profile it has held
/// all along was read here.
///
/// The realm is read by the identifier this call carries rather than off the
/// transaction's ambient context. A policy fetched from the context quietly
/// becomes no policy wherever the context is not what the caller assumed, and
/// this is called from five places with five different assumptions. A realm
/// with no policy takes anything, which is what no policy means; a realm that
/// cannot be read refuses, since a password written past a policy nobody could
/// fetch is exactly the write this exists to stop.
pub async fn refused_by_the_realm(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    realm_id: &str,
    user_id: &str,
    password: &SecretBox<String>,
) -> Result<(), Unkept> {
    let realm = realms::load(transaction, realm_id)
        .await
        .map_err(|_| Unkept::Unwritable)?
        .ok_or(Unkept::Unwritable)?;
    let Some(policy) = realm.password_policy.as_ref() else {
        return Ok(());
    };
    let person = users::load(transaction, user_id)
        .await
        .map_err(|_| Unkept::Unwritable)?
        .ok_or(Unkept::NoSuchPerson)?;
    let birthdate = person
        .attributes
        .as_ref()
        .and_then(|bag| bag.get(models::entities::user::profile::BIRTH_DATE))
        .and_then(models::entities::attributes::AttributeValue::as_str);
    if let Some(why) = policy.refuses(
        secrecy::ExposeSecret::expose_secret(password),
        About {
            username: Some(&person.user_name),
            email: Some(&person.email),
            birthdate,
        },
    ) {
        return Err(Unkept::Refused(why));
    }
    worn_before(transaction, provider, policy, user_id, password).await
}

/// Refuse a password this account has already worn, as deep as the realm asks.
///
/// The standing password counts as the first remembered: refusing the last ten
/// and taking the current one back would be a rule with a hole the width of the
/// password most likely to be typed. Compared one hash at a time, oldest last,
/// which is why how deep this goes is bounded where the policy is read back.
async fn worn_before(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    policy: &PasswordPolicy,
    user_id: &str,
    password: &SecretBox<String>,
) -> Result<(), Unkept> {
    let Some(deep) = policy.history_look_back.filter(|deep| *deep > 0) else {
        return Ok(());
    };
    let mut worn =
        credentials::load_for_user_of_type(transaction, user_id, CredentialType::Password)
            .await
            .map_err(|_| Unkept::Unwritable)?;
    worn.extend(
        credentials::load_for_user_of_type(transaction, user_id, CredentialType::PasswordHistory)
            .await
            .map_err(|_| Unkept::Unwritable)?,
    );
    for held in worn.iter().take(deep as usize) {
        let Ok(stored) = StoredPassword::Argon2id {
            encoded: held.secret.expose().to_owned(),
        }
        .to_legacy_hash() else {
            // A row in a shape this build does not read is not a match and not
            // a reason to refuse a password over.
            continue;
        };
        if crypto::password::migration::verify_and_plan(provider, password, &stored)
            .is_ok_and(|plan| plan.valid)
        {
            return Err(Unkept::Refused(PasswordRefused::Reused));
        }
    }
    Ok(())
}

/// Keep the password being replaced, and forget the ones nobody asks about.
///
/// Written whether or not a policy asks for a history today: a realm that turns
/// the rule on next month wants it to mean something then, and a history that
/// starts empty on the day it is switched on takes as many changes to fill as
/// the rule asks for. What is kept is the stored hash and nothing else, so
/// remembering costs what the password already cost.
///
/// Trimmed to the deepest a policy may ask rather than to what this realm asks
/// now: trimming to the current depth throws away exactly the rows a realm
/// needs the moment somebody deepens the rule. Written and pruned quietly,
/// since a retired password is bookkeeping and not a credential anybody
/// enrolled, and a security receiver told otherwise would hear a change of a
/// kind nobody holds on every password change.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one password"
)]
async fn remember_the_password_it_replaces(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    tenant: &str,
    realm_id: &str,
    by: &str,
    user_id: &str,
    replaced: &CredentialModel,
) -> Result<(), Unkept> {
    let mut drawn = [0u8; 16];
    // A stable identifier would collide with the row kept on the previous
    // change, and this one is only ever read as part of a set. Drawn through
    // the provider, like every other identifier this deployment mints.
    provider
        .rand()
        .fill(&mut drawn)
        .map_err(|_| Unkept::Unwritable)?;
    let kept = CredentialModel {
        credential_id: HEXLOWER.encode(&drawn),
        realm_id: realm_id.to_owned(),
        user_id: user_id.to_owned(),
        credential_type: CredentialType::PasswordHistory,
        user_label: None,
        secret: CredentialSecret::new(replaced.secret.expose().to_owned()),
        otp: None,
        priority: 0,
        metadata: models::auditable::AuditableModel::from_creator(tenant.to_owned(), by.to_owned()),
    };
    credentials::create_quietly(transaction, &kept)
        .await
        .map_err(|_| Unkept::Unwritable)?;

    let worn =
        credentials::load_for_user_of_type(transaction, user_id, CredentialType::PasswordHistory)
            .await
            .map_err(|_| Unkept::Unwritable)?;
    for stale in worn
        .iter()
        .skip(models::entities::realm::MOST_REMEMBERED as usize)
    {
        credentials::delete_quietly(transaction, &stale.credential_id)
            .await
            .map_err(|_| Unkept::Unwritable)?;
    }
    Ok(())
}

/// Write a password, replacing the one held or writing the first.
///
/// The cost is the caller's, because a realm that chose one means it to apply
/// wherever a password is written and not only where an administrator writes.
/// The policy is read here for the same reason, and for most of this
/// codebase's life it was not: a realm could declare a shape and a length and
/// then take anything at all through the admin surface, through SCIM, and
/// through provisioning, because the two callers that checked were the two a
/// person walks through themselves.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one password"
)]
pub async fn keep(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    cost: Argon2Params,
    tenant: &str,
    realm_id: &str,
    by: &str,
    user_id: &str,
    password: &SecretBox<String>,
) -> Result<(), Unkept> {
    refused_by_the_realm(transaction, provider, realm_id, user_id, password).await?;

    let StoredPassword::Argon2id { encoded } =
        StoredPassword::hash_argon2id(provider, cost, password).map_err(|_| Unkept::Unwritable)?
    else {
        return Err(Unkept::Unwritable);
    };
    let held = credentials::load_for_user_of_type(transaction, user_id, CredentialType::Password)
        .await
        .map_err(|_| Unkept::Unwritable)?;
    if let Some(existing) = held.first() {
        // The one it replaces, kept where the rule that refuses a password
        // twice can find it. Written before the replacement, since the
        // replacement is what makes the old secret unreachable.
        remember_the_password_it_replaces(
            transaction,
            provider,
            tenant,
            realm_id,
            by,
            user_id,
            existing,
        )
        .await?;
        credentials::replace_secret(
            transaction,
            &existing.credential_id,
            &CredentialSecret::new(encoded),
            None,
            by,
        )
        .await
        .map_err(|_| Unkept::Unwritable)?;
        return Ok(());
    }
    credentials::create(
        transaction,
        &CredentialModel {
            credential_id: format!("{user_id}-password"),
            realm_id: realm_id.to_owned(),
            user_id: user_id.to_owned(),
            credential_type: CredentialType::Password,
            user_label: None,
            secret: CredentialSecret::new(encoded),
            otp: None,
            priority: 0,
            metadata: models::auditable::AuditableModel::from_creator(
                tenant.to_owned(),
                by.to_owned(),
            ),
        },
    )
    .await
    .map_err(|_| Unkept::Unwritable)
}
