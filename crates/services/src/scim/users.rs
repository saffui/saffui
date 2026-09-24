//! The people a provisioner pushes: found, shown with the groups they joined,
//! born whole, replaced, patched, and taken away.

use chrono::{DateTime, Utc};
use crypto::password::storage::StoredPassword;
use crypto::provider::{Argon2Params, CryptoProvider};
use crypto::secrecy::SecretBox;
use models::entities::attributes::AttributeValue;
use models::entities::authz::GroupModel;
use models::entities::credentials::{CredentialModel, CredentialSecret, CredentialType};
use models::entities::user::{UserModel, profile};
use models::paging::Window;
use serde_json::Value;
use store::error::StoreError;
use store::providers::directory::{credentials, roles, users};
use store::query::list_query::ListQuery;
use store::tenancy::UnitOfWork;

use super::{AssertedUser, EXTERNAL_ID, Matched, Refusal, UserPatch, shown_user};
use crate::governance::sod::{Toxic, weigh_newcomer};

/// Where a person is born: the tenant and realm the row belongs to, who asks,
/// and when.
pub struct Birthplace<'a> {
    pub tenant: &'a str,
    pub realm_id: &'a str,
    pub by: &'a str,
    pub now: DateTime<Utc>,
}

/// The people a filter names, or a page of everybody when none does. A filter
/// on a group's name is refused: it asks the wrong endpoint.
pub async fn people_matching(
    transaction: &UnitOfWork,
    matched: Option<Matched>,
    page: Window,
) -> Result<Vec<UserModel>, Refusal> {
    let one = match matched {
        None => {
            return users::list(transaction, &ListQuery::new(page), true)
                .await
                .map(|held| held.items)
                .map_err(|_| Refusal::unreadable());
        }
        Some(Matched::UserName(name)) => users::load_by_name(transaction, &name).await,
        Some(Matched::Email(address)) => users::load_by_email(transaction, &address).await,
        Some(Matched::ExternalId(external)) => {
            users::load_by_attribute(transaction, EXTERNAL_ID, &external).await
        }
        Some(Matched::GroupName(_)) => {
            return Err(Refusal::invalid_filter(
                "displayName filters groups, not users",
            ));
        }
    };
    one.map(|held| held.into_iter().collect())
        .map_err(|_| Refusal::unreadable())
}

pub async fn person(transaction: &UnitOfWork, user_id: &str) -> Result<UserModel, Refusal> {
    users::load(transaction, user_id)
        .await
        .map_err(|_| Refusal::unreadable())?
        .ok_or_else(Refusal::not_found)
}

/// A User resource, with the groups the person joined.
pub async fn shown_with_groups(
    transaction: &UnitOfWork,
    base: &str,
    person: &UserModel,
) -> Result<Value, Refusal> {
    let mut groups: Vec<GroupModel> = Vec::new();
    for group_id in users::groups_of(transaction, &person.user_id)
        .await
        .map_err(|_| Refusal::unreadable())?
    {
        if let Some(group) = roles::load_group(transaction, &group_id)
            .await
            .map_err(|_| Refusal::unreadable())?
        {
            groups.push(group);
        }
    }
    Ok(shown_user(base, person, &groups))
}

/// A person born from what a provisioner asserts, whole or not at all: a
/// provisioner's identifier nobody else holds, the seat every newcomer takes
/// weighed against the separations, a name nobody else holds, the default
/// groups, and the password under the realm's policy.
pub async fn provision_person(
    transaction: &UnitOfWork,
    provider: &dyn CryptoProvider,
    at: &Birthplace<'_>,
    asserted: &AssertedUser,
    user_name: String,
) -> Result<UserModel, Refusal> {
    if let Some(external) = &asserted.external_id
        && users::load_by_attribute(transaction, EXTERNAL_ID, external)
            .await
            .map_err(|_| Refusal::unreadable())?
            .is_some()
    {
        return Err(Refusal::uniqueness(format!(
            "externalId {external} is already taken"
        )));
    }

    let mut metadata =
        models::auditable::AuditableModel::from_creator(at.tenant.to_owned(), at.by.to_owned());
    metadata.created_at = Some(at.now);
    let mut drawn = [0_u8; 16];
    provider
        .rand()
        .fill(&mut drawn)
        .map_err(|_| Refusal::unreadable())?;
    let mut person = UserModel {
        // Drawn like every other birth; SCIM addresses the row by this id,
        // and the provisioner renaming a person must not mint a stranger.
        user_id: crypto::provider::uuid_from(drawn),
        realm_id: at.realm_id.to_owned(),
        user_name,
        enabled: asserted.active.unwrap_or(true),
        email: asserted.email.clone().unwrap_or_default(),
        // A provisioner asserts an address; verifying it stays this realm's
        // own act, the same rule federation follows.
        email_verified: Some(false),
        phone_number: None,
        phone_number_verified: None,
        required_actions: None,
        not_before: None,
        user_storage: None,
        attributes: None,
        is_service_account: None,
        service_account_client_link: None,
        metadata,
    };
    asserted.apply(&mut person);

    // The same seat every newcomer takes: default groups that break a
    // separation refuse the person, and the provisioner hears why.
    store::providers::governance::sod::hold_person(transaction, &person.user_id)
        .await
        .map_err(|_| Refusal::unreadable())?;
    match weigh_newcomer(transaction).await {
        Ok(()) => {}
        Err(Toxic::Refused(said)) => return Err(Refusal::invalid(said)),
        Err(Toxic::Backend) => return Err(Refusal::unreadable()),
    }
    match users::create(transaction, &person).await {
        Ok(()) => {}
        Err(StoreError::AlreadyExists) => {
            return Err(Refusal::uniqueness(format!(
                "userName {} is already taken",
                person.user_name
            )));
        }
        Err(_) => return Err(Refusal::unreadable()),
    }
    roles::join_default_groups(transaction, &person.user_id)
        .await
        .map_err(|_| Refusal::unreadable())?;
    if let Some(password) = &asserted.password {
        plant_password(
            transaction,
            provider,
            at.tenant,
            at.realm_id,
            &person.user_id,
            password,
        )
        .await?;
    }
    Ok(person)
}

/// A person replaced by the whole document a provisioner asserts. The name is
/// the one thing a replacement may not change here. Answers the person as they
/// now read.
pub async fn replace_person(
    transaction: &UnitOfWork,
    provider: &dyn CryptoProvider,
    tenant: &str,
    realm_id: &str,
    user_id: &str,
    asserted: &AssertedUser,
) -> Result<UserModel, Refusal> {
    let mut held = person(transaction, user_id).await?;
    if let Some(renamed) = &asserted.user_name
        && renamed != &held.user_name
    {
        return Err(Refusal {
            status: 400,
            scim_type: Some("mutability"),
            detail: "userName does not change here".into(),
        });
    }
    asserted.apply(&mut held);
    users::update(transaction, &held)
        .await
        .map_err(|_| Refusal::unreadable())?;
    if let Some(password) = &asserted.password {
        plant_password(transaction, provider, tenant, realm_id, user_id, password).await?;
    }
    reread(transaction, user_id).await
}

/// A person patched by the operations a provisioner folded. A changed address
/// is unverified again. Answers the person as they now read.
pub async fn patch_person(
    transaction: &UnitOfWork,
    provider: &dyn CryptoProvider,
    tenant: &str,
    realm_id: &str,
    user_id: &str,
    folded: Vec<UserPatch>,
) -> Result<UserModel, Refusal> {
    let mut held = person(transaction, user_id).await?;
    let mut password = None;
    for change in folded {
        let bag = held.attributes.get_or_insert_with(Default::default);
        match change {
            UserPatch::Active(active) => held.enabled = active,
            UserPatch::GivenName(named) => {
                match named {
                    Some(value) => {
                        bag.insert(profile::FIRST_NAME.to_owned(), AttributeValue::Str(value));
                    }
                    None => {
                        bag.remove(profile::FIRST_NAME);
                    }
                };
            }
            UserPatch::FamilyName(named) => {
                match named {
                    Some(value) => {
                        bag.insert(profile::LAST_NAME.to_owned(), AttributeValue::Str(value));
                    }
                    None => {
                        bag.remove(profile::LAST_NAME);
                    }
                };
            }
            UserPatch::ExternalId(value) => {
                bag.insert(EXTERNAL_ID.to_owned(), AttributeValue::Str(value));
            }
            UserPatch::Password(value) => password = Some(value),
            UserPatch::Email(value) => {
                if held.email != value {
                    held.email = value;
                    held.email_verified = Some(false);
                }
            }
        }
    }
    users::update(transaction, &held)
        .await
        .map_err(|_| Refusal::unreadable())?;
    if let Some(password) = &password {
        plant_password(transaction, provider, tenant, realm_id, user_id, password).await?;
    }
    reread(transaction, user_id).await
}

pub async fn remove_person(transaction: &UnitOfWork, user_id: &str) -> Result<(), Refusal> {
    users::delete(transaction, user_id)
        .await
        .map_err(|_| Refusal::unreadable())?
        .then_some(())
        .ok_or_else(Refusal::not_found)
}

/// The person as the write left them. Gone by now is the realm failing, not a
/// resource nobody asked about.
async fn reread(transaction: &UnitOfWork, user_id: &str) -> Result<UserModel, Refusal> {
    users::load(transaction, user_id)
        .await
        .ok()
        .flatten()
        .ok_or_else(Refusal::unreadable)
}

/// The same argon2 the login checks, replacing whatever password stood.
///
/// Under the realm's policy, which this door went around: a provisioning client
/// could plant anything a realm had declared it would not have, and the realm
/// went on refusing the same password to the person who owns the account. The
/// refusal is handed back in the realm's own words rather than flattened, so a
/// directory that pushes a password too short is told which rule it broke; a
/// directory told only that the password could not be kept retries the same
/// password forever.
async fn plant_password(
    transaction: &UnitOfWork,
    provider: &dyn CryptoProvider,
    tenant: &str,
    realm_id: &str,
    user_id: &str,
    password: &str,
) -> Result<(), Refusal> {
    let unkept = || Refusal::invalid("the password could not be kept");
    let secret = SecretBox::new(Box::new(password.to_owned()));
    if let Err(crate::admin::users::Uncreatable::Invalid(said)) =
        crate::admin::users::refuse_password_against_policy(
            transaction,
            provider,
            realm_id,
            user_id,
            &secret,
        )
        .await
    {
        return Err(Refusal::invalid(said));
    }
    let StoredPassword::Argon2id { encoded } =
        StoredPassword::hash_argon2id(provider, Argon2Params::default(), &secret)
            .map_err(|_| unkept())?
    else {
        return Err(unkept());
    };
    credentials::replace_all_of_type(
        transaction,
        &CredentialModel {
            credential_id: format!("scim-{user_id}"),
            realm_id: realm_id.to_owned(),
            user_id: user_id.to_owned(),
            credential_type: CredentialType::Password,
            secret: CredentialSecret::new(encoded),
            user_label: Some("provisioned".to_owned()),
            otp: None,
            priority: 0,
            metadata: models::auditable::AuditableModel::from_creator(
                tenant.to_owned(),
                "scim".to_owned(),
            ),
        },
    )
    .await
    .map_err(|_| unkept())
}
