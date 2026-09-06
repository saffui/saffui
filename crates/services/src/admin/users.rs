use crypto::provider::{Argon2Params, CryptoProvider};
use deadpool_postgres::Transaction;
use models::auditable::AuditableModel;
use models::entities::attributes::AttributeValue;
use models::entities::user::{RequiredAction, UserCreateModel, UserModel, profile};
use models::paging::Page;
use models::sessions::login_failure::UserLoginFailure;
use secrecy::SecretBox;
use store::providers::{auth_flows, login, users};
use store::query::list_query::ListQuery;

/// What a person is created or reshaped as. `None` leaves a field alone on
/// an update; on a creation it is the absence it reads as.
#[derive(Debug, Clone, Default)]
pub struct Spec {
    /// A new username, where the realm allows renaming. The identifier
    /// underneath never moves.
    pub user_name: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub enabled: Option<bool>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub phone: Option<String>,
    pub required_actions: Option<Vec<RequiredAction>>,
    /// Every other attribute, by its full name.
    pub attributes: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Uncreatable {
    #[error("a user with this name already exists")]
    AlreadyExists,
    #[error("no such user")]
    NotFound,
    #[error("{0}")]
    Invalid(&'static str),
    #[error("the store could not be written")]
    Unwritable,
}

pub async fn create(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    tenant: &str,
    realm_id: &str,
    by: &str,
    user_name: &str,
    spec: &Spec,
) -> Result<UserModel, Uncreatable> {
    check_name(user_name)?;
    if let Some(email) = &spec.email {
        check_mail(email)?;
        check_unclaimed(transaction, email, None).await?;
    }
    if users::load_by_name(transaction, user_name)
        .await
        .map_err(|_| Uncreatable::Unwritable)?
        .is_some()
    {
        return Err(Uncreatable::AlreadyExists);
    }
    let email = spec.email.clone().unwrap_or_default();
    let mut user = UserCreateModel {
        user_name: user_name.to_owned(),
        enabled: spec.enabled.unwrap_or(true),
        email: email.clone(),
        email_verified: Some(spec.email_verified.unwrap_or(false) && !email.is_empty()),
        phone_number: spec.phone.clone(),
        phone_number_verified: spec.phone.as_ref().map(|_| false),
        required_actions: spec.required_actions.clone(),
        not_before: None,
        user_storage: None,
        attributes: None,
        is_service_account: None,
        service_account_client_link: None,
    }
    .into_model(
        // Drawn, never the name: grants, sessions and the journal point at
        // the identifier, and a rename must move none of them.
        draw(provider)?,
        realm_id.to_owned(),
        AuditableModel::from_creator(tenant.to_owned(), by.to_owned()),
    );
    apply_attributes(&mut user, spec);
    // A caller that said nothing gets what the realm registered as default,
    // read live so an administrator's registration reaches the next person.
    // A caller that said an empty list said none, and keeps none.
    if user.required_actions.is_none() {
        let defaults: Vec<_> = auth_flows::default_actions(transaction)
            .await
            .map_err(|_| Uncreatable::Unwritable)?
            .into_iter()
            .map(|registered| registered.action)
            .collect();
        if !defaults.is_empty() {
            user.required_actions = Some(defaults);
        }
    }
    users::create(transaction, &user)
        .await
        .map_err(|_| Uncreatable::Unwritable)?;
    store::providers::roles::join_default_groups(transaction, &user.user_id)
        .await
        .map_err(|_| Uncreatable::Unwritable)?;
    Ok(user)
}

/// One page of the realm's people.
pub async fn list(
    transaction: &Transaction<'_>,
    query: &ListQuery<'_>,
    with_total: bool,
) -> Result<Page<UserModel>, Uncreatable> {
    users::list(transaction, query, with_total)
        .await
        .map_err(|_| Uncreatable::Unwritable)
}

pub async fn get(transaction: &Transaction<'_>, user_id: &str) -> Result<UserModel, Uncreatable> {
    users::load(transaction, user_id)
        .await
        .map_err(|_| Uncreatable::Unwritable)?
        .ok_or(Uncreatable::NotFound)
}

pub async fn update(
    transaction: &Transaction<'_>,
    user_id: &str,
    spec: &Spec,
) -> Result<UserModel, Uncreatable> {
    let mut user = get(transaction, user_id).await?;
    if let Some(renamed) = spec
        .user_name
        .as_deref()
        .filter(|asked| *asked != user.user_name)
    {
        let allowed = store::providers::realms::of_context(transaction)
            .await
            .map_err(|_| Uncreatable::Unwritable)?
            .and_then(|realm| realm.edit_user_name_allowed)
            .unwrap_or(false);
        if !allowed {
            return Err(Uncreatable::Invalid("this realm does not rename accounts"));
        }
        check_name(renamed)?;
        if users::load_by_name(transaction, renamed)
            .await
            .map_err(|_| Uncreatable::Unwritable)?
            .is_some()
        {
            return Err(Uncreatable::AlreadyExists);
        }
        user.user_name = renamed.to_owned();
    }
    if let Some(email) = &spec.email {
        check_mail(email)?;
        check_unclaimed(transaction, email, Some(user_id)).await?;
        user.email = email.clone();
    }
    if let Some(verified) = spec.email_verified {
        user.email_verified = Some(verified && !user.email.is_empty());
    }
    if let Some(enabled) = spec.enabled {
        user.enabled = enabled;
    }
    if let Some(phone) = &spec.phone {
        user.phone_number = Some(phone.clone()).filter(|held| !held.is_empty());
        user.phone_number_verified = user.phone_number.as_ref().map(|_| false);
    }
    if let Some(actions) = &spec.required_actions {
        user.required_actions = Some(actions.clone());
    }
    apply_attributes(&mut user, spec);
    users::update(transaction, &user)
        .await
        .map_err(|_| Uncreatable::Unwritable)?;
    Ok(user)
}

/// Replace what the person signs in with. The credential is one row per
/// person, so a second password is a replacement and never a second way in.
pub async fn set_password(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    tenant: &str,
    realm_id: &str,
    by: &str,
    user_id: &str,
    password: &SecretBox<String>,
) -> Result<(), Uncreatable> {
    get(transaction, user_id).await?;
    keep_password(
        transaction,
        provider,
        Argon2Params::default(),
        tenant,
        realm_id,
        by,
        user_id,
        password,
    )
    .await
}

/// The shared writer's refusal, worn as this module's error.
///
/// The policy, the history, and the bookkeeping all live in `auth::password`,
/// under every door at once; this module only translates the refusal into the
/// error its callers already map to a spoken 422.
fn unkept(why: auth::password::Unkept) -> Uncreatable {
    match why {
        auth::password::Unkept::Refused(said) => Uncreatable::Invalid(said.spoken()),
        auth::password::Unkept::NoSuchPerson => Uncreatable::NotFound,
        auth::password::Unkept::Unwritable => Uncreatable::Unwritable,
    }
}

/// Refuse a password the realm will not have, without writing anything.
pub async fn refuse_password_against_policy(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    realm_id: &str,
    user_id: &str,
    password: &SecretBox<String>,
) -> Result<(), Uncreatable> {
    auth::password::refused_by_the_realm(transaction, provider, realm_id, user_id, password)
        .await
        .map_err(unkept)
}

/// Write a password, replacing the one held or writing the first.
///
/// The whole of it lives in `auth::password::keep`, where the login-time
/// change reads the same policy and records the same history as this door.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one password"
)]
pub async fn keep_password(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    cost: Argon2Params,
    tenant: &str,
    realm_id: &str,
    by: &str,
    user_id: &str,
    password: &SecretBox<String>,
) -> Result<(), Uncreatable> {
    auth::password::keep(
        transaction,
        provider,
        cost,
        tenant,
        realm_id,
        by,
        user_id,
        password,
    )
    .await
    .map_err(unkept)
}

pub async fn remove(transaction: &Transaction<'_>, user_id: &str) -> Result<bool, Uncreatable> {
    users::delete(transaction, user_id)
        .await
        .map_err(|_| Uncreatable::Unwritable)
}

/// The named attributes and the rest, written over what is held; an empty
/// value removes the attribute.
fn apply_attributes(user: &mut UserModel, spec: &Spec) {
    let mut held = user.attributes.take().unwrap_or_default();
    let named = [
        (profile::FIRST_NAME, spec.given_name.as_deref()),
        (profile::LAST_NAME, spec.family_name.as_deref()),
    ];
    let extra = spec
        .attributes
        .iter()
        .map(|(k, v)| (k.as_str(), Some(v.as_str())));
    for (name, value) in named.into_iter().chain(extra) {
        match value {
            Some(value) if !value.is_empty() => {
                held.insert(name.to_owned(), AttributeValue::Str(value.to_owned()));
            }
            Some(_) => {
                held.remove(name);
            }
            None => {}
        }
    }
    user.attributes = (!held.is_empty()).then_some(held);
}

/// A drawn identifier, so a rename never changes what anything points at.
fn draw(provider: &dyn CryptoProvider) -> Result<String, Uncreatable> {
    let mut bytes = [0_u8; 16];
    provider
        .rand()
        .fill(&mut bytes)
        .map_err(|_| Uncreatable::Unwritable)?;
    Ok(crypto::provider::uuid_from(bytes))
}

/// One person, by identifier first and by name second: the console holds
/// identifiers, an operator types names, and accounts born before drawn
/// identifiers answer to both because theirs are their names.
pub async fn identified(
    transaction: &Transaction<'_>,
    spelled: &str,
) -> Result<UserModel, Uncreatable> {
    if let Some(held) = users::load(transaction, spelled)
        .await
        .map_err(|_| Uncreatable::Unwritable)?
    {
        return Ok(held);
    }
    users::load_by_name(transaction, spelled)
        .await
        .map_err(|_| Uncreatable::Unwritable)?
        .ok_or(Uncreatable::NotFound)
}

/// Refuse an address another account already holds, unless the realm said
/// sharing is allowed. The guard lives at this door and not in the schema:
/// the permission is per realm, and a table constraint cannot be.
async fn check_unclaimed(
    transaction: &Transaction<'_>,
    email: &str,
    but: Option<&str>,
) -> Result<(), Uncreatable> {
    if email.is_empty() {
        return Ok(());
    }
    let sharing = store::providers::realms::of_context(transaction)
        .await
        .map_err(|_| Uncreatable::Unwritable)?
        .and_then(|realm| realm.duplicated_email_allowed)
        .unwrap_or(false);
    if sharing {
        return Ok(());
    }
    match users::load_by_email(transaction, email)
        .await
        .map_err(|_| Uncreatable::Unwritable)?
    {
        Some(held) if but != Some(held.user_id.as_str()) => {
            Err(Uncreatable::Invalid("an account already uses this address"))
        }
        _ => Ok(()),
    }
}

/// An address is either absent or the shape of one. Emptiness is absence:
/// clearing a mail address is allowed, misspelling one is not.
fn check_mail(email: &str) -> Result<(), Uncreatable> {
    if email.is_empty() || email_address::EmailAddress::is_valid(email) {
        Ok(())
    } else {
        Err(Uncreatable::Invalid(
            "this is not the shape of a mail address",
        ))
    }
}

fn check_name(user_name: &str) -> Result<(), Uncreatable> {
    let shaped = !user_name.is_empty()
        && user_name.len() <= 255
        && !user_name.chars().any(char::is_whitespace)
        && !user_name.chars().any(char::is_control);
    shaped.then_some(()).ok_or(Uncreatable::Invalid(
        "a user name has no spaces and no control characters",
    ))
}

/// What is counted against this person, and until when they are refused.
pub async fn lockout(
    transaction: &Transaction<'_>,
    user_id: &str,
) -> Result<Option<UserLoginFailure>, Uncreatable> {
    login::failures(transaction, user_id)
        .await
        .map_err(|_| Uncreatable::Unwritable)
}

/// How many recovery codes this person has left.
///
/// A count and never the codes. What an administrator needs is to see a sheet
/// running out so they can ask for a fresh one; handing them the codes would
/// make the way back into somebody else's second factor.
pub async fn recovery_codes_left(
    transaction: &Transaction<'_>,
    user_id: &str,
) -> Result<i64, Uncreatable> {
    store::providers::credentials::count_recovery_codes(transaction, user_id)
        .await
        .map_err(|_| Uncreatable::Unwritable)
}

/// Lift a lockout and forget the count.
///
/// An administrator is the way out of a lock somebody else can cause: without
/// this, a person whose account is being guessed at waits for a window they
/// did not choose.
pub async fn lift_lockout(
    transaction: &Transaction<'_>,
    user_id: &str,
) -> Result<bool, Uncreatable> {
    login::clear_failures(transaction, user_id)
        .await
        .map_err(|_| Uncreatable::Unwritable)
}
