//! Self-registration: the one door where an account is born from the outside.
//!
//! Everything here is the realm's say. The door itself opens on
//! `registration_allowed`; whether the form asks for a name or only an
//! address follows `register_email_as_username`; a fresh account owes a
//! verification when `verify_email` says so; and a held address answers
//! exactly like a fresh one when that would otherwise say who exists here.

use crypto::password::storage::StoredPassword;
use crypto::provider::CryptoProvider;
use deadpool_postgres::Transaction;
use models::entities::realm::{About, RealmModel};
use models::entities::user::RequiredAction;
use secrecy::SecretBox;
use store::providers::{auth_flows, users};

/// What the form posted.
pub struct Asked<'a> {
    pub username: Option<&'a str>,
    pub email: &'a str,
    pub given_name: Option<&'a str>,
    pub family_name: Option<&'a str>,
    pub password: &'a SecretBox<String>,
}

/// What the page is told. `verify` says which sentence to show; a registration
/// that quietly did nothing says the same thing as one that did.
pub struct Registered {
    pub verify: bool,
    /// The verification mail, when the realm demands proven addresses and can
    /// send: composed here, carried out by the caller after its commit, so
    /// the page's "a verification is on its way" is finally true.
    pub sending: Option<Box<auth::messaging::Outgoing>>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, thiserror::Error)]
pub enum Unregistrable {
    /// The realm does not open this door; said as a page that is not there.
    #[error("registration is not offered here")]
    NotOffered,
    #[error("this name is taken")]
    NameTaken,
    /// Only said where saying it does not enumerate: a realm that verifies
    /// addresses answers a held one exactly like a fresh one instead.
    #[error("an account already uses this address")]
    AddressHeld,
    #[error("{0}")]
    Refused(&'static str),
    #[error("{0}")]
    Invalid(&'static str),
    #[error("the store could not be written")]
    Unwritable,
}

#[allow(clippy::too_many_arguments, reason = "each is a distinct fact")]
pub async fn register_person(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    realm: &RealmModel,
    mail: Option<&models::entities::mail::MailSettings>,
    origin: &str,
    asked: Asked<'_>,
) -> Result<Registered, Unregistrable> {
    if realm.registration_allowed != Some(true) {
        return Err(Unregistrable::NotOffered);
    }
    let verifying = realm.verify_email == Some(true);

    // The identifier: the name asked for, or the address where the realm
    // registers by address alone.
    let email = asked.email.trim();
    if email.is_empty() || !email_address::EmailAddress::is_valid(email) {
        return Err(Unregistrable::Invalid(
            "this is not the shape of a mail address",
        ));
    }
    let user_name = if realm.register_email_as_username == Some(true) {
        email
    } else {
        asked.username.unwrap_or_default().trim()
    };

    // The policy reads the identity it defends; refused before anything is
    // written, so a weak password costs a retry and not a half-born account.
    if let Some(policy) = realm.password_policy.as_ref()
        && let Some(why) = policy.refuses(
            secrecy::ExposeSecret::expose_secret(asked.password),
            About {
                username: Some(user_name),
                email: Some(email),
                birthdate: None,
            },
        )
    {
        return Err(Unregistrable::Refused(why.spoken()));
    }

    // A held address, where the realm verifies addresses, is answered exactly
    // like a fresh one: the mail simply never comes. The hash is still paid,
    // so the two answers cost the same time. Where nothing is verified, a
    // page that could not say why it failed would just strand the person.
    if realm.duplicated_email_allowed != Some(true)
        && users::load_by_email(transaction, email)
            .await
            .map_err(|_| Unregistrable::Unwritable)?
            .is_some()
    {
        if verifying {
            let cost = realm
                .password_policy
                .as_ref()
                .map_or_else(Default::default, |policy| policy.hashing);
            let _ = StoredPassword::hash_argon2id(provider, cost, asked.password);
            return Ok(Registered {
                verify: true,
                sending: None,
            });
        }
        return Err(Unregistrable::AddressHeld);
    }

    // What the realm asks of every newcomer, plus the verification this door
    // owes when the realm demands proven addresses.
    let mut actions: Vec<RequiredAction> = auth_flows::default_actions(transaction)
        .await
        .map_err(|_| Unregistrable::Unwritable)?
        .into_iter()
        .map(|registered| registered.action)
        .collect();
    if verifying && !actions.contains(&RequiredAction::VerifyEmail) {
        actions.push(RequiredAction::VerifyEmail);
    }

    let spec = crate::admin::users::Spec {
        user_name: None,
        email: Some(email.to_owned()),
        given_name: asked.given_name.map(str::to_owned),
        family_name: asked.family_name.map(str::to_owned),
        required_actions: Some(actions),
        ..Default::default()
    };
    let born = crate::admin::users::create(
        transaction,
        provider,
        &realm.metadata.tenant,
        &realm.realm_id,
        "registration",
        user_name,
        &spec,
    )
    .await
    .map_err(|why| match why {
        crate::admin::users::Uncreatable::AlreadyExists => Unregistrable::NameTaken,
        crate::admin::users::Uncreatable::Invalid(what) => Unregistrable::Invalid(what),
        _ => Unregistrable::Unwritable,
    })?;

    let cost = realm
        .password_policy
        .as_ref()
        .map_or_else(Default::default, |policy| policy.hashing);
    crate::admin::users::keep_password(
        transaction,
        provider,
        cost,
        &realm.metadata.tenant,
        &realm.realm_id,
        "registration",
        &born.user_id,
        asked.password,
    )
    .await
    .map_err(|_| Unregistrable::Unwritable)?;

    // The verification leaves with the registration, bound to no login
    // because none exists yet: the address was just given, this is the
    // moment to prove it, and the widened spend admits the link from
    // whichever login follows it. The ceremony's own cooldown then keeps
    // the first sign-in from mailing a second one.
    let sending = match mail.filter(|_| verifying) {
        None => None,
        Some(settings) => {
            let mut drawn = [0u8; 32];
            provider
                .rand()
                .fill(&mut drawn)
                .map_err(|_| Unregistrable::Unwritable)?;
            let token = data_encoding::BASE64URL_NOPAD.encode(&drawn);
            store::providers::one_time_tokens::mint(
                transaction,
                provider.digest(),
                store::providers::one_time_tokens::Owner {
                    tenant: &realm.metadata.tenant,
                    realm_id: &realm.realm_id,
                    user_id: &born.user_id,
                    purpose: auth::login::enrolment::VERIFY_EMAIL,
                },
                &token,
                None,
                chrono::Utc::now()
                    + chrono::Duration::seconds(auth::login::enrolment::VERIFY_LIFESPAN),
                chrono::Utc::now(),
            )
            .await
            .map_err(|_| Unregistrable::Unwritable)?;
            let link = format!(
                "{origin}/realms/{}/protocol/openid-connect/login?verify_email={token}",
                realm.name,
            );
            let (worded_subject, worded_body) = auth::messaging::worded(
                realm,
                auth::login::enrolment::VERIFY_EMAIL,
                &link,
                "Confirm your address",
                "Confirm this address to finish creating your account. The link works \
                 once.\n\n{{link}}\n",
            );
            Some(Box::new(auth::messaging::Outgoing {
                settings: settings.duplicate(),
                message: auth::messaging::Message {
                    to: email.to_owned(),
                    subject: worded_subject,
                    body: worded_body,
                },
                about: auth::messaging::About {
                    user_id: born.user_id.clone(),
                    purpose: auth::login::enrolment::VERIFY_EMAIL.to_owned(),
                },
            }))
        }
    };

    Ok(Registered {
        verify: verifying,
        sending,
    })
}
