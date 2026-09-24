//! The people a directory holds, mirrored here as shadows: walked against the
//! directory off the request path, and imported whole when an operator asks.

use auth::login::directory::{Directory, DirectoryPerson, ORIGIN_ATTRIBUTE};
use chrono::Utc;
use crypto::provider::CryptoProvider;
use models::entities::attributes::AttributeValue;
use models::entities::user::{UserModel, UserStorage, profile};
use store::error::StoreError;
use store::providers::directory::users;
use store::tenancy::{TenantContext, UnitOfWork};

/// What a marker on the shadow says: this suspension is the sync's own,
/// so only the sync may lift it. An operator's disabling carries no
/// marker, and no reappearance re-enables it.
pub const SUSPENDED_BY_SYNC: &str = "federation.suspended";

/// What one realm's sync pass did.
#[derive(Debug, Default, Clone, Copy)]
pub struct Synced {
    pub refreshed: u64,
    pub suspended: u64,
    pub restored: u64,
}

impl Synced {
    pub fn total(&self) -> u64 {
        self.refreshed + self.suspended + self.restored
    }
    pub fn add(&mut self, other: Synced) {
        self.refreshed += other.refreshed;
        self.suspended += other.suspended;
        self.restored += other.restored;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the directory could not be asked, or a shadow could not be read or written")]
pub struct Unsynced;

/// Walk one realm's shadows against its directory, off the request path.
///
/// A mirror found upstream is refreshed where the directory's answer
/// differs; one the directory no longer holds is suspended, under the
/// sync's own marker, so a person removed from the directory stops
/// signing in here without their history going anywhere; and one that
/// reappears under the marker is restored. The directory being
/// unreachable ends the pass with nothing written: an outage is not a
/// departure, and suspending a realm's people over a cable would be the
/// outage deciding who may log in.
pub async fn sync_shadows(
    transaction: &UnitOfWork,
    alias: &str,
    first: bool,
    directory: &dyn Directory,
) -> Result<Synced, Unsynced> {
    let mut outcome = Synced::default();
    let shadows = users::shadows(transaction).await.map_err(|_| Unsynced)?;
    for mut shadow in shadows {
        // Each pass walks its own directory's mirrors. A shadow from before
        // the mark belongs to the first-asked directory.
        let origin = shadow
            .attributes
            .as_ref()
            .and_then(|bag| bag.get(ORIGIN_ATTRIBUTE))
            .and_then(AttributeValue::as_str);
        match origin {
            Some(held) if held != alias => continue,
            None if !first => continue,
            _ => {}
        }
        let found = directory
            .find(&shadow.user_name)
            .await
            .map_err(|()| Unsynced)?;
        match found {
            Some(person) => {
                let mut changed = false;
                let attributes = shadow.attributes.get_or_insert_with(Default::default);
                for (key, held) in [
                    (profile::FIRST_NAME, &person.first_name),
                    (profile::LAST_NAME, &person.last_name),
                ] {
                    if let Some(value) = held {
                        let fresh = AttributeValue::Str(value.clone());
                        if attributes.get(key) != Some(&fresh) {
                            attributes.insert(key.to_owned(), fresh);
                            changed = true;
                        }
                    }
                }
                if let Some(email) = &person.email
                    && &shadow.email != email
                {
                    shadow.email = email.clone();
                    // The address moved, so whatever was verified was the
                    // old one.
                    shadow.email_verified = Some(false);
                    changed = true;
                }
                let suspended = shadow
                    .attributes
                    .as_ref()
                    .and_then(|held| held.get(SUSPENDED_BY_SYNC))
                    .is_some();
                if suspended {
                    shadow
                        .attributes
                        .get_or_insert_with(Default::default)
                        .remove(SUSPENDED_BY_SYNC);
                    shadow.enabled = true;
                    outcome.restored += 1;
                    changed = true;
                } else if changed {
                    outcome.refreshed += 1;
                }
                if changed {
                    users::update(transaction, &shadow)
                        .await
                        .map_err(|_| Unsynced)?;
                }
            }
            None => {
                if !shadow.enabled {
                    continue;
                }
                shadow.enabled = false;
                shadow
                    .attributes
                    .get_or_insert_with(Default::default)
                    .insert(SUSPENDED_BY_SYNC.to_owned(), AttributeValue::Bool(true));
                users::update(transaction, &shadow)
                    .await
                    .map_err(|_| Unsynced)?;
                outcome.suspended += 1;
            }
        }
    }
    Ok(outcome)
}

/// What an operator-asked import did.
#[derive(Debug, Default, Clone, Copy)]
pub struct Imported {
    pub imported: u64,
    pub refreshed: u64,
    pub walked: u64,
}

/// Why an operator-asked import stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unimported {
    /// The directory could not be walked.
    Unwalked,
    /// A mirror could not be read or written here.
    Unwritten,
}

/// Mirror everybody the directory holds: unknown people become shadows the
/// way a first login would make them, known mirrors are refreshed the way
/// the sync refreshes them. Local people keep their names.
pub async fn import_everyone(
    transaction: &UnitOfWork,
    provider: &dyn CryptoProvider,
    context: &TenantContext,
    alias: &str,
    directory: &dyn Directory,
) -> Result<Imported, Unimported> {
    let people = directory
        .everyone()
        .await
        .map_err(|()| Unimported::Unwalked)?;
    let mut told = Imported {
        walked: people.len() as u64,
        ..Default::default()
    };
    let now = Utc::now();
    for person in people {
        let standing = users::load_by_name(transaction, &person.username)
            .await
            .map_err(|_| Unimported::Unwritten)?;
        match standing {
            None => {
                let shadow =
                    auth::login::browser::shadow_row(provider, context, alias, &person, now)
                        .map_err(|_| Unimported::Unwritten)?;
                users::create(transaction, &shadow)
                    .await
                    .map_err(|_| Unimported::Unwritten)?;
                told.imported += 1;
            }
            Some(held) if held.user_storage == Some(UserStorage::Ldap) => {
                let refreshed = refresh_shadow(transaction, held, &person)
                    .await
                    .map_err(|_| Unimported::Unwritten)?;
                if refreshed {
                    told.refreshed += 1;
                }
            }
            Some(_) => {}
        }
    }
    Ok(told)
}

async fn refresh_shadow(
    transaction: &UnitOfWork,
    mut shadow: UserModel,
    person: &DirectoryPerson,
) -> Result<bool, StoreError> {
    let mut changed = false;
    let attributes = shadow.attributes.get_or_insert_with(Default::default);
    for (key, held) in [
        (profile::FIRST_NAME, &person.first_name),
        (profile::LAST_NAME, &person.last_name),
    ] {
        if let Some(value) = held {
            let fresh = AttributeValue::Str(value.clone());
            if attributes.get(key) != Some(&fresh) {
                attributes.insert(key.to_owned(), fresh);
                changed = true;
            }
        }
    }
    if let Some(email) = &person.email
        && &shadow.email != email
    {
        shadow.email = email.clone();
        shadow.email_verified = Some(false);
        changed = true;
    }
    if changed {
        users::update(transaction, &shadow).await?;
    }
    Ok(changed)
}
