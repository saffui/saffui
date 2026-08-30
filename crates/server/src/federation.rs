use std::future::Future;
use std::pin::Pin;

use auth::login::directory::{Bound, Directory, DirectoryPerson};
use crypto::secrecy::{ExposeSecret, SecretBox};
use ldap3::{LdapConnAsync, Scope, SearchEntry};
use services::federation::LdapSettings;

/// The realm's directory, answered over LDAP. The one place in the
/// workspace a directory protocol is spoken: the flow engine sees the port
/// and nothing else.
pub struct LdapDirectory {
    pub settings: LdapSettings,
    /// The service bind, opened from its seal for this login and dropped
    /// with it.
    pub bind_password: Option<SecretBox<String>>,
}

impl LdapDirectory {
    /// One served connection. `ldap3` splits the socket driver from the
    /// handle; the driver is parked on the runtime and dies with the handle.
    async fn dial(&self) -> Result<ldap3::Ldap, ()> {
        let (connection, ldap) = LdapConnAsync::new(&self.settings.url)
            .await
            .map_err(|why| tracing::warn!(%why, "the directory could not be dialled"))?;
        ldap3::drive!(connection);
        Ok(ldap)
    }

    /// The entry answering to this name, found as the service: its DN and
    /// the attributes the mapping names.
    async fn look_up(&self, username: &str) -> Result<Option<(String, DirectoryPerson)>, ()> {
        let mut ldap = self.dial().await?;
        let bound = ldap
            .simple_bind(
                &self.settings.bind_dn,
                self.bind_password
                    .as_ref()
                    .map(|held| held.expose_secret().as_str())
                    .unwrap_or_default(),
            )
            .await
            .and_then(|answer| answer.success())
            .map_err(|why| tracing::warn!(%why, "the service bind was refused"));
        bound?;

        let wanted = [
            self.settings.username_attribute.as_str(),
            self.settings.email_attribute.as_str(),
            self.settings.first_name_attribute.as_str(),
            self.settings.last_name_attribute.as_str(),
        ];
        let (entries, _) = ldap
            .search(
                &self.settings.users_dn,
                Scope::Subtree,
                &self.settings.filter_for(username),
                &wanted,
            )
            .await
            .and_then(|answer| answer.success())
            .map_err(|why| tracing::warn!(%why, "the directory search failed"))?;
        let _ = ldap.unbind().await;

        let Some(entry) = entries.into_iter().next() else {
            return Ok(None);
        };
        let entry = SearchEntry::construct(entry);
        let first = |named: &str| {
            entry
                .attrs
                .get(named)
                .and_then(|values| values.first())
                .cloned()
        };
        let Some(username) = first(&self.settings.username_attribute) else {
            // An entry the mapping cannot name is an entry this realm cannot
            // hold: skipped, and said in the operator log.
            tracing::warn!("a directory entry carries no username attribute");
            return Ok(None);
        };
        Ok(Some((
            entry.dn,
            DirectoryPerson {
                username,
                email: first(&self.settings.email_attribute),
                first_name: first(&self.settings.first_name_attribute),
                last_name: first(&self.settings.last_name_attribute),
            },
        )))
    }
}

impl Directory for LdapDirectory {
    /// The bind is the check: a fresh connection, bound as the person's own
    /// entry. An invalid-credentials answer is a refusal; anything else that
    /// goes wrong is the directory being unreachable, which is never an
    /// admission and never a refusal pinned on the person.
    fn verify<'a>(
        &'a self,
        username: &'a str,
        offered: &'a SecretBox<String>,
    ) -> Pin<Box<dyn Future<Output = Bound> + Send + 'a>> {
        Box::pin(async move {
            let found = match self.look_up(username).await {
                Ok(Some((dn, _))) => dn,
                Ok(None) => return Bound::Refused,
                Err(()) => return Bound::Unreachable,
            };
            let Ok(mut ldap) = self.dial().await else {
                return Bound::Unreachable;
            };
            let answer = ldap.simple_bind(&found, offered.expose_secret()).await;
            let _ = ldap.unbind().await;
            match answer {
                Ok(done) => match done.success() {
                    Ok(_) => Bound::Accepted,
                    Err(ldap3::LdapError::LdapResult { result }) if result.rc == 49 => {
                        Bound::Refused
                    }
                    Err(why) => {
                        tracing::warn!(%why, "the directory answered a bind strangely");
                        Bound::Unreachable
                    }
                },
                Err(why) => {
                    tracing::warn!(%why, "the person's bind could not be asked");
                    Bound::Unreachable
                }
            }
        })
    }

    fn find<'a>(
        &'a self,
        username: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<DirectoryPerson>, ()>> + Send + 'a>> {
        Box::pin(async move { Ok(self.look_up(username).await?.map(|(_, person)| person)) })
    }
}

/// The directory as the login will speak to it, its bind secret opened from
/// the realm's seal for this attempt and dropped with it.
pub async fn directory_for(
    transaction: &deadpool_postgres::Transaction<'_>,
    sealing: &crate::api::config::Sealing,
    context: &store::tenancy::TenantContext,
    held: &models::entities::brokering::UserFederationModel,
    settings: services::federation::LdapSettings,
) -> LdapDirectory {
    let bind_password = opened_bind(transaction, sealing, context, held).await;
    LdapDirectory {
        settings,
        bind_password,
    }
}

pub async fn opened_bind(
    transaction: &deadpool_postgres::Transaction<'_>,
    sealing: &crate::api::config::Sealing,
    context: &store::tenancy::TenantContext,
    held: &models::entities::brokering::UserFederationModel,
) -> Option<crypto::secrecy::SecretBox<String>> {
    use data_encoding::BASE64;
    let sealed = held
        .configs
        .as_ref()?
        .get(services::federation::SEALED_BIND)?
        .as_str()?;
    let sealed = BASE64.decode(sealed.as_bytes()).ok()?;
    let ring = store::keyring::load(
        transaction,
        &sealing.envelope,
        &context.tenant,
        &context.realm_id,
    )
    .await
    .ok()?;
    let opened = ring
        .open(
            &sealing.envelope,
            services::federation::PURPOSE,
            services::federation::SINGLETON,
            &sealed,
        )
        .await
        .ok()?;
    let clear =
        String::from_utf8(crypto::secrecy::ExposeSecret::expose_secret(&opened).clone()).ok()?;
    Some(crypto::secrecy::SecretBox::new(Box::new(clear)))
}

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
    transaction: &deadpool_postgres::Transaction<'_>,
    directory: &LdapDirectory,
) -> Result<Synced, ()> {
    use auth::login::directory::Directory;
    use models::entities::attributes::AttributeValue;
    use models::entities::user::profile;

    let mut outcome = Synced::default();
    let shadows = store::providers::users::shadows(transaction)
        .await
        .map_err(|_| ())?;
    for mut shadow in shadows {
        let found = directory.find(&shadow.user_name).await?;
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
                    store::providers::users::update(transaction, &shadow)
                        .await
                        .map_err(|_| ())?;
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
                store::providers::users::update(transaction, &shadow)
                    .await
                    .map_err(|_| ())?;
                outcome.suspended += 1;
            }
        }
    }
    Ok(outcome)
}
