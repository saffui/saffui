//! The realm's directories, spoken to over LDAP: the one place in the workspace
//! a directory protocol is spoken.

use std::future::Future;
use std::pin::Pin;

use auth::login::directory::{Bound, Directory, DirectoryPerson};
use crypto::secrecy::{ExposeSecret, SecretBox};
use ldap3::{LdapConnAsync, Scope, SearchEntry};
use services::federation::ldap::LdapSettings;
use store::tenancy::UnitOfWork;

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

    /// Everybody, paged through the directory's own control and capped: an
    /// import mirrors identities, it is not an ETL.
    fn everyone<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<DirectoryPerson>, ()>> + Send + 'a>> {
        const CEILING: usize = 10_000;
        Box::pin(async move {
            let mut ldap = self.dial().await?;
            ldap.simple_bind(
                &self.settings.bind_dn,
                self.bind_password
                    .as_ref()
                    .map(|held| held.expose_secret().as_str())
                    .unwrap_or_default(),
            )
            .await
            .and_then(|answer| answer.success())
            .map_err(|why| tracing::warn!(%why, "the service bind was refused"))?;

            let wanted = [
                self.settings.username_attribute.as_str(),
                self.settings.email_attribute.as_str(),
                self.settings.first_name_attribute.as_str(),
                self.settings.last_name_attribute.as_str(),
            ];
            let mut search = ldap
                .streaming_search_with(
                    ldap3::adapters::PagedResults::new(500),
                    &self.settings.users_dn,
                    Scope::Subtree,
                    &self.settings.filter_for_everyone(),
                    &wanted,
                )
                .await
                .map_err(|why| tracing::warn!(%why, "the directory listing failed"))?;
            let mut people = Vec::new();
            while let Ok(Some(entry)) = search.next().await {
                if people.len() >= CEILING {
                    tracing::warn!(ceiling = CEILING, "the import stopped at its ceiling");
                    break;
                }
                let entry = SearchEntry::construct(entry);
                let first = |named: &str| {
                    entry
                        .attrs
                        .get(named)
                        .and_then(|values| values.first())
                        .cloned()
                };
                let Some(username) = first(&self.settings.username_attribute) else {
                    continue;
                };
                people.push(DirectoryPerson {
                    username,
                    email: first(&self.settings.email_attribute),
                    first_name: first(&self.settings.first_name_attribute),
                    last_name: first(&self.settings.last_name_attribute),
                });
            }
            let _ = ldap.unbind().await;
            Ok(people)
        })
    }
}

/// The directory as the login will speak to it, its bind secret opened from
/// the realm's seal for this attempt and dropped with it.
pub async fn directory_for(
    transaction: &UnitOfWork,
    sealing: &crate::Sealing,
    context: &store::tenancy::TenantContext,
    held: &models::entities::brokering::UserFederationModel,
    settings: services::federation::ldap::LdapSettings,
) -> LdapDirectory {
    let bind_password = opened_bind(transaction, sealing, context, held).await;
    LdapDirectory {
        settings,
        bind_password,
    }
}

pub async fn opened_bind(
    transaction: &UnitOfWork,
    sealing: &crate::Sealing,
    context: &store::tenancy::TenantContext,
    held: &models::entities::brokering::UserFederationModel,
) -> Option<crypto::secrecy::SecretBox<String>> {
    use data_encoding::BASE64;
    let sealed = held
        .configs
        .as_ref()?
        .get(services::federation::ldap::SEALED_BIND)?
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
    let mut opened = ring
        .open(
            &sealing.envelope,
            services::federation::ldap::PURPOSE,
            &held.alias,
            &sealed,
        )
        .await
        .ok();
    if opened.is_none() {
        opened = ring
            .open(
                &sealing.envelope,
                services::federation::ldap::PURPOSE,
                services::federation::ldap::LEGACY_SEAL_NAME,
                &sealed,
            )
            .await
            .ok();
    }
    let opened = opened?;
    let clear =
        String::from_utf8(crypto::secrecy::ExposeSecret::expose_secret(&opened).clone()).ok()?;
    Some(crypto::secrecy::SecretBox::new(Box::new(clear)))
}
