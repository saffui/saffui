//! The storage double: the whole state in memory, behind one lock. A unit of
//! work copies the state and swaps its copy in when it commits, so that an
//! abandoned one leaves nothing.
//!
//! The double serializes nothing and enforces no row security: a property
//! held by SQL is proven on Postgres, never here.

mod audit;
mod claims;
mod clients;
mod consents;
mod keys;
mod login;
mod refresh;
mod roles;
mod tenancy;

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use super::clock::FixedClock;
use super::crypto::{InstantHasher, PredictableCodes, TransparentSealer, TrustingKeys, WeakSigner};
use super::digest::WeakDigester;
use super::random::CountingRandom;
use crate::app::App;
use crate::audit::store::ChainedEvent;
use crate::authz::grants::{Membership, RoleGrant};
use crate::authz::policy::Policy;
use crate::authz::relations::{AdmittedRelation, RelationTuple, StoredSchema};
use crate::authz::roles::{Group, Role};
use crate::claims::Mapper;
use crate::clients::Client;
use crate::consent::Consent;
use crate::directory::Person;
use crate::keys::SealedSigningKey;
use crate::login::session::Session;
use crate::oidc::code::{AuthorizationCode, PendingAuthorization};
use crate::ports::crypto::WrappedDataKey;
use crate::ports::storage::{RealmLocation, Storage, StorageError, StorageUnavailable, UnitOfWork};
use crate::settings::{PublicOrigin, Settings};
use crate::tenancy::{Realm, RealmId, RealmName, RealmScope, Tenant};
use crate::tokens::store::StoredRefreshToken;

#[derive(Clone, Default)]
pub(crate) struct State {
    pub(crate) tenants: HashMap<Uuid, Tenant>,
    pub(crate) realms: HashMap<Uuid, Realm>,
    /// The chain of each realm, by realm.
    pub(crate) audit: HashMap<Uuid, Vec<ChainedEvent>>,
    /// The newest data key of each realm, by realm.
    pub(crate) data_keys: HashMap<Uuid, WrappedDataKey>,
    /// The signing keys of each realm, oldest first, by realm.
    pub(crate) signing_keys: HashMap<Uuid, Vec<SealedSigningKey>>,
    /// The clients of each realm, by realm.
    pub(crate) clients: HashMap<Uuid, Vec<Client>>,
    /// The people of each realm, by realm.
    pub(crate) persons: HashMap<Uuid, Vec<Person>>,
    /// The password of each person, by person.
    pub(crate) passwords: HashMap<Uuid, String>,
    /// The sessions of each realm, by realm.
    pub(crate) sessions: HashMap<Uuid, Vec<Session>>,
    /// The counters of the brake, by realm, digest and start of bucket.
    pub(crate) login_failures: HashMap<(Uuid, Vec<u8>, OffsetDateTime), u32>,
    /// The requests that wait for their person, by realm.
    pub(crate) pending_authorizations: HashMap<Uuid, Vec<PendingAuthorization>>,
    /// The codes of each realm, with what became of them.
    pub(crate) authorization_codes: HashMap<Uuid, Vec<KeptCode>>,
    /// The browsers people signed in from, by realm.
    pub(crate) known_browsers: HashMap<Uuid, Vec<crate::login::store::KnownBrowser>>,
    /// The refresh tokens of each realm, with what became of them.
    pub(crate) refresh_tokens: HashMap<Uuid, Vec<StoredRefreshToken>>,
    /// The authenticator of each person, by realm then person.
    pub(crate) totp: HashMap<(Uuid, Uuid), crate::login::store::TotpAuthenticator>,
    /// The codes a person typed since their last right one, by realm then person.
    pub(crate) code_attempts: HashMap<(Uuid, Uuid), u32>,
    /// The security keys of each realm, by realm.
    pub(crate) security_keys: HashMap<Uuid, Vec<crate::login::store::SecurityKey>>,
    /// What finishes an enrollment, and when it expires, by realm then person.
    pub(crate) key_enrollments: HashMap<(Uuid, Uuid), (Vec<u8>, OffsetDateTime)>,
    /// The roles of each realm and of its clients, by realm.
    pub(crate) roles: HashMap<Uuid, Vec<Role>>,
    /// The groups of each realm, by realm.
    pub(crate) groups: HashMap<Uuid, Vec<Group>>,
    /// The grants of roles to people and groups, by realm.
    pub(crate) role_grants: HashMap<Uuid, Vec<RoleGrant>>,
    /// The members of groups, by realm.
    pub(crate) memberships: HashMap<Uuid, Vec<Membership>>,
    /// The schema of relations of each realm, by realm.
    pub(crate) relation_schemas: HashMap<Uuid, StoredSchema>,
    /// The kinds of relations the schema of each realm admits, by realm.
    pub(crate) relation_kinds: HashMap<Uuid, Vec<AdmittedRelation>>,
    /// The relations each realm keeps, by realm.
    pub(crate) relations: HashMap<Uuid, Vec<RelationTuple>>,
    /// The clients that guard each type, by realm: (type, client).
    pub(crate) relation_guards: HashMap<Uuid, Vec<(String, String)>>,
    /// The policies of the clients of each realm, by realm.
    pub(crate) policies: HashMap<Uuid, Vec<Policy>>,
    /// By realm, person and client: ordered by client within a person.
    pub(crate) consents: BTreeMap<(Uuid, Uuid, String), Consent>,
    /// The mappers of the clients of each realm, by realm.
    pub(crate) mappers: HashMap<Uuid, Vec<Mapper>>,
    /// The attributes of a person, by realm then person.
    pub(crate) attributes: HashMap<(Uuid, Uuid), serde_json::Map<String, serde_json::Value>>,
}

/// A code as the double keeps it: spent codes stay, so that a replay is told.
#[derive(Clone)]
pub(crate) struct KeptCode {
    pub(crate) code: AuthorizationCode,
    pub(crate) spent_at: Option<OffsetDateTime>,
    pub(crate) family: Option<Uuid>,
    pub(crate) replayed_at: Option<OffsetDateTime>,
}

/// How often units of work read what a test counts, committed or not.
#[derive(Default)]
pub(crate) struct CountedReads {
    /// What a person allowed a client, by any of its reads.
    pub(crate) consents: AtomicUsize,
    pub(crate) pending_authorizations: AtomicUsize,
    /// A client alone, by its identifier.
    pub(crate) clients: AtomicUsize,
    /// The attributes of a person, read without taking them.
    pub(crate) attributes: AtomicUsize,
    /// The roles a person holds at an instant.
    pub(crate) held_roles: AtomicUsize,
    /// The data key of a realm.
    pub(crate) data_keys: AtomicUsize,
    /// The private halves of signing keys, one by one.
    pub(crate) private_keys: AtomicUsize,
}

#[derive(Default)]
pub struct MemoryStorage {
    state: Arc<Mutex<State>>,
    outage: Mutex<Option<StorageUnavailable>>,
    probes: AtomicUsize,
    units_of_work: AtomicUsize,
    /// The units of work opened and not yet dropped.
    live_units: Arc<AtomicUsize>,
    reads: Arc<CountedReads>,
}

pub struct MemoryUnitOfWork {
    scope: RealmScope,
    working: State,
    shared: Arc<Mutex<State>>,
    reads: Arc<CountedReads>,
    /// As on a database, a refused statement ends the transaction: nothing
    /// that follows is kept.
    failed: bool,
    /// Opened as a snapshot: every write is refused.
    read_only: bool,
    live_units: Arc<AtomicUsize>,
}

impl MemoryUnitOfWork {
    /// As a read-only transaction does: a write in a snapshot is refused.
    pub(crate) fn refuse_in_snapshot(&self) -> Result<(), StorageError> {
        if self.read_only {
            return Err(StorageError::Failed);
        }
        Ok(())
    }

    pub(crate) fn record_refusal<T>(
        &mut self,
        outcome: Result<T, StorageError>,
    ) -> Result<T, StorageError> {
        self.failed |= outcome.is_err();
        outcome
    }
}

impl MemoryStorage {
    /// An application wired on doubles, and the storage double to steer it.
    ///
    /// # Panics
    ///
    /// Never: the origin it parses is a constant.
    #[must_use]
    pub fn wire() -> (App, Arc<Self>) {
        let (app, storage, _clock) = Self::wire_with_clock();
        (app, storage)
    }

    /// As [`Self::wire`], with the clock the application reads, to move it.
    ///
    /// # Panics
    ///
    /// Never: the origin it parses is a constant.
    #[must_use]
    pub fn wire_with_clock() -> (App, Arc<Self>, Arc<FixedClock>) {
        let storage = Arc::new(Self::default());
        let clock = Arc::new(FixedClock::default());
        let app = App {
            settings: Settings::reached_directly(
                PublicOrigin::parse("https://id.example.test").expect("a well-formed origin"),
            ),
            storage: storage.clone(),
            clock: clock.clone(),
            random: Arc::new(CountingRandom::default()),
            digester: Arc::new(WeakDigester),
            sealer: Arc::new(TransparentSealer),
            signer: Arc::new(WeakSigner::default()),
            hasher: Arc::new(InstantHasher),
            one_time_codes: Arc::new(PredictableCodes::default()),
            security_keys: Arc::new(TrustingKeys::default()),
            hashing_shares: Arc::new(crate::login::fairness::HashingShares::new(4)),
            decision_shares: Arc::default(),
            key_shares: Arc::default(),
            decoy_hash: Arc::new(OnceLock::new()),
        };
        (app, storage, clock)
    }

    /// Disables the client of that identifier in every realm, as an operator would.
    pub fn disable_client(&self, client_id: &str) {
        for client in lock(&self.state).clients.values_mut().flatten() {
            if client.client_id == client_id {
                client.enabled = false;
            }
        }
    }

    /// Removes the client of that identifier from every realm, as someone
    /// with a hand in the database would: the product removes none.
    pub fn remove_client(&self, client_id: &str) {
        for clients in lock(&self.state).clients.values_mut() {
            clients.retain(|client| client.client_id != client_id);
        }
    }

    /// Makes the storage refuse everything with `reason`, as a database that is down.
    pub fn fail_with(&self, reason: StorageUnavailable) {
        *lock(&self.outage) = Some(reason);
    }

    #[must_use]
    pub fn count_probes(&self) -> usize {
        self.probes.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn count_units_of_work(&self) -> usize {
        self.units_of_work.load(Ordering::Relaxed)
    }

    /// How many units of work are open now: opened, and not yet dropped.
    #[must_use]
    pub fn count_live_units_of_work(&self) -> usize {
        self.live_units.load(Ordering::SeqCst)
    }

    /// How many statements read what a person allowed a client.
    #[must_use]
    pub fn count_consent_reads(&self) -> usize {
        self.reads.consents.load(Ordering::Relaxed)
    }

    /// How many statements read a pending request without taking it.
    #[must_use]
    pub fn count_pending_reads(&self) -> usize {
        self.reads.pending_authorizations.load(Ordering::Relaxed)
    }

    /// How many statements read a client alone, by its identifier.
    #[must_use]
    pub fn count_client_reads(&self) -> usize {
        self.reads.clients.load(Ordering::Relaxed)
    }

    /// How many statements read the attributes of a person without taking them.
    #[must_use]
    pub fn count_attribute_reads(&self) -> usize {
        self.reads.attributes.load(Ordering::Relaxed)
    }

    /// How many statements read the roles a person holds.
    #[must_use]
    pub fn count_held_role_reads(&self) -> usize {
        self.reads.held_roles.load(Ordering::Relaxed)
    }

    /// How many statements read the data key of a realm.
    #[must_use]
    pub fn count_data_key_reads(&self) -> usize {
        self.reads.data_keys.load(Ordering::Relaxed)
    }

    /// How many private halves of signing keys were read.
    #[must_use]
    pub fn count_private_key_reads(&self) -> usize {
        self.reads.private_keys.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn count_tenants(&self) -> usize {
        lock(&self.state).tenants.len()
    }

    #[must_use]
    pub fn count_realms(&self) -> usize {
        lock(&self.state).realms.len()
    }

    /// Disables the person of that username in every realm that has one.
    pub fn disable_person(&self, username: &str) {
        for persons in lock(&self.state).persons.values_mut() {
            for person in persons
                .iter_mut()
                .filter(|person| person.username == username)
            {
                person.enabled = false;
            }
        }
    }

    /// Ends every session, as if each person had signed out.
    pub fn end_every_session(&self) {
        for sessions in lock(&self.state).sessions.values_mut() {
            for session in sessions {
                session.state = crate::login::session::SessionState::Ended;
            }
        }
    }

    /// Disables the realm of that name, as an operator would.
    pub fn disable_realm(&self, name: &str) {
        for realm in lock(&self.state).realms.values_mut() {
            if realm.name.as_str() == name {
                realm.enabled = false;
            }
        }
    }

    /// The envelopes of the chain of a realm, in order, as JSON.
    ///
    /// # Panics
    ///
    /// Panics when a stored envelope is not JSON, which the double never writes.
    #[must_use]
    pub fn read_audit_envelopes(&self, realm: RealmId) -> Vec<serde_json::Value> {
        lock(&self.state)
            .audit
            .get(&realm.as_uuid())
            .map(|chain| {
                chain
                    .iter()
                    .map(|event| serde_json::from_slice(&event.envelope).expect("a JSON envelope"))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Changes the chain of a realm behind the back of the product, as
    /// someone with a hand in the database would.
    pub fn tamper_with_audit_chain(
        &self,
        realm: RealmId,
        tamper: impl FnOnce(&mut Vec<ChainedEvent>),
    ) {
        tamper(lock(&self.state).audit.entry(realm.as_uuid()).or_default());
    }

    fn open(
        &self,
        scope: RealmScope,
        read_only: bool,
    ) -> Result<Box<dyn UnitOfWork>, StorageError> {
        self.check_reachable()?;
        self.units_of_work.fetch_add(1, Ordering::Relaxed);
        self.live_units.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(MemoryUnitOfWork {
            scope,
            working: lock(&self.state).clone(),
            shared: Arc::clone(&self.state),
            reads: Arc::clone(&self.reads),
            failed: false,
            live_units: Arc::clone(&self.live_units),
            read_only,
        }))
    }

    fn check_reachable(&self) -> Result<(), StorageUnavailable> {
        match *lock(&self.outage) {
            Some(reason) => Err(reason),
            None => Ok(()),
        }
    }
}

/// A test that panicked while holding the lock must not hide its own failure
/// behind a second panic.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[async_trait]
impl Storage for MemoryStorage {
    async fn probe(&self) -> Result<(), StorageUnavailable> {
        self.probes.fetch_add(1, Ordering::Relaxed);
        self.check_reachable()
    }

    async fn locate_realm(&self, name: &RealmName) -> Result<Option<RealmLocation>, StorageError> {
        self.check_reachable()?;
        Ok(lock(&self.state)
            .realms
            .values()
            .find(|realm| realm.name == *name)
            .map(|realm| RealmLocation {
                tenant: realm.tenant,
                realm: realm.id,
                enabled: realm.enabled,
            }))
    }

    async fn begin(&self, scope: RealmScope) -> Result<Box<dyn UnitOfWork>, StorageError> {
        self.open(scope, false)
    }

    async fn begin_snapshot(&self, scope: RealmScope) -> Result<Box<dyn UnitOfWork>, StorageError> {
        // The copy a unit of work starts from is a snapshot already.
        self.open(scope, true)
    }
}

#[async_trait]
impl UnitOfWork for MemoryUnitOfWork {
    fn scope(&self) -> RealmScope {
        self.scope
    }

    async fn commit(mut self: Box<Self>) -> Result<(), StorageError> {
        if self.failed {
            return Err(StorageError::Failed);
        }
        *lock(&self.shared) = std::mem::take(&mut self.working);
        Ok(())
    }
}

impl Drop for MemoryUnitOfWork {
    fn drop(&mut self) {
        self.live_units.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::MemoryStorage;
    use crate::testkit::contract::{
        check_audit_contract, check_authenticators_contract, check_claims_contract,
        check_clients_contract, check_codes_contract, check_consents_contract,
        check_ended_sessions_contract, check_grants_contract, check_keys_contract,
        check_known_browsers_contract, check_member_groups_contract, check_persons_contract,
        check_policies_contract, check_refresh_contract, check_relations_contract,
        check_roles_contract, check_security_keys_contract, check_sign_in_contract,
        check_tenancy_contract,
    };
    use crate::testkit::drive::complete;

    #[test]
    fn the_double_passes_the_claims_contract() {
        let (app, _storage) = MemoryStorage::wire();
        complete(check_claims_contract(&app));
    }

    #[test]
    fn the_double_passes_the_tenancy_contract() {
        let (app, _storage) = MemoryStorage::wire();
        complete(check_tenancy_contract(&app));
    }

    #[test]
    fn the_double_passes_the_audit_contract() {
        let (app, _storage) = MemoryStorage::wire();
        complete(check_audit_contract(&app));
    }

    #[test]
    fn the_double_passes_the_keys_contract() {
        let (app, _storage) = MemoryStorage::wire();
        complete(check_keys_contract(&app));
    }

    #[test]
    fn the_double_passes_the_clients_contract() {
        let (app, _storage) = MemoryStorage::wire();
        complete(check_clients_contract(&app));
    }

    #[test]
    fn the_double_passes_the_persons_contract() {
        let (app, _storage) = MemoryStorage::wire();
        complete(check_persons_contract(&app));
    }

    #[test]
    fn the_double_passes_the_sign_in_contract() {
        let (app, _storage) = MemoryStorage::wire();
        complete(check_sign_in_contract(&app));
    }

    #[test]
    fn the_double_passes_the_codes_contract() {
        let (app, _storage) = MemoryStorage::wire();
        complete(check_codes_contract(&app));
    }

    #[test]
    fn the_double_passes_the_known_browsers_contract() {
        let (app, _storage) = MemoryStorage::wire();
        complete(check_known_browsers_contract(&app));
    }

    #[test]
    fn the_double_passes_the_authenticators_contract() {
        let (app, _storage) = MemoryStorage::wire();
        complete(check_authenticators_contract(&app));
    }

    #[test]
    fn the_double_passes_the_ended_sessions_contract() {
        let (app, _storage) = MemoryStorage::wire();
        complete(check_ended_sessions_contract(&app));
    }

    #[test]
    fn the_double_passes_the_security_keys_contract() {
        let (app, _storage) = MemoryStorage::wire();
        complete(check_security_keys_contract(&app));
    }

    #[test]
    fn the_double_passes_the_roles_contract() {
        let (app, _storage) = MemoryStorage::wire();
        complete(check_roles_contract(&app));
    }

    #[test]
    fn the_double_passes_the_grants_contract() {
        let (app, _storage) = MemoryStorage::wire();
        complete(check_grants_contract(&app));
    }

    #[test]
    fn the_double_passes_the_relations_contract() {
        let (app, _storage) = MemoryStorage::wire();
        complete(check_relations_contract(&app));
    }

    #[test]
    fn the_double_passes_the_policies_contract() {
        let (app, _storage) = MemoryStorage::wire();
        complete(check_policies_contract(&app));
    }

    #[test]
    fn the_double_passes_the_member_groups_contract() {
        let (app, _storage) = MemoryStorage::wire();
        complete(check_member_groups_contract(&app));
    }

    #[test]
    fn the_double_passes_the_consents_contract() {
        let (app, _storage) = MemoryStorage::wire();
        complete(check_consents_contract(&app));
    }

    #[test]
    fn the_double_passes_the_refresh_contract() {
        let (app, _storage) = MemoryStorage::wire();
        complete(check_refresh_contract(&app));
    }
}
