use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{KeptCode, MemoryUnitOfWork};
use crate::clients::store::ListWindow;
use crate::directory::Person;
use crate::directory::store::PersonStore;
use crate::login::session::{AuthenticationMethod, Session, SessionState};
use crate::login::store::{
    AuthenticatorStore, KnownBrowser, KnownBrowserStore, SecurityKey, SecurityKeyStore,
    SessionStore, ThrottleStore, TotpAuthenticator, TotpUse,
};
use crate::oidc::code::{
    AuthorizationCode, CodeStore, PendingAuthorization, PendingKeyProof, ReplayedCode,
};
use crate::ports::storage::StorageError;

impl MemoryUnitOfWork {
    fn persons_of_the_realm(&self) -> &[Person] {
        self.working
            .persons
            .get(&self.scope.realm().as_uuid())
            .map_or(&[], Vec::as_slice)
    }

    fn keep_person(&mut self, person: &Person) -> Result<(), StorageError> {
        self.refuse_in_snapshot()?;
        let known = self.persons_of_the_realm();
        if known.iter().any(|other| other.username == person.username) {
            return Err(StorageError::Taken("username"));
        }
        if person.email.is_some() && known.iter().any(|other| other.email == person.email) {
            return Err(StorageError::Taken("email"));
        }
        self.working
            .persons
            .entry(self.scope.realm().as_uuid())
            .or_default()
            .push(person.clone());
        Ok(())
    }

    fn keep_password(&mut self, person: Uuid, phc: &str) -> Result<(), StorageError> {
        self.refuse_in_snapshot()?;
        let known = self
            .persons_of_the_realm()
            .iter()
            .any(|other| other.id == person);
        // A row of the person, as the foreign key and the primary key demand.
        if !known || self.working.passwords.contains_key(&person) {
            return Err(StorageError::Failed);
        }
        self.working.passwords.insert(person, phc.to_owned());
        Ok(())
    }
}

#[async_trait]
impl PersonStore for MemoryUnitOfWork {
    async fn insert_person(&mut self, person: &Person) -> Result<(), StorageError> {
        let outcome = self.keep_person(person);
        self.record_refusal(outcome)
    }

    async fn read_person(&mut self, id: Uuid) -> Result<Option<Person>, StorageError> {
        Ok(self
            .persons_of_the_realm()
            .iter()
            .find(|person| person.id == id)
            .cloned())
    }

    async fn read_person_by_username(
        &mut self,
        username: &str,
    ) -> Result<Option<Person>, StorageError> {
        Ok(self
            .persons_of_the_realm()
            .iter()
            .find(|person| person.username == username)
            .cloned())
    }

    async fn list_persons(&mut self, window: ListWindow) -> Result<Vec<Person>, StorageError> {
        let mut persons = self.persons_of_the_realm().to_vec();
        persons.sort_by(|left, right| left.username.cmp(&right.username));
        Ok(persons
            .into_iter()
            .skip(usize::try_from(window.first).unwrap_or(usize::MAX))
            .take(usize::try_from(window.max).unwrap_or(usize::MAX))
            .collect())
    }

    async fn count_persons(&mut self) -> Result<u64, StorageError> {
        u64::try_from(self.persons_of_the_realm().len()).map_err(|_| StorageError::Failed)
    }

    async fn insert_password(
        &mut self,
        person: Uuid,
        phc: &str,
        _changed_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let outcome = self.keep_password(person, phc);
        self.record_refusal(outcome)
    }

    async fn read_password(&mut self, person: Uuid) -> Result<Option<String>, StorageError> {
        // Only a person of this realm: the scope binds the password too.
        let known = self
            .persons_of_the_realm()
            .iter()
            .any(|other| other.id == person);
        Ok(known
            .then(|| self.working.passwords.get(&person).cloned())
            .flatten())
    }
}

#[async_trait]
impl SessionStore for MemoryUnitOfWork {
    async fn insert_session(&mut self, session: &Session) -> Result<(), StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        self.working
            .sessions
            .entry(self.scope.realm().as_uuid())
            .or_default()
            .push(session.clone());
        Ok(())
    }

    async fn read_session(&mut self, id: Uuid) -> Result<Option<Session>, StorageError> {
        Ok(self
            .working
            .sessions
            .get(&self.scope.realm().as_uuid())
            .and_then(|sessions| sessions.iter().find(|session| session.id == id))
            .cloned())
    }

    async fn end_session(&mut self, id: Uuid) -> Result<bool, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let Some(active) = self
            .working
            .sessions
            .get_mut(&self.scope.realm().as_uuid())
            .and_then(|sessions| {
                sessions
                    .iter_mut()
                    .find(|session| session.id == id && session.state == SessionState::Active)
            })
        else {
            return Ok(false);
        };
        active.state = SessionState::Ended;
        Ok(true)
    }

    async fn end_sessions_proven_only_by(
        &mut self,
        person: Uuid,
        methods: &[AuthenticationMethod],
        kept: Option<Uuid>,
    ) -> Result<Vec<Uuid>, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let mut ended = Vec::new();
        if let Some(sessions) = self.working.sessions.get_mut(&self.scope.realm().as_uuid()) {
            for session in sessions.iter_mut().filter(|session| {
                session.person == person
                    && session.state == SessionState::Active
                    && session.methods == methods
                    && Some(session.id) != kept
            }) {
                session.state = SessionState::Ended;
                ended.push(session.id);
            }
        }
        Ok(ended)
    }
}

#[async_trait]
impl ThrottleStore for MemoryUnitOfWork {
    async fn count_login_failures(
        &mut self,
        identifier_digest: &[u8],
        since: OffsetDateTime,
    ) -> Result<u32, StorageError> {
        let realm = self.scope.realm().as_uuid();
        Ok(self
            .working
            .login_failures
            .iter()
            .filter(|((owner, digest, bucket), _)| {
                *owner == realm && digest.as_slice() == identifier_digest && *bucket >= since
            })
            .map(|(_, failures)| *failures)
            .sum())
    }

    async fn record_login_failure(
        &mut self,
        identifier_digest: &[u8],
        bucket_start: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let key = (
            self.scope.realm().as_uuid(),
            identifier_digest.to_vec(),
            bucket_start,
        );
        *self.working.login_failures.entry(key).or_default() += 1;
        Ok(())
    }

    async fn forget_login_failures(
        &mut self,
        identifier_digest: &[u8],
    ) -> Result<(), StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let realm = self.scope.realm().as_uuid();
        self.working.login_failures.retain(|(owner, digest, _), _| {
            *owner != realm || digest.as_slice() != identifier_digest
        });
        Ok(())
    }
}

#[async_trait]
impl CodeStore for MemoryUnitOfWork {
    async fn insert_pending_authorization(
        &mut self,
        pending: &PendingAuthorization,
    ) -> Result<(), StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        self.working
            .pending_authorizations
            .entry(self.scope.realm().as_uuid())
            .or_default()
            .push(pending.clone());
        Ok(())
    }

    async fn read_pending_authorization(
        &mut self,
        id: Uuid,
        now: OffsetDateTime,
    ) -> Result<Option<PendingAuthorization>, StorageError> {
        Ok(self
            .working
            .pending_authorizations
            .get(&self.scope.realm().as_uuid())
            .and_then(|pending| {
                pending
                    .iter()
                    .find(|request| request.id == id && request.expires_at > now)
            })
            .cloned())
    }

    async fn mark_first_factor(
        &mut self,
        id: Uuid,
        person: Uuid,
        key_proof: Option<&PendingKeyProof>,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let waiting = self
            .working
            .pending_authorizations
            .get_mut(&self.scope.realm().as_uuid())
            .and_then(|pending| {
                pending
                    .iter_mut()
                    .find(|request| request.id == id && request.expires_at > now)
            });
        Ok(waiting.is_some_and(|request| {
            request.first_factor = Some(person);
            request.key_proof = key_proof.cloned();
            true
        }))
    }

    async fn take_pending_authorization(
        &mut self,
        id: Uuid,
        now: OffsetDateTime,
    ) -> Result<Option<PendingAuthorization>, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let Some(pending) = self
            .working
            .pending_authorizations
            .get_mut(&self.scope.realm().as_uuid())
        else {
            return Ok(None);
        };
        // As the statement does: an expired request is neither returned nor removed.
        let Some(position) = pending
            .iter()
            .position(|request| request.id == id && request.expires_at > now)
        else {
            return Ok(None);
        };
        Ok(Some(pending.remove(position)))
    }

    async fn insert_authorization_code(
        &mut self,
        code: &AuthorizationCode,
    ) -> Result<(), StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        self.working
            .authorization_codes
            .entry(self.scope.realm().as_uuid())
            .or_default()
            .push(KeptCode {
                code: code.clone(),
                spent_at: None,
                family: None,
                replayed_at: None,
            });
        Ok(())
    }

    async fn spend_authorization_code(
        &mut self,
        code_digest: &[u8],
        now: OffsetDateTime,
    ) -> Result<Option<AuthorizationCode>, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let Some(kept) = self.find_code(code_digest) else {
            return Ok(None);
        };
        if kept.spent_at.is_some() || kept.code.expires_at <= now {
            return Ok(None);
        }
        kept.spent_at = Some(now);
        Ok(Some(kept.code.clone()))
    }

    async fn bind_code_family(
        &mut self,
        code_digest: &[u8],
        family: Uuid,
    ) -> Result<bool, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let Some(kept) = self.find_code(code_digest) else {
            return Ok(false);
        };
        if kept.spent_at.is_none() || kept.replayed_at.is_some() {
            return Ok(false);
        }
        kept.family = Some(family);
        Ok(true)
    }

    async fn mark_code_replayed(
        &mut self,
        code_digest: &[u8],
        client_id: &str,
        now: OffsetDateTime,
    ) -> Result<Option<ReplayedCode>, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let Some(kept) = self.find_code(code_digest) else {
            return Ok(None);
        };
        if kept.spent_at.is_none() || kept.replayed_at.is_some() || kept.code.client_id != client_id
        {
            return Ok(None);
        }
        kept.replayed_at = Some(now);
        Ok(Some(ReplayedCode {
            person: kept.code.person,
            session: kept.code.session,
            family: kept.family,
        }))
    }
}

impl MemoryUnitOfWork {
    fn find_code(&mut self, code_digest: &[u8]) -> Option<&mut KeptCode> {
        self.working
            .authorization_codes
            .get_mut(&self.scope.realm().as_uuid())?
            .iter_mut()
            .find(|kept| kept.code.code_digest == code_digest)
    }
}

#[async_trait]
impl KnownBrowserStore for MemoryUnitOfWork {
    async fn remember_browser(
        &mut self,
        browser: &KnownBrowser,
        keep: u32,
    ) -> Result<(), StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let kept = self
            .working
            .known_browsers
            .entry(self.scope.realm().as_uuid())
            .or_default();
        match kept.iter_mut().find(|known| known.device == browser.device) {
            Some(known) if known.person == browser.person => known.expires_at = browser.expires_at,
            Some(_) => {}
            None => kept.push(browser.clone()),
        }
        let mut of_the_person: Vec<(OffsetDateTime, Uuid)> = kept
            .iter()
            .filter(|known| known.person == browser.person)
            .map(|known| (known.expires_at, known.device))
            .collect();
        // The order of the statement on Postgres: latest expiry first, then the device.
        of_the_person.sort_by(|left, right| right.0.cmp(&left.0).then(left.1.cmp(&right.1)));
        let limit = usize::try_from(keep).unwrap_or(usize::MAX);
        let forgotten: Vec<Uuid> = of_the_person
            .into_iter()
            .skip(limit)
            .map(|(_, device)| device)
            .collect();
        kept.retain(|known| !forgotten.contains(&known.device));
        Ok(())
    }

    async fn read_live_browsers(
        &mut self,
        devices: &[Uuid],
        now: OffsetDateTime,
    ) -> Result<Vec<KnownBrowser>, StorageError> {
        Ok(self
            .working
            .known_browsers
            .get(&self.scope.realm().as_uuid())
            .map(|kept| {
                kept.iter()
                    .filter(|known| devices.contains(&known.device) && known.expires_at > now)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default())
    }
}

#[async_trait]
impl AuthenticatorStore for MemoryUnitOfWork {
    async fn write_pending_totp(
        &mut self,
        authenticator: &TotpAuthenticator,
    ) -> Result<bool, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let key = (self.scope.realm().as_uuid(), authenticator.person);
        if self
            .working
            .totp
            .get(&key)
            .is_some_and(|known| known.confirmed_at.is_some())
        {
            return Ok(false);
        }
        self.working.totp.insert(key, authenticator.clone());
        Ok(true)
    }

    async fn read_totp(&mut self, person: Uuid) -> Result<Option<TotpAuthenticator>, StorageError> {
        Ok(self
            .working
            .totp
            .get(&(self.scope.realm().as_uuid(), person))
            .cloned())
    }

    async fn accept_totp_step(
        &mut self,
        person: Uuid,
        judged: &[u8],
        step: i64,
        used_for: TotpUse,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let Some(known) = self
            .working
            .totp
            .get_mut(&(self.scope.realm().as_uuid(), person))
        else {
            return Ok(false);
        };
        let confirming = used_for == TotpUse::Confirmation;
        if known.sealed_secret != judged
            || known.confirmed_at.is_none() != confirming
            || known.last_step.is_some_and(|last| last >= step)
        {
            return Ok(false);
        }
        known.last_step = Some(step);
        known.confirmed_at.get_or_insert(now);
        Ok(true)
    }

    async fn delete_totp(&mut self, person: Uuid) -> Result<bool, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        Ok(self
            .working
            .totp
            .remove(&(self.scope.realm().as_uuid(), person))
            .is_some())
    }

    async fn count_code_attempt(
        &mut self,
        person: Uuid,
        _now: OffsetDateTime,
    ) -> Result<u32, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let attempts = self
            .working
            .code_attempts
            .entry((self.scope.realm().as_uuid(), person))
            .or_insert(0);
        *attempts = attempts.saturating_add(1);
        Ok(*attempts)
    }

    async fn clear_code_attempts(&mut self, person: Uuid) -> Result<(), StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        self.working
            .code_attempts
            .remove(&(self.scope.realm().as_uuid(), person));
        Ok(())
    }
}

#[async_trait]
impl SecurityKeyStore for MemoryUnitOfWork {
    async fn insert_security_key(&mut self, key: &SecurityKey) -> Result<bool, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let keys = self
            .working
            .security_keys
            .entry(self.scope.realm().as_uuid())
            .or_default();
        if keys
            .iter()
            .any(|known| known.credential_id == key.credential_id)
        {
            return Ok(false);
        }
        keys.push(key.clone());
        Ok(true)
    }

    async fn list_security_keys(&mut self, person: Uuid) -> Result<Vec<SecurityKey>, StorageError> {
        let mut held: Vec<SecurityKey> = self
            .working
            .security_keys
            .get(&self.scope.realm().as_uuid())
            .into_iter()
            .flatten()
            .filter(|key| key.person == person)
            .cloned()
            .collect();
        held.sort_by(|left, right| {
            (left.created_at, &left.credential_id).cmp(&(right.created_at, &right.credential_id))
        });
        Ok(held)
    }

    async fn record_key_use(
        &mut self,
        judged: &SecurityKey,
        record: Option<&[u8]>,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let Some(key) = self
            .working
            .security_keys
            .get_mut(&self.scope.realm().as_uuid())
            .and_then(|keys| {
                keys.iter_mut().find(|key| {
                    key.person == judged.person
                        && key.credential_id == judged.credential_id
                        && key.record == judged.record
                        && key.last_used_at == judged.last_used_at
                })
            })
        else {
            return Ok(false);
        };
        key.record = record.unwrap_or(&judged.record).to_vec();
        key.last_used_at = Some(now);
        Ok(true)
    }

    async fn delete_security_keys(&mut self, person: Uuid) -> Result<u64, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let Some(keys) = self
            .working
            .security_keys
            .get_mut(&self.scope.realm().as_uuid())
        else {
            return Ok(0);
        };
        let before = keys.len();
        keys.retain(|key| key.person != person);
        Ok(u64::try_from(before - keys.len()).unwrap_or(u64::MAX))
    }

    async fn write_key_enrollment(
        &mut self,
        person: Uuid,
        state: &[u8],
        expires_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        self.working.key_enrollments.insert(
            (self.scope.realm().as_uuid(), person),
            (state.to_vec(), expires_at),
        );
        Ok(())
    }

    async fn take_key_enrollment(
        &mut self,
        person: Uuid,
        now: OffsetDateTime,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        let key = (self.scope.realm().as_uuid(), person);
        // As the statement does: an expired enrollment is neither returned nor removed.
        if self
            .working
            .key_enrollments
            .get(&key)
            .is_none_or(|(_, expires_at)| *expires_at <= now)
        {
            return Ok(None);
        }
        Ok(self
            .working
            .key_enrollments
            .remove(&key)
            .map(|(state, _)| state))
    }
}
