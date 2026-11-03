use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{KeptCode, MemoryUnitOfWork};
use crate::clients::store::ListWindow;
use crate::directory::Person;
use crate::directory::store::PersonStore;
use crate::login::session::{Session, SessionState};
use crate::login::store::{KnownBrowser, KnownBrowserStore, SessionStore, ThrottleStore};
use crate::oidc::code::{AuthorizationCode, CodeStore, PendingAuthorization, ReplayedCode};
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

    async fn end_session(&mut self, id: Uuid) -> Result<(), StorageError> {
        let outcome = self.refuse_in_snapshot();
        self.record_refusal(outcome)?;
        if let Some(sessions) = self.working.sessions.get_mut(&self.scope.realm().as_uuid()) {
            for session in sessions.iter_mut().filter(|session| session.id == id) {
                session.state = SessionState::Ended;
            }
        }
        Ok(())
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
        if kept.spent_at.is_none() || kept.code.client_id != client_id {
            return Ok(None);
        }
        kept.replayed_at.get_or_insert(now);
        Ok(Some(ReplayedCode {
            person: kept.code.person,
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

    async fn read_known_browser(
        &mut self,
        device: Uuid,
    ) -> Result<Option<KnownBrowser>, StorageError> {
        Ok(self
            .working
            .known_browsers
            .get(&self.scope.realm().as_uuid())
            .and_then(|kept| kept.iter().find(|known| known.device == device))
            .cloned())
    }
}
