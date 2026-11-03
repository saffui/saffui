use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

use super::MemoryUnitOfWork;
use crate::clients::store::ListWindow;
use crate::directory::Person;
use crate::directory::store::PersonStore;
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
