use async_trait::async_trait;
use saffui_core::clients::store::ListWindow;
use saffui_core::directory::Person;
use saffui_core::directory::store::PersonStore;
use saffui_core::ports::storage::StorageError;
use time::OffsetDateTime;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::query::bind::col;
use crate::query::criteria::Criteria;
use crate::query::ident::Column;
use crate::query::insert::Insert;
use crate::query::list_query::ListQuery;
use crate::query::select::{Select, SortDirection};
use crate::schema::{password_credentials, persons};
use crate::work::PgUnitOfWork;

/// What is read of a person, in the order `read_person_row` reads it.
const PERSON: &[Column] = &[
    persons::PERSON_ID,
    persons::USERNAME,
    persons::EMAIL,
    persons::EMAIL_VERIFIED,
    persons::DISPLAY_NAME,
    persons::ENABLED,
    persons::CREATED_AT,
];
const PASSWORD: &[Column] = &[password_credentials::PHC];

fn read_person_row(row: &Row) -> Person {
    Person {
        id: row.get(0),
        username: row.get(1),
        email: row.get(2),
        email_verified: row.get(3),
        display_name: row.get(4),
        enabled: row.get(5),
        created_at: row.get(6),
    }
}

#[async_trait]
impl PersonStore for PgUnitOfWork {
    async fn insert_person(&mut self, person: &Person) -> Result<(), StorageError> {
        let insert = Insert::into(
            persons::TABLE,
            vec![
                col(persons::PERSON_ID, &person.id),
                col(persons::USERNAME, &person.username),
                col(persons::EMAIL, &person.email),
                col(persons::EMAIL_VERIFIED, &person.email_verified),
                col(persons::DISPLAY_NAME, &person.display_name),
                col(persons::ENABLED, &person.enabled),
                col(persons::CREATED_AT, &person.created_at),
            ],
        )
        .build();
        self.execute(&insert).await.map(|_| ())
    }

    async fn read_person(&mut self, id: Uuid) -> Result<Option<Person>, StorageError> {
        let select = Select::from(persons::TABLE, PERSON)
            .filter(Criteria::new().where_equal(persons::PERSON_ID, &id))
            .build();
        Ok(self.read_one(&select).await?.as_ref().map(read_person_row))
    }

    async fn read_person_by_username(
        &mut self,
        username: &str,
    ) -> Result<Option<Person>, StorageError> {
        let select = Select::from(persons::TABLE, PERSON)
            .filter(Criteria::new().where_equal(persons::USERNAME, &username))
            .build();
        Ok(self.read_one(&select).await?.as_ref().map(read_person_row))
    }

    async fn list_persons(&mut self, window: ListWindow) -> Result<Vec<Person>, StorageError> {
        // The name is unique in the realm: the order is total.
        let query = ListQuery::new(window).sorted_by(persons::USERNAME, SortDirection::Ascending);
        let page = query.select(persons::TABLE, PERSON);
        Ok(self
            .read_all(&page)
            .await?
            .iter()
            .map(read_person_row)
            .collect())
    }

    async fn count_persons(&mut self) -> Result<u64, StorageError> {
        let total = ListQuery::count(persons::TABLE);
        let counted: i64 = self
            .read_one(&total)
            .await?
            .ok_or(StorageError::Failed)?
            .get(0);
        u64::try_from(counted).map_err(|_| StorageError::Failed)
    }

    async fn insert_password(
        &mut self,
        person: Uuid,
        phc: &str,
        changed_at: OffsetDateTime,
    ) -> Result<(), StorageError> {
        let insert = Insert::into(
            password_credentials::TABLE,
            vec![
                col(password_credentials::PERSON_ID, &person),
                col(password_credentials::PHC, &phc),
                col(password_credentials::CHANGED_AT, &changed_at),
            ],
        )
        .build();
        self.execute(&insert).await.map(|_| ())
    }

    async fn read_password(&mut self, person: Uuid) -> Result<Option<String>, StorageError> {
        let select = Select::from(password_credentials::TABLE, PASSWORD)
            .filter(Criteria::new().where_equal(password_credentials::PERSON_ID, &person))
            .build();
        Ok(self.read_one(&select).await?.map(|row| row.get(0)))
    }
}
