use async_trait::async_trait;
use saffui_core::keys::SigningKey;
use saffui_core::keys::store::KeyStore;
use saffui_core::ports::crypto::{SignatureAlgorithm, WrappedDataKey};
use saffui_core::ports::storage::StorageError;

use crate::query::bind::col;
use crate::query::ident::Column;
use crate::query::insert::Insert;
use crate::query::select::{Select, SortDirection};
use crate::schema::{realm_data_keys, signing_keys};
use crate::work::PgUnitOfWork;

const DATA_KEY: &[Column] = &[realm_data_keys::GENERATION, realm_data_keys::WRAPPED];
const SIGNING_KEY: &[Column] = &[
    signing_keys::SIGNING_KEY_ID,
    signing_keys::KID,
    signing_keys::ALGORITHM,
    signing_keys::PUBLIC_JWK,
    signing_keys::SEALED_PRIVATE_KEY,
    signing_keys::CREATED_AT,
];

#[async_trait]
impl KeyStore for PgUnitOfWork {
    async fn insert_data_key(&mut self, key: &WrappedDataKey) -> Result<(), StorageError> {
        let generation = i32::try_from(key.generation).map_err(|_| StorageError::Failed)?;
        let insert = Insert::into(
            realm_data_keys::TABLE,
            vec![
                col(realm_data_keys::GENERATION, &generation),
                col(realm_data_keys::WRAPPED, &key.wrapped),
            ],
        )
        .build();
        self.execute(&insert).await.map(|_| ())
    }

    async fn read_data_key(&mut self) -> Result<Option<WrappedDataKey>, StorageError> {
        // The newest generation is the one that seals.
        let select = Select::from(realm_data_keys::TABLE, DATA_KEY)
            .sorted_by(realm_data_keys::GENERATION, SortDirection::Descending)
            .first_row_only()
            .build();
        self.read_one(&select)
            .await?
            .map(|row| {
                Ok(WrappedDataKey {
                    generation: u32::try_from(row.get::<_, i32>(0))
                        .map_err(|_| StorageError::Failed)?,
                    wrapped: row.get(1),
                })
            })
            .transpose()
    }

    async fn insert_signing_key(&mut self, key: &SigningKey) -> Result<(), StorageError> {
        let algorithm = key.algorithm.name();
        let insert = Insert::into(
            signing_keys::TABLE,
            vec![
                col(signing_keys::SIGNING_KEY_ID, &key.id),
                col(signing_keys::KID, &key.key_id),
                col(signing_keys::ALGORITHM, &algorithm),
                col(signing_keys::PUBLIC_JWK, &key.public_jwk),
                col(signing_keys::SEALED_PRIVATE_KEY, &key.sealed_private_key),
                col(signing_keys::CREATED_AT, &key.created_at),
            ],
        )
        .build();
        self.execute(&insert).await.map(|_| ())
    }

    async fn list_signing_keys(&mut self) -> Result<Vec<SigningKey>, StorageError> {
        // The identifier breaks the ties of the instant: the order is total.
        let select = Select::from(signing_keys::TABLE, SIGNING_KEY)
            .sorted_by(signing_keys::CREATED_AT, SortDirection::Ascending)
            .sorted_by(signing_keys::SIGNING_KEY_ID, SortDirection::Ascending)
            .build();
        self.read_all(&select)
            .await?
            .iter()
            .map(|row| {
                // The schema holds the list: a name unknown here was not
                // written by this binary.
                let algorithm: String = row.get(2);
                Ok(SigningKey {
                    id: row.get(0),
                    key_id: row.get(1),
                    algorithm: SignatureAlgorithm::parse(&algorithm).ok_or(StorageError::Failed)?,
                    public_jwk: row.get(3),
                    sealed_private_key: row.get(4),
                    created_at: row.get(5),
                })
            })
            .collect()
    }
}
