use async_trait::async_trait;
use saffui_core::keys::store::KeyStore;
use saffui_core::keys::{KeyStatus, SealedSigningKey, SigningKey};
use saffui_core::ports::crypto::{SignatureAlgorithm, WrappedDataKey};
use saffui_core::ports::storage::StorageError;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::query::bind::col;
use crate::query::criteria::Criteria;
use crate::query::ident::Column;
use crate::query::insert::Insert;
use crate::query::list_query::ListQuery;
use crate::query::select::{Select, SortDirection};
use crate::schema::{realm_data_keys, signing_keys};
use crate::work::PgUnitOfWork;

const DATA_KEY: &[Column] = &[realm_data_keys::GENERATION, realm_data_keys::WRAPPED];
/// The public half of a key: what is verified, published and listed.
const PUBLIC_KEY: &[Column] = &[
    signing_keys::SIGNING_KEY_ID,
    signing_keys::KID,
    signing_keys::ALGORITHM,
    signing_keys::PUBLIC_JWK,
    signing_keys::CREATED_AT,
    signing_keys::STATUS,
];

/// Constant SQL: the data keys of the realm stay locked until the commit, in
/// the order of their generations, and the last is the latest. A rotation
/// waits for them; a read of the keys does not.
const LOCK_SIGNING_KEYS: &str = "
    SELECT generation, wrapped FROM realm_data_keys
    WHERE tenant_id = $1 AND realm_id = $2
    ORDER BY generation
    FOR NO KEY UPDATE";

/// Constant SQL: the one read that carries a private half, of an active key
/// alone, by the index that holds one active key per algorithm.
const READ_ACTIVE_KEYS: &str = "
    SELECT signing_key_id, kid, algorithm, public_jwk, created_at, status, sealed_private_key
    FROM signing_keys
    WHERE tenant_id = $1 AND realm_id = $2 AND status = 'active' AND algorithm = ANY($3)";

const RETIRE_SIGNING_KEY: &str = "
    UPDATE signing_keys SET status = 'retired'
    WHERE tenant_id = $1 AND realm_id = $2 AND signing_key_id = $3 AND status = 'active'";

const DELETE_RETIRED_KEY: &str = "
    DELETE FROM signing_keys
    WHERE tenant_id = $1 AND realm_id = $2 AND signing_key_id = $3 AND status = 'retired'";

/// Reads the public half of a key from the first six columns of a row.
fn read_public_row(row: &Row) -> Result<SigningKey, StorageError> {
    // The schema holds both lists: a name unknown here was not written by
    // this binary.
    let (algorithm, status): (String, String) = (row.get(2), row.get(5));
    Ok(SigningKey {
        id: row.get(0),
        key_id: row.get(1),
        algorithm: SignatureAlgorithm::parse(&algorithm).ok_or(StorageError::Failed)?,
        status: KeyStatus::parse(&status).ok_or(StorageError::Failed)?,
        public_jwk: row.get(3),
        created_at: row.get(4),
    })
}

fn read_data_key_row(row: &Row) -> Result<WrappedDataKey, StorageError> {
    Ok(WrappedDataKey {
        generation: u32::try_from(row.get::<_, i32>(0)).map_err(|_| StorageError::Failed)?,
        wrapped: row.get(1),
    })
}

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
            .as_ref()
            .map(read_data_key_row)
            .transpose()
    }

    async fn insert_signing_key(&mut self, sealed: &SealedSigningKey) -> Result<(), StorageError> {
        let key = &sealed.key;
        let (algorithm, status) = (key.algorithm.name(), key.status.name());
        let insert = Insert::into(
            signing_keys::TABLE,
            vec![
                col(signing_keys::SIGNING_KEY_ID, &key.id),
                col(signing_keys::KID, &key.key_id),
                col(signing_keys::ALGORITHM, &algorithm),
                col(signing_keys::PUBLIC_JWK, &key.public_jwk),
                col(signing_keys::SEALED_PRIVATE_KEY, &sealed.sealed_private_key),
                col(signing_keys::CREATED_AT, &key.created_at),
                col(signing_keys::STATUS, &status),
            ],
        )
        .build();
        self.execute(&insert).await.map(|_| ())
    }

    async fn list_signing_keys(&mut self) -> Result<Vec<SigningKey>, StorageError> {
        // The identifier breaks the ties of the instant: the order is total.
        let select = Select::from(signing_keys::TABLE, PUBLIC_KEY)
            .sorted_by(signing_keys::CREATED_AT, SortDirection::Ascending)
            .sorted_by(signing_keys::SIGNING_KEY_ID, SortDirection::Ascending)
            .build();
        self.read_all(&select)
            .await?
            .iter()
            .map(read_public_row)
            .collect()
    }

    async fn read_signing_key(&mut self, key_id: &str) -> Result<Option<SigningKey>, StorageError> {
        let select = Select::from(signing_keys::TABLE, PUBLIC_KEY)
            .filter(Criteria::new().where_equal(signing_keys::KID, &key_id))
            .build();
        self.read_one(&select)
            .await?
            .as_ref()
            .map(read_public_row)
            .transpose()
    }

    async fn count_signing_keys(&mut self) -> Result<usize, StorageError> {
        let total = ListQuery::count(signing_keys::TABLE);
        let counted: i64 = self
            .read_one(&total)
            .await?
            .ok_or(StorageError::Failed)?
            .get(0);
        usize::try_from(counted).map_err(|_| StorageError::Failed)
    }

    async fn read_active_keys(
        &mut self,
        algorithms: &[SignatureAlgorithm],
    ) -> Result<Vec<SealedSigningKey>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let names: Vec<&str> = algorithms
            .iter()
            .map(|algorithm| algorithm.name())
            .collect();
        self.read_raw(READ_ACTIVE_KEYS, &[&tenant, &realm, &names])
            .await?
            .iter()
            .map(|row| {
                Ok(SealedSigningKey {
                    key: read_public_row(row)?,
                    sealed_private_key: row.get(6),
                })
            })
            .collect()
    }

    async fn lock_signing_keys(&mut self) -> Result<Option<WrappedDataKey>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let taken = self.read_raw(LOCK_SIGNING_KEYS, &[&tenant, &realm]).await?;
        taken.last().map(read_data_key_row).transpose()
    }

    async fn retire_signing_key(&mut self, id: Uuid) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let retired = self
            .execute_raw(RETIRE_SIGNING_KEY, &[&tenant, &realm, &id])
            .await?;
        Ok(retired == 1)
    }

    async fn delete_retired_key(&mut self, id: Uuid) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let removed = self
            .execute_raw(DELETE_RETIRED_KEY, &[&tenant, &realm, &id])
            .await?;
        Ok(removed == 1)
    }
}

#[cfg(test)]
mod tests {
    use pgcore::migrate::EMBEDDED;
    use pgcore::testkit::TestDatabase;
    use uuid::Uuid;

    use super::READ_ACTIVE_KEYS;

    /// A realm whose keys were turned over by the thousand, past any bound
    /// the product holds: the keys that sign are read by the index that
    /// holds one active key per algorithm, not from every key of the realm.
    #[tokio::test]
    async fn the_keys_that_sign_are_read_by_the_index_of_the_active_keys() {
        let database = TestDatabase::create(EMBEDDED).await;
        let mut owner = database
            .plan("saffui_owner")
            .connect_directly()
            .await
            .expect("a connection");
        let (tenant, realm) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let planting = owner.transaction().await.expect("a transaction");
        planting
            .batch_execute(&format!(
                "SELECT set_config('saffui.tenant', '{tenant}', true),
                        set_config('saffui.realm', '{realm}', true);
                 INSERT INTO tenants VALUES ('{tenant}', 'acme', now());
                 INSERT INTO realms VALUES ('{tenant}', '{realm}', 'acme', true, now());
                 INSERT INTO signing_keys (tenant_id, realm_id, signing_key_id, kid, algorithm,
                                           public_jwk, sealed_private_key, created_at, status)
                     SELECT '{tenant}', '{realm}', gen_random_uuid(), gen_random_uuid()::text,
                            a.algorithm, '{{}}', '\\x00', now(),
                            CASE WHEN t.turn = 1 THEN 'active' ELSE 'retired' END
                     FROM unnest(ARRAY['ES256', 'ES384', 'RS256', 'PS256', 'EdDSA']) AS a(algorithm)
                     CROSS JOIN generate_series(1, 1000) AS t(turn);"
            ))
            .await
            .expect("the keys of a realm");
        planting.commit().await.expect("a commit");
        owner
            .batch_execute("ANALYZE signing_keys")
            .await
            .expect("statistics");
        let algorithms = vec!["ES256", "RS256"];

        let plan: Vec<String> = owner
            .query(
                &format!("EXPLAIN {READ_ACTIVE_KEYS}"),
                &[&tenant, &realm, &algorithms],
            )
            .await
            .expect("the plan of the read")
            .iter()
            .map(|row| row.get(0))
            .collect();

        assert!(
            plan.iter()
                .any(|line| line.contains("signing_keys_one_active")),
            "{plan:#?}"
        );
    }
}
