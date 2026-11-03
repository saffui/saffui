use async_trait::async_trait;
use saffui_core::clients::Client;
use saffui_core::clients::store::ClientStore;
use saffui_core::ports::storage::StorageError;

use crate::query::bind::col;
use crate::query::criteria::Criteria;
use crate::query::ident::Column;
use crate::query::insert::Insert;
use crate::query::select::Select;
use crate::schema::clients;
use crate::work::PgUnitOfWork;

const CLIENT: &[Column] = &[
    clients::CLIENT_ROW_ID,
    clients::CLIENT_ID,
    clients::NAME,
    clients::SECRET_DIGEST,
    clients::ALLOWS_CLIENT_CREDENTIALS,
    clients::SCOPES,
    clients::ENABLED,
    clients::CREATED_AT,
];

#[async_trait]
impl ClientStore for PgUnitOfWork {
    async fn insert_client(&mut self, client: &Client) -> Result<(), StorageError> {
        let insert = Insert::into(
            clients::TABLE,
            vec![
                col(clients::CLIENT_ROW_ID, &client.id),
                col(clients::CLIENT_ID, &client.client_id),
                col(clients::NAME, &client.name),
                col(clients::SECRET_DIGEST, &client.secret_digest),
                col(
                    clients::ALLOWS_CLIENT_CREDENTIALS,
                    &client.allows_client_credentials,
                ),
                col(clients::SCOPES, &client.scopes),
                col(clients::ENABLED, &client.enabled),
                col(clients::CREATED_AT, &client.created_at),
            ],
        )
        .build();
        self.execute(&insert).await.map(|_| ())
    }

    async fn read_client(&mut self, client_id: &str) -> Result<Option<Client>, StorageError> {
        let select = Select::from(clients::TABLE, CLIENT)
            .filter(Criteria::new().where_equal(clients::CLIENT_ID, &client_id))
            .build();
        Ok(self.read_one(&select).await?.map(|row| Client {
            id: row.get(0),
            client_id: row.get(1),
            name: row.get(2),
            secret_digest: row.get(3),
            allows_client_credentials: row.get(4),
            scopes: row.get(5),
            enabled: row.get(6),
            created_at: row.get(7),
        }))
    }
}
