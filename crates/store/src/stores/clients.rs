use async_trait::async_trait;
use saffui_core::authz::capability::Capability;
use saffui_core::clients::Client;
use saffui_core::clients::store::{ClientStore, ListWindow};
use saffui_core::ports::storage::StorageError;
use tokio_postgres::Row;

use crate::query::bind::col;
use crate::query::criteria::Criteria;
use crate::query::ident::Column;
use crate::query::insert::Insert;
use crate::query::list_query::ListQuery;
use crate::query::select::{Select, SortDirection};
use crate::schema::clients;
use crate::work::PgUnitOfWork;

const CLIENT: &[Column] = &[
    clients::CLIENT_ROW_ID,
    clients::CLIENT_ID,
    clients::NAME,
    clients::SECRET_DIGEST,
    clients::ALLOWS_CLIENT_CREDENTIALS,
    clients::SCOPES,
    clients::CAPABILITIES,
    clients::ENABLED,
    clients::CREATED_AT,
    clients::ALLOWS_AUTHORIZATION_CODE,
    clients::REDIRECT_URIS,
];

fn read_client_row(row: &Row) -> Result<Client, StorageError> {
    let capabilities: Vec<String> = row.get(6);
    Ok(Client {
        id: row.get(0),
        client_id: row.get(1),
        name: row.get(2),
        secret_digest: row.get(3),
        allows_client_credentials: row.get(4),
        allows_authorization_code: row.get(9),
        redirect_uris: row.get(10),
        scopes: row.get(5),
        // The schema holds the same list: a name unknown here was not
        // written by this binary.
        capabilities: capabilities
            .iter()
            .map(|name| Capability::parse(name).ok_or(StorageError::Failed))
            .collect::<Result<_, _>>()?,
        enabled: row.get(7),
        created_at: row.get(8),
    })
}

#[async_trait]
impl ClientStore for PgUnitOfWork {
    async fn insert_client(&mut self, client: &Client) -> Result<(), StorageError> {
        let capabilities: Vec<&str> = client
            .capabilities
            .iter()
            .map(|granted| granted.name())
            .collect();
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
                col(
                    clients::ALLOWS_AUTHORIZATION_CODE,
                    &client.allows_authorization_code,
                ),
                col(clients::REDIRECT_URIS, &client.redirect_uris),
                col(clients::SCOPES, &client.scopes),
                col(clients::CAPABILITIES, &capabilities),
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
        self.read_one(&select)
            .await?
            .as_ref()
            .map(read_client_row)
            .transpose()
    }

    async fn list_clients(&mut self, window: ListWindow) -> Result<Vec<Client>, StorageError> {
        // The identifier is unique in the realm: the order is total, so a
        // window neither repeats a row nor skips one.
        let query = ListQuery::new(window).sorted_by(clients::CLIENT_ID, SortDirection::Ascending);
        let page = query.select(clients::TABLE, CLIENT);
        self.read_all(&page)
            .await?
            .iter()
            .map(read_client_row)
            .collect()
    }

    async fn count_clients(&mut self) -> Result<u64, StorageError> {
        let total = ListQuery::count(clients::TABLE);
        let counted: i64 = self
            .read_one(&total)
            .await?
            .ok_or(StorageError::Failed)?
            .get(0);
        u64::try_from(counted).map_err(|_| StorageError::Failed)
    }
}
