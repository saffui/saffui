mod registrations;

use async_trait::async_trait;
use saffui_core::authz::capability::Capability;
use saffui_core::clients::store::{ClientStore, ListWindow};
use saffui_core::clients::{
    AssertionAlgorithm, Client, ClientAuthMethod, ClientStanding, KeptProof,
};
use saffui_core::oidc::response::ResponseType;
use saffui_core::ports::crypto::SignatureAlgorithm;
use saffui_core::ports::storage::StorageError;
use time::OffsetDateTime;
use tokio_postgres::Row;

use crate::query::bind::{Built, col};
use crate::query::criteria::Criteria;
use crate::query::ident::Column;
use crate::query::insert::Insert;
use crate::query::list_query::ListQuery;
use crate::query::select::{Select, SortDirection};
use crate::query::update::Update;
use crate::schema::clients;
use crate::work::PgUnitOfWork;

const WRITE_CAPABILITIES: &str = "
    UPDATE clients SET capabilities = $4
    WHERE tenant_id = $1 AND realm_id = $2 AND client_id = $3";

/// One statement: of two uses of one assertion, one inserts and the other
/// finds the row there. The key is the one unique rule of the table: naming
/// no target, the conflict reads no column, and the role that serves needs
/// no right to read the table.
const RECORD_ASSERTION: &str = "
    INSERT INTO client_assertions (tenant_id, realm_id, client_id, token_id, kept_until)
    VALUES ($1, $2, $3, $4, $5)
    ON CONFLICT DO NOTHING";

/// Constant SQL: one statement turns a client off, and reads nothing of it
/// first. A client off already is left as it is.
const DISABLE_CLIENT: &str = "
    UPDATE clients SET enabled = false
    WHERE tenant_id = $1 AND realm_id = $2 AND client_id = $3 AND enabled";

/// Constant SQL: the columns a client that registered itself writes, and
/// only while its registration lasts. Whether it is enabled is never
/// written from what was read of it.
const WRITE_CLIENT_METADATA: &str = "
    UPDATE clients SET name = $4, scopes = $5, redirect_uris = $6,
        post_logout_redirect_uris = $7, id_token_signed_response_alg = $8,
        auth_signing_alg = $9, jwks = $10, frontchannel_logout_uri = $11
    WHERE tenant_id = $1 AND realm_id = $2 AND client_id = $3 AND self_registered
      AND EXISTS (
          SELECT 1 FROM client_registrations AS registration
          WHERE registration.tenant_id = $1 AND registration.realm_id = $2
            AND registration.client_id = $3 AND registration.ended_at IS NULL)";

/// What is read of a client for anything but identifying it: nothing of
/// what proves it.
const CLIENT: &[Column] = &[
    clients::CLIENT_ROW_ID,
    clients::CLIENT_ID,
    clients::NAME,
    clients::ALLOWS_CLIENT_CREDENTIALS,
    clients::SCOPES,
    clients::CAPABILITIES,
    clients::ENABLED,
    clients::CREATED_AT,
    clients::ALLOWS_AUTHORIZATION_CODE,
    clients::REDIRECT_URIS,
    clients::POST_LOGOUT_REDIRECT_URIS,
    clients::REQUIRES_CONSENT,
    clients::ID_TOKEN_SIGNED_RESPONSE_ALG,
    clients::AUTH_METHOD,
    clients::AUTH_SIGNING_ALG,
    clients::SELF_REGISTERED,
    clients::RESPONSE_TYPES,
    clients::REQUEST_OBJECT_SIGNING_ALG,
    clients::REQUIRE_SIGNED_REQUEST_OBJECT,
    clients::FRONTCHANNEL_LOGOUT_URI,
];

/// Constant SQL: the columns of [`CLIENT`], in its order, and the row stays
/// locked until the commit. The key of a client never changes.
const READ_CLIENT_FOR_UPDATE: &str = "
    SELECT client_row_id, client_id, name, allows_client_credentials, scopes, capabilities,
        enabled, created_at, allows_authorization_code, redirect_uris,
        post_logout_redirect_uris, requires_consent, id_token_signed_response_alg, auth_method,
        auth_signing_alg, self_registered, response_types, request_object_signing_alg,
        require_signed_request_object, frontchannel_logout_uri
    FROM clients
    WHERE tenant_id = $1 AND realm_id = $2 AND client_id = $3
    FOR NO KEY UPDATE";

/// Constant SQL: the columns of [`CLIENT`], in its order, and the row stays
/// shared until the commit: a writer of the client waits, as the reader
/// waits for one.
const READ_CLIENT_FOR_SHARE: &str = "
    SELECT client_row_id, client_id, name, allows_client_credentials, scopes, capabilities,
        enabled, created_at, allows_authorization_code, redirect_uris,
        post_logout_redirect_uris, requires_consent, id_token_signed_response_alg, auth_method,
        auth_signing_alg, self_registered, response_types, request_object_signing_alg,
        require_signed_request_object, frontchannel_logout_uri
    FROM clients
    WHERE tenant_id = $1 AND realm_id = $2 AND client_id = $3
    FOR SHARE";

/// What a token of a client is worth now, and nothing else of it.
const STANDING: &[Column] = &[clients::ENABLED, clients::SELF_REGISTERED];

/// The same, then what proves the client: read to identify it alone.
const CLIENT_WITH_PROOF: &[Column] = &[
    clients::CLIENT_ROW_ID,
    clients::CLIENT_ID,
    clients::NAME,
    clients::ALLOWS_CLIENT_CREDENTIALS,
    clients::SCOPES,
    clients::CAPABILITIES,
    clients::ENABLED,
    clients::CREATED_AT,
    clients::ALLOWS_AUTHORIZATION_CODE,
    clients::REDIRECT_URIS,
    clients::POST_LOGOUT_REDIRECT_URIS,
    clients::REQUIRES_CONSENT,
    clients::ID_TOKEN_SIGNED_RESPONSE_ALG,
    clients::AUTH_METHOD,
    clients::AUTH_SIGNING_ALG,
    clients::SELF_REGISTERED,
    clients::RESPONSE_TYPES,
    clients::REQUEST_OBJECT_SIGNING_ALG,
    clients::REQUIRE_SIGNED_REQUEST_OBJECT,
    clients::FRONTCHANNEL_LOGOUT_URI,
    clients::SECRET_DIGEST,
    clients::SEALED_SECRET,
    clients::JWKS,
];

fn read_client_row(row: &Row) -> Result<Client, StorageError> {
    let capabilities: Vec<String> = row.get(5);
    let id_token_algorithm: Option<String> = row.get(12);
    let auth_method: String = row.get(13);
    let auth_signing_alg: Option<String> = row.get(14);
    let response_types: Vec<String> = row.get(16);
    let request_object_signing_alg: Option<String> = row.get(17);
    // The schema holds the same lists: a name unknown here was not written
    // by this binary.
    Ok(Client {
        id: row.get(0),
        client_id: row.get(1),
        name: row.get(2),
        auth_method: ClientAuthMethod::parse(&auth_method).ok_or(StorageError::Failed)?,
        auth_signing_alg: auth_signing_alg
            .map(|name| AssertionAlgorithm::parse(&name).ok_or(StorageError::Failed))
            .transpose()?,
        allows_client_credentials: row.get(3),
        allows_authorization_code: row.get(8),
        redirect_uris: row.get(9),
        response_types: response_types
            .iter()
            .map(|name| ResponseType::read(name).ok_or(StorageError::Failed))
            .collect::<Result<_, _>>()?,
        post_logout_redirect_uris: row.get(10),
        frontchannel_logout_uri: row.get(19),
        requires_consent: row.get(11),
        scopes: row.get(4),
        capabilities: capabilities
            .iter()
            .map(|name| Capability::parse(name).ok_or(StorageError::Failed))
            .collect::<Result<_, _>>()?,
        id_token_signed_response_alg: id_token_algorithm
            .map(|name| SignatureAlgorithm::parse(&name).ok_or(StorageError::Failed))
            .transpose()?,
        request_object_signing_alg: request_object_signing_alg
            .map(|name| AssertionAlgorithm::parse(&name).ok_or(StorageError::Failed))
            .transpose()?,
        require_signed_request_object: row.get(18),
        enabled: row.get(6),
        self_registered: row.get(15),
        created_at: row.get(7),
    })
}

/// What proves a client, after the columns of [`CLIENT`].
fn read_proof_row(row: &Row) -> KeptProof {
    let after = CLIENT.len();
    KeptProof {
        secret_digest: row.get(after),
        sealed_secret: row.get(after + 1),
        jwks: row.get(after + 2),
    }
}

/// The clients of a realm in the order of their identifiers. The identifier
/// is unique in the realm: the order is total, so a window neither repeats
/// a row nor skips one.
fn order_clients(window: ListWindow) -> ListQuery {
    ListQuery::new(window).sorted_by(clients::CLIENT_ID, SortDirection::Ascending)
}

/// A page of clients, without what proves them.
fn select_client_page(ordered: &ListQuery) -> Built<'_> {
    ordered.select(clients::TABLE, CLIENT)
}

#[async_trait]
impl ClientStore for PgUnitOfWork {
    async fn insert_client(
        &mut self,
        client: &Client,
        proof: &KeptProof,
    ) -> Result<(), StorageError> {
        let capabilities: Vec<&str> = client
            .capabilities
            .iter()
            .map(|granted| granted.name())
            .collect();
        let id_token_algorithm = client
            .id_token_signed_response_alg
            .map(SignatureAlgorithm::name);
        let auth_method = client.auth_method.name();
        let auth_signing_alg = client.auth_signing_alg.map(AssertionAlgorithm::name);
        let request_object_signing_alg = client
            .request_object_signing_alg
            .map(AssertionAlgorithm::name);
        let response_types: Vec<&str> = client
            .response_types
            .iter()
            .map(|kind| kind.name())
            .collect();
        let insert = Insert::into(
            clients::TABLE,
            vec![
                col(clients::CLIENT_ROW_ID, &client.id),
                col(clients::CLIENT_ID, &client.client_id),
                col(clients::NAME, &client.name),
                col(clients::SECRET_DIGEST, &proof.secret_digest),
                col(clients::AUTH_METHOD, &auth_method),
                col(clients::SEALED_SECRET, &proof.sealed_secret),
                col(clients::JWKS, &proof.jwks),
                col(clients::AUTH_SIGNING_ALG, &auth_signing_alg),
                col(
                    clients::ALLOWS_CLIENT_CREDENTIALS,
                    &client.allows_client_credentials,
                ),
                col(
                    clients::ALLOWS_AUTHORIZATION_CODE,
                    &client.allows_authorization_code,
                ),
                col(clients::REDIRECT_URIS, &client.redirect_uris),
                col(clients::RESPONSE_TYPES, &response_types),
                col(
                    clients::POST_LOGOUT_REDIRECT_URIS,
                    &client.post_logout_redirect_uris,
                ),
                col(
                    clients::FRONTCHANNEL_LOGOUT_URI,
                    &client.frontchannel_logout_uri,
                ),
                col(clients::REQUIRES_CONSENT, &client.requires_consent),
                col(clients::SELF_REGISTERED, &client.self_registered),
                col(clients::SCOPES, &client.scopes),
                col(clients::CAPABILITIES, &capabilities),
                col(clients::ID_TOKEN_SIGNED_RESPONSE_ALG, &id_token_algorithm),
                col(
                    clients::REQUEST_OBJECT_SIGNING_ALG,
                    &request_object_signing_alg,
                ),
                col(
                    clients::REQUIRE_SIGNED_REQUEST_OBJECT,
                    &client.require_signed_request_object,
                ),
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

    async fn read_client_for_update(
        &mut self,
        client_id: &str,
    ) -> Result<Option<Client>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        self.read_raw(READ_CLIENT_FOR_UPDATE, &[&tenant, &realm, &client_id])
            .await?
            .first()
            .map(read_client_row)
            .transpose()
    }

    async fn read_client_for_share(
        &mut self,
        client_id: &str,
    ) -> Result<Option<Client>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        self.read_raw(READ_CLIENT_FOR_SHARE, &[&tenant, &realm, &client_id])
            .await?
            .first()
            .map(read_client_row)
            .transpose()
    }

    async fn read_client_standing(
        &mut self,
        client_id: &str,
    ) -> Result<Option<ClientStanding>, StorageError> {
        let select = Select::from(clients::TABLE, STANDING)
            .filter(Criteria::new().where_equal(clients::CLIENT_ID, &client_id))
            .build();
        Ok(self.read_one(&select).await?.map(|row| ClientStanding {
            enabled: row.get(0),
            self_registered: row.get(1),
        }))
    }

    async fn read_client_with_proof(
        &mut self,
        client_id: &str,
    ) -> Result<Option<(Client, KeptProof)>, StorageError> {
        let select = Select::from(clients::TABLE, CLIENT_WITH_PROOF)
            .filter(Criteria::new().where_equal(clients::CLIENT_ID, &client_id))
            .build();
        self.read_one(&select)
            .await?
            .as_ref()
            .map(|row| Ok((read_client_row(row)?, read_proof_row(row))))
            .transpose()
    }

    async fn list_clients(&mut self, window: ListWindow) -> Result<Vec<Client>, StorageError> {
        let ordered = order_clients(window);
        let page = select_client_page(&ordered);
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

    async fn write_client_capabilities(
        &mut self,
        client_id: &str,
        capabilities: &[Capability],
    ) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let names: Vec<&str> = capabilities
            .iter()
            .map(|capability| capability.name())
            .collect();
        let written = self
            .execute_raw(WRITE_CAPABILITIES, &[&tenant, &realm, &client_id, &names])
            .await?;
        Ok(written == 1)
    }

    async fn write_client_secret(
        &mut self,
        client_id: &str,
        secret_digest: Option<&[u8]>,
        sealed_secret: Option<&[u8]>,
    ) -> Result<bool, StorageError> {
        let update = Update::table(
            clients::TABLE,
            vec![
                col(clients::SECRET_DIGEST, &secret_digest),
                col(clients::SEALED_SECRET, &sealed_secret),
            ],
            Criteria::new().where_equal(clients::CLIENT_ID, &client_id),
        )
        .build()
        .map_err(|_| StorageError::Failed)?;
        Ok(self.execute(&update).await? == 1)
    }

    async fn write_client_auth_method(
        &mut self,
        client_id: &str,
        method: ClientAuthMethod,
    ) -> Result<bool, StorageError> {
        let name = method.name();
        let update = Update::table(
            clients::TABLE,
            vec![col(clients::AUTH_METHOD, &name)],
            Criteria::new().where_equal(clients::CLIENT_ID, &client_id),
        )
        .build()
        .map_err(|_| StorageError::Failed)?;
        Ok(self.execute(&update).await? == 1)
    }

    async fn write_client_metadata(
        &mut self,
        client: &Client,
        jwks: Option<&serde_json::Value>,
    ) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let id_token_algorithm = client
            .id_token_signed_response_alg
            .map(SignatureAlgorithm::name);
        let auth_signing_alg = client.auth_signing_alg.map(AssertionAlgorithm::name);
        let written = self
            .execute_raw(
                WRITE_CLIENT_METADATA,
                &[
                    &tenant,
                    &realm,
                    &client.client_id,
                    &client.name,
                    &client.scopes,
                    &client.redirect_uris,
                    &client.post_logout_redirect_uris,
                    &id_token_algorithm,
                    &auth_signing_alg,
                    &jwks,
                    &client.frontchannel_logout_uri,
                ],
            )
            .await?;
        Ok(written == 1)
    }

    async fn disable_client(&mut self, client_id: &str) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let disabled = self
            .execute_raw(DISABLE_CLIENT, &[&tenant, &realm, &client_id])
            .await?;
        Ok(disabled == 1)
    }

    async fn record_client_assertion(
        &mut self,
        client_id: &str,
        token_id: &str,
        kept_until: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let inserted = self
            .execute_raw(
                RECORD_ASSERTION,
                &[&tenant, &realm, &client_id, &token_id, &kept_until],
            )
            .await?;
        Ok(inserted == 1)
    }
}

#[cfg(test)]
mod tests {
    use saffui_core::clients::store::ListWindow;

    use super::{
        CLIENT, CLIENT_WITH_PROOF, READ_CLIENT_FOR_SHARE, READ_CLIENT_FOR_UPDATE, order_clients,
        select_client_page,
    };

    #[test]
    fn a_page_of_clients_reads_nothing_of_what_proves_them() {
        let ordered = order_clients(ListWindow { first: 0, max: 10 });
        let page = select_client_page(&ordered);

        for proof in ["secret_digest", "sealed_secret", "jwks"] {
            assert!(!page.sql.contains(proof), "{proof} in {}", page.sql);
        }
        assert!(page.sql.contains("auth_method"), "{}", page.sql);
    }

    #[test]
    fn a_client_read_with_its_proof_reads_the_client_first() {
        assert_eq!(&CLIENT_WITH_PROOF[..CLIENT.len()], CLIENT);
        assert_eq!(CLIENT_WITH_PROOF.len(), CLIENT.len() + 3);
    }

    #[test]
    fn a_client_is_read_and_taken_by_one_statement_of_the_columns_of_a_client() {
        let columns: Vec<&str> = CLIENT.iter().map(|column| column.0).collect();

        for (statement, lock) in [
            (READ_CLIENT_FOR_UPDATE, "FOR NO KEY UPDATE"),
            (READ_CLIENT_FOR_SHARE, "FOR SHARE"),
        ] {
            let written = statement.split_whitespace().collect::<Vec<_>>().join(" ");
            // The whole clause: the security of rows would hide a scope left out.
            assert_eq!(
                written,
                format!(
                    "SELECT {} FROM clients \
                     WHERE tenant_id = $1 AND realm_id = $2 AND client_id = $3 {lock}",
                    columns.join(", ")
                )
            );
        }
    }
}
