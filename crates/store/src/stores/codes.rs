use async_trait::async_trait;
use saffui_core::oidc::code::{AuthorizationCode, CodeStore, PendingAuthorization};
use saffui_core::ports::storage::StorageError;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::query::bind::col;
use crate::query::criteria::Criteria;
use crate::query::ident::Column;
use crate::query::insert::Insert;
use crate::query::select::Select;
use crate::schema::{authorization_codes, authorization_requests};
use crate::work::PgUnitOfWork;

const PENDING: &[Column] = &[
    authorization_requests::BROWSER_DIGEST,
    authorization_requests::CLIENT_ID,
    authorization_requests::REDIRECT_URI,
    authorization_requests::SCOPES,
    authorization_requests::STATE,
    authorization_requests::NONCE,
    authorization_requests::CODE_CHALLENGE,
    authorization_requests::EXPIRES_AT,
];

#[async_trait]
impl CodeStore for PgUnitOfWork {
    async fn insert_pending_authorization(
        &mut self,
        pending: &PendingAuthorization,
    ) -> Result<(), StorageError> {
        let insert = Insert::into(
            authorization_requests::TABLE,
            vec![
                col(authorization_requests::REQUEST_ID, &pending.id),
                col(
                    authorization_requests::BROWSER_DIGEST,
                    &pending.browser_digest,
                ),
                col(authorization_requests::CLIENT_ID, &pending.client_id),
                col(authorization_requests::REDIRECT_URI, &pending.redirect_uri),
                col(authorization_requests::SCOPES, &pending.scopes),
                col(authorization_requests::STATE, &pending.state),
                col(authorization_requests::NONCE, &pending.nonce),
                col(
                    authorization_requests::CODE_CHALLENGE,
                    &pending.code_challenge,
                ),
                col(authorization_requests::EXPIRES_AT, &pending.expires_at),
            ],
        )
        .build();
        self.execute(&insert).await.map(|_| ())
    }

    async fn read_pending_authorization(
        &mut self,
        id: Uuid,
        now: OffsetDateTime,
    ) -> Result<Option<PendingAuthorization>, StorageError> {
        let select = Select::from(authorization_requests::TABLE, PENDING)
            .filter(
                Criteria::new()
                    .where_equal(authorization_requests::REQUEST_ID, &id)
                    .where_greater(authorization_requests::EXPIRES_AT, &now),
            )
            .build();
        Ok(self
            .read_one(&select)
            .await?
            .map(|row| PendingAuthorization {
                id,
                browser_digest: row.get(0),
                client_id: row.get(1),
                redirect_uri: row.get(2),
                scopes: row.get(3),
                state: row.get(4),
                nonce: row.get(5),
                code_challenge: row.get(6),
                expires_at: row.get(7),
            }))
    }

    async fn take_pending_authorization(
        &mut self,
        id: Uuid,
        now: OffsetDateTime,
    ) -> Result<Option<PendingAuthorization>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        // Constant SQL: one statement finds the request and removes it. Of
        // two submissions of one page, the second finds no row.
        let rows = self
            .read_raw(
                "DELETE FROM authorization_requests
                 WHERE tenant_id = $1 AND realm_id = $2 AND request_id = $3 AND expires_at > $4
                 RETURNING browser_digest, client_id, redirect_uri, scopes, state, nonce,
                           code_challenge, expires_at",
                &[&tenant, &realm, &id, &now],
            )
            .await?;
        Ok(rows.first().map(|row| PendingAuthorization {
            id,
            browser_digest: row.get(0),
            client_id: row.get(1),
            redirect_uri: row.get(2),
            scopes: row.get(3),
            state: row.get(4),
            nonce: row.get(5),
            code_challenge: row.get(6),
            expires_at: row.get(7),
        }))
    }

    async fn insert_authorization_code(
        &mut self,
        code: &AuthorizationCode,
    ) -> Result<(), StorageError> {
        let insert = Insert::into(
            authorization_codes::TABLE,
            vec![
                col(authorization_codes::CODE_DIGEST, &code.code_digest),
                col(authorization_codes::CLIENT_ID, &code.client_id),
                col(authorization_codes::PERSON_ID, &code.person),
                col(authorization_codes::SESSION_ID, &code.session),
                col(authorization_codes::REDIRECT_URI, &code.redirect_uri),
                col(authorization_codes::SCOPES, &code.scopes),
                col(authorization_codes::NONCE, &code.nonce),
                col(authorization_codes::CODE_CHALLENGE, &code.code_challenge),
                col(
                    authorization_codes::AUTHENTICATED_AT,
                    &code.authenticated_at,
                ),
                col(authorization_codes::EXPIRES_AT, &code.expires_at),
            ],
        )
        .build();
        self.execute(&insert).await.map(|_| ())
    }

    async fn take_authorization_code(
        &mut self,
        code_digest: &[u8],
        now: OffsetDateTime,
    ) -> Result<Option<AuthorizationCode>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        // Constant SQL: one statement finds the code and removes it. Of two
        // exchanges of one code, the second finds no row.
        let rows = self
            .read_raw(
                "DELETE FROM authorization_codes
                 WHERE tenant_id = $1 AND realm_id = $2 AND code_digest = $3 AND expires_at > $4
                 RETURNING client_id, person_id, session_id, redirect_uri, scopes, nonce,
                           code_challenge, authenticated_at, expires_at",
                &[&tenant, &realm, &code_digest, &now],
            )
            .await?;
        Ok(rows.first().map(|row| AuthorizationCode {
            code_digest: code_digest.to_vec(),
            client_id: row.get(0),
            person: row.get(1),
            session: row.get(2),
            redirect_uri: row.get(3),
            scopes: row.get(4),
            nonce: row.get(5),
            code_challenge: row.get(6),
            authenticated_at: row.get(7),
            expires_at: row.get(8),
        }))
    }
}
