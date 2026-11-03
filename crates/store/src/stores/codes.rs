use async_trait::async_trait;
use saffui_core::oidc::code::{
    AuthorizationCode, CodeStore, PendingAuthorization, PendingKeyProof, ReplayedCode,
};
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
    authorization_requests::EXPECTED_PERSON,
    authorization_requests::FIRST_FACTOR_PERSON_ID,
    authorization_requests::KEY_PROOF_STATE,
    authorization_requests::KEY_PROOF_OPTIONS,
];

/// The proof by a key a row keeps, when the two columns hold one.
fn read_key_proof(
    state: Option<Vec<u8>>,
    options: Option<serde_json::Value>,
) -> Option<PendingKeyProof> {
    Some(PendingKeyProof {
        state: state?,
        options: options?,
    })
}

#[async_trait]
impl CodeStore for PgUnitOfWork {
    async fn insert_pending_authorization(
        &mut self,
        pending: &PendingAuthorization,
    ) -> Result<(), StorageError> {
        let key_state = pending.key_proof.as_ref().map(|proof| proof.state.clone());
        let key_options = pending
            .key_proof
            .as_ref()
            .map(|proof| proof.options.clone());
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
                col(
                    authorization_requests::EXPECTED_PERSON,
                    &pending.expected_person,
                ),
                col(
                    authorization_requests::FIRST_FACTOR_PERSON_ID,
                    &pending.first_factor,
                ),
                col(authorization_requests::KEY_PROOF_STATE, &key_state),
                col(authorization_requests::KEY_PROOF_OPTIONS, &key_options),
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
                expected_person: row.get(8),
                first_factor: row.get(9),
                key_proof: read_key_proof(row.get(10), row.get(11)),
            }))
    }

    async fn mark_first_factor(
        &mut self,
        id: Uuid,
        person: Uuid,
        key_proof: Option<&PendingKeyProof>,
        now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let key_state = key_proof.map(|proof| proof.state.clone());
        let key_options = key_proof.map(|proof| proof.options.clone());
        let marked = self
            .execute_raw(
                "UPDATE authorization_requests
                 SET first_factor_person_id = $4, key_proof_state = $6, key_proof_options = $7
                 WHERE tenant_id = $1 AND realm_id = $2 AND request_id = $3 AND expires_at > $5",
                &[
                    &tenant,
                    &realm,
                    &id,
                    &person,
                    &now,
                    &key_state,
                    &key_options,
                ],
            )
            .await?;
        Ok(marked == 1)
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
                           code_challenge, expires_at, expected_person, first_factor_person_id,
                           key_proof_state, key_proof_options",
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
            expected_person: row.get(8),
            first_factor: row.get(9),
            key_proof: read_key_proof(row.get(10), row.get(11)),
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

    async fn spend_authorization_code(
        &mut self,
        code_digest: &[u8],
        now: OffsetDateTime,
    ) -> Result<Option<AuthorizationCode>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        // Constant SQL: one statement finds the code and marks it. Of two
        // exchanges of one code, the second waits for the first, then finds
        // it spent.
        let rows = self
            .read_raw(
                "UPDATE authorization_codes SET spent_at = $4
                 WHERE tenant_id = $1 AND realm_id = $2 AND code_digest = $3
                   AND spent_at IS NULL AND expires_at > $4
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

    async fn bind_code_family(
        &mut self,
        code_digest: &[u8],
        family: Uuid,
    ) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        // Constant SQL: the row is locked until the exchange commits. A
        // replay marked before finds no row here; one marked after waits,
        // then reads the family.
        let rows = self
            .read_raw(
                "UPDATE authorization_codes SET family = $4
                 WHERE tenant_id = $1 AND realm_id = $2 AND code_digest = $3
                   AND spent_at IS NOT NULL AND replayed_at IS NULL
                 RETURNING family",
                &[&tenant, &realm, &code_digest, &family],
            )
            .await?;
        Ok(!rows.is_empty())
    }

    async fn mark_code_replayed(
        &mut self,
        code_digest: &[u8],
        client_id: &str,
        now: OffsetDateTime,
    ) -> Result<Option<ReplayedCode>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        // Constant SQL: of two replays at once, the second waits for the
        // first, then finds the code marked and matches no row.
        let rows = self
            .read_raw(
                "UPDATE authorization_codes SET replayed_at = $5
                 WHERE tenant_id = $1 AND realm_id = $2 AND code_digest = $3
                   AND client_id = $4 AND spent_at IS NOT NULL AND replayed_at IS NULL
                 RETURNING person_id, session_id, family",
                &[&tenant, &realm, &code_digest, &client_id, &now],
            )
            .await?;
        Ok(rows.first().map(|row| ReplayedCode {
            person: row.get(0),
            session: row.get(1),
            family: row.get(2),
        }))
    }
}
