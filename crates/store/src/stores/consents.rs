//! Consents.

use async_trait::async_trait;
use saffui_core::consent::store::ConsentStore;
use saffui_core::consent::{Consent, ConsentHold, ConsentTerms, ListedConsent};
use saffui_core::ports::storage::StorageError;
use uuid::Uuid;

use crate::query::criteria::Criteria;
use crate::query::ident::Column;
use crate::query::select::Select;
use crate::schema::consents;
use crate::work::PgUnitOfWork;

const CONSENT: &[Column] = &[consents::SCOPES, consents::GRANTED_AT];

/// Constant SQL: the row stays locked until the commit. A withdrawal that
/// comes after waits for it; one that came first leaves no row to lock.
const HOLD_CONSENT_SHARED: &str = "
    SELECT scopes FROM consents
    WHERE tenant_id = $1 AND realm_id = $2 AND person_id = $3 AND client_id = $4
    FOR SHARE";

/// Constant SQL: as `HOLD_CONSENT_SHARED`, and another exchange that holds
/// the row so waits its turn too. The key of the row never changes.
const HOLD_CONSENT_EXCLUSIVE: &str = "
    SELECT scopes FROM consents
    WHERE tenant_id = $1 AND realm_id = $2 AND person_id = $3 AND client_id = $4
    FOR NO KEY UPDATE";

/// Constant SQL: the flag of the client and what the person allowed it, in
/// one statement, each table under the keys of the scope.
const READ_CONSENT_TERMS: &str = "
    SELECT client.requires_consent, consent.scopes
    FROM clients AS client
    LEFT JOIN consents AS consent ON consent.tenant_id = $1 AND consent.realm_id = $2
        AND consent.person_id = $3 AND consent.client_id = client.client_id
    WHERE client.tenant_id = $1 AND client.realm_id = $2 AND client.client_id = $4";

/// Constant SQL: one statement writes the consent or widens the one kept.
/// The row stays locked until the commit: a second answer waits for the
/// first, then adds to what it allowed.
const ADD_CONSENT: &str = "
    INSERT INTO consents AS kept (tenant_id, realm_id, person_id, client_id, scopes, granted_at)
    VALUES ($1, $2, $3, $4, $5, $6)
    ON CONFLICT (tenant_id, realm_id, person_id, client_id) DO UPDATE SET
        scopes = kept.scopes || ARRAY(
            SELECT asked.scope
            FROM unnest(EXCLUDED.scopes) WITH ORDINALITY AS asked (scope, place)
            WHERE asked.scope <> ALL (kept.scopes)
            ORDER BY asked.place),
        granted_at = EXCLUDED.granted_at";

/// Constant SQL: the name of each client is read with its consent, and the
/// key of the table gives the order.
const LIST_CONSENTS: &str = "
    SELECT consent.client_id, consent.scopes, consent.granted_at, client.name
    FROM consents AS consent
    JOIN clients AS client ON client.tenant_id = consent.tenant_id
        AND client.realm_id = consent.realm_id AND client.client_id = consent.client_id
    WHERE consent.tenant_id = $1 AND consent.realm_id = $2 AND consent.person_id = $3
    ORDER BY consent.client_id
    LIMIT $4";

#[async_trait]
impl ConsentStore for PgUnitOfWork {
    async fn read_consent(
        &mut self,
        person: Uuid,
        client_id: &str,
    ) -> Result<Option<Consent>, StorageError> {
        let select = Select::from(consents::TABLE, CONSENT)
            .filter(
                Criteria::new()
                    .where_equal(consents::PERSON_ID, &person)
                    .where_equal(consents::CLIENT_ID, &client_id),
            )
            .build();
        Ok(self.read_one(&select).await?.map(|row| Consent {
            person,
            client_id: client_id.to_owned(),
            scopes: row.get(0),
            granted_at: row.get(1),
        }))
    }

    async fn hold_consent(
        &mut self,
        person: Uuid,
        client_id: &str,
        hold: ConsentHold,
    ) -> Result<Option<Vec<String>>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let statement = match hold {
            ConsentHold::Shared => HOLD_CONSENT_SHARED,
            ConsentHold::Exclusive => HOLD_CONSENT_EXCLUSIVE,
        };
        let rows = self
            .read_raw(statement, &[&tenant, &realm, &person, &client_id])
            .await?;
        Ok(rows.first().map(|row| row.get(0)))
    }

    async fn read_consent_terms(
        &mut self,
        person: Uuid,
        client_id: &str,
    ) -> Result<Option<ConsentTerms>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let rows = self
            .read_raw(READ_CONSENT_TERMS, &[&tenant, &realm, &person, &client_id])
            .await?;
        Ok(rows.first().map(|row| ConsentTerms {
            requires_consent: row.get(0),
            allowed: row.get(1),
        }))
    }

    async fn add_consent(&mut self, consent: &Consent) -> Result<(), StorageError> {
        let (tenant, realm) = self.scope_keys();
        self.execute_raw(
            ADD_CONSENT,
            &[
                &tenant,
                &realm,
                &consent.person,
                &consent.client_id,
                &consent.scopes,
                &consent.granted_at,
            ],
        )
        .await
        .map(|_| ())
    }

    async fn list_consents(
        &mut self,
        person: Uuid,
        most: u32,
    ) -> Result<Vec<ListedConsent>, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let rows = self
            .read_raw(LIST_CONSENTS, &[&tenant, &realm, &person, &i64::from(most)])
            .await?;
        Ok(rows
            .iter()
            .map(|row| ListedConsent {
                consent: Consent {
                    person,
                    client_id: row.get(0),
                    scopes: row.get(1),
                    granted_at: row.get(2),
                },
                client_name: row.get(3),
            })
            .collect())
    }

    async fn delete_consent(
        &mut self,
        person: Uuid,
        client_id: &str,
    ) -> Result<bool, StorageError> {
        let (tenant, realm) = self.scope_keys();
        let deleted = self
            .execute_raw(
                "DELETE FROM consents
                 WHERE tenant_id = $1 AND realm_id = $2 AND person_id = $3 AND client_id = $4",
                &[&tenant, &realm, &person, &client_id],
            )
            .await?;
        Ok(deleted == 1)
    }
}
