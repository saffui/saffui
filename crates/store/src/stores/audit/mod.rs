use async_trait::async_trait;
use saffui_core::audit::store::{AuditStore, ChainPosition, ChainedEvent};
use saffui_core::ports::storage::StorageError;

use crate::query::criteria::Criteria;
use crate::query::ident::Column;
use crate::query::select::{Select, SortDirection};
use crate::schema::{audit_chain_heads, audit_events};
use crate::work::PgUnitOfWork;

const EVENT: &[Column] = &[
    audit_events::SEQ,
    audit_events::PREV_HASH,
    audit_events::HASH,
    audit_events::ENVELOPE,
];
const HEAD: &[Column] = &[audit_chain_heads::SEQ, audit_chain_heads::HASH];

#[async_trait]
impl AuditStore for PgUnitOfWork {
    async fn append_audit_event(&mut self, envelope: &[u8]) -> Result<ChainPosition, StorageError> {
        // Constant SQL: the one writer of the chain is a function of the
        // database. It reads the scope from the transaction and takes no key
        // from the caller, so it cannot be pointed at another chain.
        let rows = self
            .read_raw(
                "SELECT new_seq, new_hash FROM saffui_append_audit_event($1)",
                &[&envelope],
            )
            .await?;
        let row = rows.first().ok_or(StorageError::Failed)?;
        Ok(ChainPosition {
            seq: row.get(0),
            hash: row.get(1),
        })
    }

    async fn read_audit_events(
        &mut self,
        after_seq: i64,
        limit: u32,
    ) -> Result<Vec<ChainedEvent>, StorageError> {
        let limit = i64::from(limit);
        let select = Select::from(audit_events::TABLE, EVENT)
            .filter(Criteria::new().where_greater(audit_events::SEQ, &after_seq))
            .sorted_by(audit_events::SEQ, SortDirection::Ascending)
            .limited_to(&limit)
            .build();
        let rows = self.read_all(&select).await?;
        Ok(rows
            .iter()
            .map(|row| ChainedEvent {
                seq: row.get(0),
                previous_hash: row.get(1),
                hash: row.get(2),
                envelope: row.get(3),
            })
            .collect())
    }

    async fn read_audit_head(&mut self) -> Result<Option<ChainPosition>, StorageError> {
        let select = Select::from(audit_chain_heads::TABLE, HEAD).build();
        Ok(self.read_one(&select).await?.map(|row| ChainPosition {
            seq: row.get(0),
            hash: row.get(1),
        }))
    }
}
