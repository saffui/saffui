use crypto::provider::{DigestProvider, HashAlg};
use deadpool_postgres::Transaction;
use serde_json::Value;

use crate::error::{StoreError, StoreResult};

/// Where an entry landed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Appended {
    pub seq: i64,
    pub hash: Vec<u8>,
}

/// What a verification found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// How many entries were read.
    pub entries: usize,
    /// The first sequence whose hash does not follow from what precedes it.
    /// `None` when the chain holds.
    pub broken_at: Option<i64>,
}

impl Verified {
    pub fn holds(&self) -> bool {
        self.broken_at.is_none()
    }
}

/// Open a realm's chain.
///
/// The genesis hash is derived from the realm's own identity, so two realms do
/// not start from the same value and an entry cannot be lifted from one chain
/// into the other at the same position.
pub async fn start(
    transaction: &Transaction<'_>,
    digest: &dyn DigestProvider,
    tenant: &str,
    realm_id: &str,
) -> StoreResult<bool> {
    // Length prefixed rather than separated, for the reason the sealing scope
    // gives: a separator needs a byte that cannot occur in a field, and these
    // fields can hold any byte.
    let mut preimage = b"saffui/audit-genesis/v1".to_vec();
    for field in [tenant, realm_id] {
        preimage.extend_from_slice(&(field.len() as u32).to_be_bytes());
        preimage.extend_from_slice(field.as_bytes());
    }
    let genesis = digest
        .hash(HashAlg::Sha256, &preimage)
        .map_err(|_| StoreError::Backend)?;

    let written = transaction
        .execute(
            "INSERT INTO audit_chain_heads (tenant, realm_id, head_hash) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1 \
             ON CONFLICT DO NOTHING",
            &[&genesis],
        )
        .await
        .map_err(|_| StoreError::Backend)?;

    Ok(written > 0)
}

/// Record what happened.
///
/// The realm is taken from the settings inside the function, never from the
/// entry, so an entry cannot name a chain other than the one in scope.
pub async fn append(transaction: &Transaction<'_>, entry: &Value) -> StoreResult<Appended> {
    let row = transaction
        .query_one("SELECT seq, hash FROM audit_append($1)", &[entry])
        .await
        .map_err(|_| StoreError::Backend)?;

    Ok(Appended {
        seq: row.get("seq"),
        hash: row.get("hash"),
    })
}

/// Recompute every link from the stored bytes.
///
/// Reads the envelope as the text it was hashed as rather than as a value to
/// re-render, so this checks the chain and not the agreement of two renderers.
/// It reports where the chain first breaks instead of only that it does: an
/// auditor needs to know which entries are still worth reading.
pub async fn verify(
    transaction: &Transaction<'_>,
    digest: &dyn DigestProvider,
) -> StoreResult<Verified> {
    let rows = transaction
        .query(
            "SELECT seq, envelope::text AS canonical, prev_hash, hash \
             FROM audit_events ORDER BY seq ASC",
            &[],
        )
        .await
        .map_err(|_| StoreError::Backend)?;

    let head: Option<Vec<u8>> = transaction
        .query_opt("SELECT head_hash FROM audit_chain_heads", &[])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(|row| row.get("head_hash"));
    let Some(genesis_or_head) = head else {
        return Err(StoreError::NoChain);
    };

    let mut expected_prev: Option<Vec<u8>> = None;
    let mut expected_seq = 1i64;

    for row in &rows {
        let seq: i64 = row.get("seq");
        let canonical: String = row.get("canonical");
        let prev_hash: Vec<u8> = row.get("prev_hash");
        let hash: Vec<u8> = row.get("hash");

        // A gap is not an ordering detail, it is an entry somebody removed.
        //
        // Defence in depth rather than the load bearing check: removing an
        // entry already breaks the link of the one after it, so the chain
        // catches it either way. This says so in its own terms, and would catch
        // a renumbering that somehow kept every link intact.
        if seq != expected_seq {
            return Ok(Verified {
                entries: rows.len(),
                broken_at: Some(seq),
            });
        }
        if let Some(previous) = &expected_prev
            && previous != &prev_hash
        {
            return Ok(Verified {
                entries: rows.len(),
                broken_at: Some(seq),
            });
        }
        if link(digest, &prev_hash, seq, canonical.as_bytes())? != hash {
            return Ok(Verified {
                entries: rows.len(),
                broken_at: Some(seq),
            });
        }

        expected_prev = Some(hash);
        expected_seq += 1;
    }

    // The head has to be the last link, or entries were removed from the end
    // and every remaining link still agrees.
    let tail = expected_prev.unwrap_or(genesis_or_head.clone());
    if tail != genesis_or_head {
        return Ok(Verified {
            entries: rows.len(),
            broken_at: Some(expected_seq - 1),
        });
    }

    Ok(Verified {
        entries: rows.len(),
        broken_at: None,
    })
}

/// The preimage, spelled once.
///
/// The sequence is inside the hash, so an entry cannot be moved to another
/// position and still verify.
fn link(
    digest: &dyn DigestProvider,
    prev_hash: &[u8],
    seq: i64,
    canonical: &[u8],
) -> StoreResult<Vec<u8>> {
    let mut preimage = Vec::with_capacity(prev_hash.len() + 8 + canonical.len());
    preimage.extend_from_slice(prev_hash);
    preimage.extend_from_slice(&seq.to_be_bytes());
    preimage.extend_from_slice(canonical);

    digest
        .hash(HashAlg::Sha256, &preimage)
        .map_err(|_| StoreError::Backend)
}

/// Publish a head where whoever holds write access does not decide.
pub async fn anchor(
    transaction: &Transaction<'_>,
    witness: &str,
    receipt: &str,
) -> StoreResult<Appended> {
    let head = transaction
        .query_opt("SELECT seq, head_hash FROM audit_chain_heads", &[])
        .await
        .map_err(|_| StoreError::Backend)?
        .ok_or(StoreError::NoChain)?;

    let seq: i64 = head.get("seq");
    let head_hash: Vec<u8> = head.get("head_hash");

    transaction
        .execute(
            "INSERT INTO audit_anchors (tenant, realm_id, seq, head_hash, witness, receipt) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3, $4",
            &[&seq, &head_hash, &witness, &receipt],
        )
        .await
        .map_err(|_| StoreError::Backend)?;

    Ok(Appended {
        seq,
        hash: head_hash,
    })
}
