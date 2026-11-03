//! Walking a chain from its first event to its head. The verification, not
//! the way events were appended, is what tells that a chain is whole.

use super::store::ChainedEvent;
use super::{GENESIS_HASH, hash_link};
use crate::app::App;
use crate::error::Failure;
use crate::tenancy::RealmScope;

const PAGE: u32 = 500;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainBreak {
    /// A sequence number is missing or repeated.
    Gap,
    /// An event does not name the hash of the one before it.
    Unlinked,
    /// The stored bytes of an event no longer give its hash.
    Altered,
    /// The head of the chain is not its last event.
    HeadMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainVerdict {
    Intact { events: i64 },
    Broken { at_seq: i64, reason: ChainBreak },
}

/// Verifies the whole chain of a realm, as it stood at one instant: the
/// events and the head are read in one snapshot, so that an append that
/// commits meanwhile is not taken for a break.
///
/// # Errors
///
/// Returns the storage failure when the chain cannot be read.
pub async fn verify_chain(app: &App, scope: RealmScope) -> Result<ChainVerdict, Failure> {
    let mut work = app.storage.begin_snapshot(scope).await?;
    let (mut seq, mut hash) = (0_i64, GENESIS_HASH.to_vec());
    loop {
        let page = work.read_audit_events(seq, PAGE).await?;
        let Some(last) = page.last() else {
            break;
        };
        let last_seq = last.seq;
        for event in &page {
            if let Some(reason) = check_link(app, seq, &hash, event) {
                return Ok(ChainVerdict::Broken {
                    at_seq: event.seq,
                    reason,
                });
            }
            seq = event.seq;
            hash.clone_from(&event.hash);
        }
        debug_assert_eq!(seq, last_seq);
    }
    let head = work.read_audit_head().await?;
    let matches_head = match head {
        Some(head) => head.seq == seq && head.hash == hash,
        None => seq == 0,
    };
    Ok(if matches_head {
        ChainVerdict::Intact { events: seq }
    } else {
        ChainVerdict::Broken {
            at_seq: seq,
            reason: ChainBreak::HeadMismatch,
        }
    })
}

fn check_link(app: &App, seq: i64, hash: &[u8], event: &ChainedEvent) -> Option<ChainBreak> {
    if event.seq != seq + 1 {
        return Some(ChainBreak::Gap);
    }
    if event.previous_hash != hash {
        return Some(ChainBreak::Unlinked);
    }
    let expected = hash_link(app.digester.as_ref(), hash, event.seq, &event.envelope);
    if !app.digester.equal_in_constant_time(&expected, &event.hash) {
        return Some(ChainBreak::Altered);
    }
    None
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{ChainBreak, ChainVerdict, verify_chain};
    use crate::app::App;
    use crate::audit::EventKind;
    use crate::audit::append::record_event;
    use crate::ids::mint_id;
    use crate::tenancy::{RealmId, RealmScope, TenantId};
    use crate::testkit::drive::complete;
    use crate::testkit::memory::MemoryStorage;

    /// A scope whose chain holds four events, numbered by their round.
    fn fill_chain(app: &App) -> RealmScope {
        let scope = RealmScope::bind(
            TenantId::from_uuid(mint_id(app).expect("an identifier")),
            RealmId::from_uuid(mint_id(app).expect("an identifier")),
        );
        for round in 0..4 {
            let mut work = complete(app.storage.begin(scope)).expect("a unit of work");
            complete(record_event(
                app,
                work.as_mut(),
                EventKind::RealmCreated,
                json!({ "round": round }),
            ))
            .expect("an event");
            complete(work.commit()).expect("a commit");
        }
        scope
    }

    #[test]
    fn a_chain_nobody_touched_is_intact_from_its_first_event_to_its_head() {
        let (app, _storage) = MemoryStorage::wire();
        let scope = fill_chain(&app);

        assert_eq!(
            complete(verify_chain(&app, scope)),
            Ok(ChainVerdict::Intact { events: 4 })
        );
    }

    #[test]
    fn a_realm_without_events_has_an_empty_chain_that_is_intact() {
        let (app, _storage) = MemoryStorage::wire();
        let scope = RealmScope::bind(
            TenantId::from_uuid(mint_id(&app).expect("an identifier")),
            RealmId::from_uuid(mint_id(&app).expect("an identifier")),
        );

        assert_eq!(
            complete(verify_chain(&app, scope)),
            Ok(ChainVerdict::Intact { events: 0 })
        );
    }

    #[test]
    fn an_event_whose_bytes_changed_is_found_where_it_sits() {
        let (app, storage) = MemoryStorage::wire();
        let scope = fill_chain(&app);
        storage.tamper_with_audit_chain(scope.realm(), |chain| {
            let altered =
                String::from_utf8_lossy(&chain[2].envelope).replace("\"round\":2", "\"round\":9");
            assert_ne!(
                altered.as_bytes(),
                chain[2].envelope.as_slice(),
                "the envelope was altered"
            );
            chain[2].envelope = altered.into_bytes();
        });

        assert_eq!(
            complete(verify_chain(&app, scope)),
            Ok(ChainVerdict::Broken {
                at_seq: 3,
                reason: ChainBreak::Altered
            })
        );
    }

    #[test]
    fn a_removed_event_leaves_a_gap_that_is_found() {
        let (app, storage) = MemoryStorage::wire();
        let scope = fill_chain(&app);
        storage.tamper_with_audit_chain(scope.realm(), |chain| {
            chain.remove(2);
        });

        assert_eq!(
            complete(verify_chain(&app, scope)),
            Ok(ChainVerdict::Broken {
                at_seq: 4,
                reason: ChainBreak::Gap
            })
        );
    }

    #[test]
    fn a_truncated_chain_no_longer_ends_at_its_head() {
        let (app, storage) = MemoryStorage::wire();
        let scope = fill_chain(&app);
        let mut removed = None;
        storage.tamper_with_audit_chain(scope.realm(), |chain| removed = chain.pop());
        // The double derives its head from the last event: the head is put back by hand.
        let removed = removed.expect("an event was removed");
        storage.tamper_with_audit_chain(scope.realm(), |chain| {
            if let Some(last) = chain.last_mut() {
                last.hash.clone_from(&removed.hash);
            }
        });

        let verdict = complete(verify_chain(&app, scope)).expect("a verdict");

        assert!(
            matches!(verdict, ChainVerdict::Broken { .. }),
            "{verdict:?}"
        );
    }

    #[test]
    fn two_events_swapped_are_found_at_the_first_of_them() {
        let (app, storage) = MemoryStorage::wire();
        let scope = fill_chain(&app);
        storage.tamper_with_audit_chain(scope.realm(), |chain| chain.swap(1, 2));

        assert_eq!(
            complete(verify_chain(&app, scope)),
            Ok(ChainVerdict::Broken {
                at_seq: 3,
                reason: ChainBreak::Gap
            })
        );
    }
}
