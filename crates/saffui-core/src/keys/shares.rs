//! One key made, or one set of keys of a client checked, at a time by each
//! tenant. The key makers of a node are few and every tenant shares them: a
//! tenant that asks for many at once is refused all but one, and leaves the
//! others to the rest. A client that registers itself through the protocol
//! takes no share of its tenant: its realm checks one set of keys at a time,
//! apart.

use std::collections::HashSet;
use std::hash::Hash;
use std::sync::{Arc, Mutex, PoisonError};

use crate::tenancy::TenantId;

/// The shares of a node, one for each `K` at a time: a tenant, or the realm
/// of a registration.
pub struct KeyMakingShares<K = TenantId> {
    held: Mutex<HashSet<K>>,
}

impl<K> Default for KeyMakingShares<K> {
    fn default() -> Self {
        Self {
            held: Mutex::new(HashSet::new()),
        }
    }
}

/// The key a tenant is making, or the keys it is checking. Given back when
/// dropped.
pub struct KeyMakingShare<K: Copy + Eq + Hash = TenantId> {
    shares: Arc<KeyMakingShares<K>>,
    holder: K,
}

impl<K: Copy + Eq + Hash> KeyMakingShares<K> {
    /// Takes the share of `holder`, or none while it is making or checking
    /// keys already.
    #[must_use]
    pub fn take(self: &Arc<Self>, holder: K) -> Option<KeyMakingShare<K>> {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        held.insert(holder).then(|| KeyMakingShare {
            shares: Arc::clone(self),
            holder,
        })
    }
}

impl<K: Copy + Eq + Hash> Drop for KeyMakingShare<K> {
    fn drop(&mut self) {
        self.shares
            .held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.holder);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use uuid::Uuid;

    use super::KeyMakingShares;
    use crate::tenancy::TenantId;

    #[test]
    fn a_tenant_makes_one_key_at_a_time_and_leaves_the_others_theirs() {
        let shares = Arc::new(KeyMakingShares::default());
        let (busy, other) = (
            TenantId::from_uuid(Uuid::from_u128(1)),
            TenantId::from_uuid(Uuid::from_u128(2)),
        );

        let making = shares.take(busy).expect("a share");
        assert!(shares.take(busy).is_none(), "one key at a time");
        assert!(
            shares.take(other).is_some(),
            "another tenant is not held up"
        );
        drop(making);
        assert!(
            shares.take(busy).is_some(),
            "a share given back is free again"
        );
    }
}
