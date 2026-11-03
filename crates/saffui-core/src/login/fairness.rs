//! A fair share of the password hashers. The hashers of a node are few, and
//! every tenant shares them: a realm whose sign-in page is flooded takes its
//! share, and so does an IPv6 /48 whatever realm it asks, and each leaves
//! the rest to the others. A share is held for the time of one hash, so a
//! network that is idle is never refused.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use crate::tenancy::RealmId;

pub struct HashingShares {
    per_realm: u32,
    per_network: u32,
    held: Mutex<Held>,
}

#[derive(Default)]
struct Held {
    realms: HashMap<RealmId, u32>,
    networks: HashMap<String, u32>,
}

/// One hash a realm, and the network of its caller, may run. Given back
/// when dropped.
pub struct HashingShare {
    shares: Arc<HashingShares>,
    realm: RealmId,
    network: Option<String>,
}

fn give_back<K: std::hash::Hash + Eq>(counts: &mut HashMap<K, u32>, key: &K) {
    if let Some(count) = counts.get_mut(key) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            counts.remove(key);
        }
    }
}

impl HashingShares {
    /// Shares `hashers` workers: a realm holds half of them at most, a
    /// network a quarter, and each one at least.
    #[must_use]
    pub fn new(hashers: usize) -> Self {
        let part = |divisor: usize| u32::try_from(hashers / divisor).unwrap_or(u32::MAX).max(1);
        Self {
            per_realm: part(2),
            per_network: part(4),
            held: Mutex::new(Held::default()),
        }
    }

    fn is_held_whole(&self, held: &Held, realm: RealmId, network: Option<&str>) -> bool {
        held.realms.get(&realm).copied().unwrap_or(0) >= self.per_realm
            || network.is_some_and(|network| {
                held.networks.get(network).copied().unwrap_or(0) >= self.per_network
            })
    }

    /// Tells whether a share is free for `realm` and `network` right now,
    /// and keeps none: another caller may take it before this one does.
    #[must_use]
    pub fn has_free_share(&self, realm: RealmId, network: Option<&str>) -> bool {
        let held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        !self.is_held_whole(&held, realm, network)
    }

    /// Takes a share for `realm` and for `network`, the /48 of an IPv6
    /// caller, or none when either holds its whole share already.
    #[must_use]
    pub fn take(self: &Arc<Self>, realm: RealmId, network: Option<String>) -> Option<HashingShare> {
        // A thread that panicked while holding the lock left whole counts:
        // each change is one statement.
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        if self.is_held_whole(&held, realm, network.as_deref()) {
            return None;
        }
        *held.realms.entry(realm).or_insert(0) += 1;
        if let Some(network) = &network {
            *held.networks.entry(network.clone()).or_insert(0) += 1;
        }
        Some(HashingShare {
            shares: Arc::clone(self),
            realm,
            network,
        })
    }
}

impl Drop for HashingShare {
    fn drop(&mut self) {
        let mut held = self
            .shares
            .held
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        give_back(&mut held.realms, &self.realm);
        if let Some(network) = &self.network {
            give_back(&mut held.networks, network);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use uuid::Uuid;

    use super::HashingShares;
    use crate::tenancy::RealmId;

    #[test]
    fn a_realm_holds_half_the_hashers_and_leaves_the_rest_to_the_others() {
        let shares = Arc::new(HashingShares::new(4));
        let (flooded, other) = (
            RealmId::from_uuid(Uuid::from_u128(1)),
            RealmId::from_uuid(Uuid::from_u128(2)),
        );

        let first = shares.take(flooded, None).expect("a share");
        let second = shares.take(flooded, None).expect("a second share");
        assert!(shares.take(flooded, None).is_none(), "half of four is two");
        assert!(
            shares.take(other, None).is_some(),
            "another realm is not held up"
        );

        assert!(!shares.has_free_share(flooded, None));
        assert!(shares.has_free_share(other, None));
        drop(first);
        assert!(shares.has_free_share(flooded, None));
        let third = shares
            .take(flooded, None)
            .expect("a share given back is taken again");
        drop((second, third));
        let held = shares.held.lock().expect("a lock");
        assert!(
            held.realms.is_empty() && held.networks.is_empty(),
            "every share is given back, and looking took none"
        );
    }

    #[test]
    fn a_network_holds_a_quarter_of_the_hashers_whatever_realm_it_asks() {
        let shares = Arc::new(HashingShares::new(8));
        let realm = |n| RealmId::from_uuid(Uuid::from_u128(n));
        let flooding = || Some("2001:db8:7::/48".to_owned());

        let held = [
            shares.take(realm(1), flooding()).expect("a share"),
            shares
                .take(realm(2), flooding())
                .expect("a share in another realm"),
        ];
        assert!(
            shares.take(realm(3), flooding()).is_none(),
            "a quarter of eight is two, across realms"
        );
        assert!(
            shares
                .take(realm(3), Some("2001:db8:8::/48".to_owned()))
                .is_some(),
            "another network is not held up"
        );
        assert!(shares.take(realm(3), None).is_some(), "nor an IPv4 caller");
        drop(held);
        assert!(
            shares.take(realm(3), flooding()).is_some(),
            "idle, it is never refused"
        );
    }

    #[test]
    fn a_single_hasher_is_a_share_of_one() {
        let shares = Arc::new(HashingShares::new(1));
        let realm = RealmId::from_uuid(Uuid::from_u128(1));

        let held = shares.take(realm, None).expect("a share");
        assert!(shares.take(realm, None).is_none());
        drop(held);
        assert!(shares.take(realm, None).is_some());
    }
}
