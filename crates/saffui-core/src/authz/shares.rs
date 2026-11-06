//! A fair share of the questions to the point of decision. A question holds
//! a connection of the pool while it reads the realm, a walk of relations
//! for up to its whole budget, and the pool is shared by every tenant: a
//! node answers a few questions at once, a tenant a small part of them, and
//! a question past its share is answered that the node is busy, at once,
//! with its connection given back.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use crate::tenancy::TenantId;

pub struct DecisionShares {
    per_node: u32,
    per_tenant: u32,
    held: Mutex<Held>,
}

#[derive(Default)]
struct Held {
    node: u32,
    tenants: HashMap<TenantId, u32>,
}

/// One question a tenant may have answered. Given back when dropped.
pub struct DecisionShare {
    shares: Arc<DecisionShares>,
    tenant: TenantId,
}

impl DecisionShares {
    #[must_use]
    pub fn new(per_node: u32, per_tenant: u32) -> Self {
        Self {
            per_node,
            per_tenant,
            held: Mutex::new(Held::default()),
        }
    }

    /// The shares of a node whose pool holds `connections`: a quarter of
    /// them for questions, half of that for one tenant, and one at least.
    #[must_use]
    pub fn for_pool(connections: usize) -> Self {
        let per_node = u32::try_from(connections / 4).unwrap_or(u32::MAX).max(1);
        Self::new(per_node, (per_node / 2).max(1))
    }

    /// Takes a question for `tenant`, or none when the node or the tenant
    /// holds its whole share already.
    #[must_use]
    pub fn take(self: &Arc<Self>, tenant: TenantId) -> Option<DecisionShare> {
        // A thread that panicked while holding the lock left whole counts:
        // each change is one statement.
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        if held.node >= self.per_node
            || held.tenants.get(&tenant).copied().unwrap_or(0) >= self.per_tenant
        {
            return None;
        }
        held.node += 1;
        *held.tenants.entry(tenant).or_insert(0) += 1;
        Some(DecisionShare {
            shares: Arc::clone(self),
            tenant,
        })
    }
}

impl Default for DecisionShares {
    /// The shares of a node with the pool of the default settings.
    fn default() -> Self {
        Self::for_pool(20)
    }
}

impl Drop for DecisionShare {
    fn drop(&mut self) {
        let mut held = self
            .shares
            .held
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        held.node = held.node.saturating_sub(1);
        if let Some(count) = held.tenants.get_mut(&self.tenant) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                held.tenants.remove(&self.tenant);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use uuid::Uuid;

    use super::DecisionShares;
    use crate::tenancy::TenantId;

    #[test]
    fn a_tenant_takes_its_part_of_the_questions_and_the_node_its_whole() {
        let shares = Arc::new(DecisionShares::new(3, 2));
        let tenant = |n| TenantId::from_uuid(Uuid::from_u128(n));

        let first = shares.take(tenant(1)).expect("a question");
        let second = shares.take(tenant(1)).expect("a second question");
        assert!(
            shares.take(tenant(1)).is_none(),
            "the tenant holds its part, whatever realm asks"
        );
        let other = shares
            .take(tenant(2))
            .expect("another tenant is not held up");
        assert!(shares.take(tenant(3)).is_none(), "the node holds its whole");
        drop(first);
        let again = shares
            .take(tenant(3))
            .expect("a question given back is taken again");
        drop((second, other, again));
        let held = shares.held.lock().expect("a lock");
        assert!(held.node == 0 && held.tenants.is_empty());
    }

    #[test]
    fn the_shares_of_a_node_follow_the_size_of_its_pool() {
        let of = |connections| {
            let shares = DecisionShares::for_pool(connections);
            (shares.per_node, shares.per_tenant)
        };
        assert_eq!(of(20), (5, 2));
        assert_eq!(of(8), (2, 1));
        assert_eq!(of(1), (1, 1), "one at least");
    }
}
