//! One key made at a time by each tenant. The key makers of a node are few
//! and every tenant shares them: a tenant that asks for many keys at once is
//! refused all but one, and leaves the others to the rest.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, PoisonError};

use crate::tenancy::TenantId;

#[derive(Default)]
pub struct KeyMakingShares {
    held: Mutex<HashSet<TenantId>>,
}

/// The key a tenant is making. Given back when dropped.
pub struct KeyMakingShare {
    shares: Arc<KeyMakingShares>,
    tenant: TenantId,
}

impl KeyMakingShares {
    /// Takes the share of `tenant`, or none while it is making a key already.
    #[must_use]
    pub fn take(self: &Arc<Self>, tenant: TenantId) -> Option<KeyMakingShare> {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        held.insert(tenant).then(|| KeyMakingShare {
            shares: Arc::clone(self),
            tenant,
        })
    }
}

impl Drop for KeyMakingShare {
    fn drop(&mut self) {
        self.shares
            .held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.tenant);
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
