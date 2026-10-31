use super::{RealmId, TenantId};

/// The tenant and the realm a unit of work is bound to. Only the resolver and
/// the provisioning make one: without a scope nothing is read or written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RealmScope {
    tenant: TenantId,
    realm: RealmId,
}

impl RealmScope {
    pub(crate) fn bind(tenant: TenantId, realm: RealmId) -> Self {
        Self { tenant, realm }
    }

    #[must_use]
    pub fn tenant(self) -> TenantId {
        self.tenant
    }

    #[must_use]
    pub fn realm(self) -> RealmId {
        self.realm
    }
}
