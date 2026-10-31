//! What a statement may name. Values of these types are constants written
//! by `gen-schema`: no name ever comes from a string a request carried.

/// Which keys of the scope a table carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ScopeKeys {
    Tenant,
    TenantAndRealm,
}

impl ScopeKeys {
    pub(super) fn count(self) -> usize {
        match self {
            Self::Tenant => 1,
            Self::TenantAndRealm => 2,
        }
    }

    /// The columns of the keys, as an insert names them.
    pub(super) fn names(self) -> &'static str {
        match self {
            Self::Tenant => "tenant_id",
            Self::TenantAndRealm => "tenant_id, realm_id",
        }
    }

    /// The predicate that opens every `WHERE`.
    pub(super) fn predicate(self) -> &'static str {
        match self {
            Self::Tenant => " WHERE tenant_id = $1",
            Self::TenantAndRealm => " WHERE tenant_id = $1 AND realm_id = $2",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Table {
    pub(crate) name: &'static str,
    pub(crate) keys: ScopeKeys,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Column(pub(crate) &'static str);
