use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The audit columns shared by every tenant-scoped entity.
///
/// Only [`AuditableModel::from_creator`] produces a complete record. The other
/// two are shapes for a statement that writes a subset of the columns, and the
/// fields they leave out are `None` rather than plausible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditableModel {
    pub tenant: String,
    pub created_by: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_by: Option<String>,
    pub updated_at: Option<DateTime<Utc>>,
    /// The row's version, zero where a record carries none. An update names the
    /// actor and lets the statement bump this, so it is never a second opinion.
    pub version: i32,
}

impl AuditableModel {
    /// A new row, created now by `created_by`.
    pub fn from_creator(tenant: String, created_by: String) -> Self {
        Self {
            tenant,
            created_by: Some(created_by),
            created_at: Some(Utc::now()),
            updated_by: None,
            updated_at: None,
            version: 1,
        }
    }

    /// An existing row, touched now by `updated_by`.
    ///
    /// `created_*` stay `None`: this record says who wrote, not who first wrote,
    /// and a statement built from it must not overwrite the creation columns.
    pub fn from_updater(tenant: String, updated_by: String) -> Self {
        Self {
            tenant,
            created_by: None,
            created_at: None,
            updated_by: Some(updated_by),
            updated_at: Some(Utc::now()),
            version: 0,
        }
    }

    /// A placeholder with an **empty tenant**, for a model built before the
    /// request context is known. The layer that persists it overwrites the
    /// metadata with [`AuditableModel::from_creator`] or
    /// [`AuditableModel::from_updater`], which carry the real tenant from the
    /// authenticated session.
    ///
    /// Deliberately **not** a `Default` impl: an audit record must never be
    /// built tenant-less implicitly, through `..Default::default()` or
    /// `unwrap_or_default`. Calling this is an explicit, greppable opt-in.
    pub fn unassigned() -> Self {
        Self {
            tenant: String::new(),
            created_by: None,
            created_at: None,
            updated_by: None,
            updated_at: None,
            version: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_created_row_names_its_creator_and_nothing_else() {
        let meta = AuditableModel::from_creator("acme".into(), "root".into());
        assert_eq!(meta.tenant, "acme");
        assert_eq!(meta.created_by.as_deref(), Some("root"));
        assert!(meta.created_at.is_some());
        assert_eq!(meta.updated_by, None);
        assert_eq!(meta.updated_at, None);
        assert_eq!(meta.version, 1, "a new row is at its first version");
    }

    /// An update record must not be able to overwrite the creation columns, so
    /// it does not carry values for them.
    #[test]
    fn an_updated_row_names_no_creator_and_no_version() {
        let meta = AuditableModel::from_updater("acme".into(), "ada".into());
        assert_eq!(meta.tenant, "acme");
        assert_eq!(meta.created_by, None);
        assert_eq!(meta.created_at, None);
        assert_eq!(meta.updated_by.as_deref(), Some("ada"));
        assert!(meta.updated_at.is_some());
        assert_eq!(
            meta.version, 0,
            "an update carries no version; writing this one would reset the row"
        );
    }

    /// The tenant-less record holds nothing that could be mistaken for a real
    /// value. The empty tenant is not itself the safeguard — an empty string
    /// satisfies a `NOT NULL` column — which is why the constructor is named
    /// rather than derived: what protects the row is that reaching for it has
    /// to be written down.
    #[test]
    fn the_unassigned_record_carries_no_tenant_and_no_actor() {
        let meta = AuditableModel::unassigned();
        assert!(meta.tenant.is_empty());
        assert_eq!(meta.created_by, None);
        assert_eq!(meta.created_at, None);
        assert_eq!(meta.updated_by, None);
        assert_eq!(meta.updated_at, None);
        assert_eq!(meta.version, 0);
    }
}
