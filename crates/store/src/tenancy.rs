use deadpool_postgres::{Object, Transaction};
use tokio_postgres::IsolationLevel;

use crate::error::{StoreError, StoreResult};

/// The pair that scopes every statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantContext {
    pub tenant: String,
    pub realm_id: String,
    /// The tenant's residency pin, read off the stored row rather than taken from
    /// the caller, who could otherwise name one that lets it through.
    pub region: Option<String>,
}

impl TenantContext {
    pub fn new(tenant: impl Into<String>, realm_id: impl Into<String>) -> Self {
        Self {
            tenant: tenant.into(),
            realm_id: realm_id.into(),
            region: None,
        }
    }

    /// Pin the residency region on this context.
    pub fn with_region(mut self, region: Option<String>) -> Self {
        self.region = region.filter(|region| !region.trim().is_empty());
        self
    }

    /// A context for work that spans a tenant's realms rather than sitting in
    /// one: listing them, or asking whether a name is taken.
    ///
    /// The realm is empty, which matches no row on a table keyed by both, so
    /// reaching realm scoped data with this reads nothing rather than reading
    /// everything.
    pub fn tenant_wide(tenant: impl Into<String>) -> Self {
        Self {
            tenant: tenant.into(),
            realm_id: String::new(),
            region: None,
        }
    }
}

/// What this node is, and the only way to open a scoped transaction on it.
///
/// The region is held here rather than in a process global. A global set once at
/// startup silently keeps whatever was written first, so a second configuration
/// is discarded without a word and every test in a process shares one answer.
#[derive(Debug, Clone, Default)]
pub struct Tenancy {
    node_region: Option<String>,
}

impl Tenancy {
    /// A node that does not pin where it stores data. Residency is opt in, so
    /// this serves every realm.
    pub fn unpinned() -> Self {
        Self { node_region: None }
    }

    /// A node storing data in one jurisdiction.
    pub fn in_region(region: impl Into<String>) -> Self {
        let region: String = region.into();
        Self {
            node_region: Some(region).filter(|region| !region.trim().is_empty()),
        }
    }

    pub fn node_region(&self) -> Option<&str> {
        self.node_region.as_deref()
    }

    /// Whether this node may serve a realm pinned to `pin`.
    ///
    /// Only a mismatch refuses. A node that pins nothing serves everything, and
    /// a realm that pins nothing is served anywhere, so residency is something
    /// an operator opts into on both sides rather than a default that has to be
    /// disabled.
    pub fn permits(&self, pin: Option<&str>) -> bool {
        match (self.node_region(), pin) {
            (Some(node), Some(pin)) => node == pin,
            _ => true,
        }
    }

    /// Open a transaction that says who it is for.
    ///
    /// The caller runs its statements on what comes back and commits. Any early
    /// return drops it, which rolls back.
    pub async fn transaction<'c>(
        &self,
        connection: &'c mut Object,
        context: &TenantContext,
    ) -> StoreResult<Transaction<'c>> {
        self.check_residency(context)?;
        let transaction = connection
            .transaction()
            .await
            .map_err(|_| StoreError::Backend)?;
        Self::scope(&transaction, context).await?;
        Ok(transaction)
    }

    /// The same, on a snapshot that does not move.
    ///
    /// A plain transaction groups statements without freezing what they see:
    /// each one takes a fresh snapshot. For the short read and write bursts the
    /// rest of the store performs that is the right trade, and it is wrong for
    /// anything reading several tables that have to agree.
    ///
    /// An export is exactly that. Reading users and then their roles under a
    /// moving snapshot lets a user created in between appear in the join with no
    /// matching record, and the database cannot always catch that on the way
    /// back in, because several of those references are a bare column with no
    /// constraint behind them.
    ///
    /// The cost, stated: holding a snapshot holds back vacuum on what is being
    /// read for as long as the transaction lives, which for a large realm is
    /// minutes. Declared read only so the server knows it will never write.
    pub async fn snapshot<'c>(
        &self,
        connection: &'c mut Object,
        context: &TenantContext,
    ) -> StoreResult<Transaction<'c>> {
        self.check_residency(context)?;
        let transaction = connection
            .build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .await
            .map_err(|_| StoreError::Backend)?;
        Self::scope(&transaction, context).await?;
        Ok(transaction)
    }

    /// Refused before the transaction opens, so nothing is read or written on
    /// the way to finding out.
    fn check_residency(&self, context: &TenantContext) -> StoreResult<()> {
        if self.permits(context.region.as_deref()) {
            return Ok(());
        }
        Err(StoreError::Residency {
            node: self.node_region().unwrap_or_default().to_owned(),
            pin: context.region.clone().unwrap_or_default(),
        })
    }

    async fn scope(transaction: &Transaction<'_>, context: &TenantContext) -> StoreResult<()> {
        for (setting, value) in [
            ("saffui.current_tenant", &context.tenant),
            ("saffui.current_realm", &context.realm_id),
        ] {
            transaction
                .execute("SELECT set_config($1, $2, true)", &[&setting, value])
                .await
                .map_err(|_| StoreError::Backend)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Residency is something both sides opt into. Only a mismatch refuses.
    #[test]
    fn only_a_mismatch_refuses() {
        let unpinned = Tenancy::unpinned();
        assert!(unpinned.permits(None));
        assert!(
            unpinned.permits(Some("eu-west")),
            "a node that pins nothing serves everything"
        );

        let pinned = Tenancy::in_region("eu-west");
        assert!(pinned.permits(Some("eu-west")));
        assert!(
            pinned.permits(None),
            "a realm that pins nothing is served anywhere"
        );
        assert!(!pinned.permits(Some("af-south")));
    }

    /// A region of whitespace is not a region, on either side. Read as one, a
    /// node would refuse every pinned realm it should serve.
    #[test]
    fn whitespace_is_not_a_region() {
        assert_eq!(Tenancy::in_region("   ").node_region(), None);
        assert!(Tenancy::in_region("   ").permits(Some("eu-west")));

        let context = TenantContext::new("acme", "realm-1").with_region(Some("  ".into()));
        assert_eq!(context.region, None);
    }

    /// A tenant wide context names no realm, which matches nothing on a table
    /// keyed by both rather than everything.
    #[test]
    fn a_tenant_wide_context_names_no_realm() {
        let context = TenantContext::tenant_wide("acme");
        assert_eq!(context.tenant, "acme");
        assert!(context.realm_id.is_empty());
        assert_eq!(context.region, None);
    }

    /// The refusal names both sides, since an operator seeing it has to know
    /// which of the two to change.
    #[test]
    fn a_refusal_names_the_node_and_the_pin() {
        let tenancy = Tenancy::in_region("eu-west");
        let context = TenantContext::new("acme", "realm-1").with_region(Some("af-south".into()));

        assert_eq!(
            tenancy.check_residency(&context).unwrap_err(),
            StoreError::Residency {
                node: "eu-west".to_owned(),
                pin: "af-south".to_owned()
            }
        );
        assert!(
            Tenancy::unpinned().check_residency(&context).is_ok(),
            "an unpinned node serves it"
        );
    }
}

/// Answering whose realm this is, before anything is scoped.
///
/// These are the only reads in the store that run outside the rules, and they
/// run there because the rules cannot answer them: the policies match nothing
/// until the settings are written, and the settings are written from what these
/// return. Each is a call into a function the database owns, granted to the
/// application role and to nobody else.
pub mod resolve {
    use deadpool_postgres::Object;

    use super::TenantContext;
    use crate::error::{StoreError, StoreResult};

    /// The realm a path names.
    pub async fn realm_by_name(connection: &Object, name: &str) -> StoreResult<TenantContext> {
        one(
            "SELECT tenant, realm_id, region FROM resolve_realm_by_name($1)",
            connection,
            name,
        )
        .await
    }

    /// The realm a token names.
    pub async fn realm_by_id(connection: &Object, realm_id: &str) -> StoreResult<TenantContext> {
        one(
            "SELECT tenant, realm_id, region FROM resolve_realm_by_id($1)",
            connection,
            realm_id,
        )
        .await
    }

    /// The realm a session belongs to.
    pub async fn user_session(connection: &Object, session_id: &str) -> StoreResult<TenantContext> {
        one(
            "SELECT tenant, realm_id, region FROM resolve_user_session($1)",
            connection,
            session_id,
        )
        .await
    }

    /// Every realm this deployment holds, disabled ones included, each
    /// carrying its residency so a node still refuses one pinned elsewhere.
    pub async fn every_realm(connection: &Object) -> StoreResult<Vec<TenantContext>> {
        Ok(connection
            .query("SELECT tenant, realm_id, region FROM every_realm()", &[])
            .await
            .map_err(|_| StoreError::Backend)?
            .into_iter()
            .map(|row| {
                TenantContext::new(row.get::<_, String>(0), row.get::<_, String>(1))
                    .with_region(row.get::<_, Option<String>>(2))
            })
            .collect())
    }

    /// One answer, or a refusal.
    ///
    /// Two answers is a refusal and not a choice. A name is unique within a
    /// tenant and nothing makes it unique across them, so picking the first row
    /// would resolve a request to whichever the plan happened to return, and
    /// serve one customer's realm to another customer's caller.
    ///
    /// The tenant comes off the row that was found. Taking it from the request
    /// instead would let a caller name any tenant and have the realm looked up
    /// inside it.
    async fn one(statement: &str, connection: &Object, asked: &str) -> StoreResult<TenantContext> {
        let rows = connection
            .query(statement, &[&asked])
            .await
            .map_err(|_| StoreError::Backend)?;

        match rows.len() {
            0 => Err(StoreError::NotFound {
                asked: asked.to_owned(),
            }),
            1 => {
                let row = &rows[0];
                Ok(TenantContext::new(
                    row.get::<_, String>("tenant"),
                    row.get::<_, String>("realm_id"),
                )
                .with_region(row.get::<_, Option<String>>("region")))
            }
            count => Err(StoreError::Ambiguous {
                asked: asked.to_owned(),
                count,
            }),
        }
    }
}
