use std::fmt;
use std::time::Duration;

use deadpool_postgres::{Object, Pool};
use tokio_postgres::types::ToSql;
use tokio_postgres::{Error, Row};

use crate::error::{StoreError, StoreResult};

/// Both settings in one statement, so a unit of work opens in one round trip:
/// sent in text they would each be prepared, then executed.
const SCOPE: &str = "SELECT set_config('saffui.current_tenant', $1, true), \
                     set_config('saffui.current_realm', $2, true)";

/// How many prepared statements one connection keeps before starting over.
///
/// A statement whose text is built at run time, an update naming the columns
/// it was handed, is a new text for every shape; without a ceiling a long
/// lived connection would keep one of each, on both sides of the wire.
const PREPARED_CEILING: usize = 512;

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

/// How a request names a realm before anything is scoped to it.
#[derive(Debug, Clone, Copy)]
pub enum RealmNamed<'a> {
    /// The name a path carries.
    ByName(&'a str),
    /// The identifier a token carries.
    ById(&'a str),
    /// A user session the realm holds.
    BySession(&'a str),
}

/// What a readiness probe learned about the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reached {
    NoConnection,
    NotAnswering,
    /// It answered, and this is the highest migration it has applied.
    Schema(Option<i32>),
}

/// What this node is, and the only door to the database.
///
/// The pool lives here and nowhere else. Nothing above the store can take a
/// connection, so nothing can hold one past its transaction or skip the
/// residency check on the way in.
///
/// The region is held here rather than in a process global. A global set once at
/// startup silently keeps whatever was written first, so a second configuration
/// is discarded without a word and every test in a process shares one answer.
#[derive(Clone)]
pub struct Tenancy {
    pool: Pool,
    node_region: Option<String>,
}

impl fmt::Debug for Tenancy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Tenancy")
            .field("node_region", &self.node_region)
            .finish_non_exhaustive()
    }
}

impl Tenancy {
    /// A node that does not pin where it stores data. Residency is opt in, so
    /// this serves every realm.
    pub fn unpinned(pool: Pool) -> Self {
        Self {
            pool,
            node_region: None,
        }
    }

    /// A node storing data in one jurisdiction.
    pub fn in_region(pool: Pool, region: impl Into<String>) -> Self {
        let region: String = region.into();
        Self {
            pool,
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

    /// Open a unit of work that says who it is for.
    pub async fn begin(&self, context: &TenantContext) -> StoreResult<UnitOfWork> {
        self.check_residency(context)?;
        UnitOfWork::open(self.connection().await?, context.clone(), Isolation::Moving).await
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
    pub async fn begin_snapshot(&self, context: &TenantContext) -> StoreResult<UnitOfWork> {
        self.check_residency(context)?;
        UnitOfWork::open(self.connection().await?, context.clone(), Isolation::Frozen).await
    }

    /// Resolve a realm and open a unit of work in it, on one connection.
    pub async fn begin_in(&self, realm: RealmNamed<'_>) -> StoreResult<UnitOfWork> {
        let connection = self.connection().await?;
        let context = resolve::on(&connection, realm).await?;
        self.check_residency(&context)?;
        UnitOfWork::open(connection, context, Isolation::Moving).await
    }

    /// Whose realm this is, answered before anything is scoped.
    pub async fn resolve(&self, realm: RealmNamed<'_>) -> StoreResult<TenantContext> {
        resolve::on(&self.connection().await?, realm).await
    }

    /// Every realm this deployment holds, disabled ones included, each
    /// carrying its residency so a node still refuses one pinned elsewhere.
    pub async fn every_realm(&self) -> StoreResult<Vec<TenantContext>> {
        resolve::every_realm(&self.connection().await?).await
    }

    /// Whether the database can be reached and answers inside `within`, and
    /// which schema it holds.
    pub async fn reach(&self, within: Duration) -> Reached {
        let Ok(Ok(connection)) = tokio::time::timeout(within, self.pool.get()).await else {
            return Reached::NoConnection;
        };
        if tokio::time::timeout(within, connection.simple_query("SELECT 1"))
            .await
            .is_err()
        {
            return Reached::NotAnswering;
        }
        // Read at the column's own width: `version` is an `integer`, and a wider
        // read fails to convert, which would read as a database with no schema.
        Reached::Schema(
            connection
                .query_opt("SELECT max(version) FROM schema_migrations", &[])
                .await
                .ok()
                .flatten()
                .and_then(|row| row.try_get::<_, Option<i32>>(0).ok().flatten()),
        )
    }

    async fn connection(&self) -> StoreResult<Object> {
        self.pool.get().await.map_err(|_| StoreError::Unavailable)
    }

    /// Refused before a connection is taken, so a realm pinned elsewhere costs
    /// the pool nothing.
    fn check_residency(&self, context: &TenantContext) -> StoreResult<()> {
        if self.permits(context.region.as_deref()) {
            return Ok(());
        }
        Err(StoreError::Residency {
            node: self.node_region().unwrap_or_default().to_owned(),
            pin: context.region.clone().unwrap_or_default(),
        })
    }
}

enum Isolation {
    Moving,
    Frozen,
}

/// A transaction scoped to one realm, and the connection it runs on.
///
/// It owns the connection. A connection borrowed from a binding goes back to the
/// pool when the binding drops, not when the transaction ends, so work done
/// after a commit, or a second connection taken while holding the first, kept a
/// slot nobody could use; with every slot held that way the pool stops without
/// an error. Here the commit consumes the unit and the slot comes back with it.
///
/// `BEGIN` is sent as a statement because the driver's typed transaction borrows
/// its connection, and a value holding both would refer to itself.
pub struct UnitOfWork {
    /// Empty once committed or rolled back, so dropping has nothing to undo.
    connection: Option<Object>,
    context: TenantContext,
}

impl UnitOfWork {
    async fn open(
        connection: Object,
        context: TenantContext,
        isolation: Isolation,
    ) -> StoreResult<Self> {
        // Built before anything is sent, so a failure from here on drops a unit
        // that rolls itself back.
        let unit = Self {
            connection: Some(connection),
            context,
        };
        let held = unit.held();
        let scope = held
            .prepare_cached(SCOPE)
            .await
            .map_err(|_| StoreError::Backend)?;
        let begin = match isolation {
            Isolation::Moving => "BEGIN",
            Isolation::Frozen => "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY",
        };
        let settings: [&(dyn ToSql + Sync); 2] = [&unit.context.tenant, &unit.context.realm_id];
        // Pipelined: the driver sends requests in the order they are first
        // polled, so both leave together and the unit opens in one round trip.
        let (begun, scoped) =
            tokio::join!(held.batch_execute(begin), held.execute(&scope, &settings),);
        begun.map_err(|_| StoreError::Backend)?;
        scoped.map_err(|_| StoreError::Backend)?;
        Ok(unit)
    }

    /// The realm and tenant these settings were written from, which a
    /// statement's own predicates have to agree with.
    pub fn context(&self) -> &TenantContext {
        &self.context
    }

    pub async fn query(
        &self,
        statement: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, Error> {
        let prepared = self.prepared(statement).await?;
        self.held().query(&prepared, params).await
    }

    pub async fn query_one(
        &self,
        statement: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Row, Error> {
        let prepared = self.prepared(statement).await?;
        self.held().query_one(&prepared, params).await
    }

    pub async fn query_opt(
        &self,
        statement: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Option<Row>, Error> {
        let prepared = self.prepared(statement).await?;
        self.held().query_opt(&prepared, params).await
    }

    pub async fn execute(
        &self,
        statement: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<u64, Error> {
        let prepared = self.prepared(statement).await?;
        self.held().execute(&prepared, params).await
    }

    /// Statements that bind nothing, sent together as written: a `SET LOCAL`,
    /// a savepoint.
    pub async fn batch_execute(&self, statements: &str) -> Result<(), Error> {
        self.held().batch_execute(statements).await
    }

    /// Make everything written visible together, and give the connection back.
    pub async fn commit(mut self) -> StoreResult<()> {
        let connection = self.connection.take().expect("a unit of work ends once");
        connection
            .batch_execute("COMMIT")
            .await
            .map_err(|_| StoreError::Backend)
    }

    /// Discard the work and wait for the discarding to have happened.
    ///
    /// Dropping also rolls back, without waiting. A caller about to stop its
    /// runtime, a test ending being the usual one, awaits this instead.
    pub async fn rollback(mut self) -> StoreResult<()> {
        let connection = self.connection.take().expect("a unit of work ends once");
        let mut abandoned = Abandoned(Some(connection));
        abandoned.roll_back().await
    }

    fn held(&self) -> &Object {
        self.connection
            .as_ref()
            .expect("a unit of work is not used after it ends")
    }

    async fn prepared(&self, statement: &str) -> Result<tokio_postgres::Statement, Error> {
        let held = self.held();
        let prepared = held.prepare_cached(statement).await?;
        if held.statement_cache.size() > PREPARED_CEILING {
            held.statement_cache.clear();
        }
        Ok(prepared)
    }
}

impl Drop for UnitOfWork {
    /// Roll back a unit that was never committed, which is what an early
    /// return means.
    ///
    /// Dropping cannot wait, so the rollback goes to the runtime and takes the
    /// connection with it; the pool gets the slot back only once it is clean.
    fn drop(&mut self) {
        let Some(connection) = self.connection.take() else {
            return;
        };
        let mut abandoned = Abandoned(Some(connection));
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn(async move {
                    let _ = abandoned.roll_back().await;
                });
            }
            Err(_) => drop(abandoned),
        }
    }
}

/// A connection that may still be inside a transaction.
///
/// It goes back to the pool only after its rollback has run. Dropped before
/// that, by a runtime shutting down under it or with no runtime at all, it is
/// taken out of the pool and closed, and the server ends the transaction with
/// the session. A connection is never handed to the next caller half way
/// through somebody else's work.
struct Abandoned(Option<Object>);

impl Abandoned {
    async fn roll_back(&mut self) -> StoreResult<()> {
        let Some(connection) = self.0.as_ref() else {
            return Ok(());
        };
        connection
            .batch_execute("ROLLBACK")
            .await
            .map_err(|_| StoreError::Backend)?;
        self.0.take();
        Ok(())
    }
}

impl Drop for Abandoned {
    fn drop(&mut self) {
        if let Some(connection) = self.0.take() {
            drop(Object::take(connection));
        }
    }
}

/// Answering whose realm this is, before anything is scoped.
///
/// These are the only reads in the store that run outside the rules, and they
/// run there because the rules cannot answer them: the policies match nothing
/// until the settings are written, and the settings are written from what these
/// return. Each is a call into a function the database owns, granted to the
/// application role and to nobody else.
mod resolve {
    use deadpool_postgres::Object;

    use super::{RealmNamed, TenantContext};
    use crate::error::{StoreError, StoreResult};

    pub(super) async fn on(
        connection: &Object,
        realm: RealmNamed<'_>,
    ) -> StoreResult<TenantContext> {
        let (statement, asked) = match realm {
            RealmNamed::ByName(name) => (
                "SELECT tenant, realm_id, region FROM resolve_realm_by_name($1)",
                name,
            ),
            RealmNamed::ById(realm_id) => (
                "SELECT tenant, realm_id, region FROM resolve_realm_by_id($1)",
                realm_id,
            ),
            RealmNamed::BySession(session_id) => (
                "SELECT tenant, realm_id, region FROM resolve_user_session($1)",
                session_id,
            ),
        };
        let prepared = connection
            .prepare_cached(statement)
            .await
            .map_err(|_| StoreError::Backend)?;
        let rows = connection
            .query(&prepared, &[&asked])
            .await
            .map_err(|_| StoreError::Backend)?;

        // Two answers is still a refusal and not a choice. The schema prevents
        // them; keeping the guard makes a damaged or older schema fail closed.
        // The tenant comes off the row that was found: taken from the request,
        // a caller could name any tenant and have the realm looked up in it.
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

    pub(super) async fn every_realm(connection: &Object) -> StoreResult<Vec<TenantContext>> {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use deadpool_postgres::{Manager, Pool};
    use tokio_postgres::NoTls;

    /// Never connected: these read the node's settings, not the database.
    fn tenancy(region: Option<&str>) -> Tenancy {
        let pool = Pool::builder(Manager::new(tokio_postgres::Config::new(), NoTls))
            .build()
            .expect("a pool builds without connecting");
        match region {
            Some(region) => Tenancy::in_region(pool, region),
            None => Tenancy::unpinned(pool),
        }
    }

    /// Residency is something both sides opt into. Only a mismatch refuses.
    #[test]
    fn only_a_mismatch_refuses() {
        let unpinned = tenancy(None);
        assert!(unpinned.permits(None));
        assert!(
            unpinned.permits(Some("eu-west")),
            "a node that pins nothing serves everything"
        );

        let pinned = tenancy(Some("eu-west"));
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
        assert_eq!(tenancy(Some("   ")).node_region(), None);
        assert!(tenancy(Some("   ")).permits(Some("eu-west")));

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

    /// Nothing above the store reaches the database on its own.
    ///
    /// The compiler holds the rule: a crate that does not depend on the driver
    /// cannot name a pool or a connection. This holds the manifests, so one line
    /// added to a dependency list cannot quietly undo it.
    #[test]
    fn nothing_above_the_store_depends_on_the_driver() {
        let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("the store sits among the crates");
        let mut offenders = Vec::new();
        for member in ["auth", "authz", "ldapfront", "saml", "server", "services"] {
            let manifest = std::fs::read_to_string(crates.join(member).join("Cargo.toml"))
                .expect("every member has a manifest");
            for driver in ["deadpool-postgres", "tokio-postgres"] {
                if runtime_dependencies(&manifest)
                    .iter()
                    .any(|name| name == driver)
                {
                    offenders.push(format!("{member} depends on {driver}"));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "a crate above the store can take a connection of its own, hold it past \
             its transaction, and skip the residency check; open a unit of work through \
             Tenancy instead: {offenders:?}"
        );
    }

    /// What a crate compiles against, its test only dependencies left out.
    fn runtime_dependencies(manifest: &str) -> Vec<String> {
        let mut section = "";
        let mut names = Vec::new();
        for line in manifest.lines().map(str::trim) {
            if line.starts_with('[') {
                section = line;
                if let Some(name) = line
                    .strip_prefix("[dependencies.")
                    .and_then(|rest| rest.strip_suffix(']'))
                {
                    names.push(name.to_owned());
                }
                continue;
            }
            let runtime = section == "[dependencies]"
                || (section.starts_with("[target.") && section.ends_with(".dependencies]"));
            if runtime
                && !line.starts_with('#')
                && let Some((name, _)) = line.split_once('=')
            {
                names.push(name.trim().to_owned());
            }
        }
        names
    }

    #[test]
    fn test_only_dependencies_are_not_counted() {
        let manifest = "[dependencies]\nserde = \"1\"\n\n[dev-dependencies]\ndeadpool-postgres = \"0.14\"\n\
                        [target.'cfg(unix)'.dependencies]\nlibc = \"0.2\"\n[dependencies.tokio-postgres]\nversion = \"0.7\"\n";
        assert_eq!(
            runtime_dependencies(manifest),
            vec!["serde", "libc", "tokio-postgres"]
        );
    }

    /// The refusal names both sides, since an operator seeing it has to know
    /// which of the two to change.
    #[test]
    fn a_refusal_names_the_node_and_the_pin() {
        let pinned = tenancy(Some("eu-west"));
        let context = TenantContext::new("acme", "realm-1").with_region(Some("af-south".into()));

        assert_eq!(
            pinned.check_residency(&context).unwrap_err(),
            StoreError::Residency {
                node: "eu-west".to_owned(),
                pin: "af-south".to_owned()
            }
        );
        assert!(
            tenancy(None).check_residency(&context).is_ok(),
            "an unpinned node serves it"
        );
    }
}
