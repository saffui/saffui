use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;
use crypto::provider::{DigestProvider, HashAlg};
use tokio_postgres::Client;

use super::error::MigrationError;

/// A numbered piece of SQL, applied verbatim.
#[derive(Debug, Clone, Copy)]
pub struct SqlMigration {
    pub version: i32,
    pub name: &'static str,
    pub sql: &'static str,
    /// Whether the runner wraps it in one transaction. Off for the statements
    /// PostgreSQL refuses to run inside one, `CREATE INDEX CONCURRENTLY` above all.
    pub transactional: bool,
}

/// A backfill written in Rust, which can stop and pick up again.
///
/// Not wrapped in one transaction: it is expected to advance a cursor and commit
/// in batches so a crash resumes rather than restarts. The version is recorded
/// only once it returns, so it has to survive being run twice.
#[async_trait]
pub trait DataMigration: Send + Sync {
    fn version(&self) -> i32;
    fn name(&self) -> &str;

    async fn apply(&self, client: &mut Client) -> Result<(), MigrationError>;
}

/// One step: SQL or a backfill.
#[derive(Clone)]
pub enum Migration {
    Sql(SqlMigration),
    Data(Arc<dyn DataMigration>),
}

impl std::fmt::Debug for Migration {
    /// The version and the name, never the SQL. A failing plan prints these,
    /// and a migration body in a log line is noise at best.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Migration")
            .field("version", &self.version())
            .field("name", &self.name())
            .finish_non_exhaustive()
    }
}

impl Migration {
    pub fn version(&self) -> i32 {
        match self {
            Self::Sql(m) => m.version,
            Self::Data(m) => m.version(),
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Sql(m) => m.name,
            Self::Data(m) => m.name(),
        }
    }

    /// What the history records, so an edit to something already applied is
    /// noticed.
    ///
    /// The SQL is hashed. A Rust backfill's body cannot be, so its identity
    /// stands in — which means editing one is invisible here, and that is why
    /// it must be idempotent rather than merely correct once.
    ///
    /// The digest is passed in: this crate reaches crypto through its seam like
    /// everything else, and there is no free function to reach for.
    pub fn checksum(&self, digest: &dyn DigestProvider) -> String {
        let bytes = match self {
            Self::Sql(m) => m.sql.as_bytes().to_vec(),
            Self::Data(m) => format!("rust-data:{}:{}", m.version(), m.name()).into_bytes(),
        };

        digest
            .hash(HashAlg::Sha256, &bytes)
            .map(|digest| digest.iter().map(|b| format!("{b:02x}")).collect())
            .unwrap_or_default()
    }
}

/// A row of the history table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedRecord {
    pub version: i32,
    pub name: String,
    pub checksum: String,
}

/// One migration a database has not applied yet.
///
/// Carries the name as well as the number: a version alone says nothing to
/// whoever has to decide whether to run it now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingMigration {
    pub version: i32,
    pub name: String,
}

impl From<&Migration> for PendingMigration {
    fn from(migration: &Migration) -> Self {
        Self {
            version: migration.version(),
            name: migration.name().to_owned(),
        }
    }
}

/// What is left to apply, in order.
///
/// Pure — it touches no database. It refuses four things, and each is a state a
/// deployment can reach by accident:
///
/// - a version listed twice, so which one applies is undefined;
/// - a version the database has and this build does not, which means the binary
///   is older than the schema and would not understand it;
/// - a checksum that moved, which means a file was edited after being applied,
///   so the database and the file no longer describe the same schema;
/// - a new version that sorts below one already applied, which would run out of
///   order and leave two databases with the same version number and different
///   shapes.
pub fn plan<'a>(
    embedded: &'a [Migration],
    applied: &[AppliedRecord],
    digest: &dyn DigestProvider,
) -> Result<Vec<&'a Migration>, MigrationError> {
    let mut seen = BTreeSet::new();
    for migration in embedded {
        if !seen.insert(migration.version()) {
            return Err(MigrationError::DuplicateVersion {
                version: migration.version(),
            });
        }
    }

    let mut ordered: Vec<&Migration> = embedded.iter().collect();
    ordered.sort_by_key(|migration| migration.version());

    for record in applied {
        match ordered.iter().find(|m| m.version() == record.version) {
            None => {
                return Err(MigrationError::UnknownApplied {
                    version: record.version,
                });
            }
            Some(migration) => {
                if migration.checksum(digest) != record.checksum {
                    return Err(MigrationError::ChecksumDrift {
                        version: record.version,
                        name: record.name.clone(),
                    });
                }
            }
        }
    }

    let done: BTreeSet<i32> = applied.iter().map(|record| record.version).collect();
    let highest = done.iter().copied().max();

    let mut pending = Vec::new();
    for migration in ordered {
        let version = migration.version();
        if done.contains(&version) {
            continue;
        }
        if highest.is_some_and(|high| version < high) {
            return Err(MigrationError::OutOfOrder { version });
        }
        pending.push(migration);
    }

    Ok(pending)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crypto::provider::openssl::hashing::OpenSslDigest;

    fn sql(version: i32, name: &'static str, body: &'static str) -> Migration {
        Migration::Sql(SqlMigration {
            version,
            name,
            sql: body,
            transactional: true,
        })
    }

    fn applied(migration: &Migration) -> AppliedRecord {
        AppliedRecord {
            version: migration.version(),
            name: migration.name().to_string(),
            checksum: migration.checksum(&OpenSslDigest),
        }
    }

    /// A fresh database has everything to do, in order.
    #[test]
    fn everything_is_pending_against_nothing() {
        let set = vec![sql(2, "second", "SELECT 2"), sql(1, "first", "SELECT 1")];

        let pending = plan(&set, &[], &OpenSslDigest).unwrap();

        assert_eq!(
            pending.iter().map(|m| m.version()).collect::<Vec<_>>(),
            vec![1, 2],
            "declared out of order, applied in order"
        );
    }

    /// A database already there has nothing to do.
    #[test]
    fn a_current_database_has_nothing_pending() {
        let set = vec![sql(1, "first", "SELECT 1"), sql(2, "second", "SELECT 2")];
        let history: Vec<AppliedRecord> = set.iter().map(applied).collect();

        assert!(plan(&set, &history, &OpenSslDigest).unwrap().is_empty());
    }

    /// A version listed twice is refused: which one applies would be undefined.
    #[test]
    fn a_repeated_version_is_refused() {
        let set = vec![sql(1, "first", "SELECT 1"), sql(1, "again", "SELECT 2")];

        assert_eq!(
            plan(&set, &[], &OpenSslDigest).unwrap_err(),
            MigrationError::DuplicateVersion { version: 1 }
        );
    }

    /// A database ahead of the binary is refused.
    ///
    /// It means this build is older than the schema it is looking at, and would
    /// be reading tables in a shape it does not know.
    #[test]
    fn a_database_ahead_of_the_binary_is_refused() {
        let set = vec![sql(1, "first", "SELECT 1")];
        let history = vec![
            applied(&set[0]),
            AppliedRecord {
                version: 2,
                name: "from a newer build".to_string(),
                checksum: "whatever".to_string(),
            },
        ];

        assert_eq!(
            plan(&set, &history, &OpenSslDigest).unwrap_err(),
            MigrationError::UnknownApplied { version: 2 }
        );
    }

    /// A file edited after it was applied is refused.
    ///
    /// The database and the file no longer describe the same schema, and
    /// applying the difference is not possible: the old statement already ran.
    #[test]
    fn an_edited_migration_is_refused() {
        let original = sql(1, "first", "CREATE TABLE a (id int)");
        let history = vec![applied(&original)];
        let edited = vec![sql(1, "first", "CREATE TABLE a (id bigint)")];

        assert_eq!(
            plan(&edited, &history, &OpenSslDigest).unwrap_err(),
            MigrationError::ChecksumDrift {
                version: 1,
                name: "first".to_string()
            }
        );

        // The name is not what is hashed; the content is.
        let renamed = vec![sql(1, "renamed", "CREATE TABLE a (id int)")];
        assert!(plan(&renamed, &history, &OpenSslDigest).is_ok());
    }

    /// A new migration that sorts below one already applied is refused.
    ///
    /// Two databases would end up at the same version with different shapes:
    /// the one that saw it applies it, the one already past does not.
    #[test]
    fn a_backfilled_version_is_refused() {
        let set = vec![
            sql(1, "first", "SELECT 1"),
            sql(2, "slipped in later", "SELECT 2"),
            sql(3, "third", "SELECT 3"),
        ];
        let history = vec![applied(&set[0]), applied(&set[2])];

        assert_eq!(
            plan(&set, &history, &OpenSslDigest).unwrap_err(),
            MigrationError::OutOfOrder { version: 2 }
        );
    }

    /// A version above everything applied is pending, not out of order.
    #[test]
    fn a_version_above_the_highest_is_pending() {
        let set = vec![sql(1, "first", "SELECT 1"), sql(5, "fifth", "SELECT 5")];
        let history = vec![applied(&set[0])];

        let pending = plan(&set, &history, &OpenSslDigest).unwrap();

        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].version(), 5);
    }

    /// The checksum follows the content, and two migrations are not the same.
    #[test]
    fn a_checksum_follows_the_content() {
        let one = sql(1, "first", "SELECT 1");
        let same = sql(1, "first", "SELECT 1");
        let other = sql(1, "first", "SELECT 2");

        assert_eq!(one.checksum(&OpenSslDigest), same.checksum(&OpenSslDigest));
        assert_ne!(one.checksum(&OpenSslDigest), other.checksum(&OpenSslDigest));
        assert_eq!(one.checksum(&OpenSslDigest).len(), 64, "SHA-256 in hex");
    }
}
