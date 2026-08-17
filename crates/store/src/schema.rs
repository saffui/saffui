//! The schema, and the migrations that build it.
//!
//! Forward only and consolidated by concern rather than by the date a fix was
//! needed. A database this creates has no history to replay, so a migration here
//! describes a part of the schema rather than a correction to an earlier one.

use pgcore::migrations::{Migration, SqlMigration};

/// Every migration this build carries, in order.
///
/// Each entry names its file, and the file is read at compile time, so a
/// migration that was written and never listed does not silently go unapplied
/// while the directory looks complete.
pub fn migrations() -> Vec<Migration> {
    vec![Migration::Sql(SqlMigration {
        version: 1,
        name: "tenancy",
        sql: include_str!("../migrations/V001__tenancy.sql"),
        transactional: true,
    })]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every migration is listed once, numbered in order from one, and names a
    /// file whose contents are not empty.
    ///
    /// A duplicate version is what the runner refuses, and a gap is what makes a
    /// history hard to read. Both are cheaper to catch here than against a
    /// database.
    #[test]
    fn the_migrations_are_numbered_in_order_from_one() {
        let migrations = migrations();
        assert!(!migrations.is_empty(), "a runner with nothing to run");

        for (index, migration) in migrations.iter().enumerate() {
            let (version, name, sql) = match migration {
                Migration::Sql(sql) => (sql.version, sql.name, sql.sql),
                Migration::Data(_) => panic!("this build carries no backfills yet"),
            };

            assert_eq!(
                version,
                index as i32 + 1,
                "{name} is out of order or leaves a gap"
            );
            assert!(!name.is_empty());
            assert!(
                sql.trim().len() > 100,
                "{name} looks empty, which an include of the wrong path would also"
            );
        }
    }

    /// Every table this schema creates turns row level security on and forces
    /// it.
    ///
    /// Read from the text rather than from a database, because the failure is
    /// writing a table and forgetting the two lines: a policy on a table with
    /// security disabled does nothing, and one enabled without forcing does
    /// nothing for the role that owns the tables, which is usually the role the
    /// application connects as.
    #[test]
    fn every_table_enables_and_forces_row_level_security() {
        for migration in migrations() {
            let Migration::Sql(sql) = migration else {
                continue;
            };

            let created: Vec<String> = sql
                .sql
                .lines()
                .filter_map(|line| line.trim().strip_prefix("CREATE TABLE "))
                .map(|rest| {
                    rest.trim_start_matches("IF NOT EXISTS ")
                        .split_whitespace()
                        .next()
                        .unwrap_or_default()
                        .to_lowercase()
                })
                .collect();

            assert!(!created.is_empty(), "{} creates no table", sql.name);

            for table in created {
                for clause in ["ENABLE", "FORCE"] {
                    assert!(
                        sql.sql
                            .contains(&format!("ALTER TABLE {table} {clause} ROW LEVEL SECURITY")),
                        "{}: {table} does not {clause} row level security",
                        sql.name
                    );
                }
                assert!(
                    sql.sql.contains(&format!("ON {table}\n")),
                    "{}: {table} has no policy",
                    sql.name
                );
            }
        }
    }

    /// Every policy reads the setting with the flag that makes an unset one
    /// NULL.
    ///
    /// Without it, a connection that never said who it is raises an error on
    /// some statements and matches everything on others. With it the comparison
    /// is against NULL, which is not true, so an ungoverned connection sees
    /// nothing.
    #[test]
    fn every_policy_fails_closed_on_an_unset_setting() {
        for migration in migrations() {
            let Migration::Sql(sql) = migration else {
                continue;
            };
            let statements = sql
                .sql
                .lines()
                .map(str::trim)
                .filter(|line| !line.starts_with("--"));

            let mut read_a_setting = false;
            for line in statements.filter(|line| line.contains("current_setting")) {
                read_a_setting = true;
                assert!(
                    line.contains("current_setting('saffui.current_tenant', true)")
                        || line.contains("current_setting('saffui.current_realm', true)"),
                    "{}: {line} reads a setting without failing closed",
                    sql.name
                );
            }

            assert!(
                read_a_setting,
                "{} defines policies that read no tenant at all",
                sql.name
            );
        }
    }
}
