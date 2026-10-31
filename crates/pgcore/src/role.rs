//! What the connected role is allowed to do. Row security is the second wall
//! between tenants: a node must not serve under a role that walks through it,
//! nor under one that may become such a role by `SET ROLE`.

use tokio_postgres::Client;

/// What would let a role step past row security, in the order it is looked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Privilege {
    /// A superuser, or a role that bypasses row security.
    BypassesRowSecurity,
    /// A predefined role that reads or writes every table, or reaches the
    /// files and programs of the server.
    ReachesEverything,
    /// The owner of the database, of a schema or of a relation, who can lift
    /// row security or drop what it guards.
    ActsAsOwner,
    /// May create roles and grant itself their membership.
    ManagesRoles,
    /// May open a replication connection, which reads every row.
    Replicates,
    /// Holds a privilege row security does not govern on a table:
    /// `TRUNCATE`, `REFERENCES` or `TRIGGER`.
    HoldsWholeTablePrivilege,
    /// May write a table that row security does not guard, or a view or a
    /// foreign table, which it never guards: whole or a column of it.
    WritesUnguardedTable,
    /// May read a table through a view that runs under the rights of its
    /// owner, or through a materialized view: neither is filtered for it.
    ReadsThroughView,
    /// May read a table that row security does not guard, whole or a column
    /// of it, other than the history of the migrations, which the probe reads.
    ReadsUnguardedTable,
    /// May run a function, or reach it through a view, that runs under the
    /// rights of an owner who bypasses row security or owns a table it binds
    /// without force; or may attach a trigger function that runs under the
    /// rights of its owner, whoever that is, to a table of its own. Only a
    /// superuser creates an event trigger, and its function cannot be called.
    ExecutesDefinerFunction,
}

impl Privilege {
    fn describe(self) -> &'static str {
        match self {
            Self::BypassesRowSecurity => "bypasses row security",
            Self::ReachesEverything => {
                "may act as a predefined role that reaches every table or the server itself"
            }
            Self::ActsAsOwner => {
                "has the privileges of an owner of the database, of a schema or of a table"
            }
            Self::ManagesRoles => "may create roles and grant their membership",
            Self::Replicates => "may open a replication connection, which reads every row",
            Self::HoldsWholeTablePrivilege => {
                "holds TRUNCATE, REFERENCES or TRIGGER on a table, which row security does not govern"
            }
            Self::WritesUnguardedTable => "may write a table that row security does not guard",
            Self::ReadsThroughView => {
                "may read a table through a view that row security does not filter for it"
            }
            Self::ReadsUnguardedTable => "may read a table that row security does not guard",
            Self::ExecutesDefinerFunction => {
                "may run a function that runs as an owner whom row security does not bind"
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleFacts {
    /// The role the session logged in as.
    pub name: String,
    /// The first privilege found, in the order of the variants.
    pub privilege: Option<Privilege>,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the role {name} {}: a node does not serve under it", .privilege.describe())]
pub struct PrivilegedRole {
    pub name: String,
    pub privilege: Privilege,
}

/// Every role `SET ROLE` may reach: the session user decides it, not the
/// current role, which a setting of the login may have lowered. Every relation,
/// schema and function outside the system ones, whose names a user cannot
/// start with `pg_`. Every view or materialized view that reads a table other
/// than the history, `$1`, itself or through another view. It runs with the
/// catalog alone in the search path: a function or an operator elsewhere, with
/// argument types closer than the catalog's, would answer in its place.
const READ_ROLE_FACTS: &str = "\
WITH RECURSIVE reach AS (
    SELECT m.oid, m.rolname, m.rolsuper, m.rolbypassrls, m.rolcreaterole, m.rolreplication
    FROM pg_catalog.pg_roles m
    WHERE pg_catalog.pg_has_role(session_user, m.oid, 'MEMBER')
), namespace AS (
    SELECT n.oid, n.nspowner
    FROM pg_catalog.pg_namespace n
    WHERE n.nspname <> 'information_schema'
      AND pg_catalog.left(n.nspname::text, 3) <> 'pg_'
), relation AS (
    SELECT c.oid, c.relkind, c.relrowsecurity, c.relowner, c.reloptions
    FROM pg_catalog.pg_class c
    JOIN namespace ON namespace.oid = c.relnamespace
    WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
), reads_tables (oid) AS (
    SELECT r.ev_class
    FROM pg_catalog.pg_rewrite r
    JOIN pg_catalog.pg_depend d
        ON d.classid = 'pg_catalog.pg_rewrite'::regclass AND d.objid = r.oid
        AND d.refclassid = 'pg_catalog.pg_class'::regclass
    JOIN relation ON relation.oid = d.refobjid
    WHERE relation.relkind IN ('r', 'p', 'm', 'f')
      AND relation.oid <> r.ev_class
      AND relation.oid IS DISTINCT FROM $1
    UNION
    SELECT r.ev_class
    FROM pg_catalog.pg_rewrite r
    JOIN pg_catalog.pg_depend d
        ON d.classid = 'pg_catalog.pg_rewrite'::regclass AND d.objid = r.oid
        AND d.refclassid = 'pg_catalog.pg_class'::regclass
    JOIN reads_tables ON reads_tables.oid = d.refobjid
    WHERE r.ev_class <> d.refobjid
)
SELECT session_user::text,
    EXISTS (SELECT 1 FROM reach WHERE rolsuper OR rolbypassrls),
    EXISTS (SELECT 1 FROM reach WHERE rolname IN ('pg_read_all_data', 'pg_write_all_data',
        'pg_read_server_files', 'pg_write_server_files', 'pg_execute_server_program')),
    EXISTS (SELECT 1 FROM reach JOIN pg_catalog.pg_database d
            ON d.datname = pg_catalog.current_database() AND d.datdba = reach.oid)
        OR EXISTS (SELECT 1 FROM reach JOIN namespace ON namespace.nspowner = reach.oid)
        OR EXISTS (SELECT 1 FROM reach JOIN relation ON relation.relowner = reach.oid),
    EXISTS (SELECT 1 FROM reach WHERE rolcreaterole),
    EXISTS (SELECT 1 FROM reach WHERE rolreplication),
    EXISTS (SELECT 1 FROM reach, relation
            WHERE relation.relkind IN ('r', 'p')
              AND (pg_catalog.has_table_privilege(reach.oid, relation.oid, 'TRUNCATE, REFERENCES, TRIGGER')
                   OR pg_catalog.has_any_column_privilege(reach.oid, relation.oid, 'REFERENCES'))),
    EXISTS (SELECT 1 FROM reach, relation
            WHERE NOT relation.relrowsecurity
              AND (pg_catalog.has_table_privilege(reach.oid, relation.oid, 'INSERT, UPDATE, DELETE')
                   OR pg_catalog.has_any_column_privilege(reach.oid, relation.oid, 'INSERT, UPDATE'))),
    EXISTS (SELECT 1 FROM reach, relation
            WHERE relation.relkind IN ('v', 'm')
              AND relation.oid IN (SELECT oid FROM reads_tables)
              AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_options_to_table(relation.reloptions) o
                              WHERE CASE WHEN o.option_name = 'security_invoker'
                                         THEN o.option_value::boolean ELSE false END)
              AND (pg_catalog.has_table_privilege(reach.oid, relation.oid, 'SELECT')
                   OR pg_catalog.has_any_column_privilege(reach.oid, relation.oid, 'SELECT'))),
    EXISTS (SELECT 1 FROM reach, relation
            WHERE relation.relkind IN ('r', 'p', 'm', 'f')
              AND NOT relation.relrowsecurity
              AND relation.oid IS DISTINCT FROM $1
              AND (pg_catalog.has_table_privilege(reach.oid, relation.oid, 'SELECT')
                   OR pg_catalog.has_any_column_privilege(reach.oid, relation.oid, 'SELECT'))),
    EXISTS (SELECT 1 FROM reach, pg_catalog.pg_proc p
            JOIN namespace ON namespace.oid = p.pronamespace
            JOIN pg_catalog.pg_roles definer ON definer.oid = p.proowner
            WHERE p.prosecdef
              AND p.prorettype <> 'pg_catalog.event_trigger'::regtype
              AND (p.prorettype = 'pg_catalog.trigger'::regtype
                   OR definer.rolsuper OR definer.rolbypassrls
                   OR EXISTS (SELECT 1 FROM pg_catalog.pg_class t
                              WHERE t.relrowsecurity AND NOT t.relforcerowsecurity
                                AND pg_catalog.pg_has_role(definer.oid, t.relowner, 'USAGE')))
              AND pg_catalog.has_function_privilege(reach.oid, p.oid, 'EXECUTE'))";

const LOOKED_FOR: [Privilege; 10] = [
    Privilege::BypassesRowSecurity,
    Privilege::ReachesEverything,
    Privilege::ActsAsOwner,
    Privilege::ManagesRoles,
    Privilege::Replicates,
    Privilege::HoldsWholeTablePrivilege,
    Privilege::WritesUnguardedTable,
    Privilege::ReadsThroughView,
    Privilege::ReadsUnguardedTable,
    Privilege::ExecutesDefinerFunction,
];

/// Reads the facts of the role this session logged in as, in a transaction of
/// its own: a client, not a transaction, so that it commits nothing else.
///
/// # Errors
///
/// Returns the driver's error when the catalog cannot be read.
pub async fn read_role_facts(client: &Client) -> Result<RoleFacts, tokio_postgres::Error> {
    // Found as the probe finds it, by the search path of the session.
    let history: Option<u32> = client
        .query_one(
            "SELECT pg_catalog.to_regclass('schema_migrations')::pg_catalog.oid",
            &[],
        )
        .await?
        .get(0);
    client
        .batch_execute("BEGIN; SET LOCAL search_path = pg_catalog")
        .await?;
    let read = client.query_one(READ_ROLE_FACTS, &[&history]).await;
    let ended = client
        .batch_execute(if read.is_ok() { "COMMIT" } else { "ROLLBACK" })
        .await;
    let row = read?;
    ended?;
    let privilege = LOOKED_FOR
        .iter()
        .enumerate()
        .find(|(position, _)| row.get::<_, bool>(position + 1))
        .map(|(_, privilege)| *privilege);
    Ok(RoleFacts {
        name: row.get(0),
        privilege,
    })
}

/// Refuses a role under which row security does not hold.
///
/// # Errors
///
/// Returns the name of the role and the first privilege that disqualifies it.
pub fn refuse_privileged_role(facts: &RoleFacts) -> Result<(), PrivilegedRole> {
    match facts.privilege {
        None => Ok(()),
        Some(privilege) => Err(PrivilegedRole {
            name: facts.name.clone(),
            privilege,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::{Privilege, PrivilegedRole, RoleFacts, refuse_privileged_role};

    #[test]
    fn an_ordinary_role_may_serve() {
        let ordinary = RoleFacts {
            name: "some_role".to_owned(),
            privilege: None,
        };
        assert_eq!(refuse_privileged_role(&ordinary), Ok(()));
    }

    #[test]
    fn a_privileged_role_is_refused_with_its_name_and_what_disqualifies_it() {
        let owner = RoleFacts {
            name: "some_role".to_owned(),
            privilege: Some(Privilege::ActsAsOwner),
        };
        let refused = refuse_privileged_role(&owner).expect_err("a refusal");
        assert_eq!(
            refused,
            PrivilegedRole {
                name: "some_role".to_owned(),
                privilege: Privilege::ActsAsOwner,
            }
        );
        assert_eq!(
            refused.to_string(),
            "the role some_role has the privileges of an owner of the database, of a schema or of a table: a node does not serve under it"
        );
    }
}
