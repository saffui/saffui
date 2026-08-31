use pgcore::migrations::{Migration, SqlMigration};

/// Every migration this build carries, in order.
///
/// Each entry names its file, and the file is read at compile time, so a
/// migration that was written and never listed does not silently go unapplied
/// while the directory looks complete.
pub fn migrations() -> Vec<Migration> {
    vec![
        Migration::Sql(SqlMigration {
            version: 1,
            name: "tenancy",
            sql: include_str!("../migrations/V001__tenancy.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 2,
            name: "users_and_clients",
            sql: include_str!("../migrations/V002__users_and_clients.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 3,
            name: "credentials",
            sql: include_str!("../migrations/V003__credentials.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 4,
            name: "sessions_and_tokens",
            sql: include_str!("../migrations/V004__sessions_and_tokens.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 5,
            name: "roles_and_groups",
            sql: include_str!("../migrations/V005__roles_and_groups.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 6,
            name: "organizations",
            sql: include_str!("../migrations/V006__organizations.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 7,
            name: "authentication_flows",
            sql: include_str!("../migrations/V007__authentication_flows.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 8,
            name: "realm_resolution",
            sql: include_str!("../migrations/V008__realm_resolution.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 9,
            name: "realm_data_encryption_keys",
            sql: include_str!("../migrations/V009__realm_data_encryption_keys.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 10,
            name: "realm_signing_keys",
            sql: include_str!("../migrations/V010__realm_signing_keys.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 11,
            name: "audit_chain",
            sql: include_str!("../migrations/V011__audit_chain.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 12,
            name: "client_scopes_and_mappers",
            sql: include_str!("../migrations/V012__client_scopes_and_mappers.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 13,
            name: "login_in_progress",
            sql: include_str!("../migrations/V013__login_in_progress.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 14,
            name: "oidc_core",
            sql: include_str!("../migrations/V014__oidc_core.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 15,
            name: "protected_surface",
            sql: include_str!("../migrations/V015__protected_surface.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 16,
            name: "policies",
            sql: include_str!("../migrations/V016__policies.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 17,
            name: "rebac",
            sql: include_str!("../migrations/V017__rebac.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 18,
            name: "client_secrets_at_rest",
            sql: include_str!("../migrations/V018__client_secrets_at_rest.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 19,
            name: "one_client_session_per_login",
            sql: include_str!("../migrations/V019__one_client_session_per_login.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 20,
            name: "refresh_grace",
            sql: include_str!("../migrations/V020__refresh_grace.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 21,
            name: "otp_replay",
            sql: include_str!("../migrations/V021__otp_replay.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 22,
            name: "code_reuse",
            sql: include_str!("../migrations/V022__code_reuse.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 23,
            name: "claims_request",
            sql: include_str!("../migrations/V023__claims_request.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 24,
            name: "one_active_key_per_algorithm",
            sql: include_str!("../migrations/V024__one_active_key_per_algorithm.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 25,
            name: "logout_notification_uris",
            sql: include_str!("../migrations/V025__logout_notification_uris.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 26,
            name: "client_keys",
            sql: include_str!("../migrations/V026__client_keys.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 27,
            name: "pushed_requests",
            sql: include_str!("../migrations/V027__pushed_requests.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 28,
            name: "realm_listing",
            sql: include_str!("../migrations/V028__realm_listing.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 29,
            name: "session_provenance",
            sql: include_str!("../migrations/V029__session_provenance.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 30,
            name: "offline_access",
            sql: include_str!("../migrations/V030__offline_access.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 31,
            name: "magic_link",
            sql: include_str!("../migrations/V031__magic_link.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 32,
            name: "realm_mail",
            sql: include_str!("../migrations/V032__realm_mail.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 33,
            name: "client_registration",
            sql: include_str!("../migrations/V033__client_registration.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 34,
            name: "client_secret_sealing",
            sql: include_str!("../migrations/V034__client_secret_sealing.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 35,
            name: "registered_request_uris",
            sql: include_str!("../migrations/V035__registered_request_uris.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 36,
            name: "pairwise_subjects",
            sql: include_str!("../migrations/V036__pairwise_subjects.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 37,
            name: "client_key_refresh",
            sql: include_str!("../migrations/V037__client_key_refresh.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 38,
            name: "browser_state",
            sql: include_str!("../migrations/V038__browser_state.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 39,
            name: "brute_force",
            sql: include_str!("../migrations/V039__brute_force.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 40,
            name: "offline_bounds",
            sql: include_str!("../migrations/V040__offline_bounds.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 41,
            name: "require_pushed_requests",
            sql: include_str!("../migrations/V041__require_pushed_requests.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 42,
            name: "message_receipts",
            sql: include_str!("../migrations/V042__message_receipts.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 43,
            name: "consents",
            sql: include_str!("../migrations/V043__consents.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 44,
            name: "registration_bounds",
            sql: include_str!("../migrations/V044__registration_bounds.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 45,
            name: "form_post_landings",
            sql: include_str!("../migrations/V045__form_post_landings.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 46,
            name: "realm_encryption_keys",
            sql: include_str!("../migrations/V046__realm_encryption_keys.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 47,
            name: "dpop_proofs",
            sql: include_str!("../migrations/V047__dpop_proofs.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 48,
            name: "identity_brokering",
            sql: include_str!("../migrations/V048__identity_brokering.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 49,
            name: "idp_mappers",
            sql: include_str!("../migrations/V049__idp_mappers.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 50,
            name: "user_federation",
            sql: include_str!("../migrations/V050__user_federation.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 51,
            name: "user_claim_sources",
            sql: include_str!("../migrations/V051__user_claim_sources.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 52,
            name: "realm_spnego",
            sql: include_str!("../migrations/V052__realm_spnego.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 53,
            name: "user_federations",
            sql: include_str!("../migrations/V053__user_federations.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 54,
            name: "replay_guard",
            sql: include_str!("../migrations/V054__replay_guard.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 55,
            name: "backchannel_requests",
            sql: include_str!("../migrations/V055__backchannel_requests.sql"),
            transactional: true,
        }),
        Migration::Sql(SqlMigration {
            version: 56,
            name: "backchannel_delivery",
            sql: include_str!("../migrations/V056__backchannel_delivery.sql"),
            transactional: true,
        }),
    ]
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

            // A migration is allowed to create no table: one may add a
            // function or a role and nothing else. What it may not do is create
            // a table and leave it unguarded, which is what the loop checks.
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

    /// Every function that runs with its owner's rights pins its search path.
    ///
    /// Such a function exists to see what its caller may not, so it is the one
    /// place where the caller choosing what a table name means would hand them
    /// the rows the rules were keeping. An unpinned search path is exactly that
    /// choice: a caller who can create a schema puts their own `realms` in
    /// front of the real one.
    #[test]
    fn every_definer_function_pins_its_search_path() {
        for migration in migrations() {
            let Migration::Sql(sql) = migration else {
                continue;
            };

            for (index, _) in sql.sql.match_indices("SECURITY DEFINER") {
                // The clause and the path sit in the same header, between the
                // signature and the body.
                let header_end = sql.sql[index..]
                    .find("AS $$")
                    .map(|offset| index + offset)
                    .unwrap_or(sql.sql.len());
                let start = sql.sql[..index]
                    .rfind("CREATE OR REPLACE FUNCTION")
                    .unwrap_or(0);
                assert!(
                    sql.sql[start..header_end].contains("SET search_path ="),
                    "{}: a definer function does not pin its search path",
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
                read_a_setting || !sql.sql.contains("CREATE POLICY"),
                "{} defines policies that read no tenant at all",
                sql.name
            );
        }
    }
}
