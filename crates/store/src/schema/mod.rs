//! The names of the schema. They are generated: see `generated.rs`.

#[allow(
    dead_code,
    reason = "every name that exists is generated: a statement uses the ones it decided to"
)]
pub(crate) mod generated;

pub(crate) use generated::*;

#[cfg(test)]
mod tests {
    use pgcore::migrate::EMBEDDED;
    use pgcore::testkit::TestDatabase;

    use super::TABLES;
    use crate::query::ident::ScopeKeys;

    /// What `gen-schema --check` proves, from inside the test suite:
    /// the committed constants are the schema the migrations build, no
    /// column more and no column fewer.
    #[tokio::test]
    async fn the_generated_constants_are_the_schema_the_migrations_build() {
        let database = TestDatabase::create(EMBEDDED).await;
        let client = database
            .plan("saffui_owner")
            .connect_directly()
            .await
            .expect("a connection");
        let rows = client
            .query(
                "SELECT c.table_name::text, c.column_name::text
                 FROM information_schema.columns c
                 JOIN information_schema.tables t
                   ON t.table_schema = c.table_schema AND t.table_name = c.table_name
                 WHERE c.table_schema = 'public' AND t.table_type = 'BASE TABLE'
                 ORDER BY c.table_name, c.ordinal_position",
                &[],
            )
            .await
            .expect("the catalog");
        let existing: Vec<(String, String)> =
            rows.iter().map(|row| (row.get(0), row.get(1))).collect();
        let columns_of = |table: &str| -> Vec<&str> {
            existing
                .iter()
                .filter(|(known, _)| known == table)
                .map(|(_, column)| column.as_str())
                .collect()
        };

        assert!(!TABLES.is_empty(), "the registry lists no table");
        for (table, generated) in TABLES {
            let mut expected = vec!["tenant_id"];
            if table.keys == ScopeKeys::TenantAndRealm {
                expected.push("realm_id");
            }
            expected.extend(generated.iter().map(|column| column.0));
            let mut found = columns_of(table.name);
            found.sort_unstable();
            expected.sort_unstable();
            assert_eq!(
                found, expected,
                "{} is stale: run `scripts/dev-postgres.sh gen-schema`",
                table.name
            );
        }
        // A table under row security that carries a scope key and has no
        // constant was added by a migration nobody generated for.
        let guarded: Vec<String> = client
            .query(
                "SELECT relname::text FROM pg_catalog.pg_class
                 WHERE relnamespace = 'public'::regnamespace AND relrowsecurity",
                &[],
            )
            .await
            .expect("the catalog")
            .iter()
            .map(|row| row.get(0))
            .collect();
        let mut scoped: Vec<&str> = existing
            .iter()
            .filter(|(table, column)| column == "tenant_id" && guarded.contains(table))
            .map(|(table, _)| table.as_str())
            .collect();
        scoped.dedup();
        let mut generated: Vec<&str> = TABLES.iter().map(|(table, _)| table.name).collect();
        generated.sort_unstable();
        assert_eq!(scoped, generated);
    }
}
