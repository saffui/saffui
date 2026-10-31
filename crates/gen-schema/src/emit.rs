//! The module the store compiles against, written from what exists.

use std::fmt::Write as _;

use crate::schema::TableFact;

const TENANT_KEY: &str = "tenant_id";
const REALM_KEY: &str = "realm_id";

/// Tells whether a name can be written as a Rust identifier and as a SQL
/// one without quoting. A name that cannot stops the tool: nothing here
/// ever quotes or escapes a name.
fn is_plain_identifier(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_lowercase() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum EmitError {
    #[error(
        "the schema has no table under row security that carries a scope key: an empty module would erase every constant"
    )]
    NothingToWrite,
    #[error("{0:?} cannot be written as an identifier")]
    UnwritableName(String),
}

/// Writes the module. A table that row security does not guard, or that
/// carries no scope key, is named in a comment and gets no constant: no
/// statement of the builder reaches it.
///
/// # Errors
///
/// Returns why nothing was written.
pub fn write_module(tables: &[TableFact]) -> Result<String, EmitError> {
    let mut module = String::from(
        "//! Written by `gen-schema`, never by hand: every table and column\n\
         //! that exists, read from a database the migrations built. A change of\n\
         //! schema reads as a diff of this file, beside the migration that caused\n\
         //! it. What a statement may write is not decided here.\n\
         //!\n\
         //! The keys of the scope are no constants: the builder writes them.\n\n\
         use crate::query::ident::{Column, ScopeKeys, Table};\n",
    );
    let mut scoped = Vec::new();
    let mut unscoped = Vec::new();
    for table in tables {
        if !is_plain_identifier(&table.name) {
            return Err(EmitError::UnwritableName(table.name.clone()));
        }
        let carries = |key: &str| table.columns.iter().any(|column| column.name == key);
        let keys = match (table.guarded, carries(TENANT_KEY), carries(REALM_KEY)) {
            (true, true, true) => "TenantAndRealm",
            (true, true, false) => "Tenant",
            _ => {
                unscoped.push(table.name.as_str());
                continue;
            }
        };
        scoped.push(table.name.as_str());
        let _ = write!(
            module,
            "\npub(crate) mod {name} {{\n    use super::{{Column, ScopeKeys, Table}};\n\n    \
             pub(crate) const TABLE: Table = Table {{ name: \"{name}\", keys: ScopeKeys::{keys} }};\n",
            name = table.name
        );
        let mut constants = Vec::new();
        for column in &table.columns {
            if column.name == TENANT_KEY || column.name == REALM_KEY {
                continue;
            }
            if !is_plain_identifier(&column.name) {
                return Err(EmitError::UnwritableName(column.name.clone()));
            }
            let constant = column.name.to_ascii_uppercase();
            let nullable = if column.nullable { ", nullable" } else { "" };
            let _ = write!(
                module,
                "    /// {}{nullable}\n    pub(crate) const {constant}: Column = Column(\"{}\");\n",
                column.data_type, column.name
            );
            constants.push(constant);
        }
        let _ = write!(
            module,
            "\n    /// In the order the table declares them.\n    \
             pub(crate) const ALL: &[Column] = &[{}];\n}}\n",
            constants.join(", ")
        );
    }
    if scoped.is_empty() {
        return Err(EmitError::NothingToWrite);
    }
    module.push_str("\n/// Every table a statement of the builder can reach.\n");
    module.push_str("pub(crate) const TABLES: &[(Table, &[Column])] = &[\n");
    for name in &scoped {
        let _ = writeln!(module, "    ({name}::TABLE, {name}::ALL),");
    }
    module.push_str("];\n");
    if !unscoped.is_empty() {
        let _ = write!(
            module,
            "\n// Without row security or a scope key, and so without a constant: {}.\n",
            unscoped.join(", ")
        );
    }
    Ok(module)
}

#[cfg(test)]
mod tests {
    use super::{EmitError, write_module};
    use crate::schema::{ColumnFact, TableFact};

    fn describe(name: &str, columns: &[(&str, &str, bool)]) -> TableFact {
        TableFact {
            name: name.to_owned(),
            guarded: true,
            columns: columns
                .iter()
                .map(|(name, data_type, nullable)| ColumnFact {
                    name: (*name).to_owned(),
                    data_type: (*data_type).to_owned(),
                    nullable: *nullable,
                })
                .collect(),
        }
    }

    #[test]
    fn a_table_gets_its_scope_and_a_constant_per_column_that_is_not_a_scope_key() {
        let notes = describe(
            "notes",
            &[
                ("tenant_id", "uuid", false),
                ("realm_id", "uuid", false),
                ("note_id", "uuid", false),
                ("body", "text", true),
            ],
        );
        let accounts = describe(
            "accounts",
            &[("tenant_id", "uuid", false), ("name", "text", false)],
        );

        let module = write_module(&[accounts, notes]).expect("a module");

        assert!(module.contains("pub(crate) mod notes {"), "{module}");
        assert!(module.contains("name: \"notes\", keys: ScopeKeys::TenantAndRealm"));
        assert!(module.contains("name: \"accounts\", keys: ScopeKeys::Tenant"));
        assert!(
            module.contains(
                "/// text, nullable\n    pub(crate) const BODY: Column = Column(\"body\");"
            )
        );
        assert!(module.contains("pub(crate) const ALL: &[Column] = &[NOTE_ID, BODY];"));
        assert!(
            !module.contains("TENANT_ID"),
            "a scope key is no constant: {module}"
        );
        assert!(
            module
                .contains("    (accounts::TABLE, accounts::ALL),\n    (notes::TABLE, notes::ALL),")
        );
    }

    #[test]
    fn a_table_without_a_scope_key_is_named_and_gets_no_constant() {
        let history = describe("schema_history", &[("version", "integer", false)]);
        let notes = describe(
            "notes",
            &[("tenant_id", "uuid", false), ("body", "text", false)],
        );

        let module = write_module(&[history, notes]).expect("a module");

        assert!(!module.contains("mod schema_history"), "{module}");
        assert!(module.contains(
            "// Without row security or a scope key, and so without a constant: schema_history."
        ));
    }

    #[test]
    fn a_table_that_row_security_does_not_guard_gets_no_constant_whatever_its_columns() {
        let directory = TableFact {
            guarded: false,
            ..describe(
                "directory",
                &[("tenant_id", "uuid", false), ("realm_id", "uuid", false)],
            )
        };
        let ledger = TableFact {
            guarded: false,
            ..describe(
                "ledger",
                &[("tenant_id", "uuid", false), ("entry", "text", false)],
            )
        };
        let notes = describe(
            "notes",
            &[("tenant_id", "uuid", false), ("body", "text", false)],
        );

        let module = write_module(&[directory, ledger, notes]).expect("a module");

        for unguarded in ["directory", "ledger"] {
            assert!(!module.contains(&format!("mod {unguarded}")), "{module}");
            assert!(
                !module.contains(&format!("({unguarded}::TABLE")),
                "{module}"
            );
        }
        assert!(
            module.contains(
                "// Without row security or a scope key, and so without a constant: directory, ledger."
            ),
            "{module}"
        );
    }

    #[test]
    fn an_empty_schema_or_a_name_that_needs_quoting_writes_nothing() {
        let history = describe("schema_history", &[("version", "integer", false)]);
        let quoted = describe(
            "notes",
            &[("tenant_id", "uuid", false), ("Body\"; --", "text", false)],
        );

        assert_eq!(write_module(&[]), Err(EmitError::NothingToWrite));
        assert_eq!(write_module(&[history]), Err(EmitError::NothingToWrite));
        assert_eq!(
            write_module(&[quoted]),
            Err(EmitError::UnwritableName("Body\"; --".to_owned()))
        );
    }
}
