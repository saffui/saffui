//! What exists, read from the catalog of a database the migrations built.

use tokio_postgres::Client;

pub struct ColumnFact {
    pub name: String,
    pub data_type: String,
    pub nullable: bool,
}

pub struct TableFact {
    pub name: String,
    /// Row security is enabled on it.
    pub guarded: bool,
    /// In the order the table declares them.
    pub columns: Vec<ColumnFact>,
}

/// Reads the base tables of the `public` schema, their columns, and whether
/// row security guards them.
///
/// # Errors
///
/// Returns the error of the driver.
pub async fn read_tables(client: &Client) -> Result<Vec<TableFact>, tokio_postgres::Error> {
    let rows = client
        .query(
            "SELECT c.table_name::text, c.column_name::text, c.data_type::text,
                    c.is_nullable = 'YES', k.relrowsecurity
             FROM information_schema.columns c
             JOIN information_schema.tables t
               ON t.table_schema = c.table_schema AND t.table_name = c.table_name
             JOIN pg_catalog.pg_class k
               ON k.relnamespace = 'public'::regnamespace AND k.relname = c.table_name
             WHERE c.table_schema = 'public' AND t.table_type = 'BASE TABLE'
             ORDER BY c.table_name, c.ordinal_position",
            &[],
        )
        .await?;
    let mut tables: Vec<TableFact> = Vec::new();
    for row in &rows {
        let table: String = row.get(0);
        let column = ColumnFact {
            name: row.get(1),
            data_type: row.get(2),
            nullable: row.get(3),
        };
        match tables.last_mut() {
            Some(known) if known.name == table => known.columns.push(column),
            _ => tables.push(TableFact {
                name: table,
                guarded: row.get(4),
                columns: vec![column],
            }),
        }
    }
    Ok(tables)
}
