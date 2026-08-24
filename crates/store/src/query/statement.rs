use crate::query::write_set::WriteSet;

/// An insert of everything the set assigns.
pub fn insert(table: &str, set: &WriteSet<'_>) -> String {
    let columns = set.columns();
    let placeholders: Vec<String> = (1..=columns.len()).map(|n| format!("${n}")).collect();
    format!(
        "INSERT INTO {table} ({}) VALUES ({})",
        columns.join(", "),
        placeholders.join(", ")
    )
}

/// An update of what the set assigns, keyed on what it filters.
///
/// The filter's placeholders continue after the assignments', which is the order
/// the set hands its values over in.
pub fn update(table: &str, set: &WriteSet<'_>) -> String {
    let assignments: Vec<String> = set
        .columns()
        .iter()
        .enumerate()
        .map(|(index, column)| format!("{column} = ${}", index + 1))
        .collect();

    let mut statement = format!("UPDATE {table} SET {}", assignments.join(", "));

    let filter = set.filter_columns();
    if !filter.is_empty() {
        let conditions: Vec<String> = filter
            .iter()
            .enumerate()
            .map(|(index, column)| format!("{column} = ${}", assignments.len() + index + 1))
            .collect();
        statement.push_str(&format!(" WHERE {}", conditions.join(" AND ")));
    }
    statement
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::write_set::col;

    #[test]
    fn an_insert_names_as_many_placeholders_as_columns() {
        let tenant = "acme".to_owned();
        let name = "ada".to_owned();
        let set = WriteSet::insert(vec![col("tenant", &tenant), col("name", &name)]);

        assert_eq!(
            insert("users", &set),
            "INSERT INTO users (tenant, name) VALUES ($1, $2)"
        );
        assert_eq!(set.params().len(), 2, "and as many values as placeholders");
    }

    /// The filter continues the numbering rather than restarting it, which is
    /// the order the set hands its values over in.
    #[test]
    fn an_update_numbers_its_filter_after_its_assignments() {
        let display = "Ada".to_owned();
        let tenant = "acme".to_owned();
        let id = "user-1".to_owned();
        let set = WriteSet::update(
            vec![col("display_name", &display)],
            vec![col("tenant", &tenant), col("user_id", &id)],
        );

        assert_eq!(
            update("users", &set),
            "UPDATE users SET display_name = $1 WHERE tenant = $2 AND user_id = $3"
        );
        assert_eq!(set.params().len(), 3);
    }

    /// An update that keys on nothing writes every row it can see, so it says so
    /// by carrying no clause rather than an empty one.
    #[test]
    fn an_update_that_keys_on_nothing_has_no_clause() {
        let state = "suspended".to_owned();
        let set = WriteSet::update(vec![col("state", &state)], Vec::new());

        assert_eq!(update("tenants", &set), "UPDATE tenants SET state = $1");
    }
}
