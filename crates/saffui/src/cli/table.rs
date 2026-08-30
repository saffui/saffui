use serde_json::Value;

/// How an answer is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Json,
    Table,
}

impl Format {
    /// The plan's principle: predictable by where it lands. A terminal gets
    /// a table a person scans; a pipe gets JSON a program parses. Saying
    /// `--format` overrides either.
    pub fn resting() -> Self {
        use std::io::IsTerminal;
        if std::io::stdout().is_terminal() {
            Format::Table
        } else {
            Format::Json
        }
    }
}

/// The rows of a listing answer: a bare array, or the page's items.
fn listed(body: &Value) -> Option<&Vec<Value>> {
    body.as_array().or_else(|| body["items"].as_array())
}

fn cell(row: &Value, column: &str) -> String {
    match column.split('.').fold(row, |held, part| &held[part]) {
        Value::Null => "-".to_owned(),
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// A grid of the named columns, one row per entry, widths fitted. Empty
/// listings still show the header: an empty table says the question was
/// answered, where nothing at all says it was not asked.
pub fn grid(body: &Value, columns: &[&str]) -> String {
    let rows: Vec<Vec<String>> = listed(body)
        .map(|entries| {
            entries
                .iter()
                .map(|row| columns.iter().map(|column| cell(row, column)).collect())
                .collect()
        })
        .unwrap_or_default();

    let mut widths: Vec<usize> = columns.iter().map(|column| column.len()).collect();
    for row in &rows {
        for (index, value) in row.iter().enumerate() {
            widths[index] = widths[index].max(value.len());
        }
    }

    let mut out = String::new();
    for (index, column) in columns.iter().enumerate() {
        if index > 0 {
            out.push_str("  ");
        }
        out.push_str(&format!(
            "{:<width$}",
            column.to_uppercase(),
            width = widths[index]
        ));
    }
    out.push('\n');
    for row in &rows {
        for (index, value) in row.iter().enumerate() {
            if index > 0 {
                out.push_str("  ");
            }
            out.push_str(&format!("{:<width$}", value, width = widths[index]));
        }
        out.push('\n');
    }
    out
}

/// One object as `key: value` lines, in the order asked.
pub fn card(body: &Value, fields: &[&str]) -> String {
    let mut out = String::new();
    for field in fields {
        out.push_str(&format!("{field}: {}\n", cell(body, field)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Widths fit the widest cell, pages unwrap to their items, and an
    /// absent field is a dash rather than the word null.
    #[test]
    fn a_grid_fits_what_it_shows() {
        let page = json!({ "items": [
            { "kid": "a-long-identifier", "status": "active" },
            { "kid": "b", "status": "passive", "stray": true },
        ], "first": 0 });
        let drawn = grid(&page, &["kid", "status", "priority"]);
        assert_eq!(
            drawn,
            "KID                STATUS   PRIORITY\n\
             a-long-identifier  active   -       \n\
             b                  passive  -       \n"
        );

        let bare = json!([{ "slug": "pq-hybrid", "enabled": false }]);
        let drawn = grid(&bare, &["slug", "enabled"]);
        assert!(drawn.contains("pq-hybrid  false"), "{drawn}");

        let empty = json!([]);
        let drawn = grid(&empty, &["slug"]);
        assert_eq!(drawn, "SLUG\n", "an empty listing still answers");
    }

    /// A card reads nested paths the way the grid reads columns.
    #[test]
    fn a_card_reads_nested_paths() {
        let body = json!({ "realm": { "realm_id": "main" }, "revision": 3 });
        assert_eq!(
            card(&body, &["realm.realm_id", "revision"]),
            "realm.realm_id: main\nrevision: 3\n"
        );
    }
}
