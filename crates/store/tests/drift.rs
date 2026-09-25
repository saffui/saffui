//! Every statement the store sends, prepared against the schema the
//! migrations build.
//!
//! The SQL is written by hand, so nothing but the database knows whether a
//! table, a column, a function or a cast it names exists. A statement no test
//! runs finds out in production. This reads the store's own source, rebuilds
//! each statement the way the code builds it, through the store's own
//! builders, and has the database prepare it without running it.
//!
//! A statement the reader cannot rebuild is named at its line, and has to be
//! listed below with the reason, so that nothing slips through by being
//! written in a shape the reader does not follow.

#[path = "drift/reader.rs"]
mod reader;
mod support;

use std::collections::HashMap;

use reader::read_the_store;
use support::Fixture;

/// Functions whose statement is not theirs to read: the unit of work passes
/// its caller's statement through, and the caller's is read where it is
/// written.
const UNREAD: &[(&str, &str, &str)] = &[
    (
        "tenancy.rs",
        "open",
        "the BEGIN it is handed, with the bound a pooler rides with spelled at run time",
    ),
    (
        "tenancy.rs",
        "prepared",
        "the unit of work prepares the statement its caller wrote",
    ),
    (
        "tenancy.rs",
        "batch_execute",
        "the unit of work passes the statements its caller wrote",
    ),
];

/// What one sent string holds: its statements, split where a batch carries
/// several, a quoted semicolon left alone.
fn statements_in(text: &str, batch: bool) -> Vec<String> {
    if !batch {
        return vec![text.to_owned()];
    }
    let mut statements = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for character in text.chars() {
        match character {
            '\'' => {
                quoted = !quoted;
                current.push(character);
            }
            ';' if !quoted => statements.push(std::mem::take(&mut current)),
            _ => current.push(character),
        }
    }
    statements.push(current);
    statements
        .into_iter()
        .map(|statement| statement.trim().to_owned())
        .filter(|statement| !statement.is_empty())
        .collect()
}

/// The reader follows every statement the store sends, or the statement is
/// listed with its reason; and nothing listed is left over from code that has
/// since changed.
#[test]
fn every_statement_the_store_sends_is_read_or_listed() {
    let found = read_the_store();
    let read = found.iter().filter(|held| held.read.is_ok()).count();
    assert!(read > 0, "the reader found no statement at all");
    // `SAFFUI_DRIFT_SHOW=1` prints every statement as the reader rebuilt it.
    if std::env::var("SAFFUI_DRIFT_SHOW").is_ok() {
        for held in &found {
            match &held.read {
                Ok(texts) => {
                    for text in texts {
                        eprintln!("{} `{}`: {text}", held.at(), held.function);
                    }
                }
                Err(why) => eprintln!("{} `{}`: UNREAD {why}", held.at(), held.function),
            }
        }
    }

    let mut unlisted = Vec::new();
    let mut met = vec![false; UNREAD.len()];
    for held in &found {
        let Err(why) = &held.read else {
            continue;
        };
        match UNREAD
            .iter()
            .position(|(file, function, _)| *file == held.file && *function == held.function)
        {
            Some(at) if held.via.is_none() => met[at] = true,
            _ => unlisted.push(format!("{} in `{}`: {why}", held.at(), held.function)),
        }
    }
    let stale: Vec<String> = UNREAD
        .iter()
        .zip(&met)
        .filter(|(_, met)| !**met)
        .map(|((file, function, _), _)| format!("{file} `{function}`"))
        .collect();

    eprintln!(
        "{read} statements read, {} passed through the unit of work",
        found.len() - read
    );
    assert!(
        unlisted.is_empty(),
        "statements this reader cannot rebuild; write them in a shape it follows, or \
         list them in UNREAD with the reason:\n{}",
        unlisted.join("\n")
    );
    assert!(
        stale.is_empty(),
        "listed in UNREAD, and no longer sending anything unread: {stale:?}"
    );
}

/// The reader still follows every shape the store writes its statements in:
/// one known statement per shape has to come out whole. A reader that stopped
/// following one would otherwise lose those statements without a word, and
/// with them the check.
#[test]
fn the_reader_follows_every_shape_the_store_writes_in() {
    let found = read_the_store();
    let shapes = [
        ("inside `tokio::join!`", "tenancy.rs", "commit", "COMMIT"),
        (
            "a tuple a `match` chooses",
            "tenancy.rs",
            "on",
            "FROM resolve_user_session($1)",
        ),
        (
            "a table named by a loop",
            "providers/authorization/authz_policies.rs",
            "unbind",
            "DELETE FROM policies_scopes WHERE policy_id = $1",
        ),
        (
            "a helper read at its call, its condition decided",
            "providers/authorization/authz_policies.rs",
            "verify",
            "FROM resources WHERE resource_id = member AND server_id = $2",
        ),
        (
            "the other branch of the same condition",
            "providers/authorization/authz_policies.rs",
            "verify",
            "FROM roles WHERE role_id = member )",
        ),
        (
            "a list query handed in",
            "providers/directory/users.rs",
            "list",
            " FROM users LIMIT $1 OFFSET $2",
        ),
        (
            "a write set",
            "providers/directory/users.rs",
            "create",
            "INSERT INTO users (tenant, realm_id, user_id",
        ),
        (
            "columns split, prefixed and joined",
            "providers/directory/organizations.rs",
            "by_domain",
            "SELECT o.tenant, o.realm_id",
        ),
    ];
    let missing: Vec<&str> = shapes
        .iter()
        .filter(|(_, file, function, fragment)| {
            !found.iter().any(|held| {
                held.file == *file
                    && held.function == *function
                    && held
                        .read
                        .as_ref()
                        .is_ok_and(|texts| texts.iter().any(|text| text.contains(fragment)))
            })
        })
        .map(|(shape, ..)| *shape)
        .collect();
    assert!(
        missing.is_empty(),
        "the reader no longer follows: {missing:?}"
    );

    // And it still counts what a call binds, in the shapes a call binds in.
    let counted = [
        (
            "a literal list of values",
            "providers/directory/users.rs",
            "delete",
            1,
        ),
        (
            "a list query's page, window included",
            "providers/directory/users.rs",
            "list",
            2,
        ),
        (
            "a write set's own values",
            "providers/directory/users.rs",
            "create",
            16,
        ),
    ];
    let uncounted: Vec<&str> = counted
        .iter()
        .filter(|(_, file, function, binds)| {
            !found.iter().any(|held| {
                held.file == *file && held.function == *function && held.binds == Some(*binds)
            })
        })
        .map(|(shape, ..)| *shape)
        .collect();
    assert!(
        uncounted.is_empty(),
        "the reader no longer counts: {uncounted:?}"
    );
}

/// Every statement read prepares against the migrated schema: every table,
/// column, function and cast it names exists there.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn every_statement_the_store_sends_prepares_against_the_schema() {
    let found = read_the_store();
    let fixture = Fixture::empty().await;
    let connection = fixture.connection().await;

    // What each distinct statement prepared to: how many values it names, or
    // why the database would not have it.
    let mut prepared: HashMap<String, Result<usize, String>> = HashMap::new();
    let mut refused = Vec::new();
    for held in &found {
        let Ok(texts) = &held.read else {
            continue;
        };
        for text in texts {
            for statement in statements_in(text, held.batch) {
                if !prepared.contains_key(&statement) {
                    let outcome = match connection.prepare(&statement).await {
                        Ok(ready) => Ok(ready.params().len()),
                        Err(why) => Err(why
                            .as_db_error()
                            .map_or_else(|| why.to_string(), |said| said.message().to_owned())),
                    };
                    prepared.insert(statement.clone(), outcome);
                }
                let why = match (&prepared[&statement], held.binds) {
                    (Err(why), _) => why.clone(),
                    (Ok(named), Some(binds)) if *named != binds => {
                        format!("the call binds {binds} values where the statement names {named}")
                    }
                    _ => continue,
                };
                refused.push(format!(
                    "{} in `{}`: {why}\n    {statement}",
                    held.at(),
                    held.function
                ));
            }
        }
    }

    let counted = found.iter().filter(|held| held.binds.is_some()).count();
    eprintln!(
        "{} distinct statements prepared, {counted} calls' values counted",
        prepared.len()
    );
    assert!(
        refused.is_empty(),
        "statements the schema does not hold:\n{}",
        refused.join("\n")
    );
}
