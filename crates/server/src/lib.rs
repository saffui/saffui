pub mod api;
pub mod error;
pub mod federation;
/// The mesh door's protocol shell. Compiled only when a deployment asked
/// for it, so a build without the feature carries none of the machinery.
#[cfg(feature = "mesh")]
pub mod grpc;
pub mod jobs;
pub mod mesh;
pub mod messaging;
pub mod metrics;
pub mod middleware;
pub mod negotiate;
pub mod notices;
pub mod otel;
pub mod smtp_probe;

#[cfg(test)]
mod tests {
    /// The parts of the store a door may name: the unit of work it opens, the
    /// seal it opens secrets with, the errors, the live feed's message and the
    /// shape of a listing.
    const NAMEABLE: [&str; 6] = ["error", "keyring", "live", "query", "self", "tenancy"];

    /// The doors reach the store's rows through services and nowhere else.
    ///
    /// A door parses, opens the unit of work, commits and answers; which rows
    /// to read or write, and what they mean, is decided below it. Any other
    /// part of the store named from here, the providers, the audit chain, the
    /// tenant's chain, is that decision taken in one door, where no other door
    /// shares it and no service test sees it. Grouped imports are read too, so
    /// `store::{tenancy::Tenancy, audit}` is caught like the rest.
    #[test]
    fn no_door_reaches_the_store_rows_itself() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders = Vec::new();
        let mut pending = vec![root.clone()];
        while let Some(path) = pending.pop() {
            if path.is_dir() {
                pending.extend(
                    std::fs::read_dir(&path)
                        .unwrap()
                        .map(|entry| entry.unwrap().path()),
                );
                continue;
            }
            if path.extension().is_none_or(|kind| kind != "rs") {
                continue;
            }
            let mut source = std::fs::read_to_string(&path).unwrap();
            // This module spells the paths it hunts for; what stands above it
            // may not.
            if path == root.join("lib.rs")
                && let Some(at) = source.find("#[cfg(test)]")
            {
                source.truncate(at);
            }
            for line in store_rows_named(&source) {
                offenders.push(format!("{}:{line}", path.display()));
            }
        }
        assert!(
            offenders.is_empty(),
            "a door reaches the store's rows itself; ask services instead: {offenders:#?}"
        );
    }

    /// The lines where a part of the store outside [`NAMEABLE`] is named,
    /// spaced or grouped.
    fn store_rows_named(source: &str) -> Vec<usize> {
        let mut lines = Vec::new();
        for (at, _) in source.match_indices("store") {
            let joined = source[..at]
                .chars()
                .next_back()
                .is_some_and(|held| held.is_alphanumeric() || held == '_');
            if joined {
                continue;
            }
            let rest: String = source[at + "store".len()..]
                .chars()
                .filter(|held| !held.is_whitespace())
                .take(4096)
                .collect();
            let Some(path) = rest.strip_prefix("::") else {
                continue;
            };
            let named = if path.starts_with('{') {
                heads_of(grouped(path))
            } else {
                vec![head_of(path)]
            };
            if named.iter().any(|part| !NAMEABLE.contains(part)) {
                lines.push(source[..at].lines().count().max(1));
            }
        }
        lines
    }

    /// What one brace group holds, its opening brace included and its closing
    /// one left off.
    fn grouped(path: &str) -> &str {
        let mut depth = 0;
        for (offset, held) in path.char_indices() {
            depth += match held {
                '{' => 1,
                '}' => -1,
                _ => 0,
            };
            if depth == 0 {
                return &path[..offset];
            }
        }
        path
    }

    /// The first name of each item a brace group holds, its own groups left
    /// closed.
    fn heads_of(group: &str) -> Vec<&str> {
        let inner = &group[1..];
        let mut heads = Vec::new();
        let mut depth = 0;
        let mut start = 0;
        for (offset, held) in inner.char_indices() {
            match held {
                '{' => depth += 1,
                '}' => depth -= 1,
                ',' if depth == 0 => {
                    heads.push(head_of(&inner[start..offset]));
                    start = offset + 1;
                }
                _ => {}
            }
        }
        heads.push(head_of(&inner[start..]));
        heads.retain(|head| !head.is_empty());
        heads
    }

    fn head_of(path: &str) -> &str {
        let end = path
            .find(|held: char| !(held.is_alphanumeric() || held == '_'))
            .unwrap_or(path.len());
        &path[..end]
    }

    #[test]
    fn a_named_path_is_found_however_it_is_written() {
        for (written, line) in [
            ("store::providers::realms::load(t, r)", 1),
            ("x\nuse store :: providers;", 2),
            (
                "use store::{\n    tenancy::Tenancy,\n    providers::clients,\n};",
                1,
            ),
            ("use store::{error::{A, B}, providers};", 1),
            ("store::audit::append(&first, envelope)", 1),
            ("use store::{tenancy::Tenancy, tenant_chain};", 1),
            ("store::schema::migrate(pool)", 1),
        ] {
            assert_eq!(store_rows_named(written), [line], "{written}");
        }
        for written in [
            "use store::tenancy::{RealmNamed, Tenancy};",
            "use store::{keyring, tenancy::Tenancy};",
            "store::live::Told { realm }",
            "use store::query::list_query::{ListQuery, SortDirection};",
            "Err(store::error::StoreError::Backend)",
            "use store::{self, error::{A, B}};",
            "restore::providers::x",
        ] {
            assert!(store_rows_named(written).is_empty(), "{written}");
        }
    }
}
