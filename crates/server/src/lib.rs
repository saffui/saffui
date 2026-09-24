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
    /// The doors reach the store's rows through services and nowhere else.
    ///
    /// A door parses, opens the unit of work, commits and answers; which rows
    /// to read or write, and what they mean, is decided below it. A path into
    /// `store::providers` from here is that decision taken in one door, where
    /// no other door shares it and no service test sees it. Grouped imports
    /// are read too, so `store::{providers, ...}` is caught like the rest.
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
            // This module spells the path it hunts for; what stands above it
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

    /// The lines where `store::providers` is named, spaced or grouped.
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
            let named = match rest.strip_prefix("::") {
                Some(path) if path.starts_with("providers") => true,
                Some(path) if path.starts_with('{') => grouped(path)
                    .split([',', '{'])
                    .any(|segment| segment.starts_with("providers")),
                _ => false,
            };
            if named {
                lines.push(source[..at].lines().count().max(1));
            }
        }
        lines
    }

    /// What one brace group holds, nested groups included.
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

    #[test]
    fn a_named_path_is_found_however_it_is_written() {
        assert_eq!(
            store_rows_named("store::providers::realms::load(t, r)"),
            [1]
        );
        assert_eq!(store_rows_named("x\nuse store :: providers;"), [2]);
        assert_eq!(
            store_rows_named("use store::{\n    tenancy::Tenancy,\n    providers::clients,\n};"),
            [1]
        );
        assert_eq!(
            store_rows_named("use store::{error::{A, B}, providers};"),
            [1]
        );
        assert!(store_rows_named("use store::tenancy::{RealmNamed, Tenancy};").is_empty());
        assert!(store_rows_named("use store::{keyring, tenancy::Tenancy};").is_empty());
        assert!(store_rows_named("restore::providers::x").is_empty());
    }
}
