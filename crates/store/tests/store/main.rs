//! The store on Postgres, in one binary: a module per domain of the core,
//! laid out as the adapters are, the contract every adapter plays, and what
//! the tests share.

mod authz;
mod claims;
mod clients;
mod contract;
mod keys;
mod retention;
mod support;
mod tenancy;

use std::fs;
use std::path::Path;

/// A file of this binary that no `mod` names is never compiled, and its
/// tests never run: nothing else says so.
#[test]
fn every_file_of_the_binary_is_named_by_the_module_of_its_folder() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/store");
    let mut undeclared = Vec::new();
    collect_undeclared_modules(&root, &root, &mut undeclared);
    undeclared.sort();

    assert!(
        undeclared.is_empty(),
        "named by no `mod` of their folder: {undeclared:?}"
    );
}

/// Adds to `undeclared` each file and folder under `folder` that the
/// `main.rs` or `mod.rs` of its own folder does not name, as a path from
/// `root`.
fn collect_undeclared_modules(root: &Path, folder: &Path, undeclared: &mut Vec<String>) {
    let declaring = folder.join(if folder == root { "main.rs" } else { "mod.rs" });
    let declared = fs::read_to_string(&declaring)
        .unwrap_or_else(|error| panic!("{}: {error}", declaring.display()));
    let entries = fs::read_dir(folder)
        .unwrap_or_else(|error| panic!("{}: {error}", folder.display()))
        .map(|entry| entry.expect("an entry of the folder").path());
    for path in entries {
        let module = if path.is_dir() {
            collect_undeclared_modules(root, &path, undeclared);
            path.file_name().and_then(|name| name.to_str())
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            path.file_stem()
                .and_then(|stem| stem.to_str())
                .filter(|stem| !["main", "mod"].contains(stem))
        } else {
            None
        };
        if module.is_some_and(|module| !declares_module(&declared, module)) {
            let relative = path.strip_prefix(root).expect("a path under the root");
            undeclared.push(relative.display().to_string());
        }
    }
}

/// Whether `source` holds `mod {module};` or `pub mod {module};` on a line.
fn declares_module(source: &str, module: &str) -> bool {
    source.lines().any(|line| {
        let line = line.trim();
        let line = line.strip_prefix("pub ").unwrap_or(line);
        line.strip_prefix("mod ")
            .and_then(|rest| rest.strip_suffix(';'))
            == Some(module)
    })
}
