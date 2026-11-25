//! What a test binary checks of its own folder: the files that cargo
//! builds only when a `mod` names them.

use std::fs;
use std::path::Path;

/// Each file and folder under `root` that the `main.rs` or `mod.rs` of its
/// own folder does not name, as a path from `root`, sorted.
///
/// # Panics
///
/// Panics when a folder under `root`, or the file that declares its
/// modules, cannot be read.
#[must_use]
pub fn list_undeclared_modules(root: &Path) -> Vec<String> {
    let mut undeclared = Vec::new();
    collect_undeclared_modules(root, root, &mut undeclared);
    undeclared.sort();
    undeclared
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::list_undeclared_modules;

    /// A folder of the test's own, removed when the test ends, passed or failed.
    struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_file_or_folder_no_mod_names_is_listed_and_a_declared_one_is_not() {
        let since_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("a clock after 1970");
        let root = std::env::temp_dir().join(format!(
            "saffui_layout_{}_{}",
            std::process::id(),
            since_epoch.subsec_nanos()
        ));
        // Refused if it exists already: the guard removes only what this test made.
        fs::create_dir(&root).expect("a folder of the test's own");
        let scratch = Scratch(root);
        for (file, text) in [
            ("main.rs", "mod a;\npub mod nested;\n"),
            ("a.rs", ""),
            ("stray.rs", ""),
            ("nested/mod.rs", ""),
            ("nested/deep.rs", ""),
            ("orphan/mod.rs", ""),
        ] {
            let path = scratch.0.join(file);
            fs::create_dir_all(path.parent().expect("a folder")).expect("a folder");
            fs::write(&path, text).expect("a file");
        }

        assert_eq!(
            list_undeclared_modules(&scratch.0),
            ["nested/deep.rs", "orphan", "stray.rs"]
        );
    }
}
