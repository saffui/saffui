//! The HTTP surface in one binary: the endpoints in process, the shutdown
//! on real listeners, and the scans of the sources that the compiler does
//! not make.

mod capabilities;
mod endpoints;
mod mounted;
mod shutdown;
mod templates;

use std::path::Path;

use saffui_core::testkit::layout::list_undeclared_modules;

/// A file of this binary that no `mod` names is never compiled, and its
/// tests never run: nothing else says so.
#[test]
fn every_file_of_the_binary_is_named_by_the_module_of_its_folder() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/server");
    let undeclared = list_undeclared_modules(&root);

    assert!(
        undeclared.is_empty(),
        "named by no `mod` of their folder: {undeclared:?}"
    );
}
