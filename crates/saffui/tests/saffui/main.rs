//! The product through its binary and on Postgres, in one binary: a module
//! per domain of the core, the command line of the binary itself, and what
//! the tests share.

mod audit;
mod cli;
mod clients;
mod keys;
mod login;
mod oidc;
mod retention;
mod support;
mod tenancy;

use std::path::Path;

use saffui_core::testkit::layout::list_undeclared_modules;

/// A file of this binary that no `mod` names is never compiled, and its
/// tests never run: nothing else says so.
#[test]
fn every_file_of_the_binary_is_named_by_the_module_of_its_folder() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/saffui");
    let undeclared = list_undeclared_modules(&root);

    assert!(
        undeclared.is_empty(),
        "named by no `mod` of their folder: {undeclared:?}"
    );
}
