#[allow(unused_imports)]
use super::support;
use std::path::Path;
use std::process::Command;

/// The sign-in script, run over the sign-in page.
///
/// Neither the integration suites nor the certification runs reach this: the
/// suites post the answers as JSON and never open the page, and the browser
/// that drives the certification has no `fetch`, so it declines the script and
/// posts the form instead. What a person's browser actually does was covered by
/// nothing until this, and two defects shipped through the gap.
///
/// Ignored like the tests that need a database, and run by the same
/// `--include-ignored` that runs those.
#[test]
#[ignore = "needs node"]
fn the_sign_in_script_answers_every_round() {
    let here = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/ui");
    let ran = Command::new("node")
        .arg("--test")
        .arg("--test-reporter=tap")
        .arg(here.join("login.test.mjs"))
        .output()
        .expect("node, which the certification job and every runner have");

    let told = String::from_utf8_lossy(&ran.stdout);
    assert!(
        told.contains("# fail 0"),
        "the sign-in script did not answer:\n{told}"
    );
    // A run that reached no test would say `fail 0` too.
    assert!(
        !told.contains("# pass 0"),
        "no test ran, so the script was not covered:\n{told}"
    );
    assert!(ran.status.success(), "{told}");
}
