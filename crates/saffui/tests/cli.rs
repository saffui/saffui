use std::process::{Command, Output};

fn run_saffui(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_saffui"))
        .args(arguments)
        .output()
        .expect("the saffui binary starts")
}

#[test]
fn version_flag_prints_the_version_on_stdout_and_exits_with_0() {
    let output = run_saffui(&["--version"]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        concat!("saffui ", env!("CARGO_PKG_VERSION"), "\n")
    );
    assert!(output.stderr.is_empty(), "stderr must stay empty");
}

#[test]
fn help_flag_prints_the_help_on_stdout_and_exits_with_0() {
    let output = run_saffui(&["--help"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(0));
    assert!(stdout.contains("Usage: saffui"), "stdout was: {stdout}");
    assert!(
        stdout.contains(env!("CARGO_PKG_DESCRIPTION")),
        "stdout was: {stdout}"
    );
    assert!(output.stderr.is_empty(), "stderr must stay empty");
}

#[test]
fn no_argument_prints_the_help_on_stderr_and_exits_with_2() {
    let output = run_saffui(&[]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty(), "stdout must stay empty");
    assert!(stderr.contains("Usage: saffui"), "stderr was: {stderr}");
}

#[test]
fn unknown_option_is_named_on_stderr_and_exits_with_2() {
    let output = run_saffui(&["--nope"]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty(), "stdout must stay empty");
    assert!(stderr.contains("--nope"), "stderr was: {stderr}");
}
