use std::process::Command;

/// The built binary, without any `SAFFUI_*` variable of the machine that runs
/// the tests: a test must never read the configuration of its host.
pub fn saffui_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_saffui"));
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("SAFFUI_") {
            command.env_remove(name);
        }
    }
    command
}
