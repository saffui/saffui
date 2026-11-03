use std::process::Command;

/// The root key every journey runs under: bootstrap seals with it, and the
/// node that serves afterwards must open with the same one.
const ROOT_KEY_VARIABLE: &str = "ROOT_KEY_OF_THE_JOURNEYS";
const ROOT_KEY: &str = "c2FmZnVpLWpvdXJuZXlzLXJvb3Qta2V5LTMyYnl0ZXM=";

/// The built binary, without any `SAFFUI_*` variable of the machine that runs
/// the tests: a test must never read the configuration of its host. Two
/// settings are given by default: the root key, by reference, and retention
/// off, which a journey of retention turns back on.
pub fn saffui_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_saffui"));
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("SAFFUI_") {
            command.env_remove(name);
        }
    }
    command
        .env("SAFFUI_ROOT_KEY", format!("env://{ROOT_KEY_VARIABLE}"))
        .env(ROOT_KEY_VARIABLE, ROOT_KEY)
        .env("SAFFUI_RETENTION", "off");
    command
}
