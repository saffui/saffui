use std::process::ExitCode;

fn main() -> ExitCode {
    saffui::run_command_line(std::env::args_os())
}
