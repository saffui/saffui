use std::ffi::OsString;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod cli;
mod config;
mod telemetry;

#[derive(Parser)]
#[command(version, about, arg_required_else_help = true)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the data plane and the operations plane until a signal asks to stop.
    Serve(cli::serve::ServeOptions),
}

/// Parses the command line and returns the exit code of the process.
pub fn run_command_line(arguments: impl IntoIterator<Item = OsString>) -> ExitCode {
    match Cli::try_parse_from(arguments) {
        Ok(parsed) => match parsed.command {
            Command::Serve(options) => cli::serve::run_command(&options),
        },
        Err(error) => {
            // Help and version arrive as errors: clap prints on stdout with code 0.
            let _ = error.print();
            u8::try_from(error.exit_code()).map_or(ExitCode::FAILURE, ExitCode::from)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::process::ExitCode;

    use super::run_command_line;

    #[test]
    fn usage_error_returns_code_2_without_ending_the_process() {
        let arguments = ["saffui", "--nope"].map(OsString::from);
        assert_eq!(run_command_line(arguments), ExitCode::from(2));
    }
}
