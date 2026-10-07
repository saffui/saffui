use std::ffi::OsString;
use std::process::ExitCode;

use clap::Parser;

#[derive(Parser)]
#[command(version, about, arg_required_else_help = true)]
struct Cli {}

/// Parses the command line and returns the exit code of the process.
pub fn run_command_line(arguments: impl IntoIterator<Item = OsString>) -> ExitCode {
    match Cli::try_parse_from(arguments) {
        Ok(_cli) => ExitCode::SUCCESS,
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
