use std::env;
use std::ffi::OsString;
use std::path::Path;
use std::process::ExitCode;

use enc::{Operation, process_file};

const USAGE: &str = "\
Usage:
  enc <file> E    Encrypt <file> to <file>.enc
  enc <file> D    Decrypt <file> to a sibling .dec file

The original file is never deleted or overwritten.";

fn main() -> ExitCode {
    match run(env::args_os().collect()) {
        Ok(CliOutcome::Processed(output)) => {
            println!("Success: {}", output.display());
            ExitCode::SUCCESS
        }
        Ok(CliOutcome::Help) => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Err(CliError::Usage(message)) => {
            if !message.is_empty() {
                eprintln!("Error: {message}\n");
            }
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
        Err(CliError::Operation(error)) => {
            eprintln!("Error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(arguments: Vec<OsString>) -> Result<CliOutcome, CliError> {
    if arguments.len() == 2
        && arguments[1]
            .to_str()
            .is_some_and(|arg| arg == "-h" || arg == "--help" || arg == "/?")
    {
        return Ok(CliOutcome::Help);
    }

    if arguments.len() != 3 {
        return Err(CliError::Usage(
            "expected exactly a file name followed by E or D".to_owned(),
        ));
    }

    let operation =
        Operation::parse(&arguments[2]).map_err(|error| CliError::Usage(error.to_string()))?;
    process_file(Path::new(&arguments[1]), operation)
        .map(CliOutcome::Processed)
        .map_err(CliError::Operation)
}

enum CliOutcome {
    Processed(std::path::PathBuf),
    Help,
}

enum CliError {
    Usage(String),
    Operation(anyhow::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_arguments_are_usage_errors() {
        let result = run(vec![OsString::from("enc")]);
        assert!(matches!(result, Err(CliError::Usage(_))));
    }

    #[test]
    fn invalid_operation_is_a_usage_error() {
        let result = run(vec![
            OsString::from("enc"),
            OsString::from("file"),
            OsString::from("X"),
        ]);
        assert!(matches!(result, Err(CliError::Usage(_))));
    }

    #[test]
    fn help_is_a_successful_outcome() {
        let result = run(vec![OsString::from("enc"), OsString::from("--help")]);
        assert!(matches!(result, Ok(CliOutcome::Help)));
    }
}
