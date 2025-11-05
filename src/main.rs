use std::{error::Error, os::unix::process::CommandExt, process::Command};

use clap::{Parser, Subcommand};

pub mod consts;
pub mod scan;
pub mod tui;

use scan::model::NmapScan;
use scan::parser::NmapParser;
use tui::app::App;

use crate::scan::builder::NmapCommandBuilder;

#[derive(Parser)]
#[command(name = "lazynmap")]
#[command(about = "A TUI for interactively generating nmap commands", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate if a string is a valid nmap command
    Validate {
        /// The nmap command string to validate
        command: String,
    },
    /// Launch the TUI with a pre-parsed nmap command
    Parse {
        /// The nmap command string to parse and use
        command: String,
    },
}

fn run_scan(scan: &mut NmapScan) -> Result<(), Box<dyn Error>> {
    if let Ok(app_result) = App::new(scan).start()
        && app_result.execute
    {
        let command = NmapCommandBuilder::build(scan);
        let args: Vec<&str> = command.split_whitespace().collect();
        if app_result.requires_admin {
            println!("sudo {}", &command);
            let error = Command::new("sudo").arg("nmap").args(&args).exec();
            eprintln!("Failed to exec: {}", error);
        } else {
            println!("{}", &command);
            let error = Command::new("nmap").args(&args).exec();
            eprintln!("Failed to exec: {}", error);
        }
    }
    Ok(())
}

fn validate_command(command: &str) -> Result<(), Box<dyn Error>> {
    match NmapParser::parse(command) {
        Ok(_) => {
            println!("Valid nmap command");
            Ok(())
        }
        Err(e) => {
            eprintln!("Invalid nmap command: {}", e);
            std::process::exit(1);
        }
    }
}

fn parse_and_run(command: &str) -> Result<(), Box<dyn Error>> {
    match NmapParser::parse(command) {
        Ok(mut scan) => run_scan(&mut scan),
        Err(e) => {
            eprintln!("Failed to parse nmap command: {}", e);
            std::process::exit(1);
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Validate { command }) => validate_command(&command),
        Some(Commands::Parse { command }) => parse_and_run(&command),
        None => run_scan(&mut NmapScan::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parse_no_args() {
        let cli = Cli::try_parse_from(["lazynmap"]).unwrap();
        assert!(cli.command.is_none());
    }

    #[test]
    fn test_cli_parse_validate_command() {
        let cli = Cli::try_parse_from(["lazynmap", "validate", "nmap -sS 192.168.1.1"]).unwrap();
        match cli.command {
            Some(Commands::Validate { command }) => {
                assert_eq!(command, "nmap -sS 192.168.1.1");
            }
            _ => panic!("Expected Validate command"),
        }
    }

    #[test]
    fn test_cli_parse_parse_command() {
        let cli = Cli::try_parse_from(["lazynmap", "parse", "nmap -sV example.com"]).unwrap();
        match cli.command {
            Some(Commands::Parse { command }) => {
                assert_eq!(command, "nmap -sV example.com");
            }
            _ => panic!("Expected Parse command"),
        }
    }

    #[test]
    fn test_validate_valid_command() {
        let result = NmapParser::parse("nmap -sS -p 80,443 192.168.1.1");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_invalid_flag() {
        let result = NmapParser::parse("nmap --invalid-flag test.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_invalid_value() {
        let result = NmapParser::parse("nmap -iR not-a-number test.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_command_with_multiple_flags() {
        let result = NmapParser::parse("nmap -sS -sV -O -p- -T4 192.168.1.1");
        assert!(result.is_ok());
        let scan = result.unwrap();
        assert_eq!(scan.target_specification.targets, vec!["192.168.1.1"]);
    }

    #[test]
    fn test_parse_command_with_targets() {
        let result = NmapParser::parse("nmap scanme.nmap.org");
        assert!(result.is_ok());
        let scan = result.unwrap();
        assert_eq!(scan.target_specification.targets, vec!["scanme.nmap.org"]);
    }

    #[test]
    fn test_parse_command_with_quotes() {
        let result = NmapParser::parse(r#"nmap --script "http-title" example.com"#);
        assert!(result.is_ok());
        let scan = result.unwrap();
        assert_eq!(scan.nse_script.script, vec!["http-title"]);
    }
}
