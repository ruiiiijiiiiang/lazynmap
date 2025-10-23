use std::{error::Error, os::unix::process::CommandExt, process::Command};

pub mod consts;
pub mod scan;
pub mod tui;

use scan::model::NmapScan;
use tui::app::App;

use crate::scan::builder::NmapCommandBuilder;

fn main() -> Result<(), Box<dyn Error>> {
    let mut scan = NmapScan::new();
    if let Ok(app_result) = App::new(&mut scan).start()
        && app_result.execute
    {
        let command = NmapCommandBuilder::build(&scan);
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
