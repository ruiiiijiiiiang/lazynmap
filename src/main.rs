use std::error::Error;

mod builder;
mod parser;
mod scan;
mod tui;

use builder::NmapCommandBuilder;
use parser::NmapParser;
use scan::NmapScan;
use tui::Tui;

fn main() -> Result<(), Box<dyn Error>> {
    Tui::new().run()?;
    Ok(())
}
