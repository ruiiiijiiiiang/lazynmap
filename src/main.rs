use std::error::Error;

mod scan;
mod sections;
mod tui;
mod widgets;

use scan::NmapScan;
use tui::Tui;

fn main() -> Result<(), Box<dyn Error>> {
    let mut scan = NmapScan::new();
    Tui::new(&mut scan).run()?;
    Ok(())
}
