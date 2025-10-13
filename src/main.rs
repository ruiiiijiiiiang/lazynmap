use std::error::Error;

pub mod scan;
pub mod tui;

use scan::model::NmapScan;
use tui::app::App;

fn main() -> Result<(), Box<dyn Error>> {
    let mut scan = NmapScan::new();
    App::new(&mut scan).run()?;
    Ok(())
}
