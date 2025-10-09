use std::error::Error;

mod tui;
mod widgets;

use tui::Tui;

fn main() -> Result<(), Box<dyn Error>> {
    Tui::new().run()?;
    Ok(())
}
