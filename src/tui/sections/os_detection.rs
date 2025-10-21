use ratatui::{Frame, layout::Rect};

use crate::{
    scan::flags::NmapFlag,
    tui::{
        app::App,
        utils::{even_horizontal_split, render_checkbox},
    },
};

pub fn render_os_detection(app: &mut App, frame: &mut Frame, area: Rect) {
    let col_chunks = even_horizontal_split(area, 4);
    for (&flag, &area) in [
        NmapFlag::OsDetection,
        NmapFlag::OsLimit,
        NmapFlag::OsGuess,
        NmapFlag::MaxOsRetries,
    ]
    .iter()
    .zip(col_chunks.iter())
    {
        render_checkbox(app, flag, frame, area);
    }
}
