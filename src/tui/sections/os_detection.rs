use ratatui::{Frame, layout::Rect};

use crate::{
    scan::flags::NmapFlag,
    tui::{
        app::App,
        utils::{even_horizontal_split, render_checkbox, render_checkbox_with_input},
    },
};

pub fn render_os_detection(app: &mut App, frame: &mut Frame, area: Rect) {
    let col_chunks = even_horizontal_split(area, 4);
    for (&flag, &area) in [NmapFlag::OsDetection, NmapFlag::OsLimit, NmapFlag::OsGuess]
        .iter()
        .zip(col_chunks.iter())
    {
        render_checkbox(app, flag, frame, area);
    }
    render_checkbox_with_input(app, NmapFlag::MaxOsRetries, frame, col_chunks[3]);
}
