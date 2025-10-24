use ratatui::{Frame, layout::Rect};

use crate::{
    scan::flags::NmapFlag,
    tui::{app::App, utils::render_flags_in_clamped_grid},
};

pub fn render_os_detection(app: &mut App, frame: &mut Frame, area: Rect) {
    let flags_grid = vec![vec![
        NmapFlag::OsDetection,
        NmapFlag::OsLimit,
        NmapFlag::OsGuess,
        NmapFlag::MaxOsRetries,
    ]];

    render_flags_in_clamped_grid(app, frame, area, flags_grid);
}
