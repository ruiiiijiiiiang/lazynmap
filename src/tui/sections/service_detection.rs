use ratatui::{
    Frame,
    layout::{Constraint, Direction, Flex, Layout, Rect},
};

use crate::{
    scan::flags::NmapFlag,
    tui::{
        app::App,
        utils::{render_checkbox, render_checkbox_with_input},
    },
};

pub fn render_service_detection(app: &mut App, frame: &mut Frame, area: Rect) {
    let row_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1); 2])
        .spacing(1)
        .split(area);

    // Row 0
    let row_0_col_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .flex(Flex::SpaceBetween)
        .constraints([Constraint::Percentage(33); 3])
        .spacing(1)
        .split(row_chunks[0]);
    for (&flag, &area) in [NmapFlag::VersionDetection, NmapFlag::AllPorts]
        .iter()
        .zip(row_0_col_chunks.iter())
    {
        render_checkbox(app, flag, frame, area);
    }
    render_checkbox_with_input(app, NmapFlag::VersionIntensity, frame, row_0_col_chunks[2]);

    // Row 1
    let row_1_col_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .flex(Flex::SpaceBetween)
        .constraints([Constraint::Percentage(33); 3])
        .spacing(1)
        .split(row_chunks[1]);
    for (&flag, &area) in [
        NmapFlag::VersionLight,
        NmapFlag::VersionAll,
        NmapFlag::VersionTrace,
    ]
    .iter()
    .zip(row_1_col_chunks.iter())
    {
        render_checkbox(app, flag, frame, area);
    }
}
