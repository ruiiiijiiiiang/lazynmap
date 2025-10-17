use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
};

use crate::{
    scan::{flags::NmapFlag, model::TimingTemplate},
    tui::{app::App, widgets::radio::RadioGroup},
};

pub fn render_timing(app: &mut App, frame: &mut Frame, area: Rect) {
    let row_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(area);

    let timing_radios = RadioGroup::new(TimingTemplate::all_labels())
        .with_selected(
            app.scan
                .timing
                .template
                .map(|timing_template| timing_template.as_index()),
        )
        .with_focused(match (app.focused_flag, app.focused_radio_index) {
            (NmapFlag::TimingTemplate, Some(index)) => Some(index),
            _ => None,
        });

    timing_radios.render(row_chunks[0], frame.buffer_mut());
}
