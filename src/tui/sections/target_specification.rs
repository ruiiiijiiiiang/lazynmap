use ratatui::{
    Frame,
    layout::{Constraint, Direction, Flex, Layout, Rect},
};

use crate::{
    scan::flags::NmapFlag,
    tui::{
        app::App,
        // widgets::text_input::{InputWidget, TextInput, VecStringParser},
    },
};

pub fn render_target_specification(app: &mut App, frame: &mut Frame, area: Rect) {
    let row_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            // Constraint::Length(1),
            // Constraint::Length(1),
        ])
        .split(area);

    let row_0_col_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .flex(Flex::SpaceBetween)
        .constraints([Constraint::Length(50), Constraint::Length(40)])
        .split(row_chunks[0]);

    app.input_map.get(&NmapFlag::Targets).unwrap().render(
        row_0_col_chunks[0],
        frame.buffer_mut(),
        app.focused_flag == NmapFlag::Targets,
        app.editing,
    );
}
