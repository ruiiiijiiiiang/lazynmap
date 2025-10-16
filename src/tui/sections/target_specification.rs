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
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(row_chunks[0]);

    for (index, &flag) in [NmapFlag::Targets, NmapFlag::InputFile].iter().enumerate() {
        app.input_map.get_mut(&flag).unwrap().render(
            row_0_col_chunks[index],
            frame.buffer_mut(),
            app.focused_flag == flag,
            app.editing_flag == Some(flag),
        );
    }
}
