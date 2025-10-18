use ratatui::{
    Frame,
    layout::{Constraint, Direction, Flex, Layout, Rect},
};

use crate::{scan::flags::NmapFlag, tui::app::App};

pub fn render_target_specification(app: &mut App, frame: &mut Frame, area: Rect) {
    let row_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
        ])
        .split(area);

    let flags = [
        vec![NmapFlag::Targets, NmapFlag::InputFile],
        vec![NmapFlag::Exclude, NmapFlag::ExcludeFile],
        vec![NmapFlag::RandomTargets],
    ];

    for (index, &chunk) in row_chunks.iter().enumerate() {
        let row_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .flex(Flex::SpaceBetween)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(chunk);

        for (index, &flag) in flags[index].iter().enumerate() {
            app.input_map.get_mut(&flag).unwrap().render(
                row_chunks[index],
                frame.buffer_mut(),
                app.focused_flag == flag,
                app.editing_flag == Some(flag),
            );
        }
    }
}
