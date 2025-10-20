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

pub fn render_target_specification(app: &mut App, frame: &mut Frame, area: Rect) {
    let row_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1); 5])
        .spacing(1)
        .split(area);

    // Row 0
    let row_0_col_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .flex(Flex::SpaceBetween)
        .constraints([Constraint::Percentage(50); 2])
        .spacing(1)
        .split(row_chunks[0]);
    for (&flag, &area) in [NmapFlag::Targets, NmapFlag::InputFile]
        .iter()
        .zip(row_0_col_chunks.iter())
    {
        render_checkbox_with_input(app, flag, frame, area);
    }

    // Row 1
    let row_1_col_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .flex(Flex::SpaceBetween)
        .constraints([Constraint::Percentage(50); 2])
        .spacing(1)
        .split(row_chunks[1]);
    for (&flag, &area) in [NmapFlag::Exclude, NmapFlag::ExcludeFile]
        .iter()
        .zip(row_1_col_chunks.iter())
    {
        render_checkbox_with_input(app, flag, frame, area);
    }

    // Row 2
    let row_2_col_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .flex(Flex::SpaceBetween)
        .constraints([Constraint::Percentage(50); 2])
        .spacing(1)
        .split(row_chunks[2]);
    render_checkbox_with_input(app, NmapFlag::RandomTargets, frame, row_2_col_chunks[0]);
    render_checkbox(app, NmapFlag::Unique, frame, row_2_col_chunks[1]);

    // Row 3
    let row_3_col_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .flex(Flex::SpaceBetween)
        .constraints([Constraint::Percentage(25); 4])
        .spacing(1)
        .split(row_chunks[3]);
    for (&flag, &area) in [
        NmapFlag::NoResolve,
        NmapFlag::AlwaysResolve,
        NmapFlag::ResolveAll,
        NmapFlag::SystemDns,
    ]
    .iter()
    .zip(row_3_col_chunks.iter())
    {
        render_checkbox(app, flag, frame, area);
    }

    // Row 4
    let row_4_col_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .flex(Flex::SpaceBetween)
        .constraints([Constraint::Percentage(50); 2])
        .spacing(1)
        .split(row_chunks[4]);
    render_checkbox_with_input(app, NmapFlag::DnsServers, frame, row_4_col_chunks[0]);
}
