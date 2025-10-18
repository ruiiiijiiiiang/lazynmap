use ratatui::{
    Frame,
    layout::{Constraint, Direction, Flex, Layout, Rect},
};

use crate::{
    scan::flags::NmapFlag,
    tui::{app::App, utils::render_checkbox},
};

pub fn render_host_discovery(app: &mut App, frame: &mut Frame, area: Rect) {
    let row_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(area);

    let row_0_col_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .flex(Flex::SpaceBetween)
        .constraints([
            Constraint::Length(30),
            Constraint::Length(30),
            Constraint::Length(30),
        ])
        .split(row_chunks[0]);

    for (index, &flag) in [
        NmapFlag::ListScan,
        NmapFlag::PingScan,
        NmapFlag::SkipPortScan,
    ]
    .iter()
    .enumerate()
    {
        render_checkbox(app, flag, frame, row_0_col_chunks[index]);
    }

    let row_1_col_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .flex(Flex::SpaceBetween)
        .constraints([
            Constraint::Length(30),
            Constraint::Length(30),
            Constraint::Length(30),
            Constraint::Length(30),
        ])
        .split(row_chunks[1]);

    for (index, &flag) in [
        NmapFlag::IcmpEcho,
        NmapFlag::IcmpTimestamp,
        NmapFlag::IcmpNetmask,
        NmapFlag::Traceroute,
    ]
    .iter()
    .enumerate()
    {
        render_checkbox(app, flag, frame, row_1_col_chunks[index]);
    }
}
