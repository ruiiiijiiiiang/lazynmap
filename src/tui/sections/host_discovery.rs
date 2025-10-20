use ratatui::{
    Frame,
    layout::{Constraint, Direction, Flex, Layout, Rect},
};

use crate::{
    scan::flags::NmapFlag,
    tui::{
        app::App,
        utils::{render_checkbox, render_input},
    },
};

pub fn render_host_discovery(app: &mut App, frame: &mut Frame, area: Rect) {
    let row_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1); 4])
        .spacing(1)
        .split(area);

    // Row 0
    let row_0_col_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .flex(Flex::SpaceBetween)
        .constraints([Constraint::Percentage(33); 3])
        .spacing(1)
        .split(row_chunks[0]);

    for (&flag, &area) in [
        NmapFlag::ListScan,
        NmapFlag::PingScan,
        NmapFlag::SkipPortScan,
    ]
    .iter()
    .zip(row_0_col_chunks.iter())
    {
        render_checkbox(app, flag, frame, area);
    }

    // Row 1
    let row_1_col_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .flex(Flex::SpaceBetween)
        .constraints([Constraint::Percentage(25); 4])
        .spacing(1)
        .split(row_chunks[1]);

    for (&flag, &area) in [
        NmapFlag::SynDiscovery,
        NmapFlag::AckDiscovery,
        NmapFlag::UdpDiscovery,
        NmapFlag::SctpDiscovery,
    ]
    .iter()
    .zip(row_1_col_chunks.iter())
    {
        render_input(app, flag, frame, area);
    }

    // Row 2
    let row_2_col_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .flex(Flex::SpaceBetween)
        .constraints([Constraint::Percentage(25); 4])
        .spacing(1)
        .split(row_chunks[2]);

    for (&flag, &area) in [
        NmapFlag::IcmpEcho,
        NmapFlag::IcmpTimestamp,
        NmapFlag::IcmpNetmask,
    ]
    .iter()
    .zip(row_2_col_chunks.iter())
    {
        render_checkbox(app, flag, frame, area);
    }
    render_input(app, NmapFlag::IpProtocolPing, frame, row_2_col_chunks[3]);

    // Row 3
    let row_3_col_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .flex(Flex::SpaceBetween)
        .constraints([Constraint::Percentage(33); 3])
        .spacing(1)
        .split(row_chunks[3]);
    for (&flag, &area) in [
        NmapFlag::DisableArpPing,
        NmapFlag::DiscoverIgnoreRst,
        NmapFlag::Traceroute,
    ]
    .iter()
    .zip(row_3_col_chunks.iter())
    {
        render_checkbox(app, flag, frame, area);
    }
}
