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
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
        ])
        .split(area);

    // Row 0
    let row_0_col_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .flex(Flex::SpaceBetween)
        .constraints([
            Constraint::Length(30),
            Constraint::Length(30),
            Constraint::Length(30),
            Constraint::Length(30),
        ])
        .split(row_chunks[0]);

    for (index, &flag) in [
        NmapFlag::ListScan,
        NmapFlag::PingScan,
        NmapFlag::SkipPortScan,
        NmapFlag::Traceroute,
    ]
    .iter()
    .enumerate()
    {
        render_checkbox(app, flag, frame, row_0_col_chunks[index]);
    }

    // Row 1
    let row_1_col_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .flex(Flex::SpaceBetween)
        .constraints([
            Constraint::Length(60),
            Constraint::Length(60),
            Constraint::Length(60),
            Constraint::Length(60),
        ])
        .split(row_chunks[1]);

    for (index, &flag) in [
        NmapFlag::SynDiscovery,
        NmapFlag::AckDiscovery,
        NmapFlag::UdpDiscovery,
        NmapFlag::SctpDiscovery,
    ]
    .iter()
    .enumerate()
    {
        app.input_map.get_mut(&flag).unwrap().render(
            row_1_col_chunks[index],
            frame.buffer_mut(),
            app.focused_flag == flag,
            app.editing_flag == Some(flag),
        );
    }

    // Row 2
    let row_2_col_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .flex(Flex::SpaceBetween)
        .constraints([
            Constraint::Length(30),
            Constraint::Length(30),
            Constraint::Length(30),
            Constraint::Length(60),
        ])
        .split(row_chunks[2]);

    for (index, &flag) in [
        NmapFlag::IcmpEcho,
        NmapFlag::IcmpTimestamp,
        NmapFlag::IcmpNetmask,
    ]
    .iter()
    .enumerate()
    {
        render_checkbox(app, flag, frame, row_2_col_chunks[index]);
    }
    app.input_map
        .get_mut(&NmapFlag::IpProtocolPing)
        .unwrap()
        .render(
            row_2_col_chunks[3],
            frame.buffer_mut(),
            app.focused_flag == NmapFlag::IpProtocolPing,
            app.editing_flag == Some(NmapFlag::IpProtocolPing),
        );

    // Row 3
    let row_3_col_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .flex(Flex::SpaceBetween)
        .constraints([
            Constraint::Length(30),
            Constraint::Length(30),
            Constraint::Length(30),
            Constraint::Length(60),
        ])
        .split(row_chunks[3]);
    for (index, &flag) in [
        NmapFlag::SystemDns,
        NmapFlag::NoResolve,
        NmapFlag::AlwaysResolve,
    ]
    .iter()
    .enumerate()
    {
        render_checkbox(app, flag, frame, row_3_col_chunks[index]);
    }

    app.input_map
        .get_mut(&NmapFlag::DnsServers)
        .unwrap()
        .render(
            row_3_col_chunks[3],
            frame.buffer_mut(),
            app.focused_flag == NmapFlag::DnsServers,
            app.editing_flag == Some(NmapFlag::DnsServers),
        );
}
