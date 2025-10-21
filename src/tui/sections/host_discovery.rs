use ratatui::{Frame, layout::Rect};

use crate::{
    scan::flags::NmapFlag,
    tui::{
        app::App,
        utils::{
            even_horizontal_split, even_vertical_split, render_checkbox, render_checkbox_with_input,
        },
    },
};

pub fn render_host_discovery(app: &mut App, frame: &mut Frame, area: Rect) {
    let row_chunks = even_vertical_split(area, 4);

    // Row 0
    let row_0_col_chunks = even_horizontal_split(row_chunks[0], 3);
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
    let row_1_col_chunks = even_horizontal_split(row_chunks[1], 4);
    for (&flag, &area) in [
        NmapFlag::SynDiscovery,
        NmapFlag::AckDiscovery,
        NmapFlag::UdpDiscovery,
        NmapFlag::SctpDiscovery,
    ]
    .iter()
    .zip(row_1_col_chunks.iter())
    {
        render_checkbox_with_input(app, flag, frame, area);
    }

    // Row 2
    let row_2_col_chunks = even_horizontal_split(row_chunks[2], 4);
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
    render_checkbox_with_input(app, NmapFlag::IpProtocolPing, frame, row_2_col_chunks[3]);

    // Row 3
    let row_3_col_chunks = even_horizontal_split(row_chunks[3], 3);
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
