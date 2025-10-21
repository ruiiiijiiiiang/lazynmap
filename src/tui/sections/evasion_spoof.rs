use ratatui::{Frame, layout::Rect};

use crate::{
    scan::flags::NmapFlag,
    tui::{
        app::App,
        utils::{even_horizontal_split, even_vertical_split, render_checkbox},
    },
};

pub fn render_evasion_spoof(app: &mut App, frame: &mut Frame, area: Rect) {
    let row_chunks = even_vertical_split(area, 4);

    // Row 0
    let row_0_col_chunks = even_horizontal_split(row_chunks[0], 4);
    for (&flag, &area) in [
        NmapFlag::FragmentPackets,
        NmapFlag::Mtu,
        NmapFlag::Decoys,
        NmapFlag::Proxies,
    ]
    .iter()
    .zip(row_0_col_chunks.iter())
    {
        render_checkbox(app, flag, frame, area);
    }

    // Row 1
    let row_1_col_chunks = even_horizontal_split(row_chunks[1], 4);
    for (&flag, &area) in [
        NmapFlag::SpoofIp,
        NmapFlag::SpoofMac,
        NmapFlag::Interface,
        NmapFlag::SourcePort,
    ]
    .iter()
    .zip(row_1_col_chunks.iter())
    {
        render_checkbox(app, flag, frame, area);
    }

    // Row 2
    let row_2_col_chunks = even_horizontal_split(row_chunks[2], 4);
    for (&flag, &area) in [
        NmapFlag::Data,
        NmapFlag::DataString,
        NmapFlag::DataLength,
        NmapFlag::IpOptions,
    ]
    .iter()
    .zip(row_2_col_chunks.iter())
    {
        render_checkbox(app, flag, frame, area);
    }

    // Row 3
    let row_3_col_chunks = even_horizontal_split(row_chunks[3], 4);
    for (&flag, &area) in [
        NmapFlag::Ttl,
        NmapFlag::RandomizeHosts,
        NmapFlag::Badsum,
        NmapFlag::Adler32,
    ]
    .iter()
    .zip(row_3_col_chunks.iter())
    {
        render_checkbox(app, flag, frame, area);
    }
}
