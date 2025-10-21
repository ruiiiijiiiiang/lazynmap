use ratatui::{Frame, layout::Rect};

use crate::{
    scan::flags::NmapFlag,
    tui::{
        app::App,
        utils::{even_horizontal_split, even_vertical_split, render_checkbox},
    },
};

pub fn render_miscellaneous(app: &mut App, frame: &mut Frame, area: Rect) {
    let row_chunks = even_vertical_split(area, 4);

    // Row 0
    let row_0_col_chunks = even_horizontal_split(row_chunks[0], 3);
    for (&flag, &area) in [
        NmapFlag::IpV6,
        NmapFlag::Aggressive,
        NmapFlag::ReleaseMemory,
    ]
    .iter()
    .zip(row_0_col_chunks.iter())
    {
        render_checkbox(app, flag, frame, area);
    }

    // Row 1
    let row_1_col_chunks = even_horizontal_split(row_chunks[1], 3);
    for (&flag, &area) in [NmapFlag::DataDir, NmapFlag::ServiceDb, NmapFlag::VersionDb]
        .iter()
        .zip(row_1_col_chunks.iter())
    {
        render_checkbox(app, flag, frame, area);
    }

    // Row 2
    let row_2_col_chunks = even_horizontal_split(row_chunks[2], 4);
    for (&flag, &area) in [
        NmapFlag::SendEth,
        NmapFlag::SendIp,
        NmapFlag::Privileged,
        NmapFlag::Unprivileged,
    ]
    .iter()
    .zip(row_2_col_chunks.iter())
    {
        render_checkbox(app, flag, frame, area);
    }

    // Row 3
    let row_3_col_chunks = even_horizontal_split(row_chunks[3], 4);
    for (&flag, &area) in [NmapFlag::Version, NmapFlag::Help]
        .iter()
        .zip(row_3_col_chunks.iter())
    {
        render_checkbox(app, flag, frame, area);
    }
}
