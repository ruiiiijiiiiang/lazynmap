use ratatui::{Frame, layout::Rect};

use crate::{
    scan::flags::NmapFlag,
    tui::{
        app::App,
        utils::{even_horizontal_split, even_vertical_split, render_checkbox},
    },
};

pub fn render_target_specification(app: &mut App, frame: &mut Frame, area: Rect) {
    let row_chunks = even_vertical_split(area, 5);

    // Row 0
    let row_0_col_chunks = even_horizontal_split(row_chunks[0], 2);
    for (&flag, &area) in [NmapFlag::Targets, NmapFlag::InputFile]
        .iter()
        .zip(row_0_col_chunks.iter())
    {
        render_checkbox(app, flag, frame, area);
    }

    // Row 1
    let row_1_col_chunks = even_horizontal_split(row_chunks[1], 2);
    for (&flag, &area) in [NmapFlag::Exclude, NmapFlag::ExcludeFile]
        .iter()
        .zip(row_1_col_chunks.iter())
    {
        render_checkbox(app, flag, frame, area);
    }

    // Row 2
    let row_2_col_chunks = even_horizontal_split(row_chunks[2], 2);
    for (&flag, &area) in [NmapFlag::RandomTargets, NmapFlag::Unique]
        .iter()
        .zip(row_2_col_chunks.iter())
    {
        render_checkbox(app, flag, frame, area);
    }

    // Row 3
    let row_3_col_chunks = even_horizontal_split(row_chunks[3], 4);
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
    let row_4_col_chunks = even_horizontal_split(row_chunks[4], 2);
    render_checkbox(app, NmapFlag::DnsServers, frame, row_4_col_chunks[0]);
}
