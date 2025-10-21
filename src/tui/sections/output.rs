use ratatui::{Frame, layout::Rect};

use crate::{
    scan::flags::NmapFlag,
    tui::{
        app::App,
        utils::{even_horizontal_split, even_vertical_split, render_checkbox},
    },
};

pub fn render_output(app: &mut App, frame: &mut Frame, area: Rect) {
    let row_chunks = even_vertical_split(area, 6);

    // Row 0
    let row_0_col_chunks = even_horizontal_split(row_chunks[0], 3);
    for (&flag, &area) in [NmapFlag::Normal, NmapFlag::Xml, NmapFlag::Grepable]
        .iter()
        .zip(row_0_col_chunks.iter())
    {
        render_checkbox(app, flag, frame, area);
    }

    // Row 1
    let row_1_col_chunks = even_horizontal_split(row_chunks[1], 3);
    for (&flag, &area) in [
        NmapFlag::AllFormats,
        NmapFlag::Resume,
        NmapFlag::AppendOutput,
    ]
    .iter()
    .zip(row_1_col_chunks.iter())
    {
        render_checkbox(app, flag, frame, area);
    }

    // Row 2
    let row_2_col_chunks = even_horizontal_split(row_chunks[2], 3);
    for (&flag, &area) in [
        NmapFlag::Verbosity,
        NmapFlag::Debugging,
        NmapFlag::StatsEvery,
    ]
    .iter()
    .zip(row_2_col_chunks.iter())
    {
        render_checkbox(app, flag, frame, area);
    }

    // Row 3
    let row_3_col_chunks = even_horizontal_split(row_chunks[3], 4);
    for (&flag, &area) in [
        NmapFlag::Reason,
        NmapFlag::PacketTrace,
        NmapFlag::OpenOnly,
        NmapFlag::IfList,
    ]
    .iter()
    .zip(row_3_col_chunks.iter())
    {
        render_checkbox(app, flag, frame, area);
    }

    // Row 4
    let row_4_col_chunks = even_horizontal_split(row_chunks[4], 4);
    for (&flag, &area) in [
        NmapFlag::Noninteractive,
        NmapFlag::Stylesheet,
        NmapFlag::WebXml,
        NmapFlag::NoStylesheet,
    ]
    .iter()
    .zip(row_4_col_chunks.iter())
    {
        render_checkbox(app, flag, frame, area);
    }

    //Row 5
    let row_5_col_chunks = even_horizontal_split(row_chunks[5], 2);
    render_checkbox(app, NmapFlag::ScriptKiddie, frame, row_5_col_chunks[0]);
}
