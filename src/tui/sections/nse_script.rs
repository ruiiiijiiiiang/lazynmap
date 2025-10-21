use ratatui::{Frame, layout::Rect};

use crate::{
    scan::flags::NmapFlag,
    tui::{
        app::App,
        utils::{even_horizontal_split, even_vertical_split, render_checkbox},
    },
};

pub fn render_nse_script(app: &mut App, frame: &mut Frame, area: Rect) {
    let row_chunks = even_vertical_split(area, 3);

    // Row 0
    let row_0_col_chunks = even_horizontal_split(row_chunks[0], 2);
    for (&flag, &area) in [NmapFlag::DefaultScript, NmapFlag::Script]
        .iter()
        .zip(row_0_col_chunks.iter())
    {
        render_checkbox(app, flag, frame, area);
    }

    // Row 1
    let row_1_col_chunks = even_horizontal_split(row_chunks[1], 2);
    for (&flag, &area) in [NmapFlag::ScriptArgs, NmapFlag::ScriptArgsFile]
        .iter()
        .zip(row_1_col_chunks.iter())
    {
        render_checkbox(app, flag, frame, area);
    }

    // Row 2
    let row_2_col_chunks = even_horizontal_split(row_chunks[2], 3);
    for (&flag, &area) in [
        NmapFlag::ScriptHelp,
        NmapFlag::ScriptTrace,
        NmapFlag::ScriptUpdateDb,
    ]
    .iter()
    .zip(row_2_col_chunks.iter())
    {
        render_checkbox(app, flag, frame, area);
    }
}
