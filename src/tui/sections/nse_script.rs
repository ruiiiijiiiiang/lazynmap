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

pub fn render_nse_script(app: &mut App, frame: &mut Frame, area: Rect) {
    let row_chunks = even_vertical_split(area, 3);

    // Row 0
    let row_0_col_chunks = even_horizontal_split(row_chunks[0], 2);
    render_checkbox(app, NmapFlag::DefaultScript, frame, row_0_col_chunks[0]);
    render_checkbox_with_input(app, NmapFlag::Script, frame, row_0_col_chunks[1]);

    // Row 1
    let row_1_col_chunks = even_horizontal_split(row_chunks[1], 2);
    for (&flag, &area) in [NmapFlag::ScriptArgs, NmapFlag::ScriptArgsFile]
        .iter()
        .zip(row_1_col_chunks.iter())
    {
        render_checkbox_with_input(app, flag, frame, area);
    }

    // Row 2
    let row_2_col_chunks = even_horizontal_split(row_chunks[2], 3);
    render_checkbox_with_input(app, NmapFlag::ScriptHelp, frame, row_2_col_chunks[0]);
    for (&flag, &area) in [NmapFlag::ScriptTrace, NmapFlag::ScriptUpdateDB]
        .iter()
        .zip(row_2_col_chunks.iter().skip(1))
    {
        render_checkbox(app, flag, frame, area);
    }
}
