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

pub fn render_port_specification(app: &mut App, frame: &mut Frame, area: Rect) {
    let row_chunks = even_vertical_split(area, 2);

    // Row 0
    let row_0_col_chunks = even_horizontal_split(row_chunks[0], 3);
    for (&flag, &area) in [NmapFlag::Ports, NmapFlag::ExcludePorts]
        .iter()
        .zip(row_0_col_chunks.iter())
    {
        render_checkbox_with_input(app, flag, frame, area);
    }
    render_checkbox(app, NmapFlag::FastMode, frame, row_0_col_chunks[2]);

    // Row 1
    let row_1_col_chunks = even_horizontal_split(row_chunks[1], 3);
    render_checkbox(app, NmapFlag::ConsecutivePorts, frame, row_1_col_chunks[0]);
    for (&flag, &area) in [NmapFlag::TopPorts, NmapFlag::PortRatio]
        .iter()
        .zip(row_1_col_chunks.iter().skip(1))
    {
        render_checkbox_with_input(app, flag, frame, area);
    }
}
