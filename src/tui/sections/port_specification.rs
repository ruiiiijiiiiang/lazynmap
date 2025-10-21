use ratatui::{Frame, layout::Rect};

use crate::{
    scan::flags::NmapFlag,
    tui::{
        app::App,
        utils::{even_horizontal_split, even_vertical_split, render_checkbox},
    },
};

pub fn render_port_specification(app: &mut App, frame: &mut Frame, area: Rect) {
    let row_chunks = even_vertical_split(area, 2);

    // Row 0
    let row_0_col_chunks = even_horizontal_split(row_chunks[0], 3);
    for (&flag, &area) in [NmapFlag::Ports, NmapFlag::ExcludePorts, NmapFlag::FastMode]
        .iter()
        .zip(row_0_col_chunks.iter())
    {
        render_checkbox(app, flag, frame, area);
    }

    // Row 1
    let row_1_col_chunks = even_horizontal_split(row_chunks[1], 3);
    for (&flag, &area) in [
        NmapFlag::ConsecutivePorts,
        NmapFlag::TopPorts,
        NmapFlag::PortRatio,
    ]
    .iter()
    .zip(row_1_col_chunks.iter())
    {
        render_checkbox(app, flag, frame, area);
    }
}
