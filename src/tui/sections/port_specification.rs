use ratatui::{Frame, layout::Rect};

use crate::{
    scan::flags::NmapFlag,
    tui::{app::App, utils::render_flags_in_clamped_grid},
};

pub fn render_port_specification(app: &mut App, frame: &mut Frame, area: Rect) {
    let flags_grid = vec![
        vec![NmapFlag::Ports, NmapFlag::ExcludePorts, NmapFlag::FastMode],
        vec![
            NmapFlag::ConsecutivePorts,
            NmapFlag::TopPorts,
            NmapFlag::PortRatio,
        ],
    ];

    render_flags_in_clamped_grid(app, frame, area, flags_grid);
}
