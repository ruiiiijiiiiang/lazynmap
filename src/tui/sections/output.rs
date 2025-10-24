use ratatui::{Frame, layout::Rect};

use crate::{
    scan::flags::NmapFlag,
    tui::{app::App, utils::render_flags_in_clamped_grid},
};

pub fn render_output(app: &mut App, frame: &mut Frame, area: Rect) {
    let flags_grid = vec![
        vec![NmapFlag::Normal, NmapFlag::Grepable],
        vec![
            NmapFlag::AllFormats,
            NmapFlag::Resume,
            NmapFlag::AppendOutput,
            NmapFlag::ScriptKiddie,
        ],
        vec![
            NmapFlag::Verbosity,
            NmapFlag::Debugging,
            NmapFlag::StatsEvery,
            NmapFlag::Noninteractive,
        ],
        vec![
            NmapFlag::Reason,
            NmapFlag::PacketTrace,
            NmapFlag::OpenOnly,
            NmapFlag::IfList,
        ],
        vec![
            NmapFlag::Xml,
            NmapFlag::Stylesheet,
            NmapFlag::WebXml,
            NmapFlag::NoStylesheet,
        ],
    ];

    render_flags_in_clamped_grid(app, frame, area, flags_grid);
}
