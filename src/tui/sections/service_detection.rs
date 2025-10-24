use ratatui::{Frame, layout::Rect};

use crate::{
    scan::flags::NmapFlag,
    tui::{app::App, utils::render_flags_in_clamped_grid},
};

pub fn render_service_detection(app: &mut App, frame: &mut Frame, area: Rect) {
    let flags_grid = vec![
        vec![
            NmapFlag::VersionDetection,
            NmapFlag::AllPorts,
            NmapFlag::VersionIntensity,
        ],
        vec![
            NmapFlag::VersionLight,
            NmapFlag::VersionAll,
            NmapFlag::VersionTrace,
        ],
    ];

    render_flags_in_clamped_grid(app, frame, area, flags_grid);
}
