use ratatui::{Frame, layout::Rect};

use crate::{
    scan::flags::NmapFlag,
    tui::{app::App, utils::render_flags_in_clamped_grid},
};

pub fn render_miscellaneous(app: &mut App, frame: &mut Frame, area: Rect) {
    let flags_grid = vec![
        vec![
            NmapFlag::IpV6,
            NmapFlag::Aggressive,
            NmapFlag::ReleaseMemory,
        ],
        vec![NmapFlag::DataDir, NmapFlag::ServiceDb, NmapFlag::VersionDb],
        vec![
            NmapFlag::SendEth,
            NmapFlag::SendIp,
            NmapFlag::Privileged,
            NmapFlag::Unprivileged,
        ],
        vec![NmapFlag::Version, NmapFlag::Help],
    ];

    render_flags_in_clamped_grid(app, frame, area, flags_grid);
}
