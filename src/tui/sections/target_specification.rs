use ratatui::{Frame, layout::Rect};

use crate::{
    scan::flags::NmapFlag,
    tui::{app::App, utils::render_flags_in_clamped_grid},
};

pub fn render_target_specification(app: &mut App, frame: &mut Frame, area: Rect) {
    let flags_grid = vec![
        vec![NmapFlag::Targets, NmapFlag::InputFile],
        vec![NmapFlag::Exclude, NmapFlag::ExcludeFile],
        vec![NmapFlag::RandomTargets, NmapFlag::Unique],
        vec![
            NmapFlag::NoResolve,
            NmapFlag::AlwaysResolve,
            NmapFlag::ResolveAll,
            NmapFlag::SystemDns,
        ],
        vec![NmapFlag::DnsServers],
    ];

    render_flags_in_clamped_grid(app, frame, area, flags_grid);
}
