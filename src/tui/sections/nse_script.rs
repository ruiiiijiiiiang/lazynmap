use ratatui::{Frame, layout::Rect};

use crate::{
    scan::flags::NmapFlag,
    tui::{app::App, utils::render_flags_in_clamped_grid},
};

pub fn render_nse_script(app: &mut App, frame: &mut Frame, area: Rect) {
    let flags_grid = vec![
        vec![NmapFlag::DefaultScript, NmapFlag::Script],
        vec![NmapFlag::ScriptArgs, NmapFlag::ScriptArgsFile],
        vec![
            NmapFlag::ScriptHelp,
            NmapFlag::ScriptTrace,
            NmapFlag::ScriptUpdateDb,
        ],
    ];

    render_flags_in_clamped_grid(app, frame, area, flags_grid);
}
