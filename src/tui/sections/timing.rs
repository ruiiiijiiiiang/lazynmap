use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Margin, Rect},
    widgets::Block,
};

use crate::{
    consts::IndexableEnum,
    scan::{
        flags::NmapFlag,
        model::{NsockEngine, TimingTemplate},
    },
    tui::{
        app::App,
        utils::{clamp_length_constraints, render_flags_in_clamped_grid},
        widgets::radio::{RadioGroup, RadioOption},
    },
};

pub fn render_timing(app: &mut App, frame: &mut Frame, area: Rect) {
    let desired = vec![9, 6];
    let constraints = clamp_length_constraints(&desired, area);
    let group_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);

    let flags_grid = vec![
        vec![
            NmapFlag::MinHostgroup,
            NmapFlag::MaxHostgroup,
            NmapFlag::MinParallelism,
            NmapFlag::MaxParallelism,
        ],
        vec![
            NmapFlag::MinRttTimeout,
            NmapFlag::MaxRttTimeout,
            NmapFlag::InitialRttTimeout,
        ],
        vec![
            NmapFlag::MaxRetries,
            NmapFlag::HostTimeout,
            NmapFlag::ScriptTimeout,
        ],
        vec![
            NmapFlag::ScanDelay,
            NmapFlag::MaxScanDelay,
            NmapFlag::MinRate,
            NmapFlag::MaxRate,
        ],
        vec![NmapFlag::DefeatRstRatelimit, NmapFlag::DefeatIcmpRatelimit],
    ];

    render_flags_in_clamped_grid(app, frame, group_chunks[0], flags_grid);

    let row_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3); 2])
        .split(group_chunks[1]);

    let nsock_block = Block::bordered().title("Nsock engine");
    frame.render_widget(nsock_block, row_chunks[0]);
    let mut nsock_radios = RadioGroup::new(
        NsockEngine::all_labels()
            .iter()
            .map(|label| RadioOption::Text(label.to_string()))
            .collect(),
    )
    .with_selected(
        app.scan
            .timing
            .nsock_engine
            .map(|nsock_engine| nsock_engine.as_index()),
    )
    .with_focused(match (app.focused_flag, app.focused_radio_index) {
        (NmapFlag::NsockEngine, Some(index)) => Some(index),
        _ => None,
    });
    nsock_radios.render(
        row_chunks[0].inner(Margin {
            vertical: 1,
            horizontal: 1,
        }),
        frame.buffer_mut(),
    );

    let timing_block = Block::bordered().title("Timing template");
    frame.render_widget(timing_block, row_chunks[1]);
    let mut timing_radios = RadioGroup::new(
        TimingTemplate::all_labels()
            .iter()
            .map(|label| RadioOption::Text(label.to_string()))
            .collect(),
    )
    .with_selected(
        app.scan
            .timing
            .template
            .map(|timing_template| timing_template.as_index()),
    )
    .with_focused(match (app.focused_flag, app.focused_radio_index) {
        (NmapFlag::TimingTemplate, Some(index)) => Some(index),
        _ => None,
    });
    timing_radios.render(
        row_chunks[1].inner(Margin {
            vertical: 1,
            horizontal: 1,
        }),
        frame.buffer_mut(),
    );
}
