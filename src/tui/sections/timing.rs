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
        utils::{even_horizontal_split, even_vertical_split, render_checkbox},
        widgets::radio::{RadioGroup, RadioOption},
    },
};

pub fn render_timing(app: &mut App, frame: &mut Frame, area: Rect) {
    let group_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(9), Constraint::Length(6)])
        .split(area);

    let row_chunks = even_vertical_split(group_chunks[0], 5);

    // Row 0
    let row_0_col_chunks = even_horizontal_split(row_chunks[0], 4);
    for (&flag, &area) in [
        NmapFlag::MinHostgroup,
        NmapFlag::MaxHostgroup,
        NmapFlag::MinParallelism,
        NmapFlag::MaxParallelism,
    ]
    .iter()
    .zip(row_0_col_chunks.iter())
    {
        render_checkbox(app, flag, frame, area);
    }

    // Row 1
    let row_1_col_chunks = even_horizontal_split(row_chunks[1], 3);
    for (&flag, &area) in [
        NmapFlag::MinRttTimeout,
        NmapFlag::MaxRttTimeout,
        NmapFlag::InitialRttTimeout,
    ]
    .iter()
    .zip(row_1_col_chunks.iter())
    {
        render_checkbox(app, flag, frame, area);
    }

    // Row 2
    let row_2_col_chunks = even_horizontal_split(row_chunks[2], 3);
    for (&flag, &area) in [
        NmapFlag::MaxRetries,
        NmapFlag::HostTimeout,
        NmapFlag::ScriptTimeout,
    ]
    .iter()
    .zip(row_2_col_chunks.iter())
    {
        render_checkbox(app, flag, frame, area);
    }

    // Row 3
    let row_3_col_chunks = even_horizontal_split(row_chunks[3], 4);
    for (&flag, &area) in [
        NmapFlag::ScanDelay,
        NmapFlag::MaxScanDelay,
        NmapFlag::MinRate,
        NmapFlag::MaxRate,
    ]
    .iter()
    .zip(row_3_col_chunks.iter())
    {
        render_checkbox(app, flag, frame, area);
    }

    // Row 4
    let row_4_col_chunks = even_horizontal_split(row_chunks[4], 2);
    for (&flag, &area) in [NmapFlag::DefeatRstRatelimit, NmapFlag::DefeatIcmpRatelimit]
        .iter()
        .zip(row_4_col_chunks.iter())
    {
        render_checkbox(app, flag, frame, area);
    }

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
