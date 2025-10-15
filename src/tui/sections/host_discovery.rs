use ratatui::{
    Frame,
    layout::{Constraint, Direction, Flex, Layout, Rect},
};

use crate::{
    scan::flags::{FlagValue, NmapFlag},
    tui::{
        app::App,
        widgets::checkbox::{Checkbox, CheckboxState},
    },
};

pub fn render_host_discovery(app: &mut App, frame: &mut Frame, area: Rect) {
    let row_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(area);

    let row_0_col_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .flex(Flex::SpaceBetween)
        .constraints([
            Constraint::Length(30),
            Constraint::Length(30),
            Constraint::Length(30),
        ])
        .split(row_chunks[0]);

    for (index, flag) in [
        NmapFlag::ListScan,
        NmapFlag::PingScan,
        NmapFlag::SkipPortScan,
    ]
    .iter()
    .enumerate()
    {
        render_checkbox(app, *flag, frame, row_0_col_chunks[index]);
    }

    let row_1_col_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .flex(Flex::SpaceBetween)
        .constraints([
            Constraint::Length(30),
            Constraint::Length(30),
            Constraint::Length(30),
            Constraint::Length(30),
        ])
        .split(row_chunks[1]);

    for (index, flag) in [
        NmapFlag::IcmpEcho,
        NmapFlag::IcmpTimestamp,
        NmapFlag::IcmpNetmask,
        NmapFlag::Traceroute,
    ]
    .iter()
    .enumerate()
    {
        render_checkbox(app, *flag, frame, row_1_col_chunks[index]);
    }
}

fn render_checkbox(app: &mut App, flag: NmapFlag, frame: &mut Frame, area: Rect) {
    let FlagValue::Bool(flag_value) = flag.get_flag_value(app.scan) else {
        panic!()
    };
    let mut state = CheckboxState::new(*flag_value);
    state.set_focused(app.focused_flag == flag);
    let label = flag.to_string();
    let checkbox = Checkbox::new().label(label.as_str());
    frame.render_stateful_widget(checkbox, area, &mut state);
}
