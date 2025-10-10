use ratatui::{
    Frame,
    layout::{Constraint, Direction, Flex, Layout, Rect},
    style::{Color, Style},
};

use crate::{
    tui::Tui,
    widgets::checkbox::{Checkbox, CheckboxState},
};

pub fn render_host_discovery(tui: &mut Tui, frame: &mut Frame, area: Rect) {
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

    let mut list_scan_state = CheckboxState::new(tui.scan.host_discovery.list_scan);
    let list_scan_checkbox = Checkbox::new().label("List scan (-sL)");
    frame.render_stateful_widget(
        list_scan_checkbox,
        row_0_col_chunks[0],
        &mut list_scan_state,
    );

    let mut ping_scan_state = CheckboxState::new(tui.scan.host_discovery.ping_scan);
    let ping_scan_checkbox = Checkbox::new().label("Ping scan (-sn)");
    frame.render_stateful_widget(
        ping_scan_checkbox,
        row_0_col_chunks[1],
        &mut ping_scan_state,
    );

    let mut skip_port_scan_state = CheckboxState::new(tui.scan.host_discovery.skip_port_scan);
    let skip_port_scan_checkbox = Checkbox::new().label("Skip port scan (-Pn)");
    frame.render_stateful_widget(
        skip_port_scan_checkbox,
        row_0_col_chunks[2],
        &mut skip_port_scan_state,
    );

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

    let mut icmp_echo_state = CheckboxState::new(tui.scan.host_discovery.icmp_echo);
    let icmp_echo_checkbox = Checkbox::new().label("ICMP echo (-PE)");
    frame.render_stateful_widget(
        icmp_echo_checkbox,
        row_1_col_chunks[0],
        &mut icmp_echo_state,
    );

    let mut icmp_timestamp_state = CheckboxState::new(tui.scan.host_discovery.icmp_timestamp);
    let icmp_timestamp_checkbox = Checkbox::new().label("ICMP timestamp (-PP)");
    frame.render_stateful_widget(
        icmp_timestamp_checkbox,
        row_1_col_chunks[1],
        &mut icmp_timestamp_state,
    );

    let mut icmp_netmask_state = CheckboxState::new(tui.scan.host_discovery.icmp_netmask);
    let icmp_netmask_checkbox = Checkbox::new().label("ICMP netmask (-PM)");
    frame.render_stateful_widget(
        icmp_netmask_checkbox,
        row_1_col_chunks[2],
        &mut icmp_netmask_state,
    );

    let mut traceroute_state = CheckboxState::new(tui.scan.host_discovery.traceroute);
    let traceroute_checkbox = Checkbox::new().label("Traceroute (--traceroute)");
    frame.render_stateful_widget(
        traceroute_checkbox,
        row_1_col_chunks[3],
        &mut traceroute_state,
    );
}
