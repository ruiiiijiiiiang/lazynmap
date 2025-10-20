use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
};

use crate::{
    scan::{flags::NmapFlag, model::TcpScanType},
    tui::{
        app::App,
        widgets::radio::{RadioGroup, RadioOption},
    },
};

pub fn render_scan_technique(app: &mut App, frame: &mut Frame, area: Rect) {
    let row_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7),
            // Constraint::Length(1),
            // Constraint::Length(1),
            // Constraint::Length(1),
        ])
        .spacing(1)
        .split(area);

    let mut options = [
        TcpScanType::Syn,
        TcpScanType::Connect,
        TcpScanType::Ack,
        TcpScanType::Window,
        TcpScanType::Maimon,
        TcpScanType::Null,
        TcpScanType::Fin,
        TcpScanType::Xmas,
        TcpScanType::IpProtocol,
    ]
    .iter()
    .map(|scan_type| RadioOption::Text(scan_type.to_string()))
    .collect::<Vec<RadioOption>>();

    options.push(RadioOption::Input(&mut app.tcp_scan_type_state.idle_input));
    options.push(RadioOption::Input(&mut app.tcp_scan_type_state.ftp_input));
    options.push(RadioOption::Input(
        &mut app.tcp_scan_type_state.scanflags_input,
    ));

    let mut tcp_scan_radios = RadioGroup::new(options)
        .with_num_per_row(3)
        .with_selected(
            app.scan
                .scan_technique
                .tcp
                .as_ref()
                .map(|scan_type| scan_type.as_index()),
        )
        .with_focused(match (app.focused_flag, app.focused_radio_index) {
            (NmapFlag::TcpScan, Some(index)) => Some(index),
            _ => None,
        })
        .with_editing(match app.tcp_scan_type_state.editing_scan_type {
            Some(TcpScanType::Idle(_)) => Some(9),
            Some(TcpScanType::Ftp(_)) => Some(10),
            Some(TcpScanType::Scanflags(_)) => Some(11),
            _ => None,
        });
    tcp_scan_radios.render(row_chunks[0], frame.buffer_mut());
}
