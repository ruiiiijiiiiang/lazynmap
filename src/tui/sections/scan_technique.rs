use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Margin, Rect},
    widgets::Block,
};
use strum::IntoEnumIterator;

use crate::{
    consts::{self, IndexableEnum},
    scan::{
        flags::NmapFlag,
        model::{SctpScanType, TcpScanType},
    },
    tui::{
        app::App,
        utils::render_checkbox,
        widgets::radio::{RadioGroup, RadioOption},
    },
};

pub fn render_scan_technique(app: &mut App, frame: &mut Frame, area: Rect) {
    let row_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(7), Constraint::Length(3)])
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
        .with_num_per_row(4)
        .with_selected(
            app.scan
                .scan_technique
                .tcp
                .as_ref()
                .map(|scan_type| scan_type.as_index()),
        )
        .with_focused(match (app.focused_flag, app.focused_radio_index) {
            (NmapFlag::TcpScanType, Some(index)) => Some(index),
            _ => None,
        })
        .with_marked(
            TcpScanType::iter()
                .enumerate()
                .filter_map(|(index, scan_type)| {
                    if scan_type.requires_admin() {
                        Some(index)
                    } else {
                        None
                    }
                })
                .collect(),
        )
        .with_editing(match app.tcp_scan_type_state.editing_scan_type {
            Some(TcpScanType::Idle(_)) => Some(consts::IDLE_SCAN_TYPE_INDEX),
            Some(TcpScanType::Ftp(_)) => Some(consts::FTP_SCAN_TYPE_INDEX),
            Some(TcpScanType::Scanflags(_)) => Some(consts::SCANFLAGS_SCAN_TYPE_INDEX),
            _ => None,
        });
    let tcp_block = Block::bordered().title("TCP scan type");
    frame.render_widget(tcp_block, row_chunks[0]);
    tcp_scan_radios.render(
        row_chunks[0].inner(Margin {
            vertical: 1,
            horizontal: 1,
        }),
        frame.buffer_mut(),
    );

    let column_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(33), Constraint::Percentage(67)])
        .spacing(1)
        .split(row_chunks[1]);
    let udp_block = Block::bordered().title("UDP scan");
    frame.render_widget(udp_block, column_chunks[0]);
    render_checkbox(
        app,
        NmapFlag::UdpScan,
        frame,
        column_chunks[0].inner(Margin {
            vertical: 1,
            horizontal: 1,
        }),
    );

    let sctp_block = Block::bordered().title("SCTP scan type");
    frame.render_widget(sctp_block, column_chunks[1]);
    let mut sctp_radios = RadioGroup::new(
        SctpScanType::all_labels()
            .iter()
            .map(|scan_type| RadioOption::Text(scan_type.to_string()))
            .collect(),
    )
    .with_selected(
        app.scan
            .scan_technique
            .sctp
            .map(|scan_type| scan_type.as_index()),
    )
    .with_focused(match (app.focused_flag, app.focused_radio_index) {
        (NmapFlag::SctpScanType, Some(index)) => Some(index),
        _ => None,
    });
    sctp_radios.render(
        column_chunks[1].inner(Margin {
            vertical: 1,
            horizontal: 1,
        }),
        frame.buffer_mut(),
    );
}
