use ratatui::{
    Frame,
    layout::{Constraint, Direction, Flex, Layout, Rect},
    prelude::*,
    style::Style,
    text::{Line, Span},
    widgets::{Block, BorderType, Clear, Paragraph, Scrollbar, ScrollbarOrientation, Wrap},
};
use std::{collections::HashMap, rc::Rc};
use strum::EnumMessage;

use crate::{
    consts::IndexableEnum,
    scan::{
        builder::NmapCommandBuilder,
        flags::{ADMIN_FLAGS, FlagValue, NmapFlag},
        model::{NmapScan, NsockEngine, SctpScanType, TcpScanType, TimingTemplate},
    },
    tui::{
        app::App,
        sections::{
            evasion_spoofing::render_evasion_spoofing, host_discovery::render_host_discovery,
            miscellaneous::render_miscellaneous, nse_script::render_nse_script,
            os_detection::render_os_detection, output::render_output,
            port_specification::render_port_specification, scan_technique::render_scan_technique,
            service_detection::render_service_detection,
            target_specification::render_target_specification, timing::render_timing,
        },
        widgets::{
            checkbox::Checkbox,
            text_input::{
                CompletingInput, FloatParser, InputWidget, IntParser, StringParser, TextInput,
                VecIntParser, VecStringParser,
            },
        },
    },
};

pub struct SectionData {
    pub name: &'static str,
    pub height: u16,
    pub render: fn(&mut App, &mut Frame, Rect),
    pub start: NmapFlag,
}

pub const SECTIONS: [SectionData; 11] = [
    SectionData {
        name: "Target Specification",
        height: 11,
        render: render_target_specification,
        start: NmapFlag::Targets,
    },
    SectionData {
        name: "Host Discovery",
        height: 9,
        render: render_host_discovery,
        start: NmapFlag::ListScan,
    },
    SectionData {
        name: "Scan Technique",
        height: 12,
        render: render_scan_technique,
        start: NmapFlag::TcpScanType,
    },
    SectionData {
        name: "Port Specification",
        height: 5,
        render: render_port_specification,
        start: NmapFlag::Ports,
    },
    SectionData {
        name: "Service Detection",
        height: 5,
        render: render_service_detection,
        start: NmapFlag::VersionDetection,
    },
    SectionData {
        name: "OS Detection",
        height: 3,
        render: render_os_detection,
        start: NmapFlag::OsDetection,
    },
    SectionData {
        name: "NSE Script",
        height: 7,
        render: render_nse_script,
        start: NmapFlag::DefaultScript,
    },
    SectionData {
        name: "Timing",
        height: 17,
        render: render_timing,
        start: NmapFlag::MinHostgroup,
    },
    SectionData {
        name: "Evasion and Spoofing",
        height: 9,
        render: render_evasion_spoofing,
        start: NmapFlag::FragmentPackets,
    },
    SectionData {
        name: "Output",
        height: 11,
        render: render_output,
        start: NmapFlag::Normal,
    },
    SectionData {
        name: "Miscellaneous",
        height: 9,
        render: render_miscellaneous,
        start: NmapFlag::IpV6,
    },
];

pub fn initialize_text_inputs(scan: &mut NmapScan, input_map: &mut HashMap<NmapFlag, InputWidget>) {
    // Int inputs
    for &flag in [
        NmapFlag::RandomTargets,
        NmapFlag::VersionIntensity,
        NmapFlag::TopPorts,
        NmapFlag::MaxOsRetries,
        NmapFlag::MinHostgroup,
        NmapFlag::MaxHostgroup,
        NmapFlag::MinParallelism,
        NmapFlag::MaxParallelism,
        NmapFlag::MaxRetries,
        NmapFlag::Mtu,
        NmapFlag::SourcePort,
        NmapFlag::DataLength,
        NmapFlag::Ttl,
        NmapFlag::Verbosity,
        NmapFlag::Debugging,
    ]
    .iter()
    {
        let mut input = TextInput::new(IntParser)
            .with_label(flag.to_string())
            .with_placeholder(flag.get_message().unwrap());
        if let FlagValue::Int(Some(flag_value)) = flag.get_flag_value(scan) {
            input.set_typed_value(*flag_value);
        }
        input_map.insert(flag, InputWidget::Int(input));
    }

    // Float inputs
    for &flag in [NmapFlag::PortRatio, NmapFlag::MinRate, NmapFlag::MaxRate].iter() {
        let mut input = TextInput::new(FloatParser)
            .with_label(flag.to_string())
            .with_placeholder(flag.get_message().unwrap());
        if let FlagValue::Float(Some(flag_value)) = flag.get_flag_value(scan) {
            input.set_typed_value(*flag_value);
        }
        input_map.insert(flag, InputWidget::Float(input));
    }

    // String inputs
    for &flag in [
        NmapFlag::Ports,
        NmapFlag::ExcludePorts,
        NmapFlag::ScriptArgs,
        NmapFlag::ScriptHelp,
        NmapFlag::MinRttTimeout,
        NmapFlag::MaxRttTimeout,
        NmapFlag::InitialRttTimeout,
        NmapFlag::HostTimeout,
        NmapFlag::ScriptTimeout,
        NmapFlag::ScanDelay,
        NmapFlag::MaxScanDelay,
        NmapFlag::SpoofIp,
        NmapFlag::SpoofMac,
        NmapFlag::Interface,
        NmapFlag::Data,
        NmapFlag::DataString,
        NmapFlag::IpOptions,
        NmapFlag::StatsEvery,
    ]
    .iter()
    {
        let mut input = TextInput::new(StringParser)
            .with_label(flag.to_string())
            .with_placeholder(flag.get_message().unwrap());
        if let FlagValue::String(Some(flag_value)) = flag.get_flag_value(scan) {
            input.set_typed_value(flag_value.to_string());
        }
        input_map.insert(flag, InputWidget::String(input));
    }

    // VecInt inputs
    for &flag in [
        NmapFlag::SynDiscovery,
        NmapFlag::AckDiscovery,
        NmapFlag::UdpDiscovery,
        NmapFlag::SctpDiscovery,
        NmapFlag::IpProtocolPing,
    ]
    .iter()
    {
        let mut input = TextInput::new(VecIntParser)
            .with_label(flag.to_string())
            .with_placeholder(flag.get_message().unwrap());
        if let FlagValue::VecInt(flag_value) = flag.get_flag_value(scan) {
            input.set_typed_value(flag_value.to_vec());
        }
        input_map.insert(flag, InputWidget::VecInt(input));
    }

    // VecString inputs
    for &flag in [
        NmapFlag::Targets,
        NmapFlag::Exclude,
        NmapFlag::DnsServers,
        NmapFlag::Script,
        NmapFlag::Decoys,
        NmapFlag::Proxies,
    ]
    .iter()
    {
        let mut input = TextInput::new(VecStringParser)
            .with_label(flag.to_string())
            .with_placeholder(flag.get_message().unwrap());
        if let FlagValue::VecString(flag_value) = flag.get_flag_value(scan) {
            input.set_typed_value(flag_value.to_vec());
        }
        input_map.insert(flag, InputWidget::VecString(input));
    }

    // Path inputs
    for &flag in [
        NmapFlag::InputFile,
        NmapFlag::ExcludeFile,
        NmapFlag::ScriptArgsFile,
        NmapFlag::Normal,
        NmapFlag::Xml,
        NmapFlag::Grepable,
        NmapFlag::AllFormats,
        NmapFlag::Resume,
        NmapFlag::Stylesheet,
        NmapFlag::ScriptKiddie,
        NmapFlag::DataDir,
        NmapFlag::ServiceDb,
        NmapFlag::VersionDb,
    ]
    .iter()
    {
        let mut input = CompletingInput::new()
            .with_label(flag.to_string())
            .with_placeholder(flag.get_message().unwrap());
        if let FlagValue::Path(Some(flag_value)) = flag.get_flag_value(scan) {
            input.set_typed_value(flag_value.to_path_buf());
        }
        input_map.insert(flag, InputWidget::Path(input));
    }
}

pub fn render_checkbox(app: &mut App, flag: NmapFlag, frame: &mut Frame, area: Rect) {
    let flag_value = flag.get_flag_value(app.scan);

    let (label, checked, input) = match flag_value {
        FlagValue::Bool(value) => (flag.to_string(), *value, None),
        FlagValue::Float(value) => (
            "".to_string(),
            value.is_some(),
            app.input_map.get_mut(&flag),
        ),
        FlagValue::Int(value) => (
            "".to_string(),
            value.is_some(),
            app.input_map.get_mut(&flag),
        ),
        FlagValue::String(value) => (
            "".to_string(),
            value.is_some(),
            app.input_map.get_mut(&flag),
        ),
        FlagValue::Path(value) => (
            "".to_string(),
            value.is_some(),
            app.input_map.get_mut(&flag),
        ),
        FlagValue::VecInt(value) => (
            "".to_string(),
            !value.is_empty(),
            app.input_map.get_mut(&flag),
        ),
        FlagValue::VecString(value) => (
            "".to_string(),
            !value.is_empty(),
            app.input_map.get_mut(&flag),
        ),
        _ => ("".to_string(), false, None),
    };

    let mut checkbox = Checkbox::new(label)
        .with_checked(checked)
        .with_focused(app.focused_flag == flag)
        .with_marked(flag.requires_admin());

    if let Some(input) = input {
        checkbox = checkbox
            .with_input(Some(input))
            .with_editing(app.editing_flag == Some(flag));
    }

    checkbox.render(area, frame.buffer_mut());
}

pub struct TcpScanTypeState {
    pub idle_input: InputWidget,
    pub ftp_input: InputWidget,
    pub scanflags_input: InputWidget,
    pub editing_scan_type: Option<TcpScanType>,
}

pub fn initialize_scan_type_state(scan: &NmapScan) -> TcpScanTypeState {
    let idle_input = initialize_scan_type_input(scan, TcpScanType::Idle(String::new()));
    let ftp_input = initialize_scan_type_input(scan, TcpScanType::Ftp(String::new()));
    let scanflags_input = initialize_scan_type_input(scan, TcpScanType::Scanflags(String::new()));

    TcpScanTypeState {
        idle_input,
        ftp_input,
        scanflags_input,
        editing_scan_type: None,
    }
}

pub fn initialize_scan_type_input(scan: &NmapScan, scan_type: TcpScanType) -> InputWidget {
    let mut input = TextInput::new(StringParser)
        .with_label(scan_type.to_string())
        .with_placeholder(scan_type.get_message().unwrap());

    if let Some(ref existing_scan_type) = scan.scan_technique.tcp {
        let value_to_set = match (&scan_type, existing_scan_type) {
            (TcpScanType::Scanflags(_), TcpScanType::Scanflags(val)) => Some(val),
            (TcpScanType::Idle(_), TcpScanType::Idle(val)) => Some(val),
            (TcpScanType::Ftp(_), TcpScanType::Ftp(val)) => Some(val),
            _ => None,
        };

        if let Some(value) = value_to_set {
            input.set_typed_value(value.clone());
        }
    }

    InputWidget::String(input)
}

pub fn render_sections(app: &mut App, frame: &mut Frame, area: Rect) {
    let section_block = Block::bordered()
        .border_type(BorderType::Thick)
        .title(Line::from("Sections").centered());
    let section_list = SECTIONS
        .iter()
        .enumerate()
        .map(|(index, section)| {
            if index == app.focused_section {
                Line::from(section.name).style(Style::default().fg(Color::Yellow))
            } else {
                Line::from(section.name)
            }
        })
        .collect::<Vec<_>>();
    let section_paragraph = Paragraph::new(section_list).block(section_block);
    frame.render_widget(section_paragraph, area);
}

pub fn render_details(app: &mut App, frame: &mut Frame, area: Rect) {
    let detail_block = Block::bordered()
        .border_type(BorderType::Thick)
        .title(Line::from("Flag Details").centered());
    let detailed_message = if app.focused_flag.get_variant_count().is_some()
        && let Some(radio_index) = app.focused_radio_index
    {
        match app.focused_flag {
            NmapFlag::TcpScanType => TcpScanType::from_index(radio_index)
                .unwrap()
                .get_detailed_message()
                .unwrap(),
            NmapFlag::SctpScanType => SctpScanType::from_index(radio_index)
                .unwrap()
                .get_detailed_message()
                .unwrap(),
            NmapFlag::NsockEngine => NsockEngine::from_index(radio_index)
                .unwrap()
                .get_detailed_message()
                .unwrap(),
            NmapFlag::TimingTemplate => TimingTemplate::from_index(radio_index)
                .unwrap()
                .get_detailed_message()
                .unwrap(),
            _ => "",
        }
    } else {
        app.focused_flag.get_detailed_message().unwrap()
    };
    let detail_content = Paragraph::new(detailed_message)
        .wrap(Wrap { trim: true })
        .block(detail_block);
    frame.render_widget(detail_content, area);
}

pub fn render_help(app: &mut App, frame: &mut Frame, area: Rect) {
    let help_block = Block::bordered()
        .border_type(BorderType::Thick)
        .title(Line::from("Help").centered());
    let mut help_lines = vec![Line::from("* : requires sudo").red()];
    if let Some(flag) = app.editing_flag
        && let Some(input) = app.input_map.get(&flag)
    {
        if let InputWidget::Path(_) = input {
            help_lines.extend(vec![
                Line::from(" : next selection"),
                Line::from(" : previous selection"),
                Line::from(" : parent directory"),
                Line::from(" : enter directory"),
            ]);
        }
        help_lines.extend(vec![
            Line::from("ctrl+shift+v : paste"),
            Line::from("󰌑 : confirm"),
            Line::from("󱊷 : cancel"),
        ]);
    } else {
        help_lines.extend(vec![
            Line::from("J/ : next section"),
            Line::from("K/ : previous section"),
            Line::from("L/ : next flag"),
            Line::from("H/ : previous flag"),
            Line::from("󱁐 : toggle flag"),
            Line::from("C : clear flag"),
        ]);
        if app.input_map.contains_key(&app.focused_flag) {
            help_lines.extend(vec![Line::from("󰌑 : edit value")]);
        }
        help_lines.extend(vec![Line::from("Q : quit"), Line::from("X : execute nmap")]);
    }
    let help_list = Paragraph::new(help_lines).block(help_block);
    frame.render_widget(help_list, area);
}

pub fn render_main(app: &mut App, frame: &mut Frame, area: Rect) {
    let main_block = Block::bordered()
        .border_type(BorderType::Thick)
        .title(Line::from("Nmap Flags").centered());
    let main_area = main_block.inner(area);
    frame.render_widget(main_block, area);

    let right_chunks =
        Layout::horizontal([Constraint::Min(0), Constraint::Length(1)]).split(main_area);

    let content_area = Rect {
        x: right_chunks[0].x,
        y: right_chunks[0].y,
        width: right_chunks[0].width,
        height: SECTIONS.iter().map(|section| section.height).sum(),
    };

    let flag_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            SECTIONS
                .iter()
                .map(|section| Constraint::Length(section.height)),
        )
        .split(content_area);

    for (index, (&flag_chunk, section)) in flag_chunks.iter().zip(SECTIONS.iter()).enumerate() {
        let terminal_y = flag_chunk.y as i16 - app.scroll as i16;
        if terminal_y + flag_chunk.height as i16 > right_chunks[0].y as i16
            && terminal_y < (right_chunks[0].y + right_chunks[0].height) as i16
        {
            let terminal_rect = Rect {
                x: right_chunks[0].x,
                y: terminal_y.max(right_chunks[0].y as i16) as u16,
                width: right_chunks[0].width,
                height: flag_chunk.height,
            };
            let visible_area = terminal_rect.intersection(right_chunks[0]);

            let border_style = if index == app.focused_section {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default()
            };
            let flag_block = Block::bordered()
                .title(section.name)
                .border_type(BorderType::Double)
                .border_style(border_style);
            Clear.render(visible_area, frame.buffer_mut());
            frame.render_widget(flag_block, visible_area);
            (section.render)(
                app,
                frame,
                visible_area.inner(Margin {
                    vertical: 1,
                    horizontal: 1,
                }),
            );
        }
    }

    frame.render_stateful_widget(
        Scrollbar::new(ScrollbarOrientation::VerticalRight),
        area,
        &mut app.scroll_state,
    );
}

pub fn render_footer(app: &mut App, frame: &mut Frame, area: Rect) {
    if let Some(error) = &app.error {
        let footer_block = Block::bordered()
            .border_type(BorderType::Thick)
            .border_style(Style::default().red())
            .title(Line::from("Error").centered());
        let footer_content = Paragraph::new(Line::from(error.to_string()).red())
            .centered()
            .block(footer_block);
        frame.render_widget(footer_content, area);
    } else {
        let footer_block = Block::bordered()
            .border_type(BorderType::Thick)
            .title(Line::from("Nmap Command").centered());
        let mut footer_spans = vec![Span::from(NmapCommandBuilder::build(app.scan))];
        if app.requires_admin {
            footer_spans.insert(0, Span::from("sudo ").red());
        }
        let footer_content = Paragraph::new(Line::from(footer_spans))
            .centered()
            .block(footer_block);
        frame.render_widget(footer_content, area);
    }
}

pub fn clamp_length_constraints(desired: &[u16], area: Rect) -> Vec<Constraint> {
    let mut remaining = area.height;
    let mut out = Vec::with_capacity(desired.len());
    for &d in desired {
        if remaining == 0 {
            out.push(Constraint::Length(0));
            continue;
        }
        let take = std::cmp::min(d, remaining);
        out.push(Constraint::Length(take));
        remaining = remaining.saturating_sub(take);
    }
    out
}

pub fn clamped_even_vertical_split(
    area: Rect,
    num_split: u16,
    height: u16,
    spacing: u16,
) -> Vec<Rect> {
    if num_split == 0 {
        return Vec::new();
    }

    let slot = height.saturating_add(spacing);
    let max_rows = if slot == 0 {
        num_split
    } else {
        (((area.height as u32) + spacing as u32) / slot as u32) as u16
    };

    let rows_to_make = std::cmp::min(num_split, max_rows);
    if rows_to_make == 0 {
        return Vec::new();
    }
    let constraints = vec![Constraint::Length(height); rows_to_make as usize];
    Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .spacing(spacing)
        .split(area)
        .to_vec()
}

pub fn render_flags_in_clamped_grid(
    app: &mut App,
    frame: &mut Frame,
    area: Rect,
    flags_grid: Vec<Vec<NmapFlag>>,
) {
    let row_chunks = clamped_even_vertical_split(area, flags_grid.len() as u16, 1, 1);

    for (&row_area, flags) in row_chunks.iter().zip(flags_grid.iter()) {
        let cols = even_horizontal_split(row_area, flags.len() as u16);

        for (&flag, &col_area) in flags.iter().zip(cols.iter()) {
            render_checkbox(app, flag, frame, col_area);
        }
    }
}

pub fn even_horizontal_split(area: Rect, num_split: u16) -> Rc<[Rect]> {
    if num_split == 1 {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(vec![Constraint::Percentage(50), Constraint::Percentage(50)])
            .spacing(0)
            .split(area);
        return Rc::new([chunks[0]]);
    }
    let percentage = 100 / num_split;
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints(vec![Constraint::Percentage(percentage); num_split as usize])
        .flex(Flex::SpaceBetween)
        .spacing(1)
        .split(area)
}

pub fn even_vertical_split(area: Rect, num_split: u16) -> Rc<[Rect]> {
    Layout::default()
        .direction(Direction::Vertical)
        .constraints(vec![Constraint::Length(1); num_split as usize])
        .spacing(1)
        .split(area)
}

pub fn requires_admin(scan: &mut NmapScan) -> bool {
    ADMIN_FLAGS.iter().any(|flag| {
        let flag_value = flag.get_flag_value(scan);
        match flag_value {
            FlagValue::Bool(flag_value) => *flag_value,
            FlagValue::String(flag_value) => flag_value.is_some(),
            FlagValue::VecInt(flag_value) => !flag_value.is_empty(),
            FlagValue::TcpScanType(flag_value) => {
                matches!(flag_value, Some(flag_value) if flag_value.requires_admin())
            }
            FlagValue::SctpScanType(flag_value) => flag_value.is_some(),
            _ => false,
        }
    })
}
