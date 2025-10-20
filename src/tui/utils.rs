use ratatui::{Frame, layout::Rect};
use std::collections::HashMap;
use strum::EnumMessage;

use crate::{
    scan::{
        flags::{FlagValue, NmapFlag},
        model::{NmapScan, TcpScanType},
    },
    tui::{
        app::App,
        widgets::{
            checkbox::Checkbox,
            text_input::{
                CompletingInput, FloatParser, InputWidget, IntParser, StringParser, TextInput,
                VecIntParser, VecStringParser,
            },
        },
    },
};

pub fn initialize_text_inputs(scan: &mut NmapScan, input_map: &mut HashMap<NmapFlag, InputWidget>) {
    // Int inputs
    for flag in [
        NmapFlag::RandomTargets,
        NmapFlag::VersionIntensity,
        NmapFlag::TopPorts,
    ]
    .iter()
    {
        let mut input = TextInput::new(IntParser)
            .with_label(flag.to_string())
            .with_placeholder(flag.get_message().unwrap());
        if let FlagValue::Int(Some(flag_value)) = flag.get_flag_value(scan) {
            input.set_typed_value(*flag_value);
        }
        input_map.insert(*flag, InputWidget::Int(input));
    }

    // Float input
    let flag = NmapFlag::PortRatio;
    let mut input = TextInput::new(FloatParser)
        .with_label(flag.to_string())
        .with_placeholder(flag.get_message().unwrap());
    if let FlagValue::Float(Some(flag_value)) = flag.get_flag_value(scan) {
        input.set_typed_value(*flag_value);
    }
    input_map.insert(flag, InputWidget::Float(input));

    // String inputs
    for flag in [NmapFlag::Ports, NmapFlag::ExcludePorts].iter() {
        let mut input = TextInput::new(StringParser)
            .with_label(flag.to_string())
            .with_placeholder(flag.get_message().unwrap());
        if let FlagValue::String(Some(flag_value)) = flag.get_flag_value(scan) {
            input.set_typed_value(flag_value.to_string());
        }
        input_map.insert(*flag, InputWidget::String(input));
    }

    // VecInt inputs
    for flag in [
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
        input_map.insert(*flag, InputWidget::VecInt(input));
    }

    // VecString inputs
    for flag in [NmapFlag::Targets, NmapFlag::Exclude, NmapFlag::DnsServers].iter() {
        let mut input = TextInput::new(VecStringParser)
            .with_label(flag.to_string())
            .with_placeholder(flag.get_message().unwrap());
        if let FlagValue::VecString(flag_value) = flag.get_flag_value(scan) {
            input.set_typed_value(flag_value.to_vec());
        }
        input_map.insert(*flag, InputWidget::VecString(input));
    }

    // Path inputs
    for flag in [NmapFlag::InputFile, NmapFlag::ExcludeFile].iter() {
        let mut input = CompletingInput::new()
            .with_label(flag.to_string())
            .with_placeholder(flag.get_message().unwrap());
        if let FlagValue::Path(Some(flag_value)) = flag.get_flag_value(scan) {
            input.set_typed_value(flag_value.to_path_buf());
        }
        input_map.insert(*flag, InputWidget::Path(input));
    }
}

pub fn render_checkbox(app: &mut App, flag: NmapFlag, frame: &mut Frame, area: Rect) {
    let FlagValue::Bool(flag_value) = flag.get_flag_value(app.scan) else {
        panic!()
    };
    let label = flag.to_string();
    let mut checkbox = Checkbox::new(label)
        .with_checked(*flag_value)
        .with_focused(app.focused_flag == flag);
    checkbox.render(area, frame.buffer_mut());
}

pub fn render_checkbox_with_input(app: &mut App, flag: NmapFlag, frame: &mut Frame, area: Rect) {
    let flag_value = flag.get_flag_value(app.scan);
    let checked = match flag_value {
        FlagValue::Int(value) => value.is_some(),
        FlagValue::String(value) => value.is_some(),
        FlagValue::Path(value) => value.is_some(),
        FlagValue::VecInt(value) => !value.is_empty(),
        FlagValue::VecString(value) => !value.is_empty(),
        _ => false,
    };
    let input = app.input_map.get_mut(&flag);
    let mut checkbox = Checkbox::new("")
        .with_checked(checked)
        .with_focused(app.focused_flag == flag)
        .with_input(input)
        .with_editing(app.editing_flag == Some(flag));
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
