use ratatui::{Frame, layout::Rect};
use std::collections::HashMap;
use strum::EnumMessage;

use crate::{
    scan::{
        flags::{FlagValue, NmapFlag},
        model::NmapScan,
    },
    tui::{
        app::App,
        widgets::{
            checkbox::Checkbox,
            text_input::{CompletingInput, InputWidget, IntParser, TextInput, VecStringParser},
        },
    },
};

pub fn initialize_text_inputs(scan: &mut NmapScan, input_map: &mut HashMap<NmapFlag, InputWidget>) {
    for flag in [NmapFlag::Targets, NmapFlag::Exclude].iter() {
        let mut input = TextInput::new(VecStringParser::new())
            .with_label(flag.to_string())
            .with_placeholder(flag.get_message().unwrap());
        if let FlagValue::VecString(flag_value) = flag.get_flag_value(scan) {
            input.set_typed_value(flag_value.to_vec());
        }
        input_map.insert(*flag, InputWidget::VecString(input));
    }

    for flag in [NmapFlag::InputFile, NmapFlag::ExcludeFile].iter() {
        let mut input = CompletingInput::new()
            .with_label(flag.to_string())
            .with_placeholder(flag.get_message().unwrap());
        if let FlagValue::Path(Some(flag_value)) = flag.get_flag_value(scan) {
            input.set_typed_value(flag_value.to_path_buf());
        }
        input_map.insert(*flag, InputWidget::Path(input));
    }

    for flag in [NmapFlag::RandomTargets].iter() {
        let mut input = TextInput::new(IntParser)
            .with_label(flag.to_string())
            .with_placeholder(flag.get_message().unwrap());
        if let FlagValue::U32(Some(flag_value)) = flag.get_flag_value(scan) {
            input.set_typed_value(*flag_value as i64);
        }
        input_map.insert(*flag, InputWidget::Int(input));
    }
}

pub fn render_checkbox(app: &mut App, flag: NmapFlag, frame: &mut Frame, area: Rect) {
    let FlagValue::Bool(flag_value) = flag.get_flag_value(app.scan) else {
        panic!()
    };
    let label = flag.to_string();
    let checkbox = Checkbox::new(label)
        .with_checked(*flag_value)
        .with_focused(app.focused_flag == flag);
    checkbox.render(area, frame.buffer_mut());
}
