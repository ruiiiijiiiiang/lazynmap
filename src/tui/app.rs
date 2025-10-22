use ratatui::{
    DefaultTerminal,
    crossterm::event::{self, Event, KeyCode},
    prelude::*,
    widgets::{
        Block, BorderType, Clear, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, Wrap,
    },
};
use std::{collections::HashMap, error::Error};
use strum::EnumMessage;

use crate::{
    consts::{self, IndexableEnum},
    scan::{
        builder::NmapCommandBuilder,
        flags::{FlagValue, NmapFlag},
        model::{NmapScan, NsockEngine, SctpScanType, TcpScanType, TimingTemplate},
    },
    tui::{
        sections::{
            evasion_spoof::render_evasion_spoof, host_discovery::render_host_discovery,
            miscellaneous::render_miscellaneous, nse_script::render_nse_script,
            os_detection::render_os_detection, output::render_output,
            port_specification::render_port_specification, scan_technique::render_scan_technique,
            service_detection::render_service_detection,
            target_specification::render_target_specification, timing::render_timing,
        },
        utils::{TcpScanTypeState, initialize_scan_type_state, initialize_text_inputs},
        widgets::text_input::{EventResult, InputValue, InputWidget},
    },
};

struct SectionData {
    name: &'static str,
    height: u16,
    render: fn(&mut App, &mut Frame, Rect),
    start: NmapFlag,
}

const SECTIONS: [SectionData; 11] = [
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
        render: render_evasion_spoof,
        start: NmapFlag::FragmentPackets,
    },
    SectionData {
        name: "Output",
        height: 13,
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

pub struct App<'a> {
    pub scan: &'a mut NmapScan,
    pub input_map: HashMap<NmapFlag, InputWidget>,
    pub focused_section: usize,
    pub focused_flag: NmapFlag,
    pub editing_flag: Option<NmapFlag>,
    pub focused_radio_index: Option<usize>,
    pub error: Option<String>,

    // Due to the fact that TCP scan types are valued enum variants, their inputs need to be set
    // up as special cases and tracked separately
    pub tcp_scan_type_state: TcpScanTypeState,

    scroll_state: ScrollbarState,
    scroll: u16,
    running: bool,
}

impl<'a> App<'a> {
    pub fn new(scan: &'a mut NmapScan) -> Self {
        let total_height: u16 = SECTIONS.iter().map(|section| section.height).sum();
        let mut input_map = HashMap::new();
        initialize_text_inputs(scan, &mut input_map);
        let tcp_scan_type_state = initialize_scan_type_state(scan);

        Self {
            scan,
            input_map,
            focused_section: 0,
            focused_flag: NmapFlag::first(),
            editing_flag: None,
            focused_radio_index: None,
            error: None,

            tcp_scan_type_state,

            scroll_state: ScrollbarState::new(total_height.into()),
            scroll: 0,
            running: true,
        }
    }

    pub fn start(self) -> Result<(), Box<dyn Error>> {
        color_eyre::install()?;
        let terminal = ratatui::init();

        let res = self.run(terminal);

        ratatui::restore();
        if let Err(err) = &res {
            println!("{err:?}");
        }
        res
    }

    fn run(mut self, mut terminal: DefaultTerminal) -> Result<(), Box<dyn Error>> {
        loop {
            terminal.draw(|frame| self.draw(frame))?;

            if let Ok(event) = event::read() {
                self.handle_event(event)?
            }
            if !self.running {
                return Ok(());
            }
        }
    }

    fn draw(&mut self, frame: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(15), Constraint::Length(3)])
            .split(frame.area());

        let top_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(30), Constraint::Min(0)])
            .split(chunks[0]);

        let left_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(0),
                Constraint::Length(9),
                Constraint::Length(7),
            ])
            .split(top_chunks[0]);

        let section_block = Block::bordered()
            .border_type(BorderType::Thick)
            .title(Line::from("Sections").centered());
        let section_list = SECTIONS
            .iter()
            .enumerate()
            .map(|(index, section)| {
                if index == self.focused_section {
                    Line::from(section.name).style(Style::default().fg(Color::Yellow))
                } else {
                    Line::from(section.name)
                }
            })
            .collect::<Vec<_>>();
        let section_paragraph = Paragraph::new(section_list).block(section_block);
        frame.render_widget(section_paragraph, left_chunks[0]);

        let detail_block = Block::bordered()
            .border_type(BorderType::Thick)
            .title(Line::from("Flag Details").centered());
        let detailed_message = if self.focused_flag.get_variant_count().is_some()
            && let Some(radio_index) = self.focused_radio_index
        {
            match self.focused_flag {
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
            self.focused_flag.get_detailed_message().unwrap()
        };
        let detail_content = Paragraph::new(detailed_message)
            .wrap(Wrap { trim: true })
            .block(detail_block);
        frame.render_widget(detail_content, left_chunks[1]);

        let navigation_block = Block::bordered()
            .border_type(BorderType::Thick)
            .title(Line::from("Keys").centered());
        let navigation_list = Paragraph::new(vec![
            Line::from("J / K : navigate sections"),
            Line::from("H / L : navigate flags"),
            Line::from("󱁐 : toggle flag"),
            Line::from("󰌑 : edit value"),
            Line::from("Q : quit"),
        ])
        .block(navigation_block);
        frame.render_widget(navigation_list, left_chunks[2]);

        let main_block = Block::bordered()
            .border_type(BorderType::Thick)
            .title(Line::from("Nmap Flags").centered());
        let main_area = main_block.inner(top_chunks[1]);
        frame.render_widget(main_block, top_chunks[1]);

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
            let terminal_y = flag_chunk.y as i16 - self.scroll as i16;
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

                let border_style = if index == self.focused_section {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default()
                };
                let flag_block = Block::bordered()
                    .title(section.name)
                    .border_type(BorderType::Rounded)
                    .border_style(border_style);
                Clear.render(visible_area, frame.buffer_mut());
                frame.render_widget(flag_block, visible_area);
                (section.render)(
                    self,
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
            top_chunks[1],
            &mut self.scroll_state,
        );

        if let Some(error) = &self.error {
            let footer_block = Block::bordered()
                .border_type(BorderType::Thick)
                .border_style(Style::default().red())
                .title(Line::from("Error").centered());
            let footer_content =
                Paragraph::new(Line::from(error.to_string()).style(Style::default().red()))
                    .centered()
                    .block(footer_block);
            frame.render_widget(footer_content, chunks[1]);
        } else {
            let footer_block = Block::bordered()
                .border_type(BorderType::Thick)
                .title(Line::from("Nmap Command").centered());
            let footer_content = Paragraph::new(NmapCommandBuilder::build(self.scan))
                .centered()
                .block(footer_block);
            frame.render_widget(footer_content, chunks[1]);
        }

        if let Some(flag) = self.editing_flag
            && let Some(input) = self.input_map.get(&flag)
        {
            input.render_dropdown_overlay(frame.buffer_mut());
        }
    }

    fn handle_event(&mut self, event: Event) -> Result<(), Box<dyn Error>> {
        let flag_value = self.focused_flag.get_flag_value(self.scan);
        if let Event::Key(key) = event {
            if self.editing_flag.is_some() {
                let input = self.input_map.get_mut(&self.focused_flag).unwrap();
                match input.handle_event(&event) {
                    EventResult::Submit(input_value) => {
                        match (input_value, flag_value) {
                            (InputValue::Int(input_value), FlagValue::Int(flag_value)) => {
                                *flag_value = Some(input_value);
                            }
                            (InputValue::Float(input_value), FlagValue::Float(flag_value)) => {
                                *flag_value = Some(input_value);
                            }
                            (InputValue::String(input_value), FlagValue::String(flag_value)) => {
                                *flag_value = Some(input_value);
                            }
                            (InputValue::VecInt(input_value), FlagValue::VecInt(flag_value)) => {
                                *flag_value = input_value;
                            }
                            (
                                InputValue::VecString(input_value),
                                FlagValue::VecString(flag_value),
                            ) => {
                                *flag_value = input_value;
                            }
                            (InputValue::Path(input_value), FlagValue::Path(flag_value)) => {
                                *flag_value = Some(input_value);
                            }
                            _ => {}
                        }
                        self.editing_flag = None;
                    }
                    EventResult::Cancel => {
                        match flag_value {
                            FlagValue::Int(flag_value) => *flag_value = None,
                            FlagValue::Float(flag_value) => *flag_value = None,
                            FlagValue::String(flag_value) => *flag_value = None,
                            FlagValue::VecInt(flag_value) => *flag_value = Vec::new(),
                            FlagValue::VecString(flag_value) => *flag_value = Vec::new(),
                            FlagValue::Path(flag_value) => *flag_value = None,
                            _ => {}
                        }
                        self.editing_flag = None;
                    }
                    EventResult::Consumed => self.error = input.error(),
                    _ => {}
                };
            } else if let Some(scan_type) = &self.tcp_scan_type_state.editing_scan_type {
                if matches!(
                    scan_type,
                    TcpScanType::Idle(_) | TcpScanType::Ftp(_) | TcpScanType::Scanflags(_)
                ) {
                    let input = match scan_type {
                        TcpScanType::Idle(_) => &mut self.tcp_scan_type_state.idle_input,
                        TcpScanType::Ftp(_) => &mut self.tcp_scan_type_state.ftp_input,
                        TcpScanType::Scanflags(_) => &mut self.tcp_scan_type_state.scanflags_input,
                        _ => unreachable!(),
                    };
                    match input.handle_event(&event) {
                        EventResult::Submit(InputValue::String(value)) => {
                            self.scan.scan_technique.tcp =
                                Some(scan_type.clone().with_value(value));
                            self.tcp_scan_type_state.editing_scan_type = None;
                        }
                        EventResult::Cancel => {
                            self.tcp_scan_type_state.editing_scan_type = None;
                        }
                        _ => {}
                    }
                }
            } else {
                match key.code {
                    KeyCode::Char('q') => {
                        self.running = false;
                    }
                    KeyCode::Char('j') | KeyCode::Down => {
                        self.scroll_down();
                    }
                    KeyCode::Char('k') | KeyCode::Up => {
                        self.scroll_up();
                    }
                    KeyCode::Char('l') | KeyCode::Right => {
                        match (
                            self.focused_radio_index,
                            self.focused_flag.get_variant_count(),
                        ) {
                            (Some(index), Some(count)) if index + 1 < count => {
                                self.focused_radio_index = Some(index + 1);
                            }
                            _ => {
                                self.focused_flag = self.focused_flag.next();
                                if self.focused_flag.get_variant_count().is_some() {
                                    self.focused_radio_index = Some(0);
                                } else {
                                    self.focused_radio_index = None;
                                }
                            }
                        }
                    }
                    KeyCode::Char('h') | KeyCode::Left => match self.focused_radio_index {
                        Some(index) if index > 0 => {
                            self.focused_radio_index = Some(index - 1);
                        }
                        _ => {
                            self.focused_flag = self.focused_flag.prev();
                            if let Some(count) = self.focused_flag.get_variant_count() {
                                self.focused_radio_index = Some(count.saturating_sub(1));
                            } else {
                                self.focused_radio_index = None;
                            }
                        }
                    },
                    KeyCode::Char(' ') => match flag_value {
                        FlagValue::Bool(flag_value) => *flag_value = !*flag_value,
                        FlagValue::TcpScanType(flag_value) => match self.focused_radio_index {
                            Some(radio_index) if radio_index <= 8 => {
                                *flag_value = TcpScanType::from_index(radio_index);
                            }
                            Some(consts::IDLE_SCAN_TYPE_INDEX) => {
                                let input_value = self.tcp_scan_type_state.idle_input.content();
                                let scan_type = Some(TcpScanType::Idle(input_value.to_string()));
                                *flag_value = scan_type.clone();
                                self.tcp_scan_type_state.editing_scan_type = scan_type;
                            }
                            Some(consts::FTP_SCAN_TYPE_INDEX) => {
                                let input_value = self.tcp_scan_type_state.ftp_input.content();
                                let scan_type = Some(TcpScanType::Ftp(input_value.to_string()));
                                *flag_value = scan_type.clone();
                                self.tcp_scan_type_state.editing_scan_type = scan_type;
                            }
                            Some(consts::SCANFLAGS_SCAN_TYPE_INDEX) => {
                                let input_value =
                                    self.tcp_scan_type_state.scanflags_input.content();
                                let scan_type =
                                    Some(TcpScanType::Scanflags(input_value.to_string()));
                                *flag_value = scan_type.clone();
                                self.tcp_scan_type_state.editing_scan_type = scan_type;
                            }
                            _ => (),
                        },
                        FlagValue::SctpScanType(flag_value) => {
                            *flag_value =
                                self.focused_radio_index.and_then(SctpScanType::from_index);
                        }
                        FlagValue::NsockEngine(flag_value) => {
                            *flag_value =
                                self.focused_radio_index.and_then(NsockEngine::from_index);
                        }
                        FlagValue::TimingTemplate(flag_value) => {
                            *flag_value = self
                                .focused_radio_index
                                .and_then(TimingTemplate::from_index);
                        }
                        FlagValue::Int(flag_value) => {
                            if flag_value.is_some() {
                                *flag_value = None
                            } else if let Some(input) = self.input_map.get_mut(&self.focused_flag)
                                && let Some(InputValue::Int(input_value)) = input.typed_value()
                            {
                                *flag_value = Some(input_value);
                            } else {
                                self.editing_flag = Some(self.focused_flag);
                            }
                        }
                        FlagValue::Float(flag_value) => {
                            if flag_value.is_some() {
                                *flag_value = None
                            } else if let Some(input) = self.input_map.get_mut(&self.focused_flag)
                                && let Some(InputValue::Float(input_value)) = input.typed_value()
                            {
                                *flag_value = Some(input_value);
                            } else {
                                self.editing_flag = Some(self.focused_flag);
                            }
                        }
                        FlagValue::String(flag_value) => {
                            if flag_value.is_some() {
                                *flag_value = None
                            } else if let Some(input) = self.input_map.get_mut(&self.focused_flag)
                                && let Some(InputValue::String(input_value)) = input.typed_value()
                            {
                                *flag_value = Some(input_value);
                            } else {
                                self.editing_flag = Some(self.focused_flag);
                            }
                        }
                        FlagValue::VecInt(flag_value) => {
                            if !flag_value.is_empty() {
                                *flag_value = Vec::new()
                            } else if let Some(input) = self.input_map.get_mut(&self.focused_flag)
                                && let Some(InputValue::VecInt(input_value)) = input.typed_value()
                            {
                                *flag_value = input_value;
                            } else {
                                self.editing_flag = Some(self.focused_flag);
                            }
                        }
                        FlagValue::VecString(flag_value) => {
                            if !flag_value.is_empty() {
                                *flag_value = Vec::new()
                            } else if let Some(input) = self.input_map.get_mut(&self.focused_flag)
                                && let Some(InputValue::VecString(input_value)) =
                                    input.typed_value()
                            {
                                *flag_value = input_value;
                            } else {
                                self.editing_flag = Some(self.focused_flag);
                            }
                        }
                        FlagValue::Path(flag_value) => {
                            if flag_value.is_some() {
                                *flag_value = None
                            } else if let Some(input) = self.input_map.get_mut(&self.focused_flag)
                                && let Some(InputValue::Path(input_value)) = input.typed_value()
                            {
                                *flag_value = Some(input_value);
                            } else {
                                self.editing_flag = Some(self.focused_flag);
                            }
                        }
                    },
                    KeyCode::Enter => match flag_value {
                        FlagValue::Int(_)
                        | FlagValue::Float(_)
                        | FlagValue::String(_)
                        | FlagValue::VecInt(_)
                        | FlagValue::VecString(_)
                        | FlagValue::Path(_) => self.editing_flag = Some(self.focused_flag),
                        _ => (),
                    },
                    _ => {}
                }
            }
        }
        Ok(())
    }

    fn scroll_up(&mut self) {
        self.focused_section = self.focused_section.saturating_sub(1);
        self.scroll = self
            .scroll
            .saturating_sub(SECTIONS[self.focused_section].height);
        self.scroll_state = self.scroll_state.position(self.scroll as usize);
        self.focused_flag = SECTIONS[self.focused_section].start;
        if self.focused_flag.get_variant_count().is_some() {
            self.focused_radio_index = Some(0);
        }
    }

    fn scroll_down(&mut self) {
        self.scroll = (self.scroll + SECTIONS[self.focused_section].height).min(
            SECTIONS
                .iter()
                .take(SECTIONS.len() - 1)
                .map(|section| section.height)
                .sum(),
        );
        self.scroll_state = self.scroll_state.position(self.scroll as usize);
        self.focused_section = (self.focused_section + 1).min(SECTIONS.len() - 1);
        self.focused_flag = SECTIONS[self.focused_section].start;
        if self.focused_flag.get_variant_count().is_some() {
            self.focused_radio_index = Some(0);
        }
    }
}
