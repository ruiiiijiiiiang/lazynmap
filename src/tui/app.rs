use ratatui::{
    DefaultTerminal,
    crossterm::event::{self, Event, KeyCode},
    prelude::*,
    widgets::ScrollbarState,
};
use std::{collections::HashMap, error::Error};

use crate::{
    consts::{self, IndexableEnum},
    scan::{
        flags::{FlagValue, NmapFlag},
        model::{NmapScan, NsockEngine, SctpScanType, TcpScanType, TimingTemplate},
    },
    tui::{
        utils::{
            SECTIONS, TcpScanTypeState, initialize_scan_type_state, initialize_text_inputs,
            render_details, render_footer, render_help, render_main, render_sections,
            requires_admin,
        },
        widgets::text_input::{EventResult, InputValue, InputWidget},
    },
};

pub struct AppResult {
    pub execute: bool,
    pub requires_admin: bool,
}

pub struct App<'a> {
    pub scan: &'a mut NmapScan,
    pub input_map: HashMap<NmapFlag, InputWidget>,
    pub focused_section: usize,
    pub focused_flag: NmapFlag,
    pub editing_flag: Option<NmapFlag>,
    pub focused_radio_index: Option<usize>,
    pub error: Option<String>,
    pub scroll_state: ScrollbarState,
    pub scroll: u16,
    pub running: bool,
    pub execute: bool,
    pub requires_admin: bool,

    // Due to the fact that TCP scan types are valued enum variants, their inputs need to be set
    // up as special cases and tracked separately
    pub tcp_scan_type_state: TcpScanTypeState,
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
            scroll_state: ScrollbarState::new(total_height.into()),
            scroll: 0,
            running: true,
            execute: false,
            requires_admin: false,
            tcp_scan_type_state,
        }
    }

    pub fn start(&mut self) -> Result<AppResult, Box<dyn Error>> {
        color_eyre::install()?;
        let terminal = ratatui::init();

        let res = self.run(terminal);

        ratatui::restore();
        if let Err(err) = &res {
            println!("{err:?}");
        }
        Result::Ok(AppResult {
            execute: self.execute,
            requires_admin: self.requires_admin,
        })
    }

    fn run(&mut self, mut terminal: DefaultTerminal) -> Result<(), Box<dyn Error>> {
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
                Constraint::Length(13),
            ])
            .split(top_chunks[0]);

        render_sections(self, frame, left_chunks[0]);

        render_details(self, frame, left_chunks[1]);

        render_help(self, frame, left_chunks[2]);

        render_main(self, frame, top_chunks[1]);

        render_footer(self, frame, chunks[1]);

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
                    KeyCode::Char('j') | KeyCode::Down => self.next_section(),
                    KeyCode::Char('k') | KeyCode::Up => self.prev_section(),
                    KeyCode::Char('l') | KeyCode::Right => self.next_flag(),
                    KeyCode::Char('h') | KeyCode::Left => self.prev_flag(),
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
                                && !input_value.is_empty()
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
                                && !input_value.is_empty()
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
                    KeyCode::Char('c') => match flag_value {
                        FlagValue::Bool(flag_value) => *flag_value = false,
                        FlagValue::TcpScanType(flag_value) => *flag_value = None,
                        FlagValue::SctpScanType(flag_value) => *flag_value = None,
                        FlagValue::TimingTemplate(flag_value) => *flag_value = None,
                        FlagValue::NsockEngine(flag_value) => *flag_value = None,
                        FlagValue::Int(flag_value) => *flag_value = None,
                        FlagValue::Float(flag_value) => *flag_value = None,
                        FlagValue::String(flag_value) => *flag_value = None,
                        FlagValue::VecInt(flag_value) => *flag_value = Vec::new(),
                        FlagValue::VecString(flag_value) => *flag_value = Vec::new(),
                        FlagValue::Path(flag_value) => *flag_value = None,
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
                    KeyCode::Char('x') => {
                        self.execute = true;
                        self.running = false;
                    }
                    _ => {}
                }
            }
        }
        self.requires_admin = requires_admin(self.scan);
        Ok(())
    }

    fn prev_section(&mut self) {
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

    fn next_section(&mut self) {
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

    fn prev_flag(&mut self) {
        match self.focused_radio_index {
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
                if self.focused_flag.as_index() < SECTIONS[self.focused_section].start.as_index() {
                    self.prev_section();
                }
            }
        }
    }

    fn next_flag(&mut self) {
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
                if self.focused_flag.as_index()
                    == SECTIONS[(self.focused_section + 1).min(SECTIONS.len() - 1)]
                        .start
                        .as_index()
                {
                    self.next_section();
                }
            }
        }
    }
}
