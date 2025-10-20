use ratatui::{
    DefaultTerminal,
    crossterm::event::{self, Event, KeyCode},
    prelude::*,
    widgets::{
        Block, BorderType, Clear, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState,
    },
};
use std::{collections::HashMap, error::Error};

use crate::{
    consts::{self, IndexableEnum},
    scan::{
        builder::NmapCommandBuilder,
        flags::{FlagValue, NmapFlag},
        model::{NmapScan, SctpScanType, TcpScanType, TimingTemplate},
    },
    tui::{
        sections::{
            host_discovery::render_host_discovery, port_specification::render_port_specification,
            scan_technique::render_scan_technique, service_detection::render_service_detection,
            target_specification::render_target_specification,
        },
        utils::{TcpScanTypeState, initialize_scan_type_state, initialize_text_inputs},
        widgets::text_input::{EventResult, InputValue, InputWidget},
    },
};

const SECTIONS: [(&str, u16); 10] = [
    ("Target Specification", 11),
    ("Host Discovery", 9),
    ("Scan Technique", 14),
    ("Port Specification", 5),
    ("Service Detection", 5),
    ("OS Detection", 10),
    ("Timing", 10),
    ("Evasion and Spoofing", 10),
    ("Output", 10),
    ("Miscellaneous", 10),
];

pub struct App<'a> {
    pub scan: &'a mut NmapScan,
    pub input_map: HashMap<NmapFlag, InputWidget>,
    pub focused_section: usize,
    pub focused_flag: NmapFlag,
    pub editing_flag: Option<NmapFlag>,
    pub focused_radio_index: Option<usize>,

    pub tcp_scan_type_state: TcpScanTypeState,

    scroll_state: ScrollbarState,
    scroll: u16,
    running: bool,
}

impl<'a> App<'a> {
    pub fn new(scan: &'a mut NmapScan) -> Self {
        let total_height: u16 = SECTIONS.iter().map(|(_, height)| height).sum();
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
            .constraints([Constraint::Length(25), Constraint::Min(0)])
            .split(chunks[0]);

        let left_block = Block::bordered()
            .border_type(BorderType::Thick)
            .title("Sections");
        let sections = SECTIONS
            .iter()
            .enumerate()
            .map(|(index, (title, _))| {
                if index == self.focused_section {
                    Line::from(*title).style(Style::default().fg(Color::Yellow))
                } else {
                    Line::from(*title)
                }
            })
            .collect::<Vec<_>>();
        let section_paragraph = Paragraph::new(sections).block(left_block);
        frame.render_widget(section_paragraph, top_chunks[0]);

        let right_block = Block::bordered()
            .border_type(BorderType::Thick)
            .title("Options");
        let right_area = right_block.inner(top_chunks[1]);
        frame.render_widget(right_block, top_chunks[1]);

        let right_chunks =
            Layout::horizontal([Constraint::Min(0), Constraint::Length(1)]).split(right_area);

        let content_area = Rect {
            x: right_chunks[0].x,
            y: right_chunks[0].y,
            width: right_chunks[0].width,
            height: SECTIONS.iter().map(|(_, height)| height).sum(),
        };

        let flag_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(
                SECTIONS
                    .iter()
                    .map(|(_, height)| Constraint::Length(*height)),
            )
            .split(content_area);

        for (index, flag_chunk) in flag_chunks.iter().enumerate() {
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
                    .title(SECTIONS[index].0)
                    .border_type(BorderType::Rounded)
                    .border_style(border_style);
                Clear.render(visible_area, frame.buffer_mut());
                frame.render_widget(flag_block, visible_area);
                match index {
                    0 => render_target_specification(
                        self,
                        frame,
                        visible_area.inner(Margin {
                            vertical: 1,
                            horizontal: 1,
                        }),
                    ),
                    1 => render_host_discovery(
                        self,
                        frame,
                        visible_area.inner(Margin {
                            vertical: 1,
                            horizontal: 1,
                        }),
                    ),
                    2 => render_scan_technique(
                        self,
                        frame,
                        visible_area.inner(Margin {
                            vertical: 1,
                            horizontal: 1,
                        }),
                    ),
                    3 => render_port_specification(
                        self,
                        frame,
                        visible_area.inner(Margin {
                            vertical: 1,
                            horizontal: 1,
                        }),
                    ),
                    4 => render_service_detection(
                        self,
                        frame,
                        visible_area.inner(Margin {
                            vertical: 1,
                            horizontal: 1,
                        }),
                    ),
                    _ => (),
                }
            }
        }

        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight),
            top_chunks[1],
            &mut self.scroll_state,
        );

        let footer_block = Block::bordered().title(Line::from("Nmap command").centered());
        let nmap_command = Paragraph::new(NmapCommandBuilder::build(self.scan))
            .centered()
            .block(footer_block);
        frame.render_widget(nmap_command, chunks[1]);

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
                match self
                    .input_map
                    .get_mut(&self.focused_flag)
                    .unwrap()
                    .handle_event(&event)
                {
                    EventResult::Submit(value) => {
                        match (value, flag_value) {
                            (InputValue::Int(value), FlagValue::Int(flag_value)) => {
                                *flag_value = Some(value);
                            }
                            (InputValue::VecInt(value), FlagValue::VecInt(flag_value)) => {
                                *flag_value = value;
                            }
                            (InputValue::VecString(value), FlagValue::VecString(flag_value)) => {
                                *flag_value = value;
                            }
                            (InputValue::Path(value), FlagValue::Path(flag_value)) => {
                                *flag_value = Some(value);
                            }
                            _ => {}
                        }
                        self.editing_flag = None
                    }
                    EventResult::Cancel => self.editing_flag = None,
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
                    KeyCode::Enter | KeyCode::Char(' ') => match flag_value {
                        FlagValue::Bool(flag_value) => *flag_value = !*flag_value,
                        FlagValue::TimingTemplate(flag_value) => {
                            *flag_value = self
                                .focused_radio_index
                                .and_then(TimingTemplate::from_index);
                        }
                        FlagValue::SctpScanType(flag_value) => {
                            *flag_value =
                                self.focused_radio_index.and_then(SctpScanType::from_index);
                        }
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
                        _ => self.editing_flag = Some(self.focused_flag),
                    },
                    _ => {}
                }
            }
        }
        Ok(())
    }

    fn scroll_up(&mut self) {
        self.scroll = self.scroll.saturating_sub(SECTIONS[self.focused_section].1);
        self.scroll_state = self.scroll_state.position(self.scroll as usize);
        self.focused_section = self.focused_section.saturating_sub(1);
    }

    fn scroll_down(&mut self) {
        self.scroll = (self.scroll + SECTIONS[self.focused_section].1).min(
            SECTIONS
                .iter()
                .take(SECTIONS.len() - 1)
                .map(|(_, height)| height)
                .sum(),
        );
        self.scroll_state = self.scroll_state.position(self.scroll as usize);
        self.focused_section = (self.focused_section + 1).min(SECTIONS.len() - 1);
    }
}
