use ratatui::{
    DefaultTerminal,
    crossterm::event::{self, Event, KeyCode},
    prelude::*,
    widgets::{Block, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState},
};
use std::{collections::HashMap, error::Error};

use crate::{
    scan::{
        builder::NmapCommandBuilder,
        flags::{FlagValue, NmapFlag},
        model::{NmapScan, TimingTemplate},
    },
    tui::{
        sections::{
            host_discovery::render_host_discovery,
            target_specification::render_target_specification, timing::render_timing,
        },
        utils::initialize_text_inputs,
        widgets::text_input::{EventResult, InputValue, InputWidget},
    },
};

const SECTIONS: [(&str, u16); 10] = [
    ("Target Specification", 11),
    ("Host Discovery", 10),
    ("Scan Technique", 10),
    ("Port Specification", 10),
    ("Service Detection", 10),
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

    scroll_state: ScrollbarState,
    scroll: u16,
    running: bool,
}

impl<'a> App<'a> {
    pub fn new(scan: &'a mut NmapScan) -> Self {
        let total_height: u16 = SECTIONS.iter().map(|(_, height)| height).sum();
        let mut input_map = HashMap::new();
        initialize_text_inputs(scan, &mut input_map);

        Self {
            scan,
            input_map,
            focused_section: 0,
            focused_flag: NmapFlag::first(),
            editing_flag: None,
            focused_radio_index: None,

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

        let left_block = Block::bordered().title("Sections");
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

        let right_block = Block::bordered().title("Options");
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
                    .border_style(border_style);
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
                    2 => render_timing(
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
        let nmap_command = Paragraph::new(NmapCommandBuilder::build(self.scan)).block(footer_block);
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
                        match value {
                            InputValue::Int(value) => {
                                if let FlagValue::U32(flag_value) = flag_value {
                                    *flag_value = Some(value as u32);
                                }
                            }
                            InputValue::VecString(value) => {
                                if let FlagValue::VecString(flag_value) = flag_value {
                                    *flag_value = value;
                                }
                            }
                            InputValue::Path(value) => {
                                if let FlagValue::Path(flag_value) = flag_value {
                                    *flag_value = Some(value);
                                }
                            }
                            _ => {}
                        }
                        self.editing_flag = None
                    }
                    EventResult::Cancel => self.editing_flag = None,
                    _ => {}
                };
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
                        FlagValue::VecString(_) | FlagValue::Path(_) | FlagValue::U32(_) => {
                            self.editing_flag = Some(self.focused_flag)
                        }
                        FlagValue::TimingTemplate(flag_value) => {
                            *flag_value = self
                                .focused_radio_index
                                .and_then(TimingTemplate::from_index)
                                .and_then(|new_val| {
                                    if Some(new_val) == *flag_value {
                                        None
                                    } else {
                                        Some(new_val)
                                    }
                                });
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
        }
        Ok(())
    }

    fn scroll_up(&mut self) {
        self.focused_section = self.focused_section.saturating_sub(1);
        self.scroll = self.scroll.saturating_sub(SECTIONS[self.focused_section].1);
        self.scroll_state = self.scroll_state.position(self.scroll as usize);
    }

    fn scroll_down(&mut self) {
        self.focused_section = (self.focused_section + 1).min(SECTIONS.len() - 1);
        self.scroll = (self.scroll + SECTIONS[self.focused_section].1).min(
            SECTIONS
                .iter()
                .take(SECTIONS.len() - 1)
                .map(|(_, height)| height)
                .sum(),
        );
        self.scroll_state = self.scroll_state.position(self.scroll as usize);
    }
}
