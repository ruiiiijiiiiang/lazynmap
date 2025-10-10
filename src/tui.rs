use ratatui::{
    DefaultTerminal,
    crossterm::event::{self, Event, KeyCode},
    layout::Flex,
    prelude::*,
    widgets::{Block, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState},
};
use std::error::Error;

use crate::widgets::checkbox::{Checkbox, CheckboxState};
use crate::{scan::NmapScan, sections::host_discovery::render_host_discovery};

const SECTIONS: [&str; 10] = [
    "Target Specification",
    "Host Discovery",
    "Scan Technique",
    "Port Specification",
    "Service Detection",
    "OS Detection",
    "Timing",
    "Evasion and Spoofing",
    "Output",
    "Miscellaneous",
];

pub struct Tui<'a> {
    pub scroll_state: ScrollbarState,
    pub scroll: usize,
    pub highlighted_section: usize,
    pub scan: &'a mut NmapScan,
}

impl<'a> Tui<'a> {
    pub fn new(scan: &'a mut NmapScan) -> Self {
        Self {
            scroll_state: ScrollbarState::default(),
            scroll: 0,
            highlighted_section: 0,
            scan,
        }
    }

    pub fn run(self) -> Result<(), Box<dyn Error>> {
        color_eyre::install()?;
        let terminal = ratatui::init();

        let res = self.run_app(terminal);

        ratatui::restore();
        if let Err(err) = &res {
            println!("{err:?}");
        }
        res
    }

    fn run_app(mut self, mut terminal: DefaultTerminal) -> Result<(), Box<dyn Error>> {
        loop {
            terminal.draw(|frame| self.draw(frame))?;

            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => {
                        return Ok(());
                    }
                    KeyCode::Char('j') | KeyCode::Down => {
                        self.highlighted_section = if self.highlighted_section == SECTIONS.len() - 1
                        {
                            0
                        } else {
                            self.highlighted_section + 1
                        };
                        // TODO: fix scroll
                        self.scroll = self.scroll.saturating_add(10);
                        self.scroll_state = self.scroll_state.position(self.scroll);
                    }
                    KeyCode::Char('k') | KeyCode::Up => {
                        self.highlighted_section = if self.highlighted_section == 0 {
                            SECTIONS.len() - 1
                        } else {
                            self.highlighted_section - 1
                        };
                        // TODO: fix scroll
                        self.scroll = self.scroll.saturating_sub(10);
                        self.scroll_state = self.scroll_state.position(self.scroll);
                    }
                    _ => {}
                }
            }
        }
    }

    fn draw(&mut self, frame: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(25), Constraint::Min(0)])
            .split(frame.area());

        let left_block = Block::bordered().title("Sections");
        let sections = SECTIONS
            .iter()
            .enumerate()
            .map(|(index, &section)| {
                if index == self.highlighted_section {
                    Line::from(section).style(Style::default().fg(Color::Yellow))
                } else {
                    Line::from(section)
                }
            })
            .collect::<Vec<_>>();
        let section_paragraph = Paragraph::new(sections).block(left_block);
        frame.render_widget(section_paragraph, chunks[0]);

        let right_block = Block::bordered().title("Flags");
        let flag_areas = right_block.inner(chunks[1]);
        let flag_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(10); SECTIONS.len()])
            .split(flag_areas);

        let flag_blocks = SECTIONS
            .iter()
            .enumerate()
            .map(|(index, &section)| {
                let border_style = if index == self.highlighted_section {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default()
                };
                Block::bordered().title(section).border_style(border_style)
            })
            .collect::<Vec<_>>();
        frame.render_widget(right_block, chunks[1]);
        for (index, flag_block) in flag_blocks.iter().enumerate() {
            frame.render_widget(flag_block, flag_chunks[index]);
        }

        render_host_discovery(
            self,
            frame,
            flag_chunks[1].inner(Margin {
                vertical: 1,
                horizontal: 1,
            }),
        );

        let total_height = SECTIONS.len() * 10;
        self.scroll_state = self.scroll_state.content_length(total_height);
        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("↑"))
                .end_symbol(Some("↓")),
            chunks[1],
            &mut self.scroll_state,
        );
    }
}
