use ratatui::{
    DefaultTerminal,
    crossterm::event::{self, Event, KeyCode},
    prelude::*,
    widgets::{Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState},
};
use std::error::Error;

pub struct Tui {
    pub scroll_state: ScrollbarState,
    pub scroll: usize,
    pub highlighted_section: usize,
}

impl Tui {
    pub fn new() -> Self {
        Self {
            scroll_state: ScrollbarState::default(),
            scroll: 0,
            highlighted_section: 0,
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
                        self.scroll = self.scroll.saturating_add(1);
                        self.scroll_state = self.scroll_state.position(self.scroll);
                    }
                    KeyCode::Char('k') | KeyCode::Up => {
                        self.scroll = self.scroll.saturating_sub(1);
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
            .constraints([Constraint::Length(20), Constraint::Min(0)].as_ref())
            .split(frame.area());

        let left_block = Block::default().title("Left Column").borders(Borders::ALL);
        let sections = vec![
            Line::from("Target specification"),
            Line::from("Host Discovery"),
            Line::from("Scan Technique"),
            Line::from("Port Specification"),
            Line::from("ServiceDetection"),
            Line::from("OS Detection"),
            Line::from("Timing"),
            Line::from("Firewall Evasion"),
            Line::from("Miscellaneous"),
        ];
        let section_paragraph = Paragraph::new(sections).block(left_block);
        frame.render_widget(section_paragraph, chunks[0]);

        let right_block = Block::default().title("Right Column").borders(Borders::ALL);
        let right_paragraph = Paragraph::new("Takes the rest of the space").block(right_block);
        frame.render_widget(right_paragraph, chunks[1]);
        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("↑"))
                .end_symbol(Some("↓")),
            chunks[1],
            &mut self.scroll_state,
        );
    }
}
