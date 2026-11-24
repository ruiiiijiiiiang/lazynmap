use ratatui::{
    DefaultTerminal,
    crossterm::{
        event::{
            self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, MouseButton,
            MouseEvent, MouseEventKind,
        },
        execute,
    },
    layout::Position,
    prelude::*,
    widgets::ScrollbarState,
};
use std::{collections::HashMap, error::Error, io::stdout};

use crate::{
    consts::{self, IndexableEnum},
    scan::{
        flags::{FlagValue, NmapFlag},
        model::{NmapScan, NsockEngine, SctpScanType, TcpScanType, TimingTemplate},
    },
    tui::{
        mouse::{ClickRegions, ClickTarget, SCROLL_STEP},
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

    // Clickable regions of the last drawn frame, and the area of the scrollable flags panel
    pub click_regions: ClickRegions,
    pub main_area: Rect,

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
            click_regions: ClickRegions::default(),
            main_area: Rect::default(),
            tcp_scan_type_state,
        }
    }

    pub fn start(&mut self) -> Result<AppResult, Box<dyn Error>> {
        color_eyre::install()?;
        let terminal = ratatui::init();
        execute!(stdout(), EnableMouseCapture)?;
        let panic_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let _ = execute!(stdout(), DisableMouseCapture);
            panic_hook(info);
        }));

        let res = self.run(terminal);

        let _ = execute!(stdout(), DisableMouseCapture);
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
        self.click_regions.clear();

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
                Constraint::Length(12),
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
        if let Event::Mouse(mouse) = event {
            self.handle_mouse_event(mouse);
        } else if let Event::Key(key) = event {
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
                        clear_flag_value(flag_value);
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
                        EventResult::Consumed => self.error = input.error(),
                        _ => {}
                    }
                }
            } else {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') => {
                        self.running = false;
                    }
                    KeyCode::Char('j') | KeyCode::Char('J') | KeyCode::Down => self.next_section(),
                    KeyCode::Char('k') | KeyCode::Char('K') | KeyCode::Up => self.prev_section(),
                    KeyCode::Char('l') | KeyCode::Char('L') | KeyCode::Right => self.next_flag(),
                    KeyCode::Char('h') | KeyCode::Char('H') | KeyCode::Left => self.prev_flag(),
                    KeyCode::Char(' ') => self.toggle_focused_flag(),
                    KeyCode::Char('c') | KeyCode::Char('C') => match flag_value {
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
                    KeyCode::Enter => self.edit_focused_flag(),
                    KeyCode::Char('x') | KeyCode::Char('X') => {
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

    /// Same as pressing space: toggles the focused flag or selects the focused radio option.
    fn toggle_focused_flag(&mut self) {
        let flag_value = self.focused_flag.get_flag_value(self.scan);
        match flag_value {
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
                    let input_value = self.tcp_scan_type_state.scanflags_input.content();
                    let scan_type = Some(TcpScanType::Scanflags(input_value.to_string()));
                    *flag_value = scan_type.clone();
                    self.tcp_scan_type_state.editing_scan_type = scan_type;
                }
                _ => (),
            },
            FlagValue::SctpScanType(flag_value) => {
                *flag_value = self.focused_radio_index.and_then(SctpScanType::from_index);
            }
            FlagValue::NsockEngine(flag_value) => {
                *flag_value = self.focused_radio_index.and_then(NsockEngine::from_index);
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
                    && let Some(InputValue::VecString(input_value)) = input.typed_value()
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
        }
    }

    /// Same as pressing enter: starts editing the value of the focused flag, if it has one.
    fn edit_focused_flag(&mut self) {
        match self.focused_flag.get_flag_value(self.scan) {
            FlagValue::Int(_)
            | FlagValue::Float(_)
            | FlagValue::String(_)
            | FlagValue::VecInt(_)
            | FlagValue::VecString(_)
            | FlagValue::Path(_) => self.editing_flag = Some(self.focused_flag),
            _ => (),
        }
    }

    fn handle_mouse_event(&mut self, mouse: MouseEvent) {
        if self.is_editing() {
            // While a value is being edited, only a click elsewhere matters: it closes the
            // input, then goes on to act on what was clicked.
            if mouse.kind != MouseEventKind::Down(MouseButton::Left) {
                return;
            }
            let target = self.click_regions.target_at(mouse.column, mouse.row);
            if self.is_editing_target(target) {
                return;
            }
            self.close_edit_on_click();
        }

        match mouse.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                match self.click_regions.target_at(mouse.column, mouse.row) {
                    Some(ClickTarget::Section(index)) => self.focus_section(index, true),
                    Some(ClickTarget::SectionBlock(index)) => self.focus_section(index, false),
                    Some(ClickTarget::Toggle(flag)) => {
                        self.focus_flag(flag, None);
                        self.toggle_focused_flag();
                    }
                    Some(ClickTarget::Edit(flag)) => {
                        self.focus_flag(flag, None);
                        self.edit_focused_flag();
                    }
                    Some(ClickTarget::Radio(flag, index)) => {
                        self.focus_flag(flag, Some(index));
                        self.toggle_focused_flag();
                    }
                    None => {}
                }
            }
            MouseEventKind::ScrollDown if self.is_over_main_area(mouse) => {
                self.set_scroll(self.scroll.saturating_add(SCROLL_STEP));
            }
            MouseEventKind::ScrollUp if self.is_over_main_area(mouse) => {
                self.set_scroll(self.scroll.saturating_sub(SCROLL_STEP));
            }
            _ => {}
        }
    }

    /// Closes the open input because the user clicked elsewhere. A valid value is confirmed as
    /// Enter would, an empty input clears the value as Esc would, and anything that can't be
    /// parsed is discarded so the flag keeps its previous value. Either way the input closes,
    /// so the click can never get stuck on it.
    fn close_edit_on_click(&mut self) {
        let _ = self.handle_event(Event::Key(KeyEvent::from(KeyCode::Enter)));
        // The TCP scan type inputs take any string, so only a flag input can still be open.
        let Some(flag) = self.editing_flag.take() else {
            return;
        };
        self.error = None;
        let flag_value = flag.get_flag_value(self.scan);
        let input = self.input_map.get_mut(&flag).unwrap();
        if input.content().trim().is_empty() {
            clear_flag_value(flag_value);
            input.clear();
            return;
        }
        let previous = match flag_value {
            FlagValue::Int(Some(value)) => Some(InputValue::Int(*value)),
            FlagValue::Float(Some(value)) => Some(InputValue::Float(*value)),
            FlagValue::String(Some(value)) => Some(InputValue::String(value.clone())),
            FlagValue::VecInt(value) => Some(InputValue::VecInt(value.clone())),
            FlagValue::VecString(value) => Some(InputValue::VecString(value.clone())),
            FlagValue::Path(Some(value)) => Some(InputValue::Path(value.clone())),
            _ => None,
        };
        input.clear();
        if let Some(previous) = previous {
            input.set_typed_value(previous);
        }
    }

    fn is_editing(&self) -> bool {
        self.editing_flag.is_some() || self.tcp_scan_type_state.editing_scan_type.is_some()
    }

    /// Whether `target` is the input currently being edited.
    fn is_editing_target(&self, target: Option<ClickTarget>) -> bool {
        match target {
            Some(ClickTarget::Edit(flag)) => self.editing_flag == Some(flag),
            Some(ClickTarget::Radio(NmapFlag::TcpScanType, index)) => {
                let editing_index = match self.tcp_scan_type_state.editing_scan_type {
                    Some(TcpScanType::Idle(_)) => Some(consts::IDLE_SCAN_TYPE_INDEX),
                    Some(TcpScanType::Ftp(_)) => Some(consts::FTP_SCAN_TYPE_INDEX),
                    Some(TcpScanType::Scanflags(_)) => Some(consts::SCANFLAGS_SCAN_TYPE_INDEX),
                    _ => None,
                };
                editing_index == Some(index)
            }
            _ => false,
        }
    }

    fn is_over_main_area(&self, mouse: MouseEvent) -> bool {
        self.main_area
            .contains(Position::new(mouse.column, mouse.row))
    }

    fn set_scroll(&mut self, scroll: u16) {
        let max_scroll = SECTIONS
            .iter()
            .take(SECTIONS.len() - 1)
            .map(|section| section.height)
            .sum();
        self.scroll = scroll.min(max_scroll);
        self.scroll_state = self.scroll_state.position(self.scroll as usize);
    }

    /// Focuses the first flag of a section, optionally scrolling the section to the top of the
    /// flags panel.
    fn focus_section(&mut self, index: usize, scroll: bool) {
        self.focused_section = index;
        self.focused_flag = SECTIONS[index].start;
        self.focused_radio_index = self.focused_flag.get_variant_count().map(|_| 0);
        if scroll {
            self.set_scroll(
                SECTIONS
                    .iter()
                    .take(index)
                    .map(|section| section.height)
                    .sum(),
            );
        }
    }

    fn focus_flag(&mut self, flag: NmapFlag, radio_index: Option<usize>) {
        self.focused_flag = flag;
        self.focused_radio_index = radio_index;
        self.focused_section = SECTIONS
            .iter()
            .rposition(|section| section.start.as_index() <= flag.as_index())
            .unwrap_or(0);
    }

    fn prev_section(&mut self) {
        self.focus_section(self.focused_section.saturating_sub(1), true);
    }

    fn next_section(&mut self) {
        self.focus_section((self.focused_section + 1).min(SECTIONS.len() - 1), true);
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

/// Unsets a value flag, as cancelling its input does.
fn clear_flag_value(flag_value: FlagValue) {
    match flag_value {
        FlagValue::Int(flag_value) => *flag_value = None,
        FlagValue::Float(flag_value) => *flag_value = None,
        FlagValue::String(flag_value) => *flag_value = None,
        FlagValue::VecInt(flag_value) => *flag_value = Vec::new(),
        FlagValue::VecString(flag_value) => *flag_value = Vec::new(),
        FlagValue::Path(flag_value) => *flag_value = None,
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{
        Terminal,
        backend::TestBackend,
        crossterm::event::{KeyModifiers, MouseEvent},
    };

    fn draw(app: &mut App, terminal: &mut Terminal<TestBackend>) {
        terminal.draw(|frame| app.draw(frame)).unwrap();
    }

    fn mouse(kind: MouseEventKind, column: u16, row: u16) -> Event {
        Event::Mouse(MouseEvent {
            kind,
            column,
            row,
            modifiers: KeyModifiers::NONE,
        })
    }

    fn click(app: &mut App, target: ClickTarget) {
        let area = app
            .click_regions
            .area_of(target)
            .unwrap_or_else(|| panic!("{target:?} is not on screen"));
        app.handle_event(mouse(
            MouseEventKind::Down(MouseButton::Left),
            area.x,
            area.y,
        ))
        .unwrap();
    }

    fn terminal() -> Terminal<TestBackend> {
        Terminal::new(TestBackend::new(160, 50)).unwrap()
    }

    #[test]
    fn test_click_toggles_checkbox() {
        let mut scan = NmapScan::new();
        let mut app = App::new(&mut scan);
        let mut terminal = terminal();
        draw(&mut app, &mut terminal);

        click(&mut app, ClickTarget::Toggle(NmapFlag::Unique));
        assert_eq!(app.focused_flag, NmapFlag::Unique);
        assert!(matches!(
            NmapFlag::Unique.get_flag_value(app.scan),
            FlagValue::Bool(true)
        ));

        draw(&mut app, &mut terminal);
        click(&mut app, ClickTarget::Toggle(NmapFlag::Unique));
        assert!(matches!(
            NmapFlag::Unique.get_flag_value(app.scan),
            FlagValue::Bool(false)
        ));
    }

    #[test]
    fn test_click_on_input_starts_editing() {
        let mut scan = NmapScan::new();
        let mut app = App::new(&mut scan);
        let mut terminal = terminal();
        draw(&mut app, &mut terminal);

        click(&mut app, ClickTarget::Edit(NmapFlag::RandomTargets));
        assert_eq!(app.focused_flag, NmapFlag::RandomTargets);
        assert_eq!(app.editing_flag, Some(NmapFlag::RandomTargets));

        // Clicking the input being edited keeps it open
        draw(&mut app, &mut terminal);
        click(&mut app, ClickTarget::Edit(NmapFlag::RandomTargets));
        assert_eq!(app.editing_flag, Some(NmapFlag::RandomTargets));
    }

    fn type_text(app: &mut App, text: &str) {
        for c in text.chars() {
            app.handle_event(Event::Key(KeyEvent::from(KeyCode::Char(c))))
                .unwrap();
        }
    }

    #[test]
    fn test_click_elsewhere_confirms_edit() {
        let mut scan = NmapScan::new();
        let mut app = App::new(&mut scan);
        let mut terminal = terminal();
        draw(&mut app, &mut terminal);

        click(&mut app, ClickTarget::Edit(NmapFlag::RandomTargets));
        type_text(&mut app, "42");
        draw(&mut app, &mut terminal);
        click(&mut app, ClickTarget::Toggle(NmapFlag::Unique));

        assert_eq!(app.editing_flag, None);
        assert!(matches!(
            NmapFlag::RandomTargets.get_flag_value(app.scan),
            FlagValue::Int(Some(42))
        ));
        assert_eq!(app.focused_flag, NmapFlag::Unique);
        assert!(matches!(
            NmapFlag::Unique.get_flag_value(app.scan),
            FlagValue::Bool(true)
        ));
    }

    fn assert_unique_toggled(app: &mut App) {
        assert_eq!(app.editing_flag, None);
        assert_eq!(app.error, None);
        assert_eq!(app.focused_flag, NmapFlag::Unique);
        assert!(matches!(
            NmapFlag::Unique.get_flag_value(app.scan),
            FlagValue::Bool(true)
        ));
    }

    #[test]
    fn test_click_elsewhere_from_empty_input_clears_it() {
        let mut scan = NmapScan::new();
        let mut app = App::new(&mut scan);
        let mut terminal = terminal();
        draw(&mut app, &mut terminal);

        click(&mut app, ClickTarget::Edit(NmapFlag::RandomTargets));
        draw(&mut app, &mut terminal);
        click(&mut app, ClickTarget::Toggle(NmapFlag::Unique));

        assert_unique_toggled(&mut app);
        assert!(matches!(
            NmapFlag::RandomTargets.get_flag_value(app.scan),
            FlagValue::Int(None)
        ));
    }

    #[test]
    fn test_click_elsewhere_discards_invalid_value() {
        let mut scan = NmapScan::new();
        let mut app = App::new(&mut scan);
        let mut terminal = terminal();
        draw(&mut app, &mut terminal);

        click(&mut app, ClickTarget::Edit(NmapFlag::RandomTargets));
        type_text(&mut app, "42");
        app.handle_event(Event::Key(KeyEvent::from(KeyCode::Enter)))
            .unwrap();
        draw(&mut app, &mut terminal);
        click(&mut app, ClickTarget::Edit(NmapFlag::RandomTargets));
        type_text(&mut app, "x");
        draw(&mut app, &mut terminal);
        click(&mut app, ClickTarget::Toggle(NmapFlag::Unique));

        assert_unique_toggled(&mut app);
        assert!(matches!(
            NmapFlag::RandomTargets.get_flag_value(app.scan),
            FlagValue::Int(Some(42))
        ));
        assert_eq!(app.input_map[&NmapFlag::RandomTargets].content(), "42");
    }

    #[test]
    fn test_click_section_then_radio() {
        let mut scan = NmapScan::new();
        let mut app = App::new(&mut scan);
        let mut terminal = terminal();
        draw(&mut app, &mut terminal);

        let timing = SECTIONS
            .iter()
            .position(|section| section.name == "Timing")
            .unwrap();
        click(&mut app, ClickTarget::Section(timing));
        assert_eq!(app.focused_section, timing);
        assert_eq!(app.focused_flag, SECTIONS[timing].start);
        assert_eq!(
            app.scroll,
            SECTIONS.iter().take(timing).map(|s| s.height).sum::<u16>()
        );

        draw(&mut app, &mut terminal);
        click(&mut app, ClickTarget::Radio(NmapFlag::TimingTemplate, 4));
        assert_eq!(app.focused_flag, NmapFlag::TimingTemplate);
        assert_eq!(app.focused_radio_index, Some(4));
        assert!(matches!(
            NmapFlag::TimingTemplate.get_flag_value(app.scan),
            FlagValue::TimingTemplate(Some(template)) if template.as_index() == 4
        ));
    }

    #[test]
    fn test_scroll_wheel_scrolls_main_area_only() {
        let mut scan = NmapScan::new();
        let mut app = App::new(&mut scan);
        let mut terminal = terminal();
        draw(&mut app, &mut terminal);

        let main = app.main_area;
        app.handle_event(mouse(MouseEventKind::ScrollDown, main.x + 5, main.y + 5))
            .unwrap();
        assert_eq!(app.scroll, SCROLL_STEP);
        assert_eq!(app.focused_section, 0);

        app.handle_event(mouse(MouseEventKind::ScrollDown, 0, 0))
            .unwrap();
        assert_eq!(app.scroll, SCROLL_STEP);

        for _ in 0..100 {
            app.handle_event(mouse(MouseEventKind::ScrollDown, main.x + 5, main.y + 5))
                .unwrap();
        }
        let max_scroll: u16 = SECTIONS
            .iter()
            .take(SECTIONS.len() - 1)
            .map(|s| s.height)
            .sum();
        assert_eq!(app.scroll, max_scroll);

        for _ in 0..100 {
            app.handle_event(mouse(MouseEventKind::ScrollUp, main.x + 5, main.y + 5))
                .unwrap();
        }
        assert_eq!(app.scroll, 0);
    }

    #[test]
    fn test_keyboard_navigation_realigns_after_wheel_scroll() {
        let mut scan = NmapScan::new();
        let mut app = App::new(&mut scan);
        let mut terminal = terminal();
        draw(&mut app, &mut terminal);

        let main = app.main_area;
        app.handle_event(mouse(MouseEventKind::ScrollDown, main.x + 5, main.y + 5))
            .unwrap();
        app.next_section();
        assert_eq!(app.focused_section, 1);
        assert_eq!(app.scroll, SECTIONS[0].height);
    }
}
