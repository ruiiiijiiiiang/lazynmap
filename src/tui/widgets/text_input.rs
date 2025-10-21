use ratatui::{
    buffer::Buffer,
    crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers},
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Widget},
};
use std::fs;
use std::path::{Path, PathBuf};

// ============================================================================
// Event Result
// ============================================================================

#[derive(Debug)]
pub enum EventResult<T> {
    Consumed,
    Ignored,
    Submit(T),
    Cancel,
}

pub enum InputWidget {
    String(TextInput<String>),
    Int(TextInput<u32>),
    Float(TextInput<f32>),
    VecString(TextInput<Vec<String>>),
    VecInt(TextInput<Vec<u32>>),
    Path(CompletingInput),
}

#[derive(Debug)]
pub enum InputValue {
    String(String),
    Int(u32),
    Float(f32),
    VecString(Vec<String>),
    VecInt(Vec<u32>),
    Path(PathBuf),
}

impl InputWidget {
    pub fn render(&mut self, area: Rect, buf: &mut Buffer, focused: bool, editing: bool) {
        match self {
            InputWidget::String(input) => input.render(area, buf, focused, editing),
            InputWidget::Int(input) => input.render(area, buf, focused, editing),
            InputWidget::Float(input) => input.render(area, buf, focused, editing),
            InputWidget::VecString(input) => input.render(area, buf, focused, editing),
            InputWidget::VecInt(input) => input.render(area, buf, focused, editing),
            InputWidget::Path(input) => input.render(area, buf, focused, editing),
        }
    }

    pub fn render_dropdown_overlay(&self, buf: &mut Buffer) {
        if let InputWidget::Path(input) = self {
            input.render_dropdown_overlay(buf);
        }
    }

    pub fn handle_event(&mut self, event: &Event) -> EventResult<InputValue> {
        match self {
            InputWidget::String(input) => match input.handle_event(event) {
                EventResult::Submit(v) => EventResult::Submit(InputValue::String(v)),
                EventResult::Consumed => EventResult::Consumed,
                EventResult::Cancel => EventResult::Cancel,
                EventResult::Ignored => EventResult::Ignored,
            },
            InputWidget::Int(input) => match input.handle_event(event) {
                EventResult::Submit(v) => EventResult::Submit(InputValue::Int(v)),
                EventResult::Consumed => EventResult::Consumed,
                EventResult::Cancel => EventResult::Cancel,
                EventResult::Ignored => EventResult::Ignored,
            },
            InputWidget::Float(input) => match input.handle_event(event) {
                EventResult::Submit(v) => EventResult::Submit(InputValue::Float(v)),
                EventResult::Consumed => EventResult::Consumed,
                EventResult::Cancel => EventResult::Cancel,
                EventResult::Ignored => EventResult::Ignored,
            },
            InputWidget::VecString(input) => match input.handle_event(event) {
                EventResult::Submit(v) => EventResult::Submit(InputValue::VecString(v)),
                EventResult::Consumed => EventResult::Consumed,
                EventResult::Cancel => EventResult::Cancel,
                EventResult::Ignored => EventResult::Ignored,
            },
            InputWidget::VecInt(input) => match input.handle_event(event) {
                EventResult::Submit(v) => EventResult::Submit(InputValue::VecInt(v)),
                EventResult::Consumed => EventResult::Consumed,
                EventResult::Cancel => EventResult::Cancel,
                EventResult::Ignored => EventResult::Ignored,
            },
            InputWidget::Path(input) => match input.handle_event(event) {
                EventResult::Submit(v) => EventResult::Submit(InputValue::Path(v)),
                EventResult::Consumed => EventResult::Consumed,
                EventResult::Cancel => EventResult::Cancel,
                EventResult::Ignored => EventResult::Ignored,
            },
        }
    }

    pub fn clear(&mut self) {
        match self {
            InputWidget::String(input) => input.clear(),
            InputWidget::Int(input) => input.clear(),
            InputWidget::Float(input) => input.clear(),
            InputWidget::VecString(input) => input.clear(),
            InputWidget::VecInt(input) => input.clear(),
            InputWidget::Path(input) => input.clear(),
        }
    }

    pub fn set_content(&mut self, content: String) {
        match self {
            InputWidget::String(input) => input.set_content(content),
            InputWidget::Int(input) => input.set_content(content),
            InputWidget::Float(input) => input.set_content(content),
            InputWidget::VecString(input) => input.set_content(content),
            InputWidget::VecInt(input) => input.set_content(content),
            InputWidget::Path(input) => input.set_content(content),
        }
    }

    pub fn set_typed_value(&mut self, value: InputValue) {
        match (self, value) {
            (InputWidget::String(input), InputValue::String(value)) => input.set_typed_value(value),
            (InputWidget::Int(input), InputValue::Int(value)) => input.set_typed_value(value),
            (InputWidget::Float(input), InputValue::Float(value)) => input.set_typed_value(value),
            (InputWidget::VecString(input), InputValue::VecString(value)) => {
                input.set_typed_value(value)
            }
            (InputWidget::VecInt(input), InputValue::VecInt(value)) => input.set_typed_value(value),
            (InputWidget::Path(input), InputValue::Path(value)) => input.set_typed_value(value),
            _ => {}
        }
    }

    pub fn content(&self) -> &str {
        match self {
            InputWidget::String(input) => input.content(),
            InputWidget::Int(input) => input.content(),
            InputWidget::Float(input) => input.content(),
            InputWidget::VecString(input) => input.content(),
            InputWidget::VecInt(input) => input.content(),
            InputWidget::Path(input) => input.content(),
        }
    }

    pub fn typed_value(&self) -> Option<InputValue> {
        match self {
            InputWidget::String(input) => input.value().ok().map(InputValue::String),
            InputWidget::Int(input) => input.value().ok().map(InputValue::Int),
            InputWidget::Float(input) => input.value().ok().map(InputValue::Float),
            InputWidget::VecString(input) => input.value().ok().map(InputValue::VecString),
            InputWidget::VecInt(input) => input.value().ok().map(InputValue::VecInt),
            InputWidget::Path(input) => input.value().ok().map(InputValue::Path),
        }
    }
}

// ============================================================================
// Input Buffer - Core text manipulation
// ============================================================================

#[derive(Debug, Clone)]
struct InputBuffer {
    content: String,
    cursor: usize, // Byte position
}

impl InputBuffer {
    fn new() -> Self {
        Self {
            content: String::new(),
            cursor: 0,
        }
    }

    fn insert_char(&mut self, c: char) {
        self.content.insert(self.cursor, c);
        self.cursor += c.len_utf8();
    }

    fn delete_char(&mut self) {
        if self.cursor < self.content.len() {
            self.content.remove(self.cursor);
        }
    }

    fn backspace(&mut self) {
        if self.cursor > 0 {
            let mut new_cursor = self.cursor - 1;
            while new_cursor > 0 && !self.content.is_char_boundary(new_cursor) {
                new_cursor -= 1;
            }
            self.content.remove(new_cursor);
            self.cursor = new_cursor;
        }
    }

    fn move_cursor_left(&mut self) {
        if self.cursor > 0 {
            let mut new_cursor = self.cursor - 1;
            while new_cursor > 0 && !self.content.is_char_boundary(new_cursor) {
                new_cursor -= 1;
            }
            self.cursor = new_cursor;
        }
    }

    fn move_cursor_right(&mut self) {
        if self.cursor < self.content.len() {
            let mut new_cursor = self.cursor + 1;
            while new_cursor < self.content.len() && !self.content.is_char_boundary(new_cursor) {
                new_cursor += 1;
            }
            self.cursor = new_cursor;
        }
    }

    fn move_cursor_start(&mut self) {
        self.cursor = 0;
    }

    fn move_cursor_end(&mut self) {
        self.cursor = self.content.len();
    }

    fn clear(&mut self) {
        self.content.clear();
        self.cursor = 0;
    }

    fn content(&self) -> &str {
        &self.content
    }

    fn set_content(&mut self, content: String) {
        self.cursor = content.len();
        self.content = content;
    }

    // Get cursor position in characters (for rendering)
    fn cursor_position(&self) -> usize {
        self.content[..self.cursor].chars().count()
    }
}

// ============================================================================
// Parser Trait
// ============================================================================

pub trait Parser<T> {
    fn parse(&self, input: &str) -> Result<T, String>;
    fn format(&self, value: &T) -> String;
}

// ============================================================================
// Built-in Parsers
// ============================================================================

pub struct StringParser;

impl Parser<String> for StringParser {
    fn parse(&self, input: &str) -> Result<String, String> {
        Ok(input.to_string())
    }

    fn format(&self, value: &String) -> String {
        value.to_string()
    }
}

pub struct IntParser;

impl Parser<u32> for IntParser {
    fn parse(&self, input: &str) -> Result<u32, String> {
        input
            .parse::<u32>()
            .map_err(|_| format!("Invalid integer: {}", input))
    }

    fn format(&self, value: &u32) -> String {
        value.to_string()
    }
}

pub struct FloatParser;

impl Parser<f32> for FloatParser {
    fn parse(&self, input: &str) -> Result<f32, String> {
        input
            .parse::<f32>()
            .map_err(|_| format!("Invalid float: {}", input))
    }

    fn format(&self, value: &f32) -> String {
        value.to_string()
    }
}

pub struct VecStringParser;

impl Parser<Vec<String>> for VecStringParser {
    fn parse(&self, input: &str) -> Result<Vec<String>, String> {
        if input.trim().is_empty() {
            return Ok(Vec::new());
        }
        Ok(input
            .split(",")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect())
    }

    fn format(&self, value: &Vec<String>) -> String {
        value.join(", ")
    }
}

pub struct VecIntParser;

impl Parser<Vec<u32>> for VecIntParser {
    fn parse(&self, input: &str) -> Result<Vec<u32>, String> {
        if input.trim().is_empty() {
            return Ok(Vec::new());
        }
        input
            .split(",")
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| {
                s.parse::<u32>()
                    .map_err(|_| format!("Invalid integer: {}", s))
            })
            .collect()
    }

    fn format(&self, value: &Vec<u32>) -> String {
        value
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

pub struct PathBufParser;

impl Parser<PathBuf> for PathBufParser {
    fn parse(&self, input: &str) -> Result<PathBuf, String> {
        if input.is_empty() {
            return Err("Path cannot be empty".to_string());
        }
        Ok(PathBuf::from(input))
    }

    fn format(&self, value: &PathBuf) -> String {
        value.to_string_lossy().to_string()
    }
}

// ============================================================================
// Basic Text Input Widget
// ============================================================================

pub struct TextInput<T> {
    buffer: InputBuffer,
    parser: Box<dyn Parser<T>>,
    label: Option<String>,
    pub placeholder: Option<String>,
    // focused_style: Style,
    // editing_style: Style,
    // default_style: Style,
    error: Option<String>,
}

impl<T> TextInput<T> {
    pub fn new(parser: impl Parser<T> + 'static) -> Self {
        Self {
            buffer: InputBuffer::new(),
            parser: Box::new(parser),
            label: None,
            placeholder: None,
            // focused_style: Style::default().fg(Color::Yellow),
            // editing_style: Style::default()
            //     .fg(Color::Cyan)
            //     .add_modifier(Modifier::BOLD),
            // default_style: Style::default().fg(Color::Gray),
            error: None,
        }
    }

    pub fn with_placeholder(mut self, placeholder: impl Into<String>) -> Self {
        self.placeholder = Some(placeholder.into());
        self
    }

    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    pub fn set_typed_value(&mut self, value: T) {
        let content = self.parser.format(&value);
        self.set_content(content);
    }

    pub fn handle_event(&mut self, event: &Event) -> EventResult<T> {
        if let Event::Key(key) = event {
            return self.handle_key_event(*key);
        }
        EventResult::Ignored
    }

    fn handle_key_event(&mut self, key: KeyEvent) -> EventResult<T> {
        // Clear error on any key press
        self.error = None;

        match key.code {
            KeyCode::Char(c)
                if key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT =>
            {
                self.buffer.insert_char(c);
                EventResult::Consumed
            }
            KeyCode::Backspace => {
                self.buffer.backspace();
                EventResult::Consumed
            }
            KeyCode::Delete => {
                self.buffer.delete_char();
                EventResult::Consumed
            }
            KeyCode::Left => {
                self.buffer.move_cursor_left();
                EventResult::Consumed
            }
            KeyCode::Right => {
                self.buffer.move_cursor_right();
                EventResult::Consumed
            }
            KeyCode::Home => {
                self.buffer.move_cursor_start();
                EventResult::Consumed
            }
            KeyCode::End => {
                self.buffer.move_cursor_end();
                EventResult::Consumed
            }
            KeyCode::Enter => match self.parser.parse(self.buffer.content()) {
                Ok(value) => EventResult::Submit(value),
                Err(err) => {
                    self.error = Some(err);
                    EventResult::Consumed
                }
            },
            KeyCode::Esc => EventResult::Cancel,
            _ => EventResult::Ignored,
        }
    }

    pub fn render(&self, area: Rect, buf: &mut Buffer, focused: bool, editing: bool) {
        let (bg_color, fg_color, label_color) = if editing {
            (Color::Cyan, Color::Black, Color::Cyan)
        } else if focused {
            (Color::Yellow, Color::Black, Color::Yellow)
        } else {
            (Color::Gray, Color::Black, Color::Gray)
        };

        // Calculate areas for label and input (side by side)
        let (label_area, input_area) = if let Some(label) = &self.label {
            // Calculate label width (label text + 2 spaces for padding)
            let label_width = label.len() as u16 + 2;

            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Length(label_width), // Label
                    Constraint::Min(0),              // Input box
                ])
                .split(area);
            (Some(chunks[0]), chunks[1])
        } else {
            (None, area)
        };

        // Render label if present
        if let (Some(label_area), Some(label)) = (label_area, &self.label) {
            let label_style = Style::default().fg(label_color);
            if editing {
                let _ = label_style.add_modifier(Modifier::BOLD);
            }

            let label_text = format!("{}: ", label);
            let label_line = Line::from(Span::styled(label_text, label_style));
            Paragraph::new(label_line).render(label_area, buf);
        }

        // Fill the input area with background color
        for x in input_area.left()..input_area.right() {
            for y in input_area.top()..input_area.bottom() {
                if let Some(cell) = buf.cell_mut((x, y)) {
                    cell.set_bg(bg_color);
                }
            }
        }

        // Render text or placeholder
        let display_text = if self.buffer.content().is_empty() {
            self.placeholder.as_deref().unwrap_or("")
        } else {
            self.buffer.content()
        };

        let text_style = if self.buffer.content().is_empty() {
            Style::default().fg(Color::DarkGray).bg(bg_color)
        } else {
            Style::default().fg(fg_color).bg(bg_color)
        };

        // Render text with padding
        if input_area.width > 0 && input_area.height > 0 {
            let text_to_display = if display_text.len() > input_area.width as usize {
                // Truncate if too long
                &display_text[..input_area.width as usize]
            } else {
                display_text
            };

            let text_line = Line::from(Span::styled(text_to_display, text_style));
            Paragraph::new(text_line).render(input_area, buf);
        }

        // Render cursor if editing
        if editing && input_area.width > 0 && input_area.height > 0 {
            let cursor_pos = self
                .buffer
                .cursor_position()
                .min(input_area.width as usize - 1);
            let cursor_x = input_area.x + cursor_pos as u16;
            if cursor_x < input_area.x + input_area.width
                && let Some(cell) = buf.cell_mut((cursor_x, input_area.y))
            {
                cell.set_style(
                    Style::default()
                        .fg(bg_color)
                        .bg(fg_color)
                        .add_modifier(Modifier::BOLD),
                );
            }
        }
    }

    pub fn value(&self) -> Result<T, String> {
        self.parser.parse(self.buffer.content())
    }

    pub fn clear(&mut self) {
        self.buffer.clear();
        self.error = None;
    }

    pub fn set_content(&mut self, content: String) {
        self.buffer.set_content(content);
        self.error = None;
    }

    pub fn content(&self) -> &str {
        self.buffer.content()
    }
}

// ============================================================================
// Path Completer
// ============================================================================

struct PathCompleter {
    suggestions: Vec<PathBuf>,
    selected_index: usize,
}

impl PathCompleter {
    fn new() -> Self {
        Self {
            suggestions: Vec::new(),
            selected_index: 0,
        }
    }

    fn update_suggestions(&mut self, input: &str) {
        self.suggestions.clear();
        self.selected_index = 0;

        if input.is_empty() {
            if let Ok(entries) = fs::read_dir(".") {
                self.suggestions = entries
                    .filter_map(|e| e.ok())
                    .map(|e| e.path())
                    .take(20)
                    .collect();
            }
            return;
        }

        let path = Path::new(input);
        let (dir, prefix) = if input.ends_with('/') || input.ends_with('\\') {
            (path.to_path_buf(), "")
        } else {
            let parent = path.parent();
            let prefix = path.file_name().and_then(|s| s.to_str()).unwrap_or("");

            let dir = if let Some(p) = parent {
                if p.as_os_str().is_empty() {
                    PathBuf::from(".")
                } else {
                    p.to_path_buf()
                }
            } else {
                PathBuf::from(".")
            };

            (dir, prefix)
        };

        if let Ok(entries) = fs::read_dir(dir) {
            self.suggestions = entries
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                        name.to_lowercase().starts_with(&prefix.to_lowercase())
                    } else {
                        false
                    }
                })
                .take(20)
                .collect();
        }

        self.suggestions.sort();
    }

    fn select_next(&mut self) {
        if !self.suggestions.is_empty() {
            self.selected_index = (self.selected_index + 1) % self.suggestions.len();
        }
    }

    fn select_prev(&mut self) {
        if !self.suggestions.is_empty() {
            if self.selected_index == 0 {
                self.selected_index = self.suggestions.len() - 1;
            } else {
                self.selected_index -= 1;
            }
        }
    }

    fn selected(&self) -> Option<&PathBuf> {
        self.suggestions.get(self.selected_index)
    }

    fn has_suggestions(&self) -> bool {
        !self.suggestions.is_empty()
    }
}

// ============================================================================
// Completing Input Widget (for PathBuf)
// ============================================================================

#[derive(Debug, PartialEq)]
enum CompletionMode {
    Editing,
    Selecting,
}

pub struct CompletingInput {
    input: TextInput<PathBuf>,
    completer: PathCompleter,
    mode: CompletionMode,
    max_dropdown_height: usize,
    render_area: Option<Rect>,
}

impl CompletingInput {
    pub fn new() -> Self {
        Self {
            input: TextInput::new(PathBufParser).with_placeholder("Enter path..."),
            completer: PathCompleter::new(),
            mode: CompletionMode::Editing,
            max_dropdown_height: 20,
            render_area: None,
        }
    }

    pub fn with_placeholder(mut self, placeholder: impl Into<String>) -> Self {
        self.input = self.input.with_placeholder(placeholder);
        self
    }

    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.input = self.input.with_label(label);
        self
    }

    pub fn set_typed_value(&mut self, value: PathBuf) {
        let content = self.input.parser.format(&value);
        self.set_content(content);
    }

    pub fn handle_event(&mut self, event: &Event) -> EventResult<PathBuf> {
        if let Event::Key(key) = event {
            return self.handle_key_event(*key);
        }
        EventResult::Ignored
    }

    fn handle_key_event(&mut self, key: KeyEvent) -> EventResult<PathBuf> {
        match self.mode {
            CompletionMode::Editing => {
                match key.code {
                    KeyCode::Tab => {
                        // Update suggestions and switch to selection mode
                        self.completer.update_suggestions(self.input.content());
                        if self.completer.has_suggestions() {
                            self.mode = CompletionMode::Selecting;
                            EventResult::Consumed
                        } else {
                            EventResult::Consumed
                        }
                    }
                    KeyCode::Down if key.modifiers.is_empty() => {
                        // Also allow down arrow to enter selection mode
                        self.completer.update_suggestions(self.input.content());
                        if self.completer.has_suggestions() {
                            self.mode = CompletionMode::Selecting;
                            EventResult::Consumed
                        } else {
                            EventResult::Consumed
                        }
                    }
                    _ => {
                        let result = self.input.handle_event(&Event::Key(key));
                        // Update suggestions after any text change
                        if matches!(result, EventResult::Consumed) {
                            self.completer.update_suggestions(self.input.content());
                        }
                        result
                    }
                }
            }
            CompletionMode::Selecting => {
                match key.code {
                    KeyCode::Up => {
                        self.completer.select_prev();
                        EventResult::Consumed
                    }
                    KeyCode::Down => {
                        self.completer.select_next();
                        EventResult::Consumed
                    }
                    KeyCode::Tab | KeyCode::Enter => {
                        // Accept selected suggestion
                        if let Some(selected) = self.completer.selected() {
                            let mut path_str = selected.to_string_lossy().to_string();
                            if selected.is_dir() && !path_str.ends_with('/') {
                                path_str.push('/');
                            }
                            self.input.set_content(path_str);
                            self.completer.update_suggestions(self.input.content());
                        }
                        self.mode = CompletionMode::Editing;

                        // If Enter, try to submit
                        if key.code == KeyCode::Enter {
                            return self.input.handle_event(&Event::Key(key));
                        }
                        EventResult::Consumed
                    }
                    KeyCode::Esc => {
                        self.mode = CompletionMode::Editing;
                        EventResult::Consumed
                    }
                    // Any other key switches back to editing mode
                    _ => {
                        self.mode = CompletionMode::Editing;
                        self.input.handle_event(&Event::Key(key))
                    }
                }
            }
        }
    }

    pub fn render(&mut self, area: Rect, buf: &mut Buffer, focused: bool, editing: bool) {
        self.render_area = Some(area);

        if editing && !self.completer.has_suggestions() {
            self.completer.update_suggestions(self.input.content());
        }

        self.input.render(area, buf, focused, editing);
    }

    pub fn render_dropdown_overlay(&self, buf: &mut Buffer) {
        if !self.completer.has_suggestions() {
            return;
        }
        let Some(area) = self.render_area else {
            return;
        };

        let input_height = 1;
        let dropdown_items = self
            .completer
            .suggestions
            .len()
            .min(self.max_dropdown_height);
        let dropdown_height = dropdown_items as u16 + 2;

        let space_below = buf.area().height.saturating_sub(area.y + input_height);
        let space_above = area.y;

        let offset_x = self.input.label.as_deref().unwrap_or("").len() as u16 + 2;
        let (dropdown_y, actual_height) = if space_below >= dropdown_height {
            (area.y + input_height, dropdown_height)
        } else if space_above >= dropdown_height {
            (area.y.saturating_sub(dropdown_height), dropdown_height)
        } else if space_below >= space_above {
            (area.y + input_height, space_below.min(dropdown_height))
        } else {
            let usable_height = space_above.min(dropdown_height);
            (area.y.saturating_sub(usable_height), usable_height)
        };

        // Only render if we have at least 3 lines (borders + 1 item)
        if actual_height >= 3 {
            let dropdown_area = Rect {
                x: area.x + offset_x,
                y: dropdown_y,
                width: area.width - offset_x,
                height: actual_height,
            };

            Clear.render(dropdown_area, buf);
            self.render_dropdown(dropdown_area, buf);
        }
    }

    fn render_dropdown(&self, area: Rect, buf: &mut Buffer) {
        let items: Vec<ListItem> = self
            .completer
            .suggestions
            .iter()
            .enumerate()
            .map(|(i, path)| {
                let mut display = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(path.to_str().unwrap_or("?"))
                    .to_string();

                // Add trailing slash for directories
                if path.is_dir() {
                    display.push('/');
                }

                let style = if i == self.completer.selected_index
                    && self.mode == CompletionMode::Selecting
                {
                    Style::default().bg(Color::Blue).fg(Color::White)
                } else if i == self.completer.selected_index {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default()
                };

                ListItem::new(display).style(style)
            })
            .collect();

        let list = List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .title("Select a file"),
        );

        list.render(area, buf);
    }

    pub fn value(&self) -> Result<PathBuf, String> {
        self.input.value()
    }

    pub fn clear(&mut self) {
        self.input.clear();
        self.completer.suggestions.clear();
        self.mode = CompletionMode::Editing;
        self.render_area = None;
    }

    pub fn set_content(&mut self, content: String) {
        self.input.set_content(content);
        self.completer.update_suggestions(self.input.content());
    }

    pub fn content(&self) -> &str {
        self.input.content()
    }
}

impl Default for CompletingInput {
    fn default() -> Self {
        Self::new()
    }
}
