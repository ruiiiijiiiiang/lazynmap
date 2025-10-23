use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Direction, Layout, Rect},
    prelude::*,
    style::{Color, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::tui::widgets::text_input::InputWidget;

/// Checkbox widget that manages its own state
pub struct Checkbox<'a> {
    label: String,
    checked: bool,
    focused: bool,
    marked: bool,
    input: Option<&'a mut InputWidget>,
    input_editing: bool,
    checked_style: Style,
    unchecked_style: Style,
    label_style: Style,
    focused_style: Style,
}

impl<'a> Checkbox<'a> {
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            checked: false,
            focused: false,
            marked: false,
            input: None,
            input_editing: false,
            checked_style: Style::default().fg(Color::Green),
            unchecked_style: Style::default().fg(Color::Gray),
            label_style: Style::default(),
            focused_style: Style::default().fg(Color::Yellow),
        }
    }

    pub fn with_checked(mut self, checked: bool) -> Self {
        self.checked = checked;
        self
    }

    pub fn with_focused(mut self, focused: bool) -> Self {
        self.focused = focused;
        self
    }

    pub fn with_marked(mut self, marked: bool) -> Self {
        self.marked = marked;
        self
    }

    pub fn with_input(mut self, input: Option<&'a mut InputWidget>) -> Self {
        self.input = input;
        self
    }

    pub fn with_editing(mut self, editing: bool) -> Self {
        self.input_editing = editing;
        self
    }

    pub fn with_checked_style(mut self, style: Style) -> Self {
        self.checked_style = style;
        self
    }

    pub fn with_unchecked_style(mut self, style: Style) -> Self {
        self.unchecked_style = style;
        self
    }

    pub fn with_label_style(mut self, style: Style) -> Self {
        self.label_style = style;
        self
    }

    pub fn with_focused_style(mut self, style: Style) -> Self {
        self.focused_style = style;
        self
    }

    pub fn set_checked(&mut self, checked: bool) {
        self.checked = checked;
    }

    pub fn set_focused(&mut self, focused: bool) {
        self.focused = focused;
    }

    pub fn toggle(&mut self) {
        self.checked = !self.checked;
    }

    pub fn is_checked(&self) -> bool {
        self.checked
    }

    pub fn is_focused(&self) -> bool {
        self.focused
    }

    pub fn render(&mut self, area: Rect, buf: &mut Buffer) {
        if area.width < 3 || area.height < 1 {
            return;
        }

        let (checkbox_text, checkbox_style) = if self.checked {
            ("[X]", self.checked_style)
        } else {
            ("[ ]", self.unchecked_style)
        };

        let checkbox_style = if self.focused {
            self.focused_style
        } else {
            checkbox_style
        };

        let label_style = if self.focused {
            self.focused_style
        } else {
            self.label_style
        };

        let marker = if self.marked {
            Span::styled("*", Style::default().fg(Color::Red))
        } else {
            Span::styled(" ", label_style)
        };
        let line = Line::from(vec![
            Span::styled(checkbox_text, checkbox_style),
            marker,
            Span::styled(&self.label, label_style),
        ]);

        if let Some(ref mut input) = self.input {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(line.width() as u16), Constraint::Min(0)])
                .split(area);

            Paragraph::new(line).render(chunks[0], buf);
            input.render(chunks[1], buf, self.focused, self.input_editing);
        } else {
            buf.set_line(area.x, area.y, &line, area.width);
        }
    }
}

impl Default for Checkbox<'_> {
    fn default() -> Self {
        Self::new("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkbox() {
        let mut checkbox = Checkbox::new("Test");
        assert!(!checkbox.is_checked());
        assert!(!checkbox.is_focused());

        checkbox.toggle();
        assert!(checkbox.is_checked());

        checkbox.set_focused(true);
        assert!(checkbox.is_focused());
    }
}
