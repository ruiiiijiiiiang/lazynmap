use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Direction, Layout, Rect},
    prelude::*,
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::tui::{
    config::{FOCUSED_STYLE, SELECTED_STYLE},
    widgets::text_input::InputWidget,
};

pub struct Checkbox<'a> {
    label: String,
    checked: bool,
    focused: bool,
    marked: bool,
    input: Option<&'a mut InputWidget>,
    input_editing: bool,
    checked_style: Style,
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
            checked_style: *SELECTED_STYLE,
            focused_style: *FOCUSED_STYLE,
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

        let style = Style::default()
            .patch(if self.focused {
                self.focused_style
            } else {
                Style::default()
            })
            .patch(if self.checked {
                self.checked_style
            } else {
                Style::default()
            });

        let checkbox_text = if self.checked { "[X]" } else { "[ ]" };

        let marker = if self.marked {
            Span::styled("*", style).red()
        } else {
            Span::styled(" ", style)
        };
        let line = Line::from(vec![
            Span::styled(checkbox_text, style),
            marker,
            Span::styled(&self.label, style),
        ]);

        if let Some(ref mut input) = self.input {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(line.width() as u16), Constraint::Min(0)])
                .split(area);

            Paragraph::new(line).render(chunks[0], buf);
            input.render(
                chunks[1],
                buf,
                self.focused,
                self.checked,
                self.input_editing,
            );
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
