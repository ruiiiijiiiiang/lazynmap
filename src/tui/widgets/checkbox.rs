use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
};

/// Checkbox widget that manages its own state
#[derive(Debug, Clone)]
pub struct Checkbox {
    label: String,
    checked: bool,
    focused: bool,
    checked_style: Style,
    unchecked_style: Style,
    label_style: Style,
    focused_style: Style,
}

impl Checkbox {
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            checked: false,
            focused: false,
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

    pub fn render(&self, area: Rect, buf: &mut Buffer) {
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

        // Create line with checkbox and label
        let line = Line::from(vec![
            Span::styled(checkbox_text, checkbox_style),
            Span::styled(" ", label_style),
            Span::styled(&self.label, label_style),
        ]);

        buf.set_line(area.x, area.y, &line, area.width);
    }
}

impl Default for Checkbox {
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
