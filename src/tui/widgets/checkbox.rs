use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
    text::Span,
    widgets::{StatefulWidget, Widget},
};

/// State for the Checkbox widget
#[derive(Debug, Clone, Default)]
pub struct CheckboxState {
    pub checked: bool,
    pub focused: bool,
}

impl CheckboxState {
    pub fn new(checked: bool) -> Self {
        Self {
            checked,
            focused: false,
        }
    }

    pub fn toggle(&mut self) {
        self.checked = !self.checked;
    }

    pub fn set(&mut self, checked: bool) {
        self.checked = checked;
    }

    pub fn is_checked(&self) -> bool {
        self.checked
    }

    pub fn set_focused(&mut self, focused: bool) {
        self.focused = focused;
    }

    pub fn focus(&mut self) {
        self.focused = true;
    }

    pub fn unfocus(&mut self) {
        self.focused = false;
    }

    pub fn is_focused(&self) -> bool {
        self.focused
    }
}

/// Checkbox widget with customizable colors
#[derive(Debug, Clone)]
pub struct Checkbox<'a> {
    label: Option<&'a str>,
    checked_style: Style,
    unchecked_style: Style,
    label_style: Style,
    focused_style: Style,
}

impl<'a> Checkbox<'a> {
    pub fn new() -> Self {
        Self {
            label: None,
            checked_style: Style::default().fg(Color::Green),
            unchecked_style: Style::default().fg(Color::Gray),
            label_style: Style::default(),
            focused_style: Style::default().fg(Color::Yellow),
        }
    }

    pub fn label(mut self, label: &'a str) -> Self {
        self.label = Some(label);
        self
    }

    pub fn checked_style(mut self, style: Style) -> Self {
        self.checked_style = style;
        self
    }

    pub fn unchecked_style(mut self, style: Style) -> Self {
        self.unchecked_style = style;
        self
    }

    pub fn label_style(mut self, style: Style) -> Self {
        self.label_style = style;
        self
    }

    pub fn focused_style(mut self, style: Style) -> Self {
        self.focused_style = style;
        self
    }
}

impl<'a> Default for Checkbox<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> StatefulWidget for Checkbox<'a> {
    type State = CheckboxState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        if area.width < 3 || area.height < 1 {
            return;
        }

        let (checkbox_text, style) = if state.checked {
            ("[X]", self.checked_style)
        } else {
            ("[ ]", self.unchecked_style)
        };

        // Apply focused style if focused
        let style = if state.focused {
            self.focused_style
        } else {
            style
        };

        let mut x = area.x;
        let y = area.y;

        // Render checkbox
        for (i, c) in checkbox_text.chars().enumerate() {
            if x + i as u16 >= area.x + area.width {
                break;
            }
            if let Some(cell) = buf.cell_mut((x + i as u16, y)) {
                cell.set_char(c);
                cell.set_style(style);
            }
        }
        x += 3;

        // Render label if present
        if let Some(label) = self.label
            && x < area.x + area.width
        {
            // Add space between checkbox and label
            if let Some(cell) = buf.cell_mut((x, y)) {
                cell.set_char(' ');
            }
            x += 1;

            let label_style = if state.focused {
                self.focused_style
            } else {
                self.label_style
            };

            for (i, c) in label.chars().enumerate() {
                if x + i as u16 >= area.x + area.width {
                    break;
                }
                if let Some(cell) = buf.cell_mut((x + i as u16, y)) {
                    cell.set_char(c);
                    cell.set_style(label_style);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkbox_state() {
        let mut state = CheckboxState::new(false);
        assert!(!state.is_checked());
        assert!(!state.is_focused());

        state.toggle();
        assert!(state.is_checked());

        state.set(false);
        assert!(!state.is_checked());

        state.focus();
        assert!(state.is_focused());

        state.unfocus();
        assert!(!state.is_focused());

        state.set_focused(true);
        assert!(state.is_focused());
    }
}
