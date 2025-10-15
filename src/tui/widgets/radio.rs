use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
    widgets::StatefulWidget,
};

/// State for the RadioGroup widget
#[derive(Debug, Clone)]
pub struct RadioGroupState {
    selected: Option<usize>,
    focused_index: Option<usize>,
}

impl RadioGroupState {
    pub fn new() -> Self {
        Self {
            selected: None,
            focused_index: None,
        }
    }

    pub fn with_selected(selected: Option<usize>) -> Self {
        Self {
            selected,
            focused_index: selected,
        }
    }

    pub fn select(&mut self, index: usize) {
        self.selected = Some(index);
    }

    pub fn deselect(&mut self) {
        self.selected = None;
    }

    pub fn selected(&self) -> Option<usize> {
        self.selected
    }

    pub fn is_selected(&self, index: usize) -> bool {
        self.selected == Some(index)
    }

    pub fn focus(&mut self, index: usize) {
        self.focused_index = Some(index);
    }

    pub fn unfocus(&mut self) {
        self.focused_index = None;
    }

    pub fn focused_index(&self) -> Option<usize> {
        self.focused_index
    }

    pub fn is_focused(&self, index: usize) -> bool {
        self.focused_index == Some(index)
    }

    pub fn next(&mut self, max: usize) {
        if max == 0 {
            return;
        }
        self.focused_index = Some(match self.focused_index {
            Some(i) => (i + 1) % max,
            None => 0,
        });
    }

    pub fn previous(&mut self, max: usize) {
        if max == 0 {
            return;
        }
        self.focused_index = Some(match self.focused_index {
            Some(i) => {
                if i == 0 {
                    max - 1
                } else {
                    i - 1
                }
            }
            None => max - 1,
        });
    }

    pub fn select_focused(&mut self) {
        if let Some(focused) = self.focused_index {
            self.selected = Some(focused);
        }
    }
}

impl Default for RadioGroupState {
    fn default() -> Self {
        Self::new()
    }
}

/// A single radio button option
#[derive(Debug, Clone)]
pub struct RadioButton<'a> {
    label: &'a str,
    selected: bool,
    focused: bool,
    selected_style: Style,
    unselected_style: Style,
    label_style: Style,
    focused_style: Style,
}

impl<'a> RadioButton<'a> {
    fn new(
        label: &'a str,
        selected: bool,
        focused: bool,
        selected_style: Style,
        unselected_style: Style,
        label_style: Style,
        focused_style: Style,
    ) -> Self {
        Self {
            label,
            selected,
            focused,
            selected_style,
            unselected_style,
            label_style,
            focused_style,
        }
    }

    fn render(&self, area: Rect, buf: &mut Buffer) {
        if area.width < 3 || area.height < 1 {
            return;
        }

        let (radio_text, style) = if self.selected {
            ("(●)", self.selected_style)
        } else {
            ("( )", self.unselected_style)
        };

        // Apply focused style if focused
        let style = if self.focused {
            self.focused_style
        } else {
            style
        };

        let mut x = area.x;
        let y = area.y;

        // Render radio button
        for (i, c) in radio_text.chars().enumerate() {
            if x + i as u16 >= area.x + area.width {
                break;
            }
            if let Some(cell) = buf.cell_mut((x + i as u16, y)) {
                cell.set_char(c);
                cell.set_style(style);
            }
        }
        x += 3;

        // Render label
        if x < area.x + area.width {
            // Add space between radio and label
            if let Some(cell) = buf.cell_mut((x, y)) {
                cell.set_char(' ');
            }
            x += 1;

            let label_style = if self.focused {
                self.focused_style
            } else {
                self.label_style
            };

            for (i, c) in self.label.chars().enumerate() {
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

/// Radio button group widget
#[derive(Debug, Clone)]
pub struct RadioGroup<'a> {
    options: Vec<&'a str>,
    selected_style: Style,
    unselected_style: Style,
    label_style: Style,
    focused_style: Style,
    spacing: u16,
}

impl<'a> RadioGroup<'a> {
    pub fn new(options: Vec<&'a str>) -> Self {
        Self {
            options,
            selected_style: Style::default().fg(Color::Green),
            unselected_style: Style::default().fg(Color::Gray),
            label_style: Style::default(),
            focused_style: Style::default().fg(Color::Yellow),
            spacing: 1,
        }
    }

    pub fn selected_style(mut self, style: Style) -> Self {
        self.selected_style = style;
        self
    }

    pub fn unselected_style(mut self, style: Style) -> Self {
        self.unselected_style = style;
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

    pub fn spacing(mut self, spacing: u16) -> Self {
        self.spacing = spacing;
        self
    }
}

impl<'a> StatefulWidget for RadioGroup<'a> {
    type State = RadioGroupState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        if area.height < 1 || self.options.is_empty() {
            return;
        }

        let mut y = area.y;

        for (index, option) in self.options.iter().enumerate() {
            if y >= area.y + area.height {
                break;
            }

            let radio_area = Rect {
                x: area.x,
                y,
                width: area.width,
                height: 1,
            };

            let radio = RadioButton::new(
                option,
                state.is_selected(index),
                state.is_focused(index),
                self.selected_style,
                self.unselected_style,
                self.label_style,
                self.focused_style,
            );

            radio.render(radio_area, buf);

            y += 1 + self.spacing;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_radio_group_state() {
        let mut state = RadioGroupState::new();
        assert_eq!(state.selected(), None);
        assert_eq!(state.focused_index(), None);

        state.select(1);
        assert_eq!(state.selected(), Some(1));
        assert!(state.is_selected(1));
        assert!(!state.is_selected(0));

        state.focus(2);
        assert_eq!(state.focused_index(), Some(2));
        assert!(state.is_focused(2));

        state.select_focused();
        assert_eq!(state.selected(), Some(2));
        assert!(state.is_selected(2));
        assert!(!state.is_selected(1));

        state.deselect();
        assert_eq!(state.selected(), None);
    }

    #[test]
    fn test_navigation() {
        let mut state = RadioGroupState::new();

        state.next(3);
        assert_eq!(state.focused_index(), Some(0));

        state.next(3);
        assert_eq!(state.focused_index(), Some(1));

        state.next(3);
        assert_eq!(state.focused_index(), Some(2));

        state.next(3);
        assert_eq!(state.focused_index(), Some(0));

        state.previous(3);
        assert_eq!(state.focused_index(), Some(2));
    }
}
