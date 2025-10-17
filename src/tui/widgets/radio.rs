use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Direction, Flex, Layout, Rect},
    style::{Color, Style},
};

#[derive(Debug, Clone)]
pub struct RadioButton {
    label: String,
    selected: bool,
    focused: bool,
    selected_style: Style,
    unselected_style: Style,
    label_style: Style,
    focused_style: Style,
}

impl RadioButton {
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            selected: false,
            focused: false,
            selected_style: Style::default().fg(Color::Green),
            unselected_style: Style::default().fg(Color::Gray),
            label_style: Style::default(),
            focused_style: Style::default().fg(Color::Yellow),
        }
    }

    pub fn with_selected(mut self, selected: bool) -> Self {
        self.selected = selected;
        self
    }

    pub fn with_focused(mut self, focused: bool) -> Self {
        self.focused = focused;
        self
    }

    pub fn with_selected_style(mut self, style: Style) -> Self {
        self.selected_style = style;
        self
    }

    pub fn with_unselected_style(mut self, style: Style) -> Self {
        self.unselected_style = style;
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

    pub fn set_selected(&mut self, selected: bool) {
        self.selected = selected;
    }

    pub fn set_focused(&mut self, focused: bool) {
        self.focused = focused;
    }

    pub fn is_selected(&self) -> bool {
        self.selected
    }

    pub fn is_focused(&self) -> bool {
        self.focused
    }

    pub fn render(&self, area: Rect, buf: &mut Buffer) {
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

impl Default for RadioButton {
    fn default() -> Self {
        Self::new("")
    }
}

/// Radio button group that renders multiple radio buttons and ensures mutual exclusivity
#[derive(Debug, Clone)]
pub struct RadioGroup {
    options: Vec<String>,
    selected_index: Option<usize>,
    focused_index: Option<usize>,
    selected_style: Style,
    unselected_style: Style,
    label_style: Style,
    focused_style: Style,
    spacing: u16,
    orientation: Direction,
}

impl RadioGroup {
    pub fn new(options: Vec<impl Into<String>>) -> Self {
        Self {
            options: options.into_iter().map(|s| s.into()).collect(),
            selected_index: None,
            focused_index: None,
            selected_style: Style::default().fg(Color::Green),
            unselected_style: Style::default().fg(Color::Gray),
            label_style: Style::default(),
            focused_style: Style::default().fg(Color::Yellow),
            spacing: 1,
            orientation: Direction::Horizontal,
        }
    }

    pub fn with_selected(mut self, index: Option<usize>) -> Self {
        self.selected_index = index;
        self
    }

    pub fn with_focused(mut self, index: Option<usize>) -> Self {
        self.focused_index = index;
        self
    }

    pub fn with_selected_style(mut self, style: Style) -> Self {
        self.selected_style = style;
        self
    }

    pub fn with_unselected_style(mut self, style: Style) -> Self {
        self.unselected_style = style;
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

    pub fn with_spacing(mut self, spacing: u16) -> Self {
        self.spacing = spacing;
        self
    }

    pub fn with_orientation(mut self, orientation: Direction) -> Self {
        self.orientation = orientation;
        self
    }

    pub fn set_selected(&mut self, index: Option<usize>) {
        self.selected_index = index;
    }

    pub fn set_focused(&mut self, index: Option<usize>) {
        self.focused_index = index;
    }

    pub fn select_focused(&mut self) {
        self.selected_index = self.focused_index;
    }

    pub fn next_focus(&mut self) {
        if self.options.is_empty() {
            return;
        }
        self.focused_index = Some(match self.focused_index {
            Some(i) => (i + 1) % self.options.len(),
            None => 0,
        });
    }

    pub fn previous_focus(&mut self) {
        if self.options.is_empty() {
            return;
        }
        self.focused_index = Some(match self.focused_index {
            Some(i) => {
                if i == 0 {
                    self.options.len() - 1
                } else {
                    i - 1
                }
            }
            None => self.options.len() - 1,
        });
    }

    pub fn selected_index(&self) -> Option<usize> {
        self.selected_index
    }

    pub fn focused_index(&self) -> Option<usize> {
        self.focused_index
    }

    pub fn render(&self, area: Rect, buf: &mut Buffer) {
        let constraints: Vec<Constraint> = match self.orientation {
            Direction::Vertical => self.options.iter().map(|_| Constraint::Length(1)).collect(),
            Direction::Horizontal => self
                .options
                .iter()
                .map(|option| Constraint::Length(4 + option.len() as u16))
                .collect(),
        };

        let layout = Layout::default()
            .direction(self.orientation)
            .constraints(constraints)
            .flex(Flex::SpaceBetween)
            .spacing(self.spacing)
            .split(area);

        for (index, (option, &radio_area)) in self.options.iter().zip(layout.iter()).enumerate() {
            let radio = RadioButton::new(option)
                .with_selected(self.selected_index == Some(index))
                .with_focused(self.focused_index == Some(index))
                .with_selected_style(self.selected_style)
                .with_unselected_style(self.unselected_style)
                .with_label_style(self.label_style)
                .with_focused_style(self.focused_style);

            radio.render(radio_area, buf);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_radio_button() {
        let mut radio = RadioButton::new("Option");
        assert!(!radio.is_selected());

        radio.set_selected(true);
        assert!(radio.is_selected());
    }

    #[test]
    fn test_radio_group() {
        let mut group = RadioGroup::new(vec!["A", "B", "C"]);
        assert_eq!(group.selected_index(), None);

        group.set_focused(Some(1));
        group.select_focused();
        assert_eq!(group.selected_index(), Some(1));

        group.next_focus();
        assert_eq!(group.focused_index(), Some(2));

        group.previous_focus();
        assert_eq!(group.focused_index(), Some(1));
    }
}
