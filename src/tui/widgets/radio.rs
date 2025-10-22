use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Direction, Flex, Layout, Rect},
    prelude::*,
    style::{Color, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::tui::widgets::text_input::InputWidget;

pub struct RadioButton<'a> {
    label: String,
    selected: bool,
    focused: bool,
    input: Option<&'a mut InputWidget>,
    input_editing: bool,
    selected_style: Style,
    unselected_style: Style,
    label_style: Style,
    focused_style: Style,
}

impl<'a> RadioButton<'a> {
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            selected: false,
            focused: false,
            input: None,
            input_editing: false,
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

    pub fn with_input(mut self, input: Option<&'a mut InputWidget>) -> Self {
        self.input = input;
        self
    }

    pub fn with_editing(mut self, editing: bool) -> Self {
        self.input_editing = editing;
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

    pub fn render(&mut self, area: Rect, buf: &mut Buffer) {
        if area.width < 3 || area.height < 1 {
            return;
        }

        let (radio_text, radio_style) = if self.selected {
            ("(●)", self.selected_style)
        } else {
            ("( )", self.unselected_style)
        };

        // Apply focused style if focused
        let radio_style = if self.focused {
            self.focused_style
        } else {
            radio_style
        };

        let label_style = if self.focused {
            self.focused_style
        } else {
            self.label_style
        };

        let line = Line::from(vec![
            Span::styled(radio_text, radio_style),
            Span::raw(" "),
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

impl Default for RadioButton<'_> {
    fn default() -> Self {
        Self::new("")
    }
}

pub enum RadioOption<'a> {
    Text(String),
    Input(&'a mut InputWidget),
}

impl<'a> From<&'a mut InputWidget> for RadioOption<'a> {
    fn from(input: &'a mut InputWidget) -> Self {
        RadioOption::Input(input)
    }
}

impl From<&str> for RadioOption<'_> {
    fn from(s: &str) -> Self {
        RadioOption::Text(s.to_string())
    }
}

/// Radio button group that renders multiple radio buttons and ensures mutual exclusivity
pub struct RadioGroup<'a> {
    options: Vec<RadioOption<'a>>,
    selected_index: Option<usize>,
    focused_index: Option<usize>,
    editing_index: Option<usize>,
    selected_style: Style,
    unselected_style: Style,
    label_style: Style,
    focused_style: Style,
    spacing: u16,
    num_per_row: Option<u16>,
}

impl<'a> RadioGroup<'a> {
    pub fn new<T: Into<RadioOption<'a>>>(options: Vec<T>) -> Self {
        Self {
            options: options.into_iter().map(|s| s.into()).collect(),
            selected_index: None,
            focused_index: None,
            editing_index: None,
            selected_style: Style::default().fg(Color::Green),
            unselected_style: Style::default().fg(Color::Gray),
            label_style: Style::default(),
            focused_style: Style::default().fg(Color::Yellow),
            spacing: 1,
            num_per_row: None,
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

    pub fn with_editing(mut self, index: Option<usize>) -> Self {
        self.editing_index = index;
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

    pub fn with_num_per_row(mut self, num_per_row: u16) -> Self {
        self.num_per_row = Some(num_per_row);
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

    pub fn render(&mut self, area: Rect, buf: &mut Buffer) {
        let num_per_row = self.num_per_row.unwrap_or(self.options.len() as u16);
        let num_rows = (self.options.len() as u16).div_ceil(num_per_row);

        let row_constraints: Vec<Constraint> =
            (0..num_rows).map(|_| Constraint::Length(1)).collect();
        let row_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints(row_constraints)
            .spacing(self.spacing)
            .split(area);

        for row_index in 0..num_rows as usize {
            let start_index = row_index * num_per_row as usize;
            let end_index = ((row_index + 1) * num_per_row as usize).min(self.options.len());
            let row_options = &mut self.options[start_index..end_index];

            let num_cols = row_options.len() as u16;
            let col_constraints: Vec<Constraint> = (0..num_cols)
                .map(|_| Constraint::Percentage(100 / num_cols))
                .collect();
            let col_layout = Layout::default()
                .direction(Direction::Horizontal)
                .constraints(col_constraints)
                .flex(Flex::SpaceBetween)
                .spacing(self.spacing)
                .split(row_layout[row_index]);

            for (col_index, (option, &radio_area)) in
                row_options.iter_mut().zip(col_layout.iter()).enumerate()
            {
                let index = start_index + col_index;
                let mut radio = match option {
                    RadioOption::Text(label) => RadioButton::new(label.as_str()).with_input(None),
                    RadioOption::Input(input) => RadioButton::new("")
                        .with_input(Some(input))
                        .with_editing(self.editing_index == Some(index)),
                }
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
