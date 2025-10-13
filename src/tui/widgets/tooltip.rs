use ratatui::{
    buffer::Buffer,
    layout::{Alignment, Rect},
    style::{Color, Style},
    text::{Line, Text},
    widgets::{Block, Borders, Clear, Paragraph, StatefulWidget, Widget, Wrap},
};

/// State for the Tooltip widget
#[derive(Debug, Clone, Default)]
pub struct TooltipState {
    visible: bool,
}

impl TooltipState {
    pub fn new() -> Self {
        Self { visible: false }
    }

    pub fn show(&mut self) {
        self.visible = true;
    }

    pub fn hide(&mut self) {
        self.visible = false;
    }

    pub fn toggle(&mut self) {
        self.visible = !self.visible;
    }

    pub fn is_visible(&self) -> bool {
        self.visible
    }

    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }
}

/// Position of the tooltip relative to a reference point
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TooltipPosition {
    Above,
    Below,
    Left,
    Right,
    AboveLeft,
    AboveRight,
    BelowLeft,
    BelowRight,
    Cursor(u16, u16), // Absolute position (x, y)
}

/// Tooltip widget that renders a floating window
#[derive(Debug, Clone)]
pub struct Tooltip<'a> {
    content: Text<'a>,
    position: TooltipPosition,
    reference_area: Option<Rect>,
    width: Option<u16>,
    max_width: Option<u16>,
    style: Style,
    border_style: Style,
    border_type: Borders,
    title: Option<&'a str>,
    padding: u16,
}

impl<'a> Tooltip<'a> {
    pub fn new<T>(content: T) -> Self
    where
        T: Into<Text<'a>>,
    {
        Self {
            content: content.into(),
            position: TooltipPosition::Below,
            reference_area: None,
            width: None,
            max_width: Some(40),
            style: Style::default().bg(Color::Black).fg(Color::White),
            border_style: Style::default().fg(Color::Gray),
            border_type: Borders::ALL,
            title: None,
            padding: 1,
        }
    }

    /// Set the content of the tooltip
    pub fn content<T>(mut self, content: T) -> Self
    where
        T: Into<Text<'a>>,
    {
        self.content = content.into();
        self
    }

    /// Set the position of the tooltip
    pub fn position(mut self, position: TooltipPosition) -> Self {
        self.position = position;
        self
    }

    /// Set the reference area (e.g., the widget the tooltip is attached to)
    pub fn reference_area(mut self, area: Rect) -> Self {
        self.reference_area = Some(area);
        self
    }

    /// Set a fixed width for the tooltip
    pub fn width(mut self, width: u16) -> Self {
        self.width = Some(width);
        self
    }

    /// Set the maximum width for the tooltip (used with text wrapping)
    pub fn max_width(mut self, max_width: u16) -> Self {
        self.max_width = Some(max_width);
        self
    }

    /// Set the style of the tooltip content area
    pub fn style(mut self, style: Style) -> Self {
        self.style = style;
        self
    }

    /// Set the border style
    pub fn border_style(mut self, style: Style) -> Self {
        self.border_style = style;
        self
    }

    /// Set the border type
    pub fn border_type(mut self, border_type: Borders) -> Self {
        self.border_type = border_type;
        self
    }

    /// Set a title for the tooltip
    pub fn title(mut self, title: &'a str) -> Self {
        self.title = Some(title);
        self
    }

    /// Set padding inside the tooltip
    pub fn padding(mut self, padding: u16) -> Self {
        self.padding = padding;
        self
    }

    /// Calculate the tooltip area based on position and content
    fn calculate_area(&self, parent_area: Rect) -> Rect {
        let content_width = self.width.unwrap_or_else(|| {
            let max_line_width = self
                .content
                .lines
                .iter()
                .map(|line| line.width())
                .max()
                .unwrap_or(0) as u16;

            let width = max_line_width + (self.padding * 2) + 2; // +2 for borders

            if let Some(max_w) = self.max_width {
                width.min(max_w)
            } else {
                width
            }
        });

        let content_height = (self.content.lines.len() as u16) + (self.padding * 2) + 2; // +2 for borders

        let (x, y) = match self.position {
            TooltipPosition::Cursor(cx, cy) => (cx, cy),
            _ => {
                let ref_area = self.reference_area.unwrap_or(Rect {
                    x: parent_area.width / 2,
                    y: parent_area.height / 2,
                    width: 1,
                    height: 1,
                });

                match self.position {
                    TooltipPosition::Above => {
                        (ref_area.x, ref_area.y.saturating_sub(content_height))
                    }
                    TooltipPosition::Below => (ref_area.x, ref_area.y + ref_area.height),
                    TooltipPosition::Left => (ref_area.x.saturating_sub(content_width), ref_area.y),
                    TooltipPosition::Right => (ref_area.x + ref_area.width, ref_area.y),
                    TooltipPosition::AboveLeft => (
                        ref_area.x.saturating_sub(content_width),
                        ref_area.y.saturating_sub(content_height),
                    ),
                    TooltipPosition::AboveRight => (
                        ref_area.x + ref_area.width,
                        ref_area.y.saturating_sub(content_height),
                    ),
                    TooltipPosition::BelowLeft => (
                        ref_area.x.saturating_sub(content_width),
                        ref_area.y + ref_area.height,
                    ),
                    TooltipPosition::BelowRight => {
                        (ref_area.x + ref_area.width, ref_area.y + ref_area.height)
                    }
                    TooltipPosition::Cursor(_, _) => unreachable!(),
                }
            }
        };

        // Ensure tooltip stays within parent area bounds
        let x = x.min(parent_area.width.saturating_sub(content_width));
        let y = y.min(parent_area.height.saturating_sub(content_height));
        let width = content_width.min(parent_area.width.saturating_sub(x));
        let height = content_height.min(parent_area.height.saturating_sub(y));

        Rect {
            x,
            y,
            width,
            height,
        }
    }
}

impl<'a> StatefulWidget for Tooltip<'a> {
    type State = TooltipState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        if !state.visible {
            return;
        }

        let tooltip_area = self.calculate_area(area);

        // Clear the area behind the tooltip to prevent overlap artifacts
        Clear.render(tooltip_area, buf);

        // Create the block with borders
        let mut block = Block::default()
            .borders(self.border_type)
            .style(self.style)
            .border_style(self.border_style);

        if let Some(title) = self.title {
            block = block.title(title);
        }

        let inner_area = block.inner(tooltip_area);
        block.render(tooltip_area, buf);

        // Render the content
        let paragraph = Paragraph::new(self.content.clone())
            .style(self.style)
            .wrap(Wrap { trim: true });

        paragraph.render(inner_area, buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tooltip_state() {
        let mut state = TooltipState::new();
        assert!(!state.is_visible());

        state.show();
        assert!(state.is_visible());

        state.hide();
        assert!(!state.is_visible());

        state.toggle();
        assert!(state.is_visible());

        state.set_visible(false);
        assert!(!state.is_visible());
    }
}
