use once_cell::sync::Lazy;
use ratatui::style::{Color, Modifier, Style};

pub static FOCUSED_STYLE: Lazy<Style> = Lazy::new(|| {
    Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD)
        .add_modifier(Modifier::UNDERLINED)
});
pub static SELECTED_STYLE: Lazy<Style> =
    Lazy::new(|| Style::default().bg(Color::Cyan).fg(Color::Black));
pub static EDITING_STYLE: Lazy<Style> =
    Lazy::new(|| Style::default().bg(Color::Blue).fg(Color::Black));
pub static INPUT_FOCUSED_STYLE: Lazy<Style> = Lazy::new(|| {
    Style::default()
        .bg(Color::Yellow)
        .fg(Color::Black)
        .add_modifier(Modifier::BOLD)
        .add_modifier(Modifier::UNDERLINED)
});
