//! TUI color palette: a bright, high-contrast variant inspired by the
//! opencode theme, lightened so text and accents pop on dark terminals.

use ratatui::style::{Color, Modifier, Style};

/// Default text color.
pub const INK: Color = Color::Rgb(0xf4, 0xf4, 0xf4);
/// Muted / de-emphasized text.
pub const MUTED: Color = Color::Rgb(0x9a, 0x9a, 0x9a);
/// Primary accent (peach).
pub const PRIMARY: Color = Color::Rgb(0xff, 0xc0, 0x92);
/// Secondary accent (violet) — headings / highlights.
pub const ACCENT: Color = Color::Rgb(0xc0, 0xa3, 0xf5);
/// Success / healthy (green).
pub const SUCCESS: Color = Color::Rgb(0x94, 0xea, 0xa2);
/// Warning (orange).
pub const WARNING: Color = Color::Rgb(0xfe, 0xbd, 0x5c);
/// Error / failed (red).
pub const ERROR: Color = Color::Rgb(0xff, 0x87, 0x8e);
/// Informational (teal).
pub const INFO: Color = Color::Rgb(0x6f, 0xd0, 0xda);
/// Dimmed / low-saturation (small-sample heatmap cells).
pub const DIM: Color = Color::Rgb(0x77, 0x77, 0x77);

/// Selected-row highlight: bold light text on a strong indigo background, so
/// the selection stays obvious on any terminal color scheme (a mid-gray
/// background washes out on some).
pub fn selected() -> Style {
    Style::default()
        .fg(INK)
        .bg(Color::Rgb(0x3f, 0x51, 0xb5))
        .add_modifier(Modifier::BOLD)
}
