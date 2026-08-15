//! TUI color palette, matching the opencode dark theme
//! (https://opencode.ai, `packages/ui/src/theme/themes/opencode.json`).

use ratatui::style::Color;

/// Default text color.
pub const INK: Color = Color::Rgb(0xee, 0xee, 0xee);
/// Muted / de-emphasized text.
pub const MUTED: Color = Color::Rgb(0x80, 0x80, 0x80);
/// Primary accent (peach).
pub const PRIMARY: Color = Color::Rgb(0xfa, 0xb2, 0x83);
/// Secondary accent (violet) — headings / highlights.
pub const ACCENT: Color = Color::Rgb(0x9d, 0x7c, 0xd8);
/// Success / healthy (green).
pub const SUCCESS: Color = Color::Rgb(0x7f, 0xd8, 0x8f);
/// Warning (orange).
pub const WARNING: Color = Color::Rgb(0xf5, 0xa7, 0x42);
/// Error / failed (red).
pub const ERROR: Color = Color::Rgb(0xe0, 0x6c, 0x75);
/// Informational (teal).
pub const INFO: Color = Color::Rgb(0x56, 0xb6, 0xc2);
