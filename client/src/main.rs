//! Reboot Client - Remote power management controller
//!
//! GUI application for sending authenticated remote shutdown, restart,
//! and Wake-on-LAN commands to the agent.

mod config;
mod connection;
mod target;
mod ui;
mod wol;

use iced::font::Family;
use iced::{Font, Size};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

/// Default font with Chinese support (Microsoft YaHei on Windows)
const DEFAULT_FONT: Font = Font {
    family: Family::Name("Microsoft YaHei"),
    weight: iced::font::Weight::Normal,
    stretch: iced::font::Stretch::Normal,
    style: iced::font::Style::Normal,
};

fn main() -> iced::Result {
    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("Failed to set subscriber");

    tracing::info!("Reboot Client starting...");

    // Run the GUI with Chinese font support
    iced::application("远程电源管理 - 多目标控制", ui::App::update, ui::App::view)
        .window_size(Size::new(1000.0, 700.0))
        .resizable(true)
        .theme(ui::App::theme)
        .default_font(DEFAULT_FONT)
        .run_with(ui::App::new)
}
