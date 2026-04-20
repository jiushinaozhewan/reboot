//! Reboot Client - Remote power management controller
//!
//! GUI application for sending authenticated remote shutdown, restart,
//! and Wake-on-LAN commands to the agent.

mod config;
mod connection;
mod logging;
mod scan;
mod secret_store;
mod target;
mod ui;
mod wol;

use iced::font::Family;
use iced::{Font, Size};

/// Default font with Chinese support (Microsoft YaHei on Windows)
const DEFAULT_FONT: Font = Font {
    family: Family::Name("Microsoft YaHei"),
    weight: iced::font::Weight::Normal,
    stretch: iced::font::Stretch::Normal,
    style: iced::font::Style::Normal,
};

fn main() -> iced::Result {
    let config = config::Config::load_or_create();
    logging::init(config.log_enabled);

    // Run the GUI with Chinese font support
    iced::application("远程电源管理 - 多目标控制", ui::App::update, ui::App::view)
        .window_size(Size::new(1000.0, 700.0))
        .resizable(true)
        .theme(ui::App::theme)
        .default_font(DEFAULT_FONT)
        .run_with(move || ui::App::new_with_config(config.clone()))
}
