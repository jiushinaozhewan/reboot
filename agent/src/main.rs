//! Reboot Agent - Remote power management service
//!
//! Runs as a system tray application, accepting remote commands for
//! shutdown, restart, and Wake-on-LAN coordination.

#![windows_subsystem = "windows"]

mod config;
mod executor;
mod security;
mod server;
mod tray;

use config::Config;
use server::Server;
use std::sync::{mpsc, Arc, Mutex};
use tokio::sync::watch;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

fn main() {
    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_file(true)
        .with_line_number(true)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("Failed to set subscriber");

    info!("Reboot Agent starting...");

    // Load or create configuration
    let (config, is_new) = match Config::load_or_create() {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            show_error(&format!("配置加载失败: {}", e));
            return;
        }
    };

    let psk_hex = config.psk_hex.clone();
    let port = config.port;

    // Show welcome dialog on first run
    if is_new {
        tray::show_welcome_dialog(&psk_hex, port);
    }

    // Create shutdown channel
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Create action channel for tray
    let (action_tx, action_rx) = mpsc::channel();

    // Shared config for modifications
    let shared_config = Arc::new(Mutex::new(config.clone()));

    // Start server in background thread
    let server_config = config.clone();
    let server_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create runtime");

        rt.block_on(async {
            let server = match Server::new(server_config, shutdown_rx) {
                Ok(s) => s,
                Err(e) => {
                    error!("Failed to create server: {}", e);
                    return;
                }
            };

            if let Err(e) = server.run().await {
                error!("Server error: {}", e);
            }
        });
    });

    // Check auto-start status
    let autostart_enabled = tray::is_autostart_enabled();

    // Handle tray actions in background
    let tray_config = shared_config.clone();
    std::thread::spawn(move || {
        while let Ok(action) = action_rx.recv() {
            match action {
                tray::TrayAction::SetPort => {
                    let current_port = {
                        let cfg = tray_config.lock().unwrap();
                        cfg.port
                    };

                    if let Some(new_port) = tray::show_port_dialog(current_port) {
                        // Update config
                        {
                            let mut cfg = tray_config.lock().unwrap();
                            cfg.port = new_port;
                            if let Err(e) = cfg.save() {
                                error!("Failed to save config: {}", e);
                                show_error(&format!("保存配置失败: {}", e));
                                continue;
                            }
                        }

                        info!("Port changed to {}", new_port);

                        // Ask user to restart
                        if tray::show_restart_confirm_dialog(&format!(
                            "端口已更改为 {}\n配置已保存。",
                            new_port
                        )) {
                            restart_application();
                        }
                    }
                }
                tray::TrayAction::ShowKey => {
                    let psk_hex = {
                        let cfg = tray_config.lock().unwrap();
                        cfg.psk_hex.clone()
                    };
                    tray::show_key_dialog(&psk_hex);
                }
                tray::TrayAction::SetKey => {
                    let current_key = {
                        let cfg = tray_config.lock().unwrap();
                        cfg.psk_hex.clone()
                    };

                    if let Some(new_key) = tray::show_set_key_dialog(&current_key) {
                        // Update config
                        {
                            let mut cfg = tray_config.lock().unwrap();
                            cfg.psk_hex = new_key.clone();
                            if let Err(e) = cfg.save() {
                                error!("Failed to save config: {}", e);
                                show_error(&format!("保存配置失败: {}", e));
                                continue;
                            }
                        }

                        info!("PSK key changed");

                        // Ask user to restart
                        if tray::show_restart_confirm_dialog("密钥已更改\n配置已保存。") {
                            restart_application();
                        }
                    }
                }
                tray::TrayAction::ToggleAutoStart => {
                    let current_state = tray::is_autostart_enabled();
                    let new_state = !current_state;

                    match tray::set_autostart_enabled(new_state) {
                        Ok(()) => {
                            info!(
                                "Auto-start {}",
                                if new_state { "enabled" } else { "disabled" }
                            );
                            let msg = if new_state {
                                "开机启动已启用"
                            } else {
                                "开机启动已禁用"
                            };
                            let _ = native_dialog::MessageDialog::new()
                                .set_title("开机启动")
                                .set_text(msg)
                                .set_type(native_dialog::MessageType::Info)
                                .show_alert();
                        }
                        Err(e) => {
                            error!("Failed to set auto-start: {}", e);
                            show_error(&format!("设置开机启动失败: {}", e));
                        }
                    }
                }
                tray::TrayAction::Exit => {
                    info!("Exit requested via tray");
                    let _ = shutdown_tx.send(true);
                    // Give server time to shutdown
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    std::process::exit(0);
                }
            }
        }
    });

    // Run tray event loop (blocks)
    if let Err(e) = tray::run_tray(action_tx, autostart_enabled) {
        error!("Tray error: {}", e);
    }

    // Wait for server to finish
    let _ = server_handle.join();

    info!("Reboot Agent stopped");
}

fn show_error(message: &str) {
    use native_dialog::{MessageDialog, MessageType};

    let _ = MessageDialog::new()
        .set_title("错误")
        .set_text(message)
        .set_type(MessageType::Error)
        .show_alert();
}

/// Restart the application
fn restart_application() {
    use std::process::Command;

    info!("Restarting application...");

    // Get current executable path
    if let Ok(exe_path) = std::env::current_exe() {
        // Spawn new instance
        let _ = Command::new(&exe_path).spawn();
    }

    // Exit current instance
    std::process::exit(0);
}
