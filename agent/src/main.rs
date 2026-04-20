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
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;
use tracing::{error, info, warn, Level};
use tracing_subscriber::fmt::writer::MakeWriter;
use tracing_subscriber::FmtSubscriber;

#[derive(Clone)]
struct FileLogWriter {
    controller: Arc<LogController>,
}

struct LogController {
    enabled: AtomicBool,
    file: Mutex<Option<std::fs::File>>,
    path: PathBuf,
}

impl LogController {
    fn new(path: PathBuf, enabled: bool) -> Self {
        Self {
            enabled: AtomicBool::new(enabled),
            file: Mutex::new(None),
            path,
        }
    }

    fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
        if !enabled {
            if let Ok(mut file) = self.file.lock() {
                *file = None;
            }
        }
    }

    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        if !self.is_enabled() {
            return Ok(buf.len());
        }

        let mut file_guard = self
            .file
            .lock()
            .map_err(|_| io::Error::other("log file lock poisoned"))?;

        if file_guard.is_none() {
            if let Some(parent) = self.path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?;
            *file_guard = Some(file);
        }

        match file_guard.as_mut() {
            Some(file) => file.write(buf),
            None => Err(io::Error::other("log file unavailable")),
        }
    }

    fn flush(&self) -> io::Result<()> {
        if !self.is_enabled() {
            return Ok(());
        }

        let mut file_guard = self
            .file
            .lock()
            .map_err(|_| io::Error::other("log file lock poisoned"))?;

        if let Some(file) = file_guard.as_mut() {
            file.flush()
        } else {
            Ok(())
        }
    }
}

impl<'a> MakeWriter<'a> for FileLogWriter {
    type Writer = FileLogGuard;

    fn make_writer(&'a self) -> Self::Writer {
        FileLogGuard {
            controller: self.controller.clone(),
        }
    }
}

struct FileLogGuard {
    controller: Arc<LogController>,
}

impl Write for FileLogGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.controller.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.controller.flush()
    }
}

fn main() {
    #[cfg(windows)]
    if let Some(exit_code) = tray::run_dialog_helper_if_requested() {
        std::process::exit(exit_code);
    }

    let log_dir = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|dir| dir.to_path_buf()))
        .or_else(|| {
            Config::config_path()
                .ok()
                .and_then(|path| path.parent().map(|dir| dir.to_path_buf()))
        })
        .unwrap_or_else(std::env::temp_dir);
    let log_path = log_dir.join("log.txt");

    // Load or create configuration
    let (config, is_new) = match Config::load_or_create() {
        Ok(result) => result,
        Err(e) => {
            show_error(&format!("配置加载失败: {}", e));
            return;
        }
    };

    let log_controller = Arc::new(LogController::new(log_path.clone(), config.log_enabled));
    let file_writer = FileLogWriter {
        controller: log_controller.clone(),
    };

    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_file(true)
        .with_line_number(true)
        .with_ansi(false)
        .with_writer(file_writer)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("Failed to set subscriber");

    if config.log_enabled {
        info!("Reboot Agent starting...");
        info!("Logging to {:?}", log_path);
        if let Ok(exe_path) = std::env::current_exe() {
            info!("Executable path: {:?}", exe_path);
        }
    }

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
                    show_error(&format!("服务初始化失败: {}", e));
                    std::process::exit(1);
                }
            };

            if let Err(e) = server.run().await {
                error!("Server error: {}", e);
                show_error(&format!("服务启动失败: {}", e));
                std::process::exit(1);
            }
        });
    });

    if let Err(e) = tray::migrate_legacy_autostart() {
        error!("Failed to migrate legacy auto-start setting: {}", e);
    }

    // Check auto-start status
    let autostart_enabled = tray::is_autostart_enabled();
    let log_enabled = config.log_enabled;

    // Handle tray actions in background
    let tray_config = shared_config.clone();
    let tray_log_controller = log_controller.clone();
    std::thread::spawn(move || {
        info!("Tray action worker thread started");
        while let Ok(action) = action_rx.recv() {
            info!("Tray action worker received action: {:?}", action);
            match action {
                tray::TrayAction::SetPort => {
                    info!("Handling tray action SetPort");
                    let current_port = {
                        let cfg = tray_config.lock().unwrap();
                        cfg.port
                    };

                    if let Some(new_port) = tray::show_port_dialog(current_port) {
                        info!("Port dialog returned new port: {}", new_port);
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
                            info!("Restart confirmed after port change");
                            restart_application(&shutdown_tx);
                        } else {
                            info!("Restart declined after port change");
                        }
                    } else {
                        info!("Port dialog returned without changes");
                    }
                }
                tray::TrayAction::ShowKey => {
                    info!("Handling tray action ShowKey");
                    let psk_hex = {
                        let cfg = tray_config.lock().unwrap();
                        cfg.psk_hex.clone()
                    };
                    tray::show_key_dialog(&psk_hex);
                    info!("ShowKey dialog completed");
                }
                tray::TrayAction::SetKey => {
                    info!("Handling tray action SetKey");
                    let current_key = {
                        let cfg = tray_config.lock().unwrap();
                        cfg.psk_hex.clone()
                    };

                    if let Some(new_key) = tray::show_set_key_dialog(&current_key) {
                        info!("SetKey dialog returned a new key, length={}", new_key.len());
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
                            info!("Restart confirmed after key change");
                            restart_application(&shutdown_tx);
                        } else {
                            info!("Restart declined after key change");
                        }
                    } else {
                        info!("SetKey dialog returned without changes");
                    }
                }
                tray::TrayAction::ToggleAutoStart => {
                    info!("Handling tray action ToggleAutoStart");
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
                            info!("ToggleAutoStart completed successfully");
                        }
                        Err(e) => {
                            error!("Failed to set auto-start: {}", e);
                            show_error(&format!("设置开机启动失败: {}", e));
                        }
                    }
                }
                tray::TrayAction::ToggleLogging => {
                    let new_state = {
                        let mut cfg = tray_config.lock().unwrap();
                        cfg.log_enabled = !cfg.log_enabled;
                        if let Err(e) = cfg.save() {
                            error!("Failed to save config: {}", e);
                            show_error(&format!("保存配置失败: {}", e));
                            continue;
                        }
                        cfg.log_enabled
                    };

                    tray_log_controller.set_enabled(new_state);
                    if new_state {
                        info!("Debug logging enabled");
                        info!("Logging to {:?}", tray_log_controller.path);
                    }

                    let msg = if new_state {
                        "调试日志已启用，后续日志将写入程序目录中的 log.txt"
                    } else {
                        "调试日志已禁用，后续不再写入 log.txt"
                    };
                    let _ = native_dialog::MessageDialog::new()
                        .set_title("调试日志")
                        .set_text(msg)
                        .set_type(native_dialog::MessageType::Info)
                        .show_alert();
                }
                tray::TrayAction::Exit => {
                    info!("Exit requested via tray");
                    let _ = shutdown_tx.send(true);
                    // Give server time to shutdown
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    info!("Tray action worker exiting process");
                    std::process::exit(0);
                }
            }
        }

        warn!("Tray action worker channel closed");
    });

    // Run tray event loop (blocks)
    if let Err(e) = tray::run_tray(action_tx, autostart_enabled, log_enabled) {
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
fn restart_application(shutdown_tx: &watch::Sender<bool>) {
    use std::process::Command;

    info!("Restarting application...");

    let _ = shutdown_tx.send(true);
    std::thread::sleep(Duration::from_millis(300));

    // Get current executable path
    if let Ok(exe_path) = std::env::current_exe() {
        info!("Current executable for restart: {:?}", exe_path);
        #[cfg(windows)]
        {
            let exe_path = exe_path.to_string_lossy().replace('\'', "''");
            let relaunch_script = format!(
                "Start-Sleep -Milliseconds 1200; Start-Process -FilePath '{}'",
                exe_path
            );
            match Command::new("powershell.exe")
                .args([
                    "-NoProfile",
                    "-WindowStyle",
                    "Hidden",
                    "-Command",
                    &relaunch_script,
                ])
                .spawn()
            {
                Ok(_) => info!("Relaunch helper process started"),
                Err(e) => error!("Failed to spawn relaunch helper: {}", e),
            }
        }

        #[cfg(not(windows))]
        {
            match Command::new(&exe_path).spawn() {
                Ok(_) => info!("Relaunch process started"),
                Err(e) => error!("Failed to relaunch process: {}", e),
            }
        }
    } else {
        error!("Failed to resolve current executable for restart");
    }

    // Exit current instance
    info!("Current process exiting for restart");
    std::process::exit(0);
}
