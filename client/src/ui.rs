//! GUI implementation using iced

use crate::config::Config;
use crate::connection::Connection;
use crate::wol;

use common::psk_from_hex;
use iced::widget::{button, column, container, row, text, text_input, Space};
use iced::{Color, Element, Length, Task, Theme};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info};

/// Application state
pub struct App {
    /// IP address input
    ip_input: String,
    /// Port input
    port_input: String,
    /// PSK input (hex)
    psk_input: String,
    /// Connection state
    connection: Option<Arc<Mutex<Connection>>>,
    /// Status message
    status: String,
    /// Status color
    status_color: Color,
    /// Saved MAC address
    saved_mac: Option<[u8; 6]>,
    /// Show confirmation dialog
    confirm_dialog: Option<ConfirmAction>,
    /// Configuration
    config: Config,
}

/// Actions that require confirmation
#[derive(Debug, Clone, Copy)]
pub enum ConfirmAction {
    Shutdown,
    Restart,
}

/// Application messages
#[derive(Debug, Clone)]
pub enum Message {
    // Input changes
    IpChanged(String),
    PortChanged(String),
    PskChanged(String),

    // Connection
    Connect,
    Disconnect,
    Connected(Result<(Arc<Mutex<Connection>>, Option<[u8; 6]>), String>),

    // Commands
    ShutdownPressed,
    RestartPressed,
    WakePressed,

    // Confirmation dialog
    ConfirmYes,
    ConfirmNo,

    // Command results
    CommandResult(Result<String, String>),
}

impl App {
    pub fn new() -> (Self, Task<Message>) {
        let config = Config::load_or_create();

        let app = Self {
            ip_input: config.last_ip.clone(),
            port_input: config.last_port.to_string(),
            psk_input: config.psk_hex.clone(),
            connection: None,
            status: "未连接".into(),
            status_color: Color::from_rgb(0.5, 0.5, 0.5),
            saved_mac: config.get_mac(),
            confirm_dialog: None,
            config,
        };

        (app, Task::none())
    }

    pub fn title(&self) -> String {
        "远程电源管理".into()
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::IpChanged(value) => {
                self.ip_input = value;
                Task::none()
            }

            Message::PortChanged(value) => {
                // Only allow digits
                if value.chars().all(|c| c.is_ascii_digit()) {
                    self.port_input = value;
                }
                Task::none()
            }

            Message::PskChanged(value) => {
                // Only allow hex characters
                if value.chars().all(|c| c.is_ascii_hexdigit()) {
                    self.psk_input = value;
                }
                Task::none()
            }

            Message::Connect => {
                if self.connection.is_some() {
                    return Task::none();
                }

                // Validate inputs
                let port: u16 = match self.port_input.parse() {
                    Ok(p) => p,
                    Err(_) => {
                        self.set_status("无效的端口号", true);
                        return Task::none();
                    }
                };

                let psk = match psk_from_hex(&self.psk_input) {
                    Ok(p) => p,
                    Err(_) => {
                        self.set_status("无效的密钥（需要64位十六进制）", true);
                        return Task::none();
                    }
                };

                let addr = format!("{}:{}", self.ip_input, port);
                self.set_status(&format!("正在连接 {}...", addr), false);

                // Save config
                self.config.last_ip = self.ip_input.clone();
                self.config.last_port = port;
                self.config.psk_hex = self.psk_input.clone();
                let _ = self.config.save();

                // Connect asynchronously
                Task::perform(
                    async move {
                        let conn = Connection::connect(&addr, psk).await.map_err(|e| e.to_string())?;
                        let conn = Arc::new(Mutex::new(conn));

                        // Try to get MAC address
                        let mac = {
                            let mut guard = conn.lock().await;
                            guard.get_mac_address().await.ok()
                        };

                        Ok((conn, mac))
                    },
                    Message::Connected,
                )
            }

            Message::Connected(result) => {
                match result {
                    Ok((conn, mac)) => {
                        self.connection = Some(conn);

                        // Save MAC if we got one, otherwise clear old cached value
                        if let Some(m) = mac {
                            self.saved_mac = Some(m);
                            self.config.set_mac(&m);
                            let _ = self.config.save();
                            info!("Saved MAC address: {}", wol::format_mac(&m));

                            let mac_info = format!(" | MAC: {}", wol::format_mac(&m));
                            self.set_status(&format!("已连接{}", mac_info), false);
                        } else {
                            self.saved_mac = None;
                            self.config.saved_mac = None;
                            let _ = self.config.save();
                            info!("MAC address not available; cleared cached MAC");
                            self.set_status("已连接 | MAC 获取失败", true);
                        }
                    }
                    Err(e) => {
                        self.set_status(&format!("连接失败: {}", e), true);
                    }
                }
                Task::none()
            }

            Message::Disconnect => {
                self.connection = None;
                self.set_status("已断开", false);
                Task::none()
            }

            Message::ShutdownPressed => {
                if self.connection.is_some() {
                    self.confirm_dialog = Some(ConfirmAction::Shutdown);
                }
                Task::none()
            }

            Message::RestartPressed => {
                if self.connection.is_some() {
                    self.confirm_dialog = Some(ConfirmAction::Restart);
                }
                Task::none()
            }

            Message::ConfirmYes => {
                let action = self.confirm_dialog.take();
                if let Some(action) = action {
                    let action_name = match action {
                        ConfirmAction::Shutdown => "关机",
                        ConfirmAction::Restart => "重启",
                    };
                    self.set_status(&format!("正在发送{}命令...", action_name), false);

                    // Get connection parameters for new connection
                    let addr = format!("{}:{}", self.ip_input, self.port_input);
                    let psk = match psk_from_hex(&self.psk_input) {
                        Ok(p) => p,
                        Err(_) => {
                            self.set_status("无效的密钥", true);
                            return Task::none();
                        }
                    };

                    return Task::perform(
                        async move {
                            // Create a new connection for each command
                            let mut conn = Connection::connect(&addr, psk)
                                .await
                                .map_err(|e| e.to_string())?;

                            match action {
                                ConfirmAction::Shutdown => {
                                    conn.shutdown(true, 30).await.map(|_| "关机命令已发送（30秒后执行）".to_string())
                                }
                                ConfirmAction::Restart => {
                                    conn.restart(true, 30).await.map(|_| "重启命令已发送（30秒后执行）".to_string())
                                }
                            }
                            .map_err(|e| e.to_string())
                        },
                        Message::CommandResult,
                    );
                }
                Task::none()
            }

            Message::ConfirmNo => {
                self.confirm_dialog = None;
                Task::none()
            }

            Message::WakePressed => {
                match self.saved_mac {
                    Some(mac) => {
                        self.set_status("正在发送唤醒包...", false);

                        // Compute broadcast address from IP
                        let broadcast = compute_broadcast(&self.ip_input);

                        return Task::perform(
                            async move {
                                wol::send_magic_packet(&mac, broadcast.as_deref())
                                    .map(|_| "唤醒包已发送".to_string())
                                    .map_err(|e| e.to_string())
                            },
                            Message::CommandResult,
                        );
                    }
                    None => {
                        self.set_status("未保存 MAC 地址，请先连接一次", true);
                    }
                }
                Task::none()
            }

            Message::CommandResult(result) => {
                match result {
                    Ok(msg) => self.set_status(&msg, false),
                    Err(e) => self.set_status(&format!("错误: {}", e), true),
                }
                Task::none()
            }
        }
    }

    pub fn view(&self) -> Element<Message> {
        let connected = self.connection.is_some();

        // Connection row
        let ip_input = text_input("IP 地址", &self.ip_input)
            .on_input(Message::IpChanged)
            .width(150)
            .padding(8);

        let port_input = text_input("端口", &self.port_input)
            .on_input(Message::PortChanged)
            .width(70)
            .padding(8);

        let connect_btn = if connected {
            button(text("断开").size(14))
                .on_press(Message::Disconnect)
                .padding([8, 16])
        } else {
            button(text("连接").size(14))
                .on_press(Message::Connect)
                .padding([8, 16])
        };

        let connection_row = row![
            text("IP:").size(14),
            ip_input,
            Space::with_width(10),
            text("端口:").size(14),
            port_input,
            Space::with_width(10),
            connect_btn,
        ]
        .spacing(5)
        .align_y(iced::Alignment::Center);

        // PSK row
        let psk_input = text_input("认证密钥 (64位十六进制)", &self.psk_input)
            .on_input(Message::PskChanged)
            .width(Length::Fill)
            .padding(8);

        let psk_row = row![text("密钥:").size(14), psk_input,]
            .spacing(5)
            .align_y(iced::Alignment::Center);

        // Control buttons - only enabled when connected and no dialog shown
        let can_operate = connected && self.confirm_dialog.is_none();

        let shutdown_btn = button(text("关机").size(14))
            .on_press_maybe(can_operate.then_some(Message::ShutdownPressed))
            .padding([10, 20])
            .style(button::danger);

        let wake_btn = button(text("开机 (WoL)").size(14))
            .on_press_maybe(self.confirm_dialog.is_none().then_some(Message::WakePressed))
            .padding([10, 20])
            .style(button::success);

        let restart_btn = button(text("重启").size(14))
            .on_press_maybe(can_operate.then_some(Message::RestartPressed))
            .padding([10, 20])
            .style(button::secondary);

        let control_row = row![shutdown_btn, wake_btn, restart_btn,]
            .spacing(20)
            .align_y(iced::Alignment::Center);

        // Status
        let status_text = text(&self.status).size(12).color(self.status_color);

        // Check if dialog should be shown
        if let Some(action) = self.confirm_dialog {
            let action_name = match action {
                ConfirmAction::Shutdown => "关机",
                ConfirmAction::Restart => "重启",
            };

            // Show confirmation dialog instead of main content
            let dialog_content = column![
                text(format!("确定要{}吗？", action_name)).size(18),
                Space::with_height(15),
                text("此操作将在30秒后执行").size(14),
                Space::with_height(25),
                row![
                    button(text("取消").size(14))
                        .on_press(Message::ConfirmNo)
                        .padding([10, 30]),
                    Space::with_width(30),
                    button(text("确定").size(14))
                        .on_press(Message::ConfirmYes)
                        .padding([10, 30])
                        .style(button::danger),
                ]
            ]
            .align_x(iced::Alignment::Center)
            .spacing(5);

            return container(dialog_content)
                .width(Length::Fill)
                .height(Length::Fill)
                .center_x(Length::Fill)
                .center_y(Length::Fill)
                .into();
        }

        // Main layout (normal view)
        let content = column![
            connection_row,
            psk_row,
            Space::with_height(10),
            control_row,
            Space::with_height(10),
            status_text,
        ]
        .spacing(10)
        .padding(20);

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x(Length::Fill)
            .into()
    }

    pub fn theme(&self) -> Theme {
        Theme::Light
    }

    fn set_status(&mut self, msg: &str, is_error: bool) {
        self.status = msg.to_string();
        self.status_color = if is_error {
            Color::from_rgb(0.8, 0.2, 0.2)
        } else {
            Color::from_rgb(0.2, 0.6, 0.2)
        };
    }
}

/// Compute broadcast address from IP (simple /24 assumption)
fn compute_broadcast(ip: &str) -> Option<String> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() == 4 {
        Some(format!("{}.{}.{}.255", parts[0], parts[1], parts[2]))
    } else {
        None
    }
}
