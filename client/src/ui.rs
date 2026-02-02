//! GUI implementation using iced

use crate::config::Config;
use crate::connection::Connection;
use crate::target::{Target, TargetStatus};
use crate::wol;

use common::psk_from_hex;
use iced::widget::{button, checkbox, column, container, row, scrollable, text, text_input, Space};
use iced::{Color, Element, Length, Task, Theme};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info};

/// Application state
pub struct App {
    /// PSK input (hex) - shared by all targets
    psk_input: String,
    /// Target count input
    target_count_input: String,
    /// List of targets
    targets: Vec<Target>,
    /// Status message
    status: String,
    /// Status color
    status_color: Color,
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
    PskChanged(String),
    TargetCountChanged(String),
    TargetCountConfirm,
    
    // Target field changes
    TargetSelected(usize, bool),
    TargetAliasChanged(usize, String),
    TargetIpChanged(usize, String),
    TargetPortChanged(usize, String),
    
    // Batch operations
    SelectAll(bool),
    TestConnection,
    ShutdownPressed,
    RestartPressed,
    WakePressed,

    // Connection results
    ConnectionResult(usize, Result<(Arc<Mutex<Connection>>, Option<[u8; 6]>), String>),

    // Confirmation dialog
    ConfirmYes,
    ConfirmNo,

    // Command results
    CommandResult(Vec<(usize, Result<String, String>)>),
    
    // Save configuration
    SaveConfig,
}

impl App {
    pub fn new() -> (Self, Task<Message>) {
        let config = Config::load_or_create();
        let targets = config.to_targets();

        let app = Self {
            psk_input: config.psk_hex.clone(),
            target_count_input: config.target_count.to_string(),
            targets,
            status: "就绪".into(),
            status_color: Color::from_rgb(0.2, 0.6, 0.2),
            confirm_dialog: None,
            config,
        };

        (app, Task::none())
    }

    pub fn title(&self) -> String {
        "远程电源管理 - 多目标控制".into()
    }
    
    /// Get count of selected targets
    fn selected_count(&self) -> usize {
        self.targets.iter().filter(|t| t.selected).count()
    }
    
    /// Check if any target is selected
    fn has_selection(&self) -> bool {
        self.selected_count() > 0
    }
    
    /// Check if all targets are selected
    fn all_selected(&self) -> bool {
        !self.targets.is_empty() && self.targets.iter().all(|t| t.selected)
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::PskChanged(value) => {
                // Only allow hex characters
                if value.chars().all(|c| c.is_ascii_hexdigit()) {
                    self.psk_input = value;
                }
                Task::none()
            }
            
            Message::TargetCountChanged(value) => {
                // Only allow digits
                if value.chars().all(|c| c.is_ascii_digit()) {
                    self.target_count_input = value;
                }
                Task::none()
            }
            
            Message::TargetCountConfirm => {
                // Parse and validate target count
                if let Ok(count) = self.target_count_input.parse::<usize>() {
                    if count > 0 && count <= 200 {
                        let current_len = self.targets.len();
                        
                        // Resize targets vector
                        if count > current_len {
                            // Add new targets
                            for id in current_len..count {
                                self.targets.push(Target::new(id));
                            }
                        } else if count < current_len {
                            // Remove excess targets
                            self.targets.truncate(count);
                        }
                        
                        // Update IDs
                        for (id, target) in self.targets.iter_mut().enumerate() {
                            target.id = id;
                        }
                        self.set_status(&format!("已设置 {} 个目标", count), false);
                    } else {
                        self.set_status("目标数量必须在 1-200 之间", true);
                    }
                } else {
                    self.set_status("无效的目标数量", true);
                }
                Task::none()
            }
            
            Message::TargetSelected(id, selected) => {
                if let Some(target) = self.targets.get_mut(id) {
                    target.selected = selected;
                }
                Task::none()
            }
            
            Message::TargetAliasChanged(id, value) => {
                if let Some(target) = self.targets.get_mut(id) {
                    target.alias = value;
                }
                Task::none()
            }
            
            Message::TargetIpChanged(id, value) => {
                if let Some(target) = self.targets.get_mut(id) {
                    target.ip = value;
                }
                Task::none()
            }
            
            Message::TargetPortChanged(id, value) => {
                // Only allow digits
                if value.chars().all(|c| c.is_ascii_digit()) {
                    if let Some(target) = self.targets.get_mut(id) {
                        target.port = value;
                    }
                }
                Task::none()
            }
            
            Message::SelectAll(selected) => {
                for target in &mut self.targets {
                    target.selected = selected;
                }
                Task::none()
            }

            Message::TestConnection => {
                // Validate PSK
                let psk = match psk_from_hex(&self.psk_input) {
                    Ok(p) => p,
                    Err(_) => {
                        self.set_status("无效的密钥（需要64位十六进制）", true);
                        return Task::none();
                    }
                };

                // Get selected targets
                let selected_targets: Vec<(usize, String)> = self.targets
                    .iter()
                    .filter(|t| t.selected && t.is_valid())
                    .map(|t| (t.id, t.address().unwrap()))
                    .collect();

                if selected_targets.is_empty() {
                    self.set_status("请选择至少一个有效的目标", true);
                    return Task::none();
                }

                // Mark all selected targets as connecting
                for target in &mut self.targets {
                    if target.selected && target.is_valid() {
                        target.set_connecting();
                    }
                }

                self.set_status(&format!("正在连接 {} 个目标...", selected_targets.len()), false);

                // Connect to all selected targets concurrently
                let tasks: Vec<_> = selected_targets
                    .into_iter()
                    .map(|(id, addr)| {
                        Task::perform(
                            async move {
                                let result = async {
                                    let conn = Connection::connect(&addr, psk).await.map_err(|e| e.to_string())?;
                                    let conn = Arc::new(Mutex::new(conn));

                                    // Try to get MAC address
                                    let mac = {
                                        let mut guard = conn.lock().await;
                                        guard.get_mac_address().await.ok()
                                    };

                                    Ok((conn, mac))
                                }.await;
                                (id, result)
                            },
                            |(id, result)| Message::ConnectionResult(id, result),
                        )
                    })
                    .collect();

                Task::batch(tasks)
            }

            Message::ConnectionResult(id, result) => {
                if let Some(target) = self.targets.get_mut(id) {
                    match result {
                        Ok((conn, mac)) => {
                            target.set_connected(mac);
                            target.set_connection(conn);
                            info!("Target {} ({}) connected", id, target.alias);
                        }
                        Err(e) => {
                            target.set_error(e.clone());
                            error!("Target {} ({}) failed: {}", id, target.alias, e);
                        }
                    }
                }

                // Update status message
                let connected = self.targets.iter().filter(|t| matches!(t.status, TargetStatus::Connected)).count();
                let failed = self.targets.iter().filter(|t| t.status.is_error()).count();
                self.set_status(&format!("连接完成: {} 成功, {} 失败", connected, failed), failed > 0);

                Task::none()
            }

            Message::ShutdownPressed => {
                if self.has_selection() {
                    self.confirm_dialog = Some(ConfirmAction::Shutdown);
                }
                Task::none()
            }

            Message::RestartPressed => {
                if self.has_selection() {
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

                    // Validate PSK
                    let psk = match psk_from_hex(&self.psk_input) {
                        Ok(p) => p,
                        Err(_) => {
                            self.set_status("无效的密钥", true);
                            return Task::none();
                        }
                    };

                    // Get selected connected targets
                    let selected_targets: Vec<(usize, String)> = self.targets
                        .iter()
                        .filter(|t| t.selected && matches!(t.status, TargetStatus::Connected) && t.is_valid())
                        .map(|t| (t.id, t.address().unwrap()))
                        .collect();

                    if selected_targets.is_empty() {
                        self.set_status("没有已连接的目标", true);
                        return Task::none();
                    }

                    // Execute command on all selected targets concurrently
                    let tasks: Vec<_> = selected_targets
                        .into_iter()
                        .map(|(id, addr)| {
                            Task::perform(
                                async move {
                                    let result = async {
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
                                    }.await;
                                    (id, result)
                                },
                                |(id, result)| Message::CommandResult(vec![(id, result)]),
                            )
                        })
                        .collect();

                    return Task::batch(tasks);
                }
                Task::none()
            }

            Message::ConfirmNo => {
                self.confirm_dialog = None;
                Task::none()
            }

            Message::WakePressed => {
                // Get selected targets with MAC addresses
                let targets_with_mac: Vec<(usize, [u8; 6], Option<String>)> = self.targets
                    .iter()
                    .filter(|t| t.selected && t.mac.is_some())
                    .map(|t| (t.id, t.mac.unwrap(), compute_broadcast(&t.ip)))
                    .collect();

                if targets_with_mac.is_empty() {
                    self.set_status("所选目标无 MAC 地址，请先连接一次", true);
                    return Task::none();
                }

                self.set_status(&format!("正在发送唤醒包到 {} 个目标...", targets_with_mac.len()), false);

                // Send WoL packets to all selected targets
                let tasks: Vec<_> = targets_with_mac
                    .into_iter()
                    .map(|(id, mac, broadcast)| {
                        Task::perform(
                            async move {
                                let result = wol::send_magic_packet(&mac, broadcast.as_deref())
                                    .map(|_| "唤醒包已发送".to_string())
                                    .map_err(|e| e.to_string());
                                (id, result)
                            },
                            |(id, result)| Message::CommandResult(vec![(id, result)]),
                        )
                    })
                    .collect();

                Task::batch(tasks)
            }

            Message::CommandResult(results) => {
                let success_count = results.iter().filter(|(_, r)| r.is_ok()).count();
                let fail_count = results.iter().filter(|(_, r)| r.is_err()).count();
                
                if fail_count == 0 {
                    self.set_status(&format!("操作完成: {} 个成功", success_count), false);
                } else {
                    self.set_status(&format!("操作完成: {} 成功, {} 失败", success_count, fail_count), true);
                }
                
                Task::none()
            }
            
            Message::SaveConfig => {
                // Update config with current targets
                self.config.psk_hex = self.psk_input.clone();
                self.config.update_targets(&self.targets);
                
                match self.config.save() {
                    Ok(_) => self.set_status("配置已保存", false),
                    Err(e) => self.set_status(&format!("保存失败: {}", e), true),
                }
                
                Task::none()
            }
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        // Check if dialog should be shown
        if let Some(action) = self.confirm_dialog {
            let action_name = match action {
                ConfirmAction::Shutdown => "关机",
                ConfirmAction::Restart => "重启",
            };

            let selected = self.selected_count();

            // Show confirmation dialog instead of main content
            let dialog_content = column![
                text(format!("确定要{}选中的 {} 个目标吗？", action_name, selected)).size(18),
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

        // Top control row: target count + PSK + save button
        let target_count_input = text_input("1-200", &self.target_count_input)
            .on_input(Message::TargetCountChanged)
            .width(80)
            .padding(8);

        let confirm_count_btn = button(text("确定").size(14))
            .on_press(Message::TargetCountConfirm)
            .padding([8, 16]);

        let psk_input = text_input("认证密钥 (64位十六进制)", &self.psk_input)
            .on_input(Message::PskChanged)
            .width(400)
            .padding(8);

        let save_btn = button(text("保存配置").size(14))
            .on_press(Message::SaveConfig)
            .padding([8, 16]);

        let top_row = row![
            text("目标数量:").size(14),
            target_count_input,
            confirm_count_btn,
            Space::with_width(20),
            text("全局密钥:").size(14),
            psk_input,
            Space::with_width(10),
            save_btn,
        ]
        .spacing(5)
        .align_y(iced::Alignment::Center)
        .padding([10, 20]);

        // Table header
        let select_all_checkbox = checkbox("", self.all_selected())
            .on_toggle(Message::SelectAll);

        let header = row![
            container(select_all_checkbox).width(40),
            container(text("别名").size(13)).width(120),
            container(text("IP地址").size(13)).width(150),
            container(text("端口").size(13)).width(80),
            container(text("状态").size(13)).width(120),
            container(text("MAC地址").size(13)).width(160),
        ]
        .spacing(5)
        .padding([5, 20]);

        // Target list (scrollable)
        let target_rows: Element<_> = self.targets
            .iter()
            .fold(column![].spacing(3), |col, target| {
                let checkbox_widget = checkbox("", target.selected)
                    .on_toggle(move |checked| Message::TargetSelected(target.id, checked));

                let alias_input = text_input("别名", &target.alias)
                    .on_input(move |value| Message::TargetAliasChanged(target.id, value))
                    .width(120)
                    .padding(6);

                let ip_input = text_input("IP地址", &target.ip)
                    .on_input(move |value| Message::TargetIpChanged(target.id, value))
                    .width(150)
                    .padding(6);

                let port_input = text_input("端口", &target.port)
                    .on_input(move |value| Message::TargetPortChanged(target.id, value))
                    .width(80)
                    .padding(6);

                let status_text = text(target.status.text())
                    .size(13)
                    .color(target.status.color());

                let mac_text = text(target.mac_display())
                    .size(12);

                let row_widget = row![
                    container(checkbox_widget).width(40),
                    alias_input,
                    ip_input,
                    port_input,
                    container(status_text).width(120),
                    container(mac_text).width(160),
                ]
                .spacing(5)
                .padding([2, 20])
                .align_y(iced::Alignment::Center);

                col.push(row_widget)
            })
            .into();

        let scrollable_list = scrollable(target_rows)
            .height(400)
            .width(Length::Fill);

        // Bottom control buttons
        let has_selection = self.has_selection();

        let test_conn_btn = button(text("测试连接").size(14))
            .on_press_maybe(has_selection.then_some(Message::TestConnection))
            .padding([10, 20]);

        let shutdown_btn = button(text("关机").size(14))
            .on_press_maybe(has_selection.then_some(Message::ShutdownPressed))
            .padding([10, 20])
            .style(button::danger);

        let restart_btn = button(text("重启").size(14))
            .on_press_maybe(has_selection.then_some(Message::RestartPressed))
            .padding([10, 20])
            .style(button::secondary);

        let wake_btn = button(text("开机 (WoL)").size(14))
            .on_press_maybe(has_selection.then_some(Message::WakePressed))
            .padding([10, 20])
            .style(button::success);

        let selected_count = self.selected_count();
        let total_count = self.targets.len();

        let bottom_row = row![
            text(format!("已选中: {}/{}", selected_count, total_count)).size(14),
            Space::with_width(20),
            test_conn_btn,
            Space::with_width(10),
            shutdown_btn,
            Space::with_width(10),
            restart_btn,
            Space::with_width(10),
            wake_btn,
        ]
        .spacing(5)
        .align_y(iced::Alignment::Center)
        .padding([10, 20]);

        // Status bar
        let status_text = text(&self.status).size(12).color(self.status_color);
        let status_row = container(status_text)
            .padding([5, 20]);

        // Main layout
        let content = column![
            top_row,
            header,
            scrollable_list,
            bottom_row,
            status_row,
        ]
        .spacing(5);

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
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
