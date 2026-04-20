//! GUI implementation using iced

use crate::config::Config;
use crate::connection::Connection;
use crate::logging;
use crate::scan;
use crate::target::{Target, TargetStatus};
use crate::wol;

use iced::widget::{button, checkbox, column, container, row, scrollable, text, text_input, Space};
use iced::{Color, Element, Length, Task, Theme};
use tracing::{error, info};

#[derive(Debug, Clone)]
pub(crate) struct ConnectionOutcome {
    mac: Option<[u8; 6]>,
    warning: Option<String>,
}

/// Application state
pub struct App {
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
    /// CIDR or IP range input for auto-scan
    scan_subnet_input: String,
    /// Port input for auto-scan
    scan_port_input: String,
    /// Whether a scan is in progress
    is_scanning: bool,
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
    TargetCountChanged(String),
    TargetCountConfirm,
    
    // Target field changes
    TargetSelected(usize, bool),
    TargetAliasChanged(usize, String),
    TargetIpChanged(usize, String),
    TargetPortChanged(usize, String),
    TargetBroadcastChanged(usize, String),
    TargetMacChanged(usize, String),
    TargetPskChanged(usize, String),
    ScanSubnetChanged(String),
    ScanPortChanged(String),
    StartScan,
    ScanCompleted(Result<Vec<String>, String>),
    
    // Batch operations
    SelectAll(bool),
    TestConnection,
    ShutdownPressed,
    RestartPressed,
    WakePressed,

    // Connection results
    ConnectionResult(usize, Result<ConnectionOutcome, String>),

    // Confirmation dialog
    ConfirmYes,
    ConfirmNo,

    // Command results
    CommandResult(Vec<(usize, Result<String, String>)>),
    
    // Save configuration
    SaveConfig,
    ToggleLogging(bool),
}

impl App {
    pub fn new_with_config(config: Config) -> (Self, Task<Message>) {
        let (targets, load_warning) = config.to_targets();
        let has_load_warning = load_warning.is_some();

        let app = Self {
            target_count_input: config.target_count.to_string(),
            targets,
            status: load_warning.unwrap_or_else(|| "就绪".into()),
            status_color: if has_load_warning {
                Color::from_rgb(0.8, 0.2, 0.2)
            } else {
                Color::from_rgb(0.2, 0.6, 0.2)
            },
            confirm_dialog: None,
            config,
            scan_subnet_input: String::new(),
            scan_port_input: common::DEFAULT_PORT.to_string(),
            is_scanning: false,
        };

        (app, Task::none())
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

    fn ensure_target_capacity(&mut self, count: usize) {
        let capped = count.min(200);
        let current_len = self.targets.len();
        if capped > current_len {
            for id in current_len..capped {
                self.targets.push(Target::new(id));
            }
        }

        self.target_count_input = self.targets.len().to_string();
    }

    fn apply_scan_results(&mut self, ips: &[String], port: u16) {
        self.ensure_target_capacity(ips.len());
        for (index, ip) in ips.iter().enumerate() {
            if let Some(target) = self.targets.get_mut(index) {
                target.apply_scanned_address(ip.clone(), port);
            }
        }
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
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

            Message::TargetBroadcastChanged(id, value) => {
                if let Some(target) = self.targets.get_mut(id) {
                    target.broadcast = value;
                }
                Task::none()
            }

            Message::TargetMacChanged(id, value) => {
                let is_valid_input = value.chars().all(|c| {
                    c.is_ascii_hexdigit() || matches!(c, ':' | '-' | '.' | ' ')
                });

                if is_valid_input {
                    if let Some(target) = self.targets.get_mut(id) {
                        target.set_mac_input(value);
                    }
                }
                Task::none()
            }

            Message::TargetPskChanged(id, value) => {
                if value.chars().all(|c| c.is_ascii_hexdigit()) {
                    if let Some(target) = self.targets.get_mut(id) {
                        target.set_psk_input(value);
                    }
                }
                Task::none()
            }

            Message::ScanSubnetChanged(value) => {
                self.scan_subnet_input = value;
                Task::none()
            }

            Message::ScanPortChanged(value) => {
                if value.chars().all(|c| c.is_ascii_digit()) {
                    self.scan_port_input = value;
                }
                Task::none()
            }

            Message::StartScan => {
                if self.is_scanning {
                    return Task::none();
                }

                let subnet = self.scan_subnet_input.trim().to_string();
                let port = match self.scan_port_input.trim().parse::<u16>() {
                    Ok(port) if port > 0 => port,
                    _ => {
                        self.set_status("扫描端口无效，请输入 1-65535", true);
                        return Task::none();
                    }
                };

                self.is_scanning = true;
                self.set_status(
                    &format!("正在扫描 {} 的 {} 端口...", subnet, port),
                    false,
                );

                Task::perform(
                    async move { scan::scan_subnet(&subnet, port).await },
                    Message::ScanCompleted,
                )
            }

            Message::ScanCompleted(result) => {
                self.is_scanning = false;
                let port = self
                    .scan_port_input
                    .trim()
                    .parse::<u16>()
                    .unwrap_or(common::DEFAULT_PORT);

                match result {
                    Ok(ips) if ips.is_empty() => {
                        self.set_status("扫描完成，未发现可连接目标", true);
                    }
                    Ok(ips) => {
                        let found_count = ips.len();
                        let truncated = found_count > 200;
                        let applied: Vec<String> = ips.into_iter().take(200).collect();
                        self.apply_scan_results(&applied, port);
                        self.set_status(
                            &format!(
                                "扫描完成，发现 {} 个目标{}，已自动填入目标列表",
                                found_count,
                                if truncated { "（仅保留前 200 个）" } else { "" }
                            ),
                            false,
                        );
                    }
                    Err(e) => self.set_status(&format!("扫描失败: {}", e), true),
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
                // Get selected targets
                let selected_targets: Vec<(usize, String, [u8; 32])> = self.targets
                    .iter()
                    .filter(|t| t.selected && t.is_valid() && t.has_valid_psk())
                    .filter_map(|t| Some((t.id, t.address()?, t.parse_psk().ok()?)))
                    .collect();

                if selected_targets.is_empty() {
                    self.set_status("请选择至少一个同时具备有效地址和独立密钥的目标", true);
                    return Task::none();
                }

                // Mark all selected targets as connecting
                for target in &mut self.targets {
                    if target.selected && target.is_valid() && target.has_valid_psk() {
                        target.set_connecting();
                    }
                }

                self.set_status(&format!("正在连接 {} 个目标...", selected_targets.len()), false);

                // Connect to all selected targets concurrently
                let tasks: Vec<_> = selected_targets
                    .into_iter()
                    .map(|(id, addr, psk)| {
                        Task::perform(
                            async move {
                                let result = async {
                                    let mut conn = Connection::connect(&addr, psk)
                                        .await
                                        .map_err(|e| e.to_string())?;
                                    match conn.get_mac_address().await {
                                        Ok(mac) => Ok(ConnectionOutcome {
                                            mac: Some(mac),
                                            warning: None,
                                        }),
                                        Err(mac_error) => match wol::lookup_mac_via_arp(
                                            addr.split(':').next().unwrap_or_default(),
                                        ) {
                                            Ok(mac) => Ok(ConnectionOutcome {
                                                mac: Some(mac),
                                                warning: Some(format!(
                                                    "目标 {} 已连接，agent 返回 MAC 失败，已从 ARP 获取到 MAC",
                                                    addr
                                                )),
                                            }),
                                            Err(arp_error) => Ok(ConnectionOutcome {
                                                mac: None,
                                                warning: Some(format!(
                                                    "目标 {} 已连接，但获取 MAC 失败: {}；ARP 回退失败: {}",
                                                    addr, mac_error, arp_error
                                                )),
                                            }),
                                        },
                                    }
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
                let mut should_persist_mac = false;
                let mut warning_message = None;
                if let Some(target) = self.targets.get_mut(id) {
                    match result {
                        Ok(outcome) => {
                            target.set_connected(outcome.mac);
                            should_persist_mac = outcome.mac.is_some();
                            warning_message = outcome.warning;
                            info!("Target {} ({}) connected", id, target.alias);
                        }
                        Err(e) => {
                            target.set_error(e.clone());
                            error!("Target {} ({}) failed: {}", id, target.alias, e);
                        }
                    }
                }

                if should_persist_mac {
                    if let Err(e) = self.config.update_targets(&self.targets) {
                        error!("Failed to refresh target cache before saving MAC: {}", e);
                    } else if let Err(e) = self.config.save() {
                        error!("Failed to persist target MAC addresses: {}", e);
                    }
                }

                // Update status message
                let connected = self.targets.iter().filter(|t| matches!(t.status, TargetStatus::Connected)).count();
                let failed = self.targets.iter().filter(|t| t.status.is_error()).count();
                if let Some(warning) = warning_message {
                    self.set_status(
                        &format!(
                            "连接完成: {} 成功, {} 失败。{}",
                            connected, failed, warning
                        ),
                        true,
                    );
                } else {
                    self.set_status(
                        &format!("连接完成: {} 成功, {} 失败", connected, failed),
                        failed > 0,
                    );
                }

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

                    // Get selected connected targets
                    let selected_targets: Vec<(usize, String, [u8; 32])> = self.targets
                        .iter()
                        .filter(|t| {
                            t.selected
                                && matches!(t.status, TargetStatus::Connected)
                                && t.is_valid()
                                && t.has_valid_psk()
                        })
                        .filter_map(|t| Some((t.id, t.address()?, t.parse_psk().ok()?)))
                        .collect();

                    if selected_targets.is_empty() {
                        self.set_status("没有已连接且已配置独立密钥的目标", true);
                        return Task::none();
                    }

                    // Execute command on all selected targets concurrently
                    let tasks: Vec<_> = selected_targets
                        .into_iter()
                        .map(|(id, addr, psk)| {
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
                let targets_with_mac: Vec<(usize, String, [u8; 6], Option<String>)> = self.targets
                    .iter()
                    .filter(|t| t.selected && t.mac.is_some())
                    .map(|t| {
                        (
                            t.id,
                            t.ip.clone(),
                            t.mac.unwrap(),
                            t.broadcast_target().map(str::to_owned),
                        )
                    })
                    .collect();

                if targets_with_mac.is_empty() {
                    self.set_status("所选目标无 MAC 地址，请先连接一次", true);
                    return Task::none();
                }

                self.set_status(&format!("正在发送唤醒包到 {} 个目标...", targets_with_mac.len()), false);

                // Send WoL packets to all selected targets
                let tasks: Vec<_> = targets_with_mac
                    .into_iter()
                    .map(|(id, ip, mac, broadcast)| {
                        Task::perform(
                            async move {
                                let result = wol::send_magic_packet(
                                    &mac,
                                    Some(ip.as_str()),
                                    broadcast.as_deref(),
                                )
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
                let first_error = results
                    .iter()
                    .find_map(|(_, result)| result.as_ref().err())
                    .cloned();
                
                if fail_count == 0 {
                    self.set_status(&format!("操作完成: {} 个成功", success_count), false);
                } else if let Some(error) = first_error {
                    self.set_status(
                        &format!("操作完成: {} 成功, {} 失败: {}", success_count, fail_count, error),
                        true,
                    );
                } else {
                    self.set_status(&format!("操作完成: {} 成功, {} 失败", success_count, fail_count), true);
                }
                
                Task::none()
            }
            
            Message::SaveConfig => {
                if let Some(index) = self
                    .targets
                    .iter()
                    .enumerate()
                    .find_map(|(index, target)| (!target.has_valid_mac_or_empty()).then_some(index))
                {
                    self.set_status(
                        &format!(
                            "保存失败: 第 {} 个目标的 MAC 地址格式无效",
                            index + 1
                        ),
                        true,
                    );
                    error!(
                        "Invalid MAC while saving config for target {}",
                        index
                    );
                    return Task::none();
                }

                if let Some(index) = self
                    .targets
                    .iter()
                    .enumerate()
                    .find_map(|(index, target)| (!target.has_valid_psk_or_empty()).then_some(index))
                {
                    self.set_status(
                        &format!(
                            "保存失败: 第 {} 个目标的密钥格式无效（需要64位十六进制）",
                            index + 1
                        ),
                        true,
                    );
                    error!("Invalid PSK while saving config for target {}", index);
                    return Task::none();
                }

                // Update config with current targets
                if let Err(e) = self.config.update_targets(&self.targets) {
                    self.set_status(&format!("保存失败: {}", e), true);
                    return Task::none();
                }
                
                match self.config.save() {
                    Ok(_) => self.set_status("配置已保存", false),
                    Err(e) => self.set_status(&format!("保存失败: {}", e), true),
                }
                
                Task::none()
            }

            Message::ToggleLogging(enabled) => {
                let previous = self.config.log_enabled;
                self.config.log_enabled = enabled;

                match self.config.save() {
                    Ok(_) => {
                        logging::set_enabled(enabled);
                        let path = logging::log_path()
                            .map(|path| path.display().to_string())
                            .unwrap_or_else(|| "程序目录/log.txt".to_string());
                        if enabled {
                            self.set_status(
                                &format!("调试日志已启用，写入 {}", path),
                                false,
                            );
                        } else {
                            self.set_status("调试日志已禁用", false);
                        }
                    }
                    Err(e) => {
                        self.config.log_enabled = previous;
                        self.set_status(&format!("切换调试日志失败: {}", e), true);
                    }
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

        // Top control row: target count + save button
        let target_count_input = text_input("1-200", &self.target_count_input)
            .on_input(Message::TargetCountChanged)
            .width(80)
            .padding(8);

        let confirm_count_btn = button(text("确定").size(14))
            .on_press(Message::TargetCountConfirm)
            .padding([8, 16]);

        let save_btn = button(text("保存配置").size(14))
            .on_press(Message::SaveConfig)
            .padding([8, 16]);

        let log_checkbox = checkbox("调试日志", self.config.log_enabled)
            .on_toggle(Message::ToggleLogging);

        let top_row = row![
            text("目标数量:").size(14),
            target_count_input,
            confirm_count_btn,
            Space::with_width(20),
            text("密钥策略: 每目标独立，保存时本地加密").size(14),
            Space::with_width(20),
            log_checkbox,
            Space::with_width(20),
            save_btn,
        ]
        .spacing(5)
        .align_y(iced::Alignment::Center)
        .padding([10, 20]);

        let scan_subnet_input = text_input("网段，例如 10.0.0.0/24", &self.scan_subnet_input)
            .on_input(Message::ScanSubnetChanged)
            .width(220)
            .padding(8);

        let scan_port_input = text_input("端口", &self.scan_port_input)
            .on_input(Message::ScanPortChanged)
            .width(80)
            .padding(8);

        let scan_btn = button(text(if self.is_scanning { "扫描中..." } else { "自动扫描" }).size(14))
            .on_press_maybe((!self.is_scanning).then_some(Message::StartScan))
            .padding([8, 16]);

        let scan_row = row![
            text("自动发现:").size(14),
            scan_subnet_input,
            text("端口").size(14),
            scan_port_input,
            scan_btn,
            Space::with_width(15),
            text("扫描到后按顺序填入目标 IP，不够会自动新增条目").size(13),
        ]
        .spacing(5)
        .align_y(iced::Alignment::Center)
        .padding([10, 20]);

        // Table header
        let select_all_checkbox = checkbox("", self.all_selected())
            .on_toggle(Message::SelectAll);

        let header = row![
            container(select_all_checkbox).width(40),
            container(text("别名").size(13)).width(100),
            container(text("IP地址").size(13)).width(130),
            container(text("端口").size(13)).width(70),
            container(text("广播地址").size(13)).width(120),
            container(text("MAC地址").size(13)).width(160),
            container(text("目标密钥").size(13)).width(220),
            container(text("状态").size(13)).width(100),
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
                    .id(iced::widget::text_input::Id::new(format!(
                        "target-{}-alias",
                        target.id
                    )))
                    .on_input(move |value| Message::TargetAliasChanged(target.id, value))
                    .width(100)
                    .padding(6);

                let ip_input = text_input("IP地址", &target.ip)
                    .id(iced::widget::text_input::Id::new(format!(
                        "target-{}-ip",
                        target.id
                    )))
                    .on_input(move |value| Message::TargetIpChanged(target.id, value))
                    .width(130)
                    .padding(6);

                let port_input = text_input("端口", &target.port)
                    .id(iced::widget::text_input::Id::new(format!(
                        "target-{}-port",
                        target.id
                    )))
                    .on_input(move |value| Message::TargetPortChanged(target.id, value))
                    .width(70)
                    .padding(6);

                let broadcast_input = text_input("广播地址(可选)", &target.broadcast)
                    .id(iced::widget::text_input::Id::new(format!(
                        "target-{}-broadcast",
                        target.id
                    )))
                    .on_input(move |value| Message::TargetBroadcastChanged(target.id, value))
                    .width(120)
                    .padding(6);

                let mac_input = text_input("MAC地址(可手动填)", target.mac_text())
                    .id(iced::widget::text_input::Id::new(format!(
                        "target-{}-mac",
                        target.id
                    )))
                    .on_input(move |value| Message::TargetMacChanged(target.id, value))
                    .width(160)
                    .padding(6);

                let psk_input = text_input("64位十六进制", target.psk_text())
                    .id(iced::widget::text_input::Id::new(format!(
                        "target-{}-psk",
                        target.id
                    )))
                    .on_input(move |value| Message::TargetPskChanged(target.id, value))
                    .secure(true)
                    .width(220)
                    .padding(6);

                let status_text = text(target.status.text())
                    .size(13)
                    .color(target.status.color());

                let row_widget = row![
                    container(checkbox_widget).width(40),
                    alias_input,
                    ip_input,
                    port_input,
                    broadcast_input,
                    mac_input,
                    psk_input,
                    container(status_text).width(100),
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
            scan_row,
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
