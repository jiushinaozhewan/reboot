//! Multi-target management data structures

use crate::connection::Connection;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Status of a single target
#[derive(Debug, Clone, PartialEq)]
pub enum TargetStatus {
    /// Not connected
    Disconnected,
    /// Currently connecting
    Connecting,
    /// Successfully connected
    Connected,
    /// Connection or operation error
    Error(String),
}

impl TargetStatus {
    /// Get status text for display
    pub fn text(&self) -> &str {
        match self {
            TargetStatus::Disconnected => "○ 断开",
            TargetStatus::Connecting => "⟳ 连接中",
            TargetStatus::Connected => "● 已连接",
            TargetStatus::Error(_) => "⚠ 错误",
        }
    }

    /// Get status color
    pub fn color(&self) -> iced::Color {
        match self {
            TargetStatus::Disconnected => iced::Color::from_rgb(0.5, 0.5, 0.5), // Gray
            TargetStatus::Connecting => iced::Color::from_rgb(0.2, 0.5, 0.9),   // Blue
            TargetStatus::Connected => iced::Color::from_rgb(0.2, 0.7, 0.2),    // Green
            TargetStatus::Error(_) => iced::Color::from_rgb(0.9, 0.3, 0.2),     // Red
        }
    }

    /// Check if status is error
    pub fn is_error(&self) -> bool {
        matches!(self, TargetStatus::Error(_))
    }

    /// Get error message if status is error
    pub fn error_message(&self) -> Option<&str> {
        match self {
            TargetStatus::Error(msg) => Some(msg),
            _ => None,
        }
    }
}

/// A single target device
#[derive(Debug, Clone)]
pub struct Target {
    /// Unique identifier
    pub id: usize,
    /// Whether this target is selected for batch operations
    pub selected: bool,
    /// Display alias/name
    pub alias: String,
    /// IP address
    pub ip: String,
    /// Port number
    pub port: String,
    /// Connection status
    pub status: TargetStatus,
    /// MAC address (obtained after successful connection)
    pub mac: Option<[u8; 6]>,
    /// Active connection (not serialized)
    #[allow(dead_code)]
    pub connection: Option<Arc<Mutex<Connection>>>,
}

impl Target {
    /// Create a new target with default values
    pub fn new(id: usize) -> Self {
        Self {
            id,
            selected: false,
            alias: format!("目标-{}", id + 1),
            ip: String::new(),
            port: "7890".to_string(),
            status: TargetStatus::Disconnected,
            mac: None,
            connection: None,
        }
    }

    /// Check if this target has valid input
    pub fn is_valid(&self) -> bool {
        !self.ip.is_empty() && !self.port.is_empty() && self.port.parse::<u16>().is_ok()
    }

    /// Get formatted address for connection
    pub fn address(&self) -> Option<String> {
        if self.is_valid() {
            Some(format!("{}:{}", self.ip, self.port))
        } else {
            None
        }
    }

    /// Get port as u16
    pub fn port_u16(&self) -> Option<u16> {
        self.port.parse().ok()
    }

    /// Format MAC address for display
    pub fn mac_display(&self) -> String {
        match &self.mac {
            Some(mac) => format!(
                "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            ),
            None => "未获取".to_string(),
        }
    }

    /// Set connection status to connecting
    pub fn set_connecting(&mut self) {
        self.status = TargetStatus::Connecting;
    }

    /// Set connection status to connected with optional MAC
    pub fn set_connected(&mut self, mac: Option<[u8; 6]>) {
        self.status = TargetStatus::Connected;
        if let Some(m) = mac {
            self.mac = Some(m);
        }
    }

    /// Set connection status to error
    pub fn set_error(&mut self, msg: String) {
        self.status = TargetStatus::Error(msg);
        self.connection = None;
    }

    /// Set connection status to disconnected
    pub fn set_disconnected(&mut self) {
        self.status = TargetStatus::Disconnected;
        self.connection = None;
    }

    /// Set the active connection
    pub fn set_connection(&mut self, conn: Arc<Mutex<Connection>>) {
        self.connection = Some(conn);
    }

    /// Clear the active connection
    pub fn clear_connection(&mut self) {
        self.connection = None;
    }
}

/// Serializable target configuration (for saving to file)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TargetConfig {
    pub alias: String,
    pub ip: String,
    pub port: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
}

impl From<&Target> for TargetConfig {
    fn from(target: &Target) -> Self {
        Self {
            alias: target.alias.clone(),
            ip: target.ip.clone(),
            port: target.port.clone(),
            mac: target.mac.map(|mac| {
                format!(
                    "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                )
            }),
        }
    }
}

impl TargetConfig {
    /// Convert to Target (runtime representation)
    pub fn to_target(&self, id: usize) -> Target {
        let mac = self.mac.as_ref().and_then(|s| crate::wol::parse_mac(s).ok());
        
        Target {
            id,
            selected: false,
            alias: self.alias.clone(),
            ip: self.ip.clone(),
            port: self.port.clone(),
            status: TargetStatus::Disconnected,
            mac,
            connection: None,
        }
    }
}
