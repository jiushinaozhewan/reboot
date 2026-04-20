//! Multi-target management data structures

use crate::secret_store;
use crate::wol;
use common::{psk_from_hex, ConfigError};

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
    /// Optional per-target WoL broadcast address
    pub broadcast: String,
    /// Editable MAC address text, either manually entered or auto-discovered
    pub mac_input: String,
    /// Per-target PSK input (hex encoded)
    pub psk_input: String,
    /// Connection status
    pub status: TargetStatus,
    /// Parsed MAC address used for WoL
    pub mac: Option<[u8; 6]>,
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
            broadcast: String::new(),
            mac_input: String::new(),
            psk_input: String::new(),
            status: TargetStatus::Disconnected,
            mac: None,
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

    /// Get the current editable MAC text
    pub fn mac_text(&self) -> &str {
        &self.mac_input
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
            self.mac_input = format_mac(m);
        }
    }

    /// Set connection status to error
    pub fn set_error(&mut self, msg: String) {
        self.status = TargetStatus::Error(msg);
    }

    /// Apply a newly scanned address and clear stale connection-derived state
    pub fn apply_scanned_address(&mut self, ip: String, port: u16) {
        let ip_changed = self.ip != ip;
        self.ip = ip;
        self.port = port.to_string();
        self.status = TargetStatus::Disconnected;
        if ip_changed {
            self.mac = None;
            self.mac_input.clear();
        }
    }

    /// Get the configured broadcast target, if any
    pub fn broadcast_target(&self) -> Option<&str> {
        let broadcast = self.broadcast.trim();
        (!broadcast.is_empty()).then_some(broadcast)
    }

    /// Update the editable MAC text and refresh the parsed MAC if valid
    pub fn set_mac_input(&mut self, value: String) {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            self.mac_input.clear();
            self.mac = None;
            return;
        }

        match wol::parse_mac(trimmed) {
            Ok(mac) => {
                self.mac = Some(mac);
                self.mac_input = format_mac(mac);
            }
            Err(_) => {
                self.mac_input = value;
                self.mac = None;
            }
        }
    }

    /// Check whether the MAC field is empty or valid
    pub fn has_valid_mac_or_empty(&self) -> bool {
        self.mac_input.trim().is_empty() || self.mac.is_some()
    }

    /// Get the current editable PSK text
    pub fn psk_text(&self) -> &str {
        &self.psk_input
    }

    /// Update the editable PSK text
    pub fn set_psk_input(&mut self, value: String) {
        self.psk_input = value.trim().to_string();
    }

    /// Check whether the PSK field is empty or valid
    pub fn has_valid_psk_or_empty(&self) -> bool {
        self.psk_input.trim().is_empty() || self.parse_psk().is_ok()
    }

    /// Check whether the target has a usable PSK
    pub fn has_valid_psk(&self) -> bool {
        self.parse_psk().is_ok()
    }

    /// Parse the PSK input into bytes
    pub fn parse_psk(&self) -> Result<[u8; 32], common::CryptoError> {
        psk_from_hex(&self.psk_input)
    }
}

/// Serializable target configuration (for saving to file)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TargetConfig {
    pub alias: String,
    pub ip: String,
    pub port: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broadcast: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub psk_protected: Option<String>,
}

impl From<&Target> for TargetConfig {
    fn from(target: &Target) -> Self {
        Self::try_from_target(target).unwrap_or_else(|_| Self {
            alias: target.alias.clone(),
            ip: target.ip.clone(),
            port: target.port.clone(),
            broadcast: target.broadcast_target().map(str::to_owned),
            mac: target.mac.map(format_mac),
            psk_protected: None,
        })
    }
}

impl TargetConfig {
    /// Convert a runtime target into a serializable target configuration
    pub fn try_from_target(target: &Target) -> Result<Self, ConfigError> {
        let psk_protected = if target.psk_input.trim().is_empty() {
            None
        } else {
            target
                .parse_psk()
                .map_err(|e| ConfigError::ParseError(e.to_string()))?;
            Some(secret_store::protect_secret(target.psk_input.trim())?)
        };

        Ok(Self {
            alias: target.alias.clone(),
            ip: target.ip.clone(),
            port: target.port.clone(),
            broadcast: target.broadcast_target().map(str::to_owned),
            mac: target.mac.map(format_mac),
            psk_protected,
        })
    }

    /// Convert to Target (runtime representation)
    pub fn to_target(&self, id: usize, fallback_psk: Option<&str>) -> (Target, Option<String>) {
        let mac_text = self.mac.clone().unwrap_or_default();
        let mac = self.mac.as_ref().and_then(|s| crate::wol::parse_mac(s).ok());
        let (psk_input, warning) = match self.psk_protected.as_deref() {
            Some(protected) => match secret_store::unprotect_secret(protected) {
                Ok(psk) => (psk, None),
                Err(e) => (
                    String::new(),
                    Some(format!("目标“{}”的密钥无法解密: {}", self.alias, e)),
                ),
            },
            None => (fallback_psk.unwrap_or_default().to_string(), None),
        };
        
        (
            Target {
                id,
                selected: false,
                alias: self.alias.clone(),
                ip: self.ip.clone(),
                port: self.port.clone(),
                broadcast: self.broadcast.clone().unwrap_or_default(),
                mac_input: mac.map(format_mac).unwrap_or(mac_text),
                psk_input,
                status: TargetStatus::Disconnected,
                mac,
            },
            warning,
        )
    }
}

fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

#[cfg(test)]
mod tests {
    use super::{Target, TargetConfig};

    #[test]
    fn test_set_manual_mac_normalizes_valid_input() {
        let mut target = Target::new(0);
        target.set_mac_input("001122334455".to_string());

        assert_eq!(target.mac, Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
        assert_eq!(target.mac_text(), "00:11:22:33:44:55");
        assert!(target.has_valid_mac_or_empty());
    }

    #[test]
    fn test_set_manual_mac_keeps_invalid_text_for_fixup() {
        let mut target = Target::new(0);
        target.set_mac_input("00:11:22".to_string());

        assert_eq!(target.mac, None);
        assert_eq!(target.mac_text(), "00:11:22");
        assert!(!target.has_valid_mac_or_empty());
    }

    #[test]
    fn test_psk_validation() {
        let mut target = Target::new(0);
        target.set_psk_input(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        );

        assert!(target.has_valid_psk());
    }

    #[test]
    fn test_target_config_roundtrip_protects_psk() {
        let mut target = Target::new(0);
        target.set_psk_input(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        );

        let config = TargetConfig::try_from_target(&target).unwrap();
        assert!(config.psk_protected.is_some());

        let (restored, warning) = config.to_target(0, None);
        assert!(warning.is_none());
        assert_eq!(restored.psk_text(), target.psk_text());
    }
}
