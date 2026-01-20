//! Configuration management for the client

use common::{psk_from_hex, psk_to_hex, ConfigError};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::info;

/// Client configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    /// Last connected IP address
    #[serde(default)]
    pub last_ip: String,

    /// Last connected port
    #[serde(default = "default_port")]
    pub last_port: u16,

    /// Pre-shared key (hex encoded)
    #[serde(default)]
    pub psk_hex: String,

    /// Saved MAC address from the agent
    #[serde(default)]
    pub saved_mac: Option<String>,
}

fn default_port() -> u16 {
    common::DEFAULT_PORT
}

impl Config {
    /// Get the PSK as bytes
    pub fn get_psk(&self) -> Result<[u8; 32], ConfigError> {
        if self.psk_hex.is_empty() {
            return Err(ConfigError::ParseError("PSK not configured".into()));
        }
        psk_from_hex(&self.psk_hex).map_err(|e| ConfigError::ParseError(e.to_string()))
    }

    /// Set the PSK from bytes
    pub fn set_psk(&mut self, psk: &[u8; 32]) {
        self.psk_hex = psk_to_hex(psk);
    }

    /// Get the saved MAC address as bytes
    pub fn get_mac(&self) -> Option<[u8; 6]> {
        self.saved_mac
            .as_ref()
            .and_then(|s| crate::wol::parse_mac(s).ok())
    }

    /// Set the saved MAC address
    pub fn set_mac(&mut self, mac: &[u8; 6]) {
        self.saved_mac = Some(crate::wol::format_mac(mac));
    }

    /// Get the config file path
    pub fn config_path() -> Result<PathBuf, ConfigError> {
        let app_data = dirs::config_dir().ok_or(ConfigError::NotFound)?;
        let config_dir = app_data.join("reboot-client");
        Ok(config_dir.join("config.toml"))
    }

    /// Load configuration from file
    pub fn load() -> Result<Self, ConfigError> {
        let path = Self::config_path()?;

        if !path.exists() {
            return Err(ConfigError::NotFound);
        }

        let content =
            std::fs::read_to_string(&path).map_err(|e| ConfigError::ReadError(e.to_string()))?;

        let config: Config =
            toml::from_str(&content).map_err(|e| ConfigError::ParseError(e.to_string()))?;

        info!("Configuration loaded from {:?}", path);
        Ok(config)
    }

    /// Save configuration to file
    pub fn save(&self) -> Result<(), ConfigError> {
        let path = Self::config_path()?;

        // Ensure directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| ConfigError::WriteError(e.to_string()))?;
        }

        let content =
            toml::to_string_pretty(self).map_err(|e| ConfigError::WriteError(e.to_string()))?;

        std::fs::write(&path, content).map_err(|e| ConfigError::WriteError(e.to_string()))?;

        info!("Configuration saved to {:?}", path);
        Ok(())
    }

    /// Load or create default configuration
    pub fn load_or_create() -> Self {
        match Self::load() {
            Ok(config) => config,
            Err(_) => {
                let config = Config::default();
                let _ = config.save();
                config
            }
        }
    }
}
