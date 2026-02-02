//! Configuration management for the client

use crate::target::{Target, TargetConfig};
use common::{psk_from_hex, psk_to_hex, ConfigError};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::info;

/// Client configuration for multi-target management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Pre-shared key (hex encoded) - shared by all targets
    #[serde(default)]
    pub psk_hex: String,

    /// Number of targets to display
    #[serde(default = "default_target_count")]
    pub target_count: usize,

    /// List of target configurations
    #[serde(default)]
    pub targets: Vec<TargetConfig>,
}

fn default_target_count() -> usize {
    10
}

impl Default for Config {
    fn default() -> Self {
        Self {
            psk_hex: String::new(),
            target_count: default_target_count(),
            targets: Vec::new(),
        }
    }
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

    /// Generate runtime targets from configuration
    pub fn to_targets(&self) -> Vec<Target> {
        let mut targets = Vec::new();
        
        // Convert saved target configs to runtime targets
        for (id, config) in self.targets.iter().enumerate() {
            targets.push(config.to_target(id));
        }
        
        // Fill remaining slots with empty targets up to target_count
        for id in targets.len()..self.target_count {
            targets.push(Target::new(id));
        }
        
        targets
    }

    /// Save targets to configuration
    pub fn update_targets(&mut self, targets: &[Target]) {
        self.targets = targets.iter().map(TargetConfig::from).collect();
        self.target_count = targets.len();
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
