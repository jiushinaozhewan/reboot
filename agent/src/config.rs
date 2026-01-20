//! Configuration management for the agent

use common::{decrypt, derive_hardware_key, encrypt, generate_psk, psk_to_hex, ConfigError};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{error, info};

/// Agent configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Port to listen on
    pub port: u16,
    /// Pre-shared key for authentication (hex encoded)
    pub psk_hex: String,
    /// Optional IP whitelist (empty = allow all)
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    /// Maximum requests per IP per minute
    #[serde(default = "default_rate_limit")]
    pub rate_limit: u32,
}

fn default_rate_limit() -> u32 {
    10
}

impl Default for Config {
    fn default() -> Self {
        let psk = generate_psk();
        Self {
            port: common::DEFAULT_PORT,
            psk_hex: psk_to_hex(&psk),
            allowed_ips: vec![],
            rate_limit: default_rate_limit(),
        }
    }
}

impl Config {
    /// Get the PSK as bytes
    pub fn get_psk(&self) -> Result<[u8; 32], ConfigError> {
        common::psk_from_hex(&self.psk_hex).map_err(|e| ConfigError::ParseError(e.to_string()))
    }

    /// Get the config file path
    pub fn config_path() -> Result<PathBuf, ConfigError> {
        let app_data = dirs::config_dir().ok_or(ConfigError::NotFound)?;
        let config_dir = app_data.join("reboot-agent");
        Ok(config_dir.join("config.enc"))
    }

    /// Load configuration from encrypted file
    pub fn load() -> Result<Self, ConfigError> {
        let path = Self::config_path()?;

        if !path.exists() {
            return Err(ConfigError::NotFound);
        }

        let encrypted = std::fs::read(&path).map_err(|e| ConfigError::ReadError(e.to_string()))?;

        let key = derive_hardware_key();
        let decrypted =
            decrypt(&encrypted, &key).map_err(|e| ConfigError::CryptoError(e))?;

        let json =
            String::from_utf8(decrypted).map_err(|e| ConfigError::ParseError(e.to_string()))?;

        let config: Config =
            serde_json::from_str(&json).map_err(|e| ConfigError::ParseError(e.to_string()))?;

        info!("Configuration loaded from {:?}", path);
        Ok(config)
    }

    /// Save configuration to encrypted file
    pub fn save(&self) -> Result<(), ConfigError> {
        let path = Self::config_path()?;

        // Ensure directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| ConfigError::WriteError(e.to_string()))?;
        }

        let json =
            serde_json::to_string_pretty(self).map_err(|e| ConfigError::WriteError(e.to_string()))?;

        let key = derive_hardware_key();
        let encrypted =
            encrypt(json.as_bytes(), &key).map_err(|e| ConfigError::CryptoError(e))?;

        std::fs::write(&path, encrypted).map_err(|e| ConfigError::WriteError(e.to_string()))?;

        info!("Configuration saved to {:?}", path);
        Ok(())
    }

    /// Load or create default configuration
    pub fn load_or_create() -> Result<(Self, bool), ConfigError> {
        match Self::load() {
            Ok(config) => Ok((config, false)),
            Err(ConfigError::NotFound) => {
                info!("Config not found, creating default");
                let config = Config::default();
                config.save()?;
                Ok((config, true))
            }
            Err(e) => {
                error!("Failed to load config: {}", e);
                Err(e)
            }
        }
    }

    /// Update the port and save
    pub fn set_port(&mut self, port: u16) -> Result<(), ConfigError> {
        self.port = port;
        self.save()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.port, common::DEFAULT_PORT);
        assert!(!config.psk_hex.is_empty());
        assert_eq!(config.psk_hex.len(), 64); // 32 bytes = 64 hex chars
    }
}
