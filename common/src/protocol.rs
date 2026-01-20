//! Protocol definitions for communication between Agent and Client
//!
//! Uses MessagePack for efficient binary serialization.

use serde::{Deserialize, Serialize};

/// Protocol version
pub const PROTOCOL_VERSION: u8 = 1;

/// Default port for the agent server
pub const DEFAULT_PORT: u16 = 7890;

/// Command request from client to agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandRequest {
    /// Protocol version
    pub version: u8,
    /// Unique request ID (for tracking and anti-replay)
    pub request_id: u32,
    /// Unix timestamp in seconds
    pub timestamp: u64,
    /// Authentication token (HMAC-SHA256 of request data)
    pub auth_token: [u8; 32],
    /// The command to execute
    pub command: Command,
}

/// Available commands
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Command {
    /// Shutdown the system
    Shutdown {
        /// Force close all applications
        force: bool,
        /// Delay in seconds before shutdown
        delay_sec: u16,
    },
    /// Restart the system
    Restart {
        /// Force close all applications
        force: bool,
        /// Delay in seconds before restart
        delay_sec: u16,
    },
    /// Heartbeat/connectivity check
    Ping,
    /// Request the agent's MAC address (for WoL)
    GetMacAddress,
    /// Cancel a pending shutdown/restart
    CancelShutdown,
}

/// Response from agent to client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResponse {
    /// Echo of the request ID
    pub request_id: u32,
    /// Response status
    pub status: Status,
    /// Optional message (error description, etc.)
    pub message: Option<String>,
    /// MAC address (only for GetMacAddress command)
    pub mac_address: Option<[u8; 6]>,
}

/// Response status codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    /// Command executed successfully
    Success = 0,
    /// Authentication failed
    AuthFailed = 1,
    /// Invalid or malformed command
    InvalidCommand = 2,
    /// Command execution failed
    ExecutionFailed = 3,
    /// Request timed out or expired
    Timeout = 4,
    /// Rate limit exceeded
    RateLimited = 5,
    /// Command not supported
    NotSupported = 6,
}

impl CommandRequest {
    /// Create a new command request
    pub fn new(command: Command, psk: &[u8; 32]) -> Self {
        use rand::Rng;
        use std::time::{SystemTime, UNIX_EPOCH};

        let request_id = rand::thread_rng().gen();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut request = Self {
            version: PROTOCOL_VERSION,
            request_id,
            timestamp,
            auth_token: [0u8; 32],
            command,
        };

        // Generate auth token
        request.auth_token = crate::crypto::compute_auth_token(&request, psk);
        request
    }

    /// Validate the request timestamp (anti-replay)
    pub fn is_timestamp_valid(&self, tolerance_secs: u64) -> bool {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let diff = if now > self.timestamp {
            now - self.timestamp
        } else {
            self.timestamp - now
        };

        diff <= tolerance_secs
    }
}

impl CommandResponse {
    /// Create a success response
    pub fn success(request_id: u32) -> Self {
        Self {
            request_id,
            status: Status::Success,
            message: None,
            mac_address: None,
        }
    }

    /// Create a success response with MAC address
    pub fn success_with_mac(request_id: u32, mac: [u8; 6]) -> Self {
        Self {
            request_id,
            status: Status::Success,
            message: None,
            mac_address: Some(mac),
        }
    }

    /// Create an error response
    pub fn error(request_id: u32, status: Status, message: impl Into<String>) -> Self {
        Self {
            request_id,
            status,
            message: Some(message.into()),
            mac_address: None,
        }
    }
}

/// Serialize a message to MessagePack bytes
pub fn serialize<T: Serialize>(msg: &T) -> Result<Vec<u8>, crate::errors::ProtocolError> {
    rmp_serde::to_vec(msg).map_err(|e| crate::errors::ProtocolError::SerializationError(e.to_string()))
}

/// Deserialize a message from MessagePack bytes
pub fn deserialize<'a, T: Deserialize<'a>>(data: &'a [u8]) -> Result<T, crate::errors::ProtocolError> {
    rmp_serde::from_slice(data).map_err(|e| crate::errors::ProtocolError::DeserializationError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_deserialize() {
        let psk = [0u8; 32];
        let request = CommandRequest::new(Command::Ping, &psk);

        let bytes = serialize(&request).unwrap();
        let decoded: CommandRequest = deserialize(&bytes).unwrap();

        assert_eq!(decoded.request_id, request.request_id);
    }

    #[test]
    fn test_timestamp_validation() {
        let psk = [0u8; 32];
        let request = CommandRequest::new(Command::Ping, &psk);

        // Should be valid within 60 seconds
        assert!(request.is_timestamp_valid(60));
    }
}
