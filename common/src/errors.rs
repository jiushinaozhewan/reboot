//! Error types for the reboot system

use thiserror::Error;

/// Protocol-related errors
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("Invalid protocol version: expected {expected}, got {got}")]
    VersionMismatch { expected: u8, got: u8 },

    #[error("Message too large: {size} bytes (max: {max})")]
    MessageTooLarge { size: usize, max: usize },
}

/// Cryptographic operation errors
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Invalid encryption key")]
    InvalidKey,

    #[error("Invalid key length: expected 32 bytes")]
    InvalidKeyLength,

    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Invalid ciphertext format")]
    InvalidCiphertext,

    #[error("Invalid hex string")]
    InvalidHexString,
}

/// Network-related errors
#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Timeout")]
    Timeout,

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("TLS error: {0}")]
    TlsError(String),
}

/// Command execution errors
#[derive(Debug, Error)]
pub enum ExecutionError {
    #[error("Command failed: {0}")]
    CommandFailed(String),

    #[error("Permission denied")]
    PermissionDenied,

    #[error("Operation not supported")]
    NotSupported,

    #[error("System error: {0}")]
    SystemError(String),
}

/// Configuration errors
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Config file not found")]
    NotFound,

    #[error("Failed to read config: {0}")]
    ReadError(String),

    #[error("Failed to write config: {0}")]
    WriteError(String),

    #[error("Invalid config format: {0}")]
    ParseError(String),

    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),
}
