//! Cryptographic utilities for authentication and configuration encryption

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::Sha256;

use crate::errors::CryptoError;
use crate::protocol::CommandRequest;

type HmacSha256 = Hmac<Sha256>;

/// Generate a random 32-byte PSK
pub fn generate_psk() -> [u8; 32] {
    let mut psk = [0u8; 32];
    rand::thread_rng().fill(&mut psk);
    psk
}

/// Compute authentication token for a request using HMAC-SHA256
pub fn compute_auth_token(request: &CommandRequest, psk: &[u8; 32]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(psk).expect("HMAC accepts any key length");

    // Include all fields except auth_token in the HMAC
    mac.update(&[request.version]);
    mac.update(&request.request_id.to_le_bytes());
    mac.update(&request.timestamp.to_le_bytes());

    // Serialize command to bytes for hashing
    let command_bytes = rmp_serde::to_vec(&request.command).unwrap_or_default();
    mac.update(&command_bytes);

    let result = mac.finalize();
    let bytes = result.into_bytes();

    let mut token = [0u8; 32];
    token.copy_from_slice(&bytes);
    token
}

/// Verify authentication token
pub fn verify_auth_token(request: &CommandRequest, psk: &[u8; 32]) -> bool {
    let expected = compute_auth_token(request, psk);
    // Constant-time comparison to prevent timing attacks
    constant_time_eq(&expected, &request.auth_token)
}

/// Constant-time byte comparison
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Encrypt data using AES-256-GCM
pub fn encrypt(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt data using AES-256-GCM
pub fn decrypt(ciphertext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() < 12 {
        return Err(CryptoError::InvalidCiphertext);
    }

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;

    // Extract nonce and ciphertext
    let nonce = Nonce::from_slice(&ciphertext[..12]);
    let encrypted = &ciphertext[12..];

    cipher
        .decrypt(nonce, encrypted)
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Derive a key from hardware fingerprint (Windows)
#[cfg(windows)]
pub fn derive_hardware_key() -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();

    // Use computer name as a basic fingerprint
    // In production, you might want to use more hardware-specific info
    if let Ok(name) = std::env::var("COMPUTERNAME") {
        hasher.update(name.as_bytes());
    }

    // Add username for additional uniqueness
    if let Ok(user) = std::env::var("USERNAME") {
        hasher.update(user.as_bytes());
    }

    // Add a salt
    hasher.update(b"reboot-agent-config-key-v1");

    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Derive a key from hardware fingerprint (non-Windows fallback)
#[cfg(not(windows))]
pub fn derive_hardware_key() -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();

    // Use hostname
    if let Ok(hostname) = std::env::var("HOSTNAME") {
        hasher.update(hostname.as_bytes());
    }

    // Add user
    if let Ok(user) = std::env::var("USER") {
        hasher.update(user.as_bytes());
    }

    hasher.update(b"reboot-agent-config-key-v1");

    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Convert PSK to hex string for display
pub fn psk_to_hex(psk: &[u8; 32]) -> String {
    hex::encode(psk)
}

/// Parse PSK from hex string
pub fn psk_from_hex(hex_str: &str) -> Result<[u8; 32], CryptoError> {
    let bytes = hex::decode(hex_str.trim()).map_err(|_| CryptoError::InvalidHexString)?;

    if bytes.len() != 32 {
        return Err(CryptoError::InvalidKeyLength);
    }

    let mut psk = [0u8; 32];
    psk.copy_from_slice(&bytes);
    Ok(psk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = generate_psk();
        let plaintext = b"Hello, World!";

        let ciphertext = encrypt(plaintext, &key).unwrap();
        let decrypted = decrypt(&ciphertext, &key).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_auth_token() {
        let psk = generate_psk();
        let request = CommandRequest::new(crate::protocol::Command::Ping, &psk);

        assert!(verify_auth_token(&request, &psk));

        // Wrong PSK should fail
        let wrong_psk = generate_psk();
        assert!(!verify_auth_token(&request, &wrong_psk));
    }

    #[test]
    fn test_psk_hex_conversion() {
        let psk = generate_psk();
        let hex = psk_to_hex(&psk);
        let recovered = psk_from_hex(&hex).unwrap();

        assert_eq!(psk, recovered);
    }
}
