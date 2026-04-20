//! Local secret protection for client-side per-target keys

use common::ConfigError;

#[cfg(not(windows))]
use common::{decrypt, derive_hardware_key, encrypt};

#[cfg(windows)]
use windows::core::PCWSTR;
#[cfg(windows)]
use windows::Win32::Foundation::{LocalFree, HLOCAL};
#[cfg(windows)]
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};

/// Protect a secret for local storage.
pub fn protect_secret(secret: &str) -> Result<String, ConfigError> {
    #[cfg(windows)]
    {
        protect_secret_windows(secret)
    }

    #[cfg(not(windows))]
    {
        let key = derive_hardware_key();
        let encrypted = encrypt(secret.as_bytes(), &key).map_err(ConfigError::CryptoError)?;
        Ok(hex::encode(encrypted))
    }
}

/// Recover a locally stored secret.
pub fn unprotect_secret(secret: &str) -> Result<String, ConfigError> {
    #[cfg(windows)]
    {
        unprotect_secret_windows(secret)
    }

    #[cfg(not(windows))]
    {
        let encrypted =
            hex::decode(secret).map_err(|e| ConfigError::ParseError(e.to_string()))?;
        let key = derive_hardware_key();
        let decrypted = decrypt(&encrypted, &key).map_err(ConfigError::CryptoError)?;
        String::from_utf8(decrypted).map_err(|e| ConfigError::ParseError(e.to_string()))
    }
}

#[cfg(windows)]
fn protect_secret_windows(secret: &str) -> Result<String, ConfigError> {
    let input_bytes = secret.as_bytes();
    let input = CRYPT_INTEGER_BLOB {
        cbData: input_bytes.len() as u32,
        pbData: input_bytes.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();

    unsafe {
        CryptProtectData(
            &input,
            PCWSTR::null(),
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
        .map_err(|e| ConfigError::WriteError(e.to_string()))?;

        let result = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = LocalFree(HLOCAL(output.pbData.cast()));
        Ok(hex::encode(result))
    }
}

#[cfg(windows)]
fn unprotect_secret_windows(secret: &str) -> Result<String, ConfigError> {
    let mut encrypted =
        hex::decode(secret).map_err(|e| ConfigError::ParseError(e.to_string()))?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: encrypted.len() as u32,
        pbData: encrypted.as_mut_ptr(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();

    unsafe {
        CryptUnprotectData(
            &input,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
        .map_err(|e| ConfigError::ReadError(e.to_string()))?;

        let result = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = LocalFree(HLOCAL(output.pbData.cast()));
        String::from_utf8(result).map_err(|e| ConfigError::ParseError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::{protect_secret, unprotect_secret};

    #[test]
    fn test_secret_roundtrip() {
        let secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let protected = protect_secret(secret).unwrap();
        let recovered = unprotect_secret(&protected).unwrap();

        assert_eq!(recovered, secret);
    }
}
