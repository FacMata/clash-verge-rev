//! Encrypted subscription decryption module
//!
//! This module provides functionality to decrypt encrypted subscriptions
//! using AES-256-GCM with HKDF-SHA256 key derivation.

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead as _, KeyInit as _},
};
use anyhow::{Context as _, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use hkdf::Hkdf;
use sha2::Sha256;

/// Encryption protocol constants
/// Note: Salt value is a fixed protocol constant for compatibility with encrypted subscription services
const HKDF_SALT: &[u8] = b"\x76\x32\x62\x6f\x61\x72\x64\x2d\x73\x75\x62\x73\x63\x72\x69\x62\x65\x2d\x6b\x65\x79";
const HKDF_INFO: &[u8] = b"aes-256-gcm-key";
const IV_LENGTH: usize = 12;
const TAG_LENGTH: usize = 16;
const MIN_CIPHERTEXT_LENGTH: usize = IV_LENGTH + TAG_LENGTH;

/// Decrypt encrypted subscription content
///
/// # Arguments
/// * `encrypted_b64` - Base64 encoded encrypted content from API response
/// * `uuid` - User UUID (typically 36 characters with hyphens)
///
/// # Returns
/// * `Result<String>` - Decrypted subscription content (UTF-8 string)
///
/// # Errors
/// * Base64 decoding failure
/// * Ciphertext too short
/// * Decryption failure (wrong UUID)
/// * UTF-8 conversion failure
pub fn decrypt_subscription(encrypted_b64: &str, uuid: &str) -> Result<String> {
    // 1. Derive AES key using HKDF-SHA256
    let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), uuid.as_bytes());
    let mut key_bytes = [0u8; 32];
    hkdf.expand(HKDF_INFO, &mut key_bytes)
        .map_err(|e| anyhow::anyhow!("HKDF key derivation failed: {}", e))?;

    // 2. Base64 decode the ciphertext
    let data = BASE64
        .decode(encrypted_b64.trim())
        .context("Failed to decode Base64: invalid subscription data")?;

    // 3. Validate minimum length: IV (12) + AuthTag (16) = 28 bytes minimum
    if data.len() < MIN_CIPHERTEXT_LENGTH {
        bail!(
            "Encrypted data too short: expected at least {} bytes, got {}",
            MIN_CIPHERTEXT_LENGTH,
            data.len()
        );
    }

    // 4. Extract components: IV (first 12 bytes), ciphertext+tag (rest)
    let (iv, ciphertext_with_tag) = data.split_at(IV_LENGTH);

    // 5. Decrypt using AES-256-GCM
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(iv);

    let plaintext = cipher
        .decrypt(nonce, ciphertext_with_tag)
        .map_err(|_| anyhow::anyhow!("Decryption failed: please verify UUID is correct"))?;

    // 6. Convert to UTF-8 string
    String::from_utf8(plaintext).context("Failed to convert decrypted content to UTF-8")
}

/// Check if HTTP response indicates encrypted content
///
/// # Arguments
/// * `headers` - HTTP response headers
///
/// # Returns
/// * `bool` - true if `X-Encrypted: 1` header is present
pub fn is_encrypted_response(headers: &reqwest::header::HeaderMap) -> bool {
    headers
        .get("X-Encrypted")
        .is_some_and(|v| v.to_str().unwrap_or("") == "1")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_is_encrypted_response() {
        let mut headers = reqwest::header::HeaderMap::new();
        assert!(!is_encrypted_response(&headers));

        headers.insert("X-Encrypted", "1".parse().unwrap());
        assert!(is_encrypted_response(&headers));

        headers.insert("X-Encrypted", "0".parse().unwrap());
        assert!(!is_encrypted_response(&headers));
    }

    #[test]
    fn test_decrypt_invalid_base64() {
        let result = decrypt_subscription("not-valid-base64!!!", "test-uuid");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Base64"));
    }

    #[test]
    fn test_decrypt_too_short() {
        let result = decrypt_subscription("YWJjZA==", "test-uuid"); // "abcd" = 4 bytes
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }
}
