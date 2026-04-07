//! Core encryption/decryption using XChaCha20-Poly1305 + Argon2id

use argon2::{self, Argon2, Algorithm, Version, Params};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use zeroize::Zeroize;

use crate::format::{GhostHeader, FORMAT_VERSION};

/// Minimum passphrase length — enforced at encryption time
pub const MIN_PASSPHRASE_LENGTH: usize = 12;

/// Validate passphrase strength. Only enforced on encryption, not decryption
/// (an old folder encrypted with a short passphrase still needs to be openable).
pub fn validate_passphrase(passphrase: &str) -> Result<(), String> {
    if passphrase.len() < MIN_PASSPHRASE_LENGTH {
        return Err(format!(
            "Passphrase too short: {} characters (minimum {}). Longer is stronger — try a sentence you'll remember.",
            passphrase.len(),
            MIN_PASSPHRASE_LENGTH
        ));
    }
    Ok(())
}

/// Derive a 256-bit key from a passphrase using Argon2id
pub fn derive_key(passphrase: &str, salt: &[u8; 32]) -> Result<[u8; 32], String> {
    let params = Params::new(65536, 3, 1, Some(32)).map_err(|e| format!("Argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| format!("Key derivation failed: {e}"))?;

    Ok(key)
}

/// Encrypt plaintext bytes. Returns the full .ghost file contents (header + ciphertext).
pub fn encrypt(plaintext: &[u8], passphrase: &str, salt: &[u8; 32]) -> Result<Vec<u8>, String> {
    validate_passphrase(passphrase)?;
    let mut key = derive_key(passphrase, salt)?;

    let cipher =
        XChaCha20Poly1305::new_from_slice(&key).map_err(|e| format!("Cipher init: {e}"))?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("Encryption failed: {e}"))?;

    // Build file
    let header = GhostHeader {
        version: FORMAT_VERSION,
        salt: *salt,
        nonce: nonce_bytes,
    };

    let mut output = header.to_bytes();
    output.extend_from_slice(&ciphertext);

    // Wipe key from memory
    key.zeroize();

    Ok(output)
}

/// Decrypt a .ghost file's contents. Returns the original plaintext.
pub fn decrypt(file_data: &[u8], passphrase: &str) -> Result<Vec<u8>, String> {
    let header = GhostHeader::from_bytes(file_data)?;
    let ciphertext = &file_data[crate::format::HEADER_SIZE..];

    let mut key = derive_key(passphrase, &header.salt)?;

    let cipher =
        XChaCha20Poly1305::new_from_slice(&key).map_err(|e| format!("Cipher init: {e}"))?;

    let nonce = XNonce::from_slice(&header.nonce);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed — wrong key or corrupted file".to_string())?;

    key.zeroize();

    Ok(plaintext)
}

/// Generate a random 32-byte salt
pub fn generate_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let plaintext = b"---\nvmdId: TEST-001\n---\n\n# Hello GhostIT\n\nThis is a test.";
        let passphrase = "test-passphrase-123";
        let salt = generate_salt();

        let encrypted = encrypt(plaintext, passphrase, &salt).unwrap();

        assert!(encrypted.len() > plaintext.len());
        assert_eq!(&encrypted[0..4], b"GHST");

        let decrypted = decrypt(&encrypted, passphrase).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let plaintext = b"secret content";
        let salt = generate_salt();

        let encrypted = encrypt(plaintext, "correct-key-long-enough", &salt).unwrap();
        let result = decrypt(&encrypted, "wrong-key-also-long");

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("wrong key"));
    }

    #[test]
    fn empty_content() {
        let plaintext = b"";
        let salt = generate_salt();

        let encrypted = encrypt(plaintext, "long-enough-key!", &salt).unwrap();
        let decrypted = decrypt(&encrypted, "long-enough-key!").unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn unicode_content() {
        let plaintext = "halicon's café résumé — naïve coöperation 🍄".as_bytes();
        let salt = generate_salt();

        let encrypted = encrypt(plaintext, "long-enough-key!", &salt).unwrap();
        let decrypted = decrypt(&encrypted, "long-enough-key!").unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn short_passphrase_rejected() {
        let plaintext = b"secret";
        let salt = generate_salt();

        let result = encrypt(plaintext, "short", &salt);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too short"));
    }
}
