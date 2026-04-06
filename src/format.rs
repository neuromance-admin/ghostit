//! Chitin file format (.chitin)
//!
//! Layout (per file):
//!   [4 bytes]  magic: b"CHTN"
//!   [2 bytes]  format version: u16 LE (currently 1)
//!   [32 bytes] salt (for key derivation — same salt across all files in a vault)
//!   [24 bytes] nonce (unique per file)
//!   [N bytes]  encrypted payload (XChaCha20-Poly1305 ciphertext + 16-byte auth tag)
//!
//! Manifest file (.chitin-manifest):
//!   Same format as above. Decrypted payload is JSON mapping
//!   opaque filenames -> original relative paths.

pub const MAGIC: &[u8; 4] = b"CHTN";
pub const FORMAT_VERSION: u16 = 1;
pub const HEADER_SIZE: usize = 4 + 2 + 32 + 24; // 62 bytes

/// Parsed header from a .chitin file
#[derive(Debug, Clone)]
pub struct ChitinHeader {
    pub version: u16,
    pub salt: [u8; 32],
    pub nonce: [u8; 24],
}

impl ChitinHeader {
    /// Parse header from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < HEADER_SIZE {
            return Err(format!(
                "File too small: {} bytes, need at least {}",
                data.len(),
                HEADER_SIZE
            ));
        }

        if &data[0..4] != MAGIC {
            return Err("Not a Chitin file (bad magic bytes)".into());
        }

        let version = u16::from_le_bytes([data[4], data[5]]);
        if version != FORMAT_VERSION {
            return Err(format!(
                "Unsupported format version: {} (expected {})",
                version, FORMAT_VERSION
            ));
        }

        let mut salt = [0u8; 32];
        salt.copy_from_slice(&data[6..38]);

        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&data[38..62]);

        Ok(Self {
            version,
            salt,
            nonce,
        })
    }

    /// Serialize header to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_SIZE);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce);
        out
    }
}
