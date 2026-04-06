//! Folder-level operations: encrypt, decrypt, lock, unlock

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::crypto;

/// Manifest: maps opaque filenames to original relative paths
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Manifest {
    pub source_id: String,
    pub version: u16,
    pub files: HashMap<String, String>, // opaque_name -> original_relative_path
}

/// Generate an opaque filename from the original path
fn opaque_name(relative_path: &str, salt: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(relative_path.as_bytes());
    let hash = hasher.finalize();
    format!("{}.ghost", hex::encode(&hash[..16]))
}

/// Encrypt an entire directory into a target directory of .ghost blobs
pub fn encrypt_dir(
    source_dir: &Path,
    target_dir: &Path,
    passphrase: &str,
) -> Result<(), String> {
    if !source_dir.is_dir() {
        return Err(format!("Source is not a directory: {}", source_dir.display()));
    }

    fs::create_dir_all(target_dir)
        .map_err(|e| format!("Failed to create target dir: {e}"))?;

    let salt = crypto::generate_salt();
    let mut manifest = Manifest {
        source_id: String::new(),
        version: 1,
        files: HashMap::new(),
    };

    // Walk and encrypt every file
    let entries: Vec<_> = WalkDir::new(source_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .collect();

    let total = entries.len();
    for (i, entry) in entries.iter().enumerate() {
        let abs_path = entry.path();
        let relative = abs_path
            .strip_prefix(source_dir)
            .map_err(|e| format!("Path strip failed: {e}"))?
            .to_string_lossy()
            .to_string();

        let plaintext =
            fs::read(abs_path).map_err(|e| format!("Failed to read {}: {e}", relative))?;

        let opaque = opaque_name(&relative, &salt);
        let encrypted = crypto::encrypt(&plaintext, passphrase, &salt)?;

        let target_path = target_dir.join(&opaque);
        fs::write(&target_path, &encrypted)
            .map_err(|e| format!("Failed to write {}: {e}", opaque))?;

        manifest.files.insert(opaque, relative.clone());

        eprintln!("  [{}/{}] {}", i + 1, total, relative);
    }

    // Encrypt and write the manifest
    let manifest_json =
        serde_json::to_string_pretty(&manifest).map_err(|e| format!("Manifest serialize: {e}"))?;
    let encrypted_manifest = crypto::encrypt(manifest_json.as_bytes(), passphrase, &salt)?;

    // Write salt file (needed to derive the same key for the manifest)
    let salt_path = target_dir.join(".ghost-salt");
    fs::write(&salt_path, hex::encode(salt))
        .map_err(|e| format!("Failed to write salt: {e}"))?;

    let manifest_path = target_dir.join(".ghost-manifest");
    fs::write(&manifest_path, encrypted_manifest)
        .map_err(|e| format!("Failed to write manifest: {e}"))?;

    eprintln!(
        "  Encrypted {} files into {}",
        total,
        target_dir.display()
    );

    Ok(())
}

/// Decrypt an encrypted directory back to a target directory
pub fn decrypt_dir(
    encrypted_dir: &Path,
    target_dir: &Path,
    passphrase: &str,
) -> Result<(), String> {
    if !encrypted_dir.is_dir() {
        return Err(format!(
            "Encrypted dir not found: {}",
            encrypted_dir.display()
        ));
    }

    // Read the manifest
    let manifest_path = encrypted_dir.join(".ghost-manifest");
    let manifest_data =
        fs::read(&manifest_path).map_err(|e| format!("Failed to read manifest: {e}"))?;

    let manifest_json = crypto::decrypt(&manifest_data, passphrase)?;
    let manifest: Manifest = serde_json::from_slice(&manifest_json)
        .map_err(|e| format!("Manifest parse failed: {e}"))?;

    fs::create_dir_all(target_dir)
        .map_err(|e| format!("Failed to create target dir: {e}"))?;

    let total = manifest.files.len();
    for (i, (opaque, original_path)) in manifest.files.iter().enumerate() {
        let encrypted_path = encrypted_dir.join(opaque);
        let file_data = fs::read(&encrypted_path)
            .map_err(|e| format!("Failed to read {}: {e}", opaque))?;

        let plaintext = crypto::decrypt(&file_data, passphrase)?;

        let output_path = target_dir.join(original_path);
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create dir {}: {e}", parent.display()))?;
        }

        fs::write(&output_path, &plaintext)
            .map_err(|e| format!("Failed to write {}: {e}", original_path))?;

        eprintln!("  [{}/{}] {}", i + 1, total, original_path);
    }

    eprintln!(
        "  Decrypted {} files into {}",
        total,
        target_dir.display()
    );

    Ok(())
}

/// Encrypt a directory in place: encrypt to temp, verify round-trip, then replace original
pub fn encrypt_in_place(source_dir: &Path, passphrase: &str) -> Result<(), String> {
    if !source_dir.is_dir() {
        return Err(format!("Source is not a directory: {}", source_dir.display()));
    }

    // Step 1: Encrypt to a temp directory
    let temp_encrypted = tempfile::Builder::new()
        .prefix("ghostid-encrypt-")
        .tempdir()
        .map_err(|e| format!("Failed to create temp dir: {e}"))?;

    eprintln!("  Encrypting to staging area...");
    encrypt_dir(source_dir, temp_encrypted.path(), passphrase)?;

    // Step 2: Verify round-trip by decrypting back to another temp dir
    let temp_verify = tempfile::Builder::new()
        .prefix("ghostid-verify-")
        .tempdir()
        .map_err(|e| format!("Failed to create verify dir: {e}"))?;

    eprintln!("  Verifying round-trip...");
    decrypt_dir(temp_encrypted.path(), temp_verify.path(), passphrase)?;

    // Step 3: Compare every file against the original
    let originals: Vec<_> = WalkDir::new(source_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .collect();

    for entry in &originals {
        let relative = entry
            .path()
            .strip_prefix(source_dir)
            .map_err(|e| format!("Path strip failed: {e}"))?;
        let verify_path = temp_verify.path().join(relative);

        if !verify_path.exists() {
            return Err(format!(
                "Verification failed: {} missing after round-trip",
                relative.display()
            ));
        }

        let original = fs::read(entry.path())
            .map_err(|e| format!("Failed to read original {}: {e}", relative.display()))?;
        let recovered = fs::read(&verify_path)
            .map_err(|e| format!("Failed to read verified {}: {e}", relative.display()))?;

        if original != recovered {
            return Err(format!(
                "Verification failed: {} differs after round-trip. Original untouched.",
                relative.display()
            ));
        }
    }

    eprintln!("  Verification passed. Replacing original...");

    // Step 4: Remove original contents
    for entry in fs::read_dir(source_dir)
        .map_err(|e| format!("Failed to read source dir: {e}"))?
    {
        let entry = entry.map_err(|e| format!("Dir entry error: {e}"))?;
        let path = entry.path();
        if path.is_dir() {
            fs::remove_dir_all(&path)
                .map_err(|e| format!("Failed to remove {}: {e}", path.display()))?;
        } else {
            fs::remove_file(&path)
                .map_err(|e| format!("Failed to remove {}: {e}", path.display()))?;
        }
    }

    // Step 5: Move encrypted contents into the original directory
    for entry in fs::read_dir(temp_encrypted.path())
        .map_err(|e| format!("Failed to read encrypted dir: {e}"))?
    {
        let entry = entry.map_err(|e| format!("Dir entry error: {e}"))?;
        let dest = source_dir.join(entry.file_name());
        fs::rename(entry.path(), &dest)
            .map_err(|e| format!("Failed to move {}: {e}", entry.file_name().to_string_lossy()))?;
    }

    eprintln!(
        "  In-place encryption complete. {} is now encrypted.",
        source_dir.display()
    );

    Ok(())
}

/// Unlock a directory to a temporary workspace (returns the temp dir path)
pub fn unlock_dir(encrypted_dir: &Path, passphrase: &str) -> Result<PathBuf, String> {
    let temp_dir = tempfile::Builder::new()
        .prefix("ghostid-unlocked-")
        .tempdir()
        .map_err(|e| format!("Failed to create temp dir: {e}"))?;

    let temp_path = temp_dir.keep(); // persist it (caller manages cleanup)

    decrypt_dir(encrypted_dir, &temp_path, passphrase)?;

    Ok(temp_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PASSPHRASE: &str = "ghostid-test-key-2026";

    /// Helper: decrypt the shipped encrypted test data to a temp dir
    fn decrypt_test_data() -> (tempfile::TempDir, PathBuf) {
        let encrypted = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/encrypted");
        let temp = tempfile::tempdir().unwrap();
        decrypt_dir(&encrypted, temp.path(), TEST_PASSPHRASE).unwrap();
        let path = temp.path().to_path_buf();
        (temp, path)
    }

    #[test]
    fn decrypt_and_re_encrypt_round_trip() {
        let (_temp_plain, plaintext_path) = decrypt_test_data();

        // Re-encrypt into GhostID format
        let temp_re_encrypted = tempfile::tempdir().unwrap();
        encrypt_dir(&plaintext_path, temp_re_encrypted.path(), TEST_PASSPHRASE).unwrap();

        // Verify re-encrypted files have GHST magic
        let manifest_path = temp_re_encrypted.path().join(".ghost-manifest");
        assert!(manifest_path.exists());
        let manifest_bytes = fs::read(&manifest_path).unwrap();
        assert_eq!(&manifest_bytes[0..4], b"GHST");

        // Decrypt the re-encrypted data
        let temp_final = tempfile::tempdir().unwrap();
        decrypt_dir(temp_re_encrypted.path(), temp_final.path(), TEST_PASSPHRASE).unwrap();

        // Compare against the first decryption — should be identical
        for entry in WalkDir::new(&plaintext_path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let relative = entry.path().strip_prefix(&plaintext_path).unwrap();
            let original = fs::read(entry.path()).unwrap();
            let recovered = fs::read(temp_final.path().join(relative)).unwrap();
            assert_eq!(
                original, recovered,
                "Mismatch in {}",
                relative.display()
            );
        }
    }

    #[test]
    fn wrong_passphrase_fails() {
        let encrypted = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/encrypted");
        let temp_decrypted = tempfile::tempdir().unwrap();

        let result = decrypt_dir(&encrypted, temp_decrypted.path(), "wrong-key");
        assert!(result.is_err());
    }

    #[test]
    fn decrypted_data_has_expected_structure() {
        let (_temp, plaintext_path) = decrypt_test_data();

        assert!(plaintext_path.join("System/VaultIdentity.md").exists());
        assert!(plaintext_path.join("System/VMD-Index.json").exists());
        assert!(plaintext_path.join("Projects/TestProject.md").exists());
        assert!(plaintext_path.join("Sessions/2026-04-06-test-session.md").exists());
        assert!(plaintext_path.join("People/Owner/testuser.md").exists());
    }

    #[test]
    fn encrypted_files_are_not_plaintext() {
        let encrypted = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/encrypted");

        for entry in WalkDir::new(&encrypted)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |ext| ext == "ghost"))
        {
            let bytes = fs::read(entry.path()).unwrap();
            assert_eq!(&bytes[0..4], b"GHST", "Missing magic in {}", entry.path().display());

            let after_header = &bytes[crate::format::HEADER_SIZE..];
            let as_text = String::from_utf8_lossy(after_header);
            assert!(!as_text.contains("# "), "Plaintext leaked in {}", entry.path().display());
            assert!(!as_text.contains("vmdId"), "Plaintext leaked in {}", entry.path().display());
        }
    }
}
