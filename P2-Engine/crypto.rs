// crates/clawfs/src/crypto.rs
//
// AES-256-GCM encryption for ClawFS (P1.4 spec).
// Key sourced from kernel keyring — never touches disk.

use anyhow::{Context, Result};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
    Aes256Gcm, Nonce, Key,
};

const NONCE_LEN: usize = 12;  // 96-bit nonce (P1.4 frozen)
const KEY_LEN:   usize = 32;  // 256-bit key

/// Encrypt plaintext using AES-256-GCM.
/// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
pub fn encrypt(key_source: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let key_bytes = load_key(key_source)?;
    let key       = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher    = Aes256Gcm::new(key);

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("AES-GCM encrypt failed: {e}"))?;

    // Prepend nonce: nonce || ciphertext+tag
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt ciphertext (nonce || ciphertext+tag format).
pub fn decrypt(key_source: &str, blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < NONCE_LEN + 16 {
        anyhow::bail!("Ciphertext too short (expected at least {} bytes)", NONCE_LEN + 16);
    }

    let key_bytes = load_key(key_source)?;
    let key       = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher    = Aes256Gcm::new(key);

    let nonce      = Nonce::from_slice(&blob[..NONCE_LEN]);
    let ciphertext = &blob[NONCE_LEN..];

    cipher.decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("AES-GCM decrypt failed (wrong key or corrupted data): {e}"))
}

/// Derive a key from the configured source.
/// Priority: kernel keyring → environment variable → dev mode random key
fn load_key(source: &str) -> Result<Vec<u8>> {
    if source == "keyring" {
        load_from_keyring()
    } else if let Some(env_var) = source.strip_prefix("env:") {
        let hex = std::env::var(env_var)
            .with_context(|| format!("Env var {env_var} not set for ClawFS key"))?;
        hex_decode(&hex)
    } else if let Some(path) = source.strip_prefix("file:") {
        let hex = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read key file: {path}"))?;
        hex_decode(hex.trim())
    } else if source == "dev_random" {
        // Dev mode only — generates a new random key each process start
        // Data encrypted with this key is NOT persistent
        tracing::warn!("ClawFS using dev_random key — data is NOT persistent across restarts!");
        let mut key = vec![0u8; KEY_LEN];
        OsRng.fill_bytes(&mut key);
        Ok(key)
    } else {
        anyhow::bail!("Unknown key source: {source}")
    }
}

fn load_from_keyring() -> Result<Vec<u8>> {
    // Use keyctl syscall via /proc/keys or keyutils
    // keyctl search @s user clawos-fs-key
    let output = std::process::Command::new("keyctl")
        .args(["pipe", "@s", "user", "clawfs-key"])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            if out.stdout.len() == KEY_LEN {
                Ok(out.stdout)
            } else {
                hex_decode(&String::from_utf8_lossy(&out.stdout).trim())
            }
        }
        _ => {
            // Fallback for dev environments without keyctl
            tracing::warn!("kernel keyring unavailable — falling back to env:CLAWFS_KEY");
            let hex = std::env::var("CLAWFS_KEY")
                .context("Neither kernel keyring nor CLAWFS_KEY env var is available")?;
            hex_decode(&hex)
        }
    }
}

fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    let clean: String = hex.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if clean.len() != KEY_LEN * 2 {
        anyhow::bail!("Key must be {} hex chars (got {})", KEY_LEN * 2, clean.len());
    }
    (0..KEY_LEN)
        .map(|i| u8::from_str_radix(&clean[i*2..i*2+2], 16)
            .map_err(|e| anyhow::anyhow!("Invalid hex: {e}")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let source = "env:CLAWFS_KEY";
        // Inject a test key
        unsafe { std::env::set_var("CLAWFS_KEY", "a".repeat(64)); }

        let plaintext = b"Hello, ClawFS!";
        let ciphertext = encrypt(source, plaintext).unwrap();
        let decrypted  = decrypt(source, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn different_nonces_produce_different_ciphertexts() {
        unsafe { std::env::set_var("CLAWFS_KEY", "b".repeat(64)); }
        let source = "env:CLAWFS_KEY";
        let pt = b"same plaintext";
        let ct1 = encrypt(source, pt).unwrap();
        let ct2 = encrypt(source, pt).unwrap();
        assert_ne!(ct1, ct2); // Different nonces
    }

    #[test]
    fn tampered_ciphertext_fails_decryption() {
        unsafe { std::env::set_var("CLAWFS_KEY", "c".repeat(64)); }
        let source = "env:CLAWFS_KEY";
        let mut ct = encrypt(source, b"secret").unwrap();
        ct[15] ^= 0xFF; // Tamper with ciphertext
        assert!(decrypt(source, &ct).is_err());
    }
}
