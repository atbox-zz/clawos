// crates/clawfs/src/crypto.rs
//
// AES-256-GCM encryption for ClawFS (P1.4 spec).
// Key sourced from kernel keyring — never touches disk.
//
// FIX H-02 (audit #4 — patch):
//   - load_from_keyring() now uses the `keyutils` crate (direct syscall)
//     instead of spawning an external `keyctl` process, eliminating the
//     PATH-pollution attack surface.
//   - The fallback to CLAWFS_KEY env var now emits `tracing::error!`
//     (was `warn!`) so operators always notice when keyring is absent in
//     production.  Operators can set `keyring_fallback_allowed = false` in
//     config to make the fallback a hard failure.
//   - A boolean `ALLOW_ENV_FALLBACK` compile-time constant controls whether
//     the env-var fallback is permitted; it is `false` in release builds
//     unless explicitly opted in via `--cfg clawfs_allow_env_key`.
//
// FIX M-02 (audit #4 — patch):
//   - Tests no longer use `unsafe { std::env::set_var(...) }`.
//     Key bytes are injected directly via the `load_key_bytes` helper
//     instead of going through the env-var code path, eliminating the
//     UB data race on the process environment block.

use aes_gcm::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{Context, Result};

const NONCE_LEN: usize = 12; // 96-bit nonce (P1.4 frozen)
const KEY_LEN: usize = 32; // 256-bit key

// FIX H-02: env-var fallback is only allowed in debug builds or when
// the `clawfs_allow_env_key` cfg flag is explicitly set at compile time.
// Release builds without this flag will hard-fail if the keyring is absent.
#[cfg(any(debug_assertions, clawfs_allow_env_key))]
const ALLOW_ENV_FALLBACK: bool = true;
#[cfg(not(any(debug_assertions, clawfs_allow_env_key)))]
const ALLOW_ENV_FALLBACK: bool = false;

/// Encrypt plaintext using AES-256-GCM.
/// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
pub fn encrypt(key_source: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let key_bytes = load_key(key_source)?;
    encrypt_with_key(&key_bytes, plaintext)
}

/// Encrypt with explicit key bytes (used by tests to avoid env-var UB).
pub fn encrypt_with_key(key_bytes: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if key_bytes.len() != KEY_LEN {
        anyhow::bail!("Key must be {} bytes, got {}", KEY_LEN, key_bytes.len());
    }
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("AES-GCM encrypt failed: {e}"))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt ciphertext (nonce || ciphertext+tag format).
pub fn decrypt(key_source: &str, blob: &[u8]) -> Result<Vec<u8>> {
    let key_bytes = load_key(key_source)?;
    decrypt_with_key(&key_bytes, blob)
}

/// Decrypt with explicit key bytes (used by tests to avoid env-var UB).
pub fn decrypt_with_key(key_bytes: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < NONCE_LEN + 16 {
        anyhow::bail!(
            "Ciphertext too short (expected at least {} bytes)",
            NONCE_LEN + 16
        );
    }
    if key_bytes.len() != KEY_LEN {
        anyhow::bail!("Key must be {} bytes, got {}", KEY_LEN, key_bytes.len());
    }
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&blob[..NONCE_LEN]);
    let ciphertext = &blob[NONCE_LEN..];

    cipher
        .decrypt(nonce, ciphertext)
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
        // ✅ 加入路徑約束：只允許讀取 /etc/clawos/ 或 /var/lib/clawos/ 下的 key 檔
        /////////////////////////////////////////////////////////////////////////
        let allowed_prefixes = ["/etc/clawos/", "/var/lib/clawos/"];
        let canonical = std::fs::canonicalize(path)
            .with_context(|| format!("Cannot resolve key file path: {path}"))?;
        let allowed = allowed_prefixes
            .iter()
            .any(|prefix| canonical.starts_with(prefix));
        if !allowed {
            anyhow::bail!(
                "Key file '{}' is outside allowed directories {:?}",
                path,
                allowed_prefixes
            );
        }
        let hex = std::fs::read_to_string(&canonical)
            .with_context(|| format!("Cannot read key file: {path}"))?;
        hex_decode(hex.trim())
    } else if source == "dev_random" {
        #[cfg(not(debug_assertions))]
        anyhow::bail!(
            "ClawFS key source 'dev_random' is not permitted in release builds. \
             Set key_source to 'keyring', 'env:CLAWFS_KEY', or 'file:/path'."
        );
        #[cfg(debug_assertions)]
        {
            tracing::warn!("ClawFS using dev_random key — data is NOT persistent across restarts!");
            let mut key = vec![0u8; KEY_LEN];
            OsRng.fill_bytes(&mut key);
            Ok(key)
        }
    } else {
        anyhow::bail!("Unknown key source: {source}")
    }
}

fn load_from_keyring() -> Result<Vec<u8>> {
    // FIX H-02: use direct keyutils syscall instead of spawning external `keyctl`.
    // This eliminates the PATH-pollution / binary-substitution attack surface.
    //
    // keyutils crate wraps the request_key(2) syscall directly:
    //   request_key("user", "clawfs-key", None, KEY_SPEC_SESSION_KEYRING)
    //
    // If the keyutils crate is unavailable at link time (e.g. no libkeyutils),
    // we compile-gate to the env-var path.

    #[cfg(feature = "keyutils")]
    {
        use keyutils::{KeyType, Keyring};
        match Keyring::attach_or_create(keyutils::SpecialKeyring::Session) {
            Ok(ring) => {
                match ring.search(KeyType::User, "clawfs-key") {
                    Ok(key) => {
                        let raw = key.read()?;
                        if raw.len() == KEY_LEN {
                            return Ok(raw);
                        }
                        // hex-encoded form
                        let hex_str =
                            String::from_utf8(raw).context("keyring key is not valid UTF-8")?;
                        return hex_decode(hex_str.trim());
                    }
                    Err(e) => {
                        tracing::debug!("keyutils search failed: {e}; trying env fallback");
                    }
                }
            }
            Err(e) => {
                tracing::debug!("keyutils attach failed: {e}; trying env fallback");
            }
        }
    }

    // FIX H-02: fallback now emits ERROR, not warn, so it appears in
    // production alerting.  Additionally, the fallback is compile-time
    // gated: release builds fail hard unless `clawfs_allow_env_key` is set.
    if !ALLOW_ENV_FALLBACK {
        anyhow::bail!(
            "ClawFS kernel keyring unavailable and env-var fallback is disabled \
             in this build. Configure the keyring key 'clawfs-key' or rebuild \
             with cfg(clawfs_allow_env_key) if you intend to use CLAWFS_KEY."
        );
    }

    tracing::error!(
        "ClawOS: kernel keyring unavailable — falling back to CLAWFS_KEY env var. \
         This is not recommended for production. Configure the kernel keyring."
    );
    let hex = std::env::var("CLAWFS_KEY")
        .context("Neither kernel keyring nor CLAWFS_KEY env var is available")?;
    hex_decode(&hex)
}

fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    let clean: String = hex.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if clean.len() != KEY_LEN * 2 {
        anyhow::bail!(
            "Key must be {} hex chars (got {})",
            KEY_LEN * 2,
            clean.len()
        );
    }
    (0..KEY_LEN)
        .map(|i| {
            u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16)
                .map_err(|e| anyhow::anyhow!("Invalid hex: {e}"))
        })
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────
//
// FIX M-02: all tests now use encrypt_with_key / decrypt_with_key, passing
// key bytes directly. No unsafe { set_var } calls — eliminates the multi-
// threaded data race on the environment block (UB in Rust 1.80+).

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key(fill: u8) -> Vec<u8> {
        vec![fill; KEY_LEN]
    }

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let key = test_key(0xAA);
        let plaintext = b"Hello, ClawFS!";
        let ciphertext = encrypt_with_key(&key, plaintext).unwrap();
        let decrypted = decrypt_with_key(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn different_nonces_produce_different_ciphertexts() {
        let key = test_key(0xBB);
        let pt = b"same plaintext";
        let ct1 = encrypt_with_key(&key, pt).unwrap();
        let ct2 = encrypt_with_key(&key, pt).unwrap();
        assert_ne!(ct1, ct2); // Different nonces
    }

    #[test]
    fn tampered_ciphertext_fails_decryption() {
        let key = test_key(0xCC);
        let mut ct = encrypt_with_key(&key, b"secret").unwrap();
        ct[15] ^= 0xFF; // Tamper with ciphertext
        assert!(decrypt_with_key(&key, &ct).is_err());
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let key_a = test_key(0xAA);
        let key_b = test_key(0xBB);
        let ct = encrypt_with_key(&key_a, b"secret").unwrap();
        assert!(decrypt_with_key(&key_b, &ct).is_err());
    }

    #[test]
    fn ciphertext_too_short_returns_error() {
        let key = test_key(0xDD);
        let short = vec![0u8; NONCE_LEN + 10]; // tag is 16 bytes; 10 < 16
        assert!(decrypt_with_key(&key, &short).is_err());
    }

    #[test]
    fn hex_decode_rejects_wrong_length() {
        assert!(hex_decode("aabb").is_err()); // too short
        assert!(hex_decode(&"aa".repeat(33)).is_err()); // too long
    }
}
