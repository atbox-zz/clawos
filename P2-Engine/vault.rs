// crates/clawfs/src/vault.rs
//
// ClawFS Vault — immutable store for P1 frozen spec artifacts.
// RULE-002: all output artifacts must have SHA256 hash in Vault.
// RULE-003: modifying frozen specs requires dual-agent review.
// E-05: Secrets Vault (kernel keyring integration).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::{info, warn, error};
use chrono::Utc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    pub spec_id:    String,    // e.g. "P1.2", "A-01-output"
    pub path:       String,    // original artifact path
    pub sha256:     String,    // hex-encoded SHA256
    pub frozen_at:  i64,       // Unix epoch ms
    pub signed_by:  String,    // agent name
    pub phase:      String,    // P1 | P2 | P3 | P4
}

pub struct Vault {
    vault_dir: PathBuf,
}

impl Vault {
    pub fn new(vault_dir: &str) -> Self {
        Self { vault_dir: PathBuf::from(vault_dir) }
    }

    pub async fn init(&self) -> Result<()> {
        tokio::fs::create_dir_all(&self.vault_dir).await
            .context("Failed to create vault directory")?;
        info!(path = %self.vault_dir.display(), "Vault initialised");
        Ok(())
    }

    /// Freeze an artifact in the vault. Write-once: returns Ok if already exists with same hash.
    pub async fn freeze(&self, entry: VaultEntry) -> Result<()> {
        let record_path = self.vault_dir.join(format!("{}.json", entry.spec_id));

        if record_path.exists() {
            let existing: VaultEntry = self.load_entry(&record_path).await?;
            if existing.sha256 == entry.sha256 {
                info!(spec_id = %entry.spec_id, "Already frozen with same hash — no-op");
                return Ok(());
            } else {
                // Hash mismatch on write-once entry is a critical violation (RULE-003)
                error!(
                    spec_id    = %entry.spec_id,
                    old_sha256 = %existing.sha256,
                    new_sha256 = %entry.sha256,
                    "VAULT VIOLATION: attempt to overwrite frozen spec with different hash!"
                );
                anyhow::bail!("E002: SPEC_HASH_MISMATCH — vault entry {} is frozen and cannot be modified. \
                    Requires dual-agent review (Security + Core Dev).", entry.spec_id);
            }
        }

        let json = serde_json::to_string_pretty(&entry)?;
        tokio::fs::write(&record_path, json).await
            .with_context(|| format!("Failed to write vault entry: {}", record_path.display()))?;

        info!(spec_id = %entry.spec_id, sha256 = %entry.sha256[..16], signed_by = %entry.signed_by, "✅ Spec frozen in vault");
        Ok(())
    }

    /// Verify an artifact's SHA256 matches the vault record.
    /// Returns Err(E002) if mismatch or not found.
    pub async fn verify(&self, spec_id: &str, actual_sha256: &str) -> Result<()> {
        let record_path = self.vault_dir.join(format!("{spec_id}.json"));

        if !record_path.exists() {
            anyhow::bail!("E002: Spec '{spec_id}' not found in Vault — has it been frozen?");
        }

        let entry = self.load_entry(&record_path).await?;

        if entry.sha256 != actual_sha256 {
            error!(
                spec_id  = spec_id,
                expected = %entry.sha256,
                actual   = %actual_sha256,
                "Vault verification FAILED"
            );
            anyhow::bail!("E002: SPEC_HASH_MISMATCH for '{}' — expected {}, got {}",
                spec_id, &entry.sha256[..16], &actual_sha256[..16]);
        }

        Ok(())
    }

    /// Compute SHA256 of a file and return its hex string.
    pub fn sha256_of_file(path: &str) -> Result<String> {
        let data = std::fs::read(path)
            .with_context(|| format!("Cannot read file for hashing: {path}"))?;
        Ok(sha256_hex(&data))
    }

    pub fn sha256_of_bytes(data: &[u8]) -> String {
        sha256_hex(data)
    }

    pub async fn list_frozen(&self) -> Result<Vec<VaultEntry>> {
        let mut entries = vec![];
        let mut dir = tokio::fs::read_dir(&self.vault_dir).await?;
        while let Some(e) = dir.next_entry().await? {
            if e.path().extension().map(|x| x == "json").unwrap_or(false) {
                if let Ok(entry) = self.load_entry(&e.path()).await {
                    entries.push(entry);
                }
            }
        }
        entries.sort_by(|a, b| a.frozen_at.cmp(&b.frozen_at));
        Ok(entries)
    }

    async fn load_entry(&self, path: &Path) -> Result<VaultEntry> {
        let data = tokio::fs::read_to_string(path).await?;
        serde_json::from_str(&data).context("Invalid vault entry JSON")
    }
}

fn sha256_hex(data: &[u8]) -> String {
    use std::fmt::Write;
    let digest = ring::digest::digest(&ring::digest::SHA256, data);
    let mut hex = String::with_capacity(64);
    for b in digest.as_ref() { write!(hex, "{b:02x}").unwrap(); }
    hex
}

/// Helper: freeze a spec file from disk into the vault.
pub async fn freeze_spec_file(
    vault:    &Vault,
    spec_id:  &str,
    file_path: &str,
    agent:    &str,
    phase:    &str,
) -> Result<String> {
    let sha256 = Vault::sha256_of_file(file_path)?;
    vault.freeze(VaultEntry {
        spec_id:   spec_id.to_string(),
        path:      file_path.to_string(),
        sha256:    sha256.clone(),
        frozen_at: Utc::now().timestamp_millis(),
        signed_by: agent.to_string(),
        phase:     phase.to_string(),
    }).await?;
    Ok(sha256)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn freeze_and_verify() {
        let tmp  = TempDir::new().unwrap();
        let vault = Vault::new(tmp.path().to_str().unwrap());
        vault.init().await.unwrap();

        let sha = "abcdef1234567890".repeat(4);
        vault.freeze(VaultEntry {
            spec_id:  "P1.2".into(),
            path:     "/specs/p1/seccomp.json".into(),
            sha256:   sha.clone(),
            frozen_at: 0,
            signed_by: "Security Agent".into(),
            phase:    "P1".into(),
        }).await.unwrap();

        // Verify with correct hash → Ok
        vault.verify("P1.2", &sha).await.unwrap();

        // Verify with wrong hash → Err
        assert!(vault.verify("P1.2", "wrong").await.is_err());
    }

    #[tokio::test]
    async fn write_once_same_hash_is_noop() {
        let tmp  = TempDir::new().unwrap();
        let vault = Vault::new(tmp.path().to_str().unwrap());
        vault.init().await.unwrap();

        let entry = VaultEntry {
            spec_id: "P1.1".into(), path: "/x".into(),
            sha256: "aabb".repeat(16), frozen_at: 0,
            signed_by: "WASM Agent".into(), phase: "P1".into(),
        };

        vault.freeze(entry.clone()).await.unwrap();
        vault.freeze(entry).await.unwrap(); // same hash → no-op
    }

    #[tokio::test]
    async fn write_once_different_hash_is_error() {
        let tmp   = TempDir::new().unwrap();
        let vault  = Vault::new(tmp.path().to_str().unwrap());
        vault.init().await.unwrap();

        vault.freeze(VaultEntry {
            spec_id: "P1.3".into(), path: "/y".into(),
            sha256: "aaaa".repeat(16), frozen_at: 0,
            signed_by: "eBPF Agent".into(), phase: "P1".into(),
        }).await.unwrap();

        let result = vault.freeze(VaultEntry {
            spec_id: "P1.3".into(), path: "/y".into(),
            sha256: "bbbb".repeat(16), // DIFFERENT hash!
            frozen_at: 0,
            signed_by: "Attacker".into(), phase: "P1".into(),
        }).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("E002"));
    }
}
