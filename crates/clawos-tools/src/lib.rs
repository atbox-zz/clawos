// crates/clawos-tools/src/lib.rs
//
// clawos-tools — WASM tool build + install + registry sync
//
// Responsible for:
//   1. Compiling WASM tools from source (cargo component build)
//   2. Validating manifests against WIT world
//   3. Installing tool.wasm + manifest.json to tools_dir
//   4. Syncing the agent's ToolRegistry
//
// Used by: Makefile `make build-tools`, CI/CD, agent preflight

#![allow(dead_code)]
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::{error, info, warn};

// ── Manifest ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolManifest {
    pub name: String,
    pub version: String,
    pub description: String,
    pub capabilities: Vec<String>,
    pub wasm_path: String,
    pub wit_world: String,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub rate_limit: Option<serde_json::Value>,
}

impl ToolManifest {
    pub fn is_enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
    }

    pub fn load(manifest_path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(manifest_path)
            .with_context(|| format!("Cannot read manifest: {}", manifest_path.display()))?;
        serde_json::from_str(&content)
            .with_context(|| format!("Invalid manifest JSON: {}", manifest_path.display()))
    }

    pub fn validate(&self) -> Vec<String> {
        let mut errors = vec![];
        if self.name.is_empty() {
            errors.push("name is empty".into());
        }
        if self.version.is_empty() {
            errors.push("version is empty".into());
        }
        if self.wasm_path.is_empty() {
            errors.push("wasm_path is empty".into());
        }
        let valid_worlds = ["clawos-tool", "clawos-channel"];
        if !valid_worlds.contains(&self.wit_world.as_str()) {
            errors.push(format!(
                "wit_world '{}' must be one of: {:?}",
                self.wit_world, valid_worlds
            ));
        }
        errors
    }
}

// ── Tool record ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct InstalledTool {
    pub manifest: ToolManifest,
    pub wasm_path: PathBuf,
    pub wasm_size: u64,
    pub sha256: String,
}

// ── Tool Manager ──────────────────────────────────────────────

pub struct ToolManager {
    tools_dir: PathBuf,  // /var/lib/clawos/tools
    source_dir: PathBuf, // repo tools/ directory
}

impl ToolManager {
    pub fn new(tools_dir: impl Into<PathBuf>, source_dir: impl Into<PathBuf>) -> Self {
        Self {
            tools_dir: tools_dir.into(),
            source_dir: source_dir.into(),
        }
    }

    /// Scan installed tools directory and return all valid installed tools.
    pub fn scan_installed(&self) -> Result<Vec<InstalledTool>> {
        let mut tools = vec![];
        let dir = &self.tools_dir;
        if !dir.exists() {
            warn!(?dir, "Tools directory does not exist");
            return Ok(vec![]);
        }

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let tool_dir = entry.path();
            if !tool_dir.is_dir() {
                continue;
            }

            let manifest_path = tool_dir.join("manifest.json");
            if !manifest_path.exists() {
                continue;
            }

            match self.load_installed(&tool_dir) {
                Ok(tool) => tools.push(tool),
                Err(e) => warn!(path = ?tool_dir, "Failed to load tool: {e}"),
            }
        }

        info!(count = tools.len(), "Scanned installed tools");
        Ok(tools)
    }

    fn load_installed(&self, tool_dir: &Path) -> Result<InstalledTool> {
        let manifest = ToolManifest::load(&tool_dir.join("manifest.json"))?;

        // Validate manifest
        let errors = manifest.validate();
        if !errors.is_empty() {
            anyhow::bail!(
                "Manifest validation failed for {}: {:?}",
                manifest.name,
                errors
            );
        }

        let wasm_path = tool_dir.join("tool.wasm");
        let (wasm_size, sha256) = if wasm_path.exists() {
            let data = std::fs::read(&wasm_path)?;
            let sha = compute_sha256(&data);
            (data.len() as u64, sha)
        } else {
            warn!(tool = %manifest.name, "tool.wasm missing — stub mode");
            (0, String::new())
        };

        Ok(InstalledTool {
            manifest,
            wasm_path,
            wasm_size,
            sha256,
        })
    }

    /// Build a WASM tool from source using cargo component.
    pub fn build_tool(&self, tool_name: &str) -> Result<PathBuf> {
        let src_dir = self.source_dir.join(tool_name);
        if !src_dir.exists() {
            anyhow::bail!("Tool source not found: {}", src_dir.display());
        }

        info!(tool = tool_name, "Building WASM tool");

        let status = std::process::Command::new("cargo")
            .args(["build", "--target", "wasm32-wasi", "--release"])
            .current_dir(&src_dir)
            .status()
            .context("cargo build failed")?;

        if !status.success() {
            anyhow::bail!("cargo build failed for tool: {tool_name}");
        }

        // Find the output wasm
        let wasm_name = tool_name.replace('-', "_");
        let wasm_src = src_dir
            .ancestors()
            .find(|p| p.join("target").exists())
            .unwrap_or(&src_dir)
            .join("target/wasm32-wasi/release")
            .join(format!("{wasm_name}.wasm"));

        if !wasm_src.exists() {
            anyhow::bail!("WASM output not found: {}", wasm_src.display());
        }

        info!(tool = tool_name, path = ?wasm_src, "WASM built successfully");
        Ok(wasm_src)
    }

    /// Install a compiled tool into tools_dir.
    pub fn install_tool(&self, tool_name: &str, wasm_src: &Path) -> Result<InstalledTool> {
        let src_dir = self.source_dir.join(tool_name);
        let dest_dir = self.tools_dir.join(tool_name);
        std::fs::create_dir_all(&dest_dir)?;

        // Copy manifest
        let manifest_src = src_dir.join("manifest.json");
        let manifest_dest = dest_dir.join("manifest.json");
        std::fs::copy(&manifest_src, &manifest_dest)?;

        // Copy wasm
        let wasm_dest = dest_dir.join("tool.wasm");
        std::fs::copy(wasm_src, &wasm_dest)?;

        let wasm_data = std::fs::read(&wasm_dest)?;
        let wasm_size = wasm_data.len() as u64;
        let sha256 = compute_sha256(&wasm_data);

        info!(
            tool = tool_name,
            size = wasm_size,
            sha = &sha256[..16],
            "Tool installed"
        );

        let manifest = ToolManifest::load(&manifest_dest)?;
        Ok(InstalledTool {
            manifest,
            wasm_path: wasm_dest,
            wasm_size,
            sha256,
        })
    }

    /// Build + install all tools found in source_dir.
    pub fn install_all(&self) -> Result<Vec<InstalledTool>> {
        let mut installed = vec![];
        for entry in std::fs::read_dir(&self.source_dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if !entry.path().is_dir() {
                continue;
            }
            if !entry.path().join("Cargo.toml").exists() {
                continue;
            }

            info!(tool = %name, "Building + installing tool");
            match self
                .build_tool(&name)
                .and_then(|w| self.install_tool(&name, &w))
            {
                Ok(t) => installed.push(t),
                Err(e) => error!(tool = %name, "Install failed: {e}"),
            }
        }
        Ok(installed)
    }

    /// Print a status table of all tools.
    pub fn status_table(&self) -> Result<()> {
        let tools = self.scan_installed()?;
        println!(
            "  {:<20} {:<10} {:<8} {}",
            "Tool", "Version", "WASM", "Status"
        );
        println!("  {}", "─".repeat(60));
        for t in &tools {
            let wasm_ok = t.wasm_path.exists();
            let size = if wasm_ok {
                format!("{:.0}KB", t.wasm_size / 1024)
            } else {
                "missing".into()
            };
            let status = if !t.manifest.is_enabled() {
                "disabled"
            } else if wasm_ok {
                "ready"
            } else {
                "stub"
            };
            println!(
                "  {:<20} {:<10} {:<8} {}",
                t.manifest.name, t.manifest.version, size, status
            );
        }
        if tools.is_empty() {
            println!("  (no tools installed)");
        }
        Ok(())
    }
}

fn compute_sha256(data: &[u8]) -> String {
    use std::fmt::Write;
    let digest = ring::digest::digest(&ring::digest::SHA256, data);
    let mut s = String::with_capacity(64);
    for b in digest.as_ref() {
        write!(s, "{b:02x}").unwrap();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_manifest(name: &str) -> String {
        serde_json::json!({
            "name": name, "version": "0.1.0",
            "description": "test", "capabilities": [],
            "wasm_path": "tool.wasm", "wit_world": "clawos-tool"
        })
        .to_string()
    }

    #[test]
    fn manifest_validates_correctly() {
        let m: ToolManifest = serde_json::from_str(&make_manifest("test-tool")).unwrap();
        assert!(m.validate().is_empty());
    }

    #[test]
    fn manifest_rejects_bad_wit_world() {
        let mut m: ToolManifest = serde_json::from_str(&make_manifest("bad")).unwrap();
        m.wit_world = "bad-world".into();
        assert!(!m.validate().is_empty());
    }

    #[test]
    fn scan_installed_empty_dir() {
        let tmp = TempDir::new().unwrap();
        let mgr = ToolManager::new(tmp.path(), tmp.path());
        let tools = mgr.scan_installed().unwrap();
        assert!(tools.is_empty());
    }

    #[test]
    fn scan_installed_finds_tool() {
        let tmp = TempDir::new().unwrap();
        let tool_dir = tmp.path().join("test-tool");
        std::fs::create_dir(&tool_dir).unwrap();
        std::fs::write(tool_dir.join("manifest.json"), make_manifest("test-tool")).unwrap();

        let mgr = ToolManager::new(tmp.path(), tmp.path());
        let tools = mgr.scan_installed().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].manifest.name, "test-tool");
    }
}
