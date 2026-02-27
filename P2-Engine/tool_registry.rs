// crates/clawos-agent/src/agent/tool_registry.rs
//
// Tool Registry — D-06: scans ClawFS tools directory,
// loads WASM binaries, validates capabilities.
// Phase P2: skeleton. Phase P3: real tool payloads from IronClaw tools-src/.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tracing::{info, warn, debug};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolManifest {
    pub name:         String,
    pub version:      String,
    pub description:  String,
    pub capabilities: Vec<Capability>,
    pub wasm_path:    String,
    pub wit_world:    String,   // must be "clawos-tool" per P1.1
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Capability {
    /// Read from ClawFS workspace
    FsRead,
    /// Write to ClawFS workspace
    FsWrite,
    /// Make HTTP requests (URL checked against allowlist)
    HttpFetch,
    /// Call the LLM
    LlmComplete,
    /// Invoke other tools
    ToolChain,
    /// Access secrets (injected by host, never visible to WASM)
    SecretsInject,
}

pub struct ToolRegistry {
    tools_dir: String,
    tools:     HashMap<String, ToolManifest>,
}

impl ToolRegistry {
    pub fn new(tools_dir: &str) -> Self {
        Self { tools_dir: tools_dir.to_string(), tools: HashMap::new() }
    }

    /// Scan tools directory and load all manifests.
    /// Each tool lives in tools_dir/{name}/manifest.json + tool.wasm
    pub async fn scan(&mut self) -> Result<()> {
        let dir = Path::new(&self.tools_dir);
        if !dir.exists() {
            warn!(path = %self.tools_dir, "Tools directory not found — creating empty registry");
            tokio::fs::create_dir_all(dir).await?;
            return Ok(());
        }

        let mut entries = tokio::fs::read_dir(dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            if !entry.file_type().await?.is_dir() { continue; }

            let manifest_path = entry.path().join("manifest.json");
            if !manifest_path.exists() {
                debug!(path = %entry.path().display(), "No manifest.json, skipping");
                continue;
            }

            match load_manifest(&manifest_path).await {
                Ok(manifest) => {
                    info!(tool = %manifest.name, version = %manifest.version, caps = ?manifest.capabilities, "Tool registered");
                    self.tools.insert(manifest.name.clone(), manifest);
                }
                Err(e) => {
                    warn!(path = %manifest_path.display(), error = %e, "Failed to load tool manifest");
                }
            }
        }

        info!(count = self.tools.len(), "Tool scan complete");
        Ok(())
    }

    pub fn has_tool(&self, name: &str) -> bool {
        self.tools.contains_key(name)
    }

    pub fn get_tool(&self, name: &str) -> Option<&ToolManifest> {
        self.tools.get(name)
    }

    pub fn tool_names(&self) -> Vec<String> {
        self.tools.keys().cloned().collect()
    }

    pub fn len(&self) -> usize { self.tools.len() }
    pub fn is_empty(&self) -> bool { self.tools.is_empty() }

    /// Verify a tool has the requested capability (security boundary).
    pub fn check_capability(&self, tool_name: &str, cap: &Capability) -> bool {
        self.tools
            .get(tool_name)
            .map(|m| m.capabilities.contains(cap))
            .unwrap_or(false)
    }

    /// Register a built-in stub tool (used in P2 before real WASM tools land in P3).
    pub fn register_stub(&mut self, name: &str, description: &str, caps: Vec<Capability>) {
        let manifest = ToolManifest {
            name:         name.to_string(),
            version:      "0.0.1-stub".to_string(),
            description:  description.to_string(),
            capabilities: caps,
            wasm_path:    format!("stub://{name}"),
            wit_world:    "clawos-tool".to_string(),
        };
        info!(tool = name, "Stub tool registered");
        self.tools.insert(name.to_string(), manifest);
    }
}

async fn load_manifest(path: &Path) -> Result<ToolManifest> {
    let content = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("Cannot read manifest: {}", path.display()))?;

    let manifest: ToolManifest = serde_json::from_str(&content)
        .with_context(|| format!("Invalid manifest JSON: {}", path.display()))?;

    // Validate WIT world (P1.1 requirement)
    if manifest.wit_world != "clawos-tool" && manifest.wit_world != "clawos-channel" {
        anyhow::bail!(
            "Tool '{}' has invalid wit_world '{}' — must be 'clawos-tool' or 'clawos-channel'",
            manifest.name, manifest.wit_world
        );
    }

    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_check() {
        let mut reg = ToolRegistry::new("/tmp/test-tools");
        reg.register_stub("web-search", "Search the web", vec![Capability::HttpFetch]);

        assert!(reg.check_capability("web-search", &Capability::HttpFetch));
        assert!(!reg.check_capability("web-search", &Capability::FsWrite));
        assert!(!reg.check_capability("nonexistent", &Capability::FsRead));
    }

    #[test]
    fn tool_names_returns_all() {
        let mut reg = ToolRegistry::new("/tmp");
        reg.register_stub("tool-a", "a", vec![]);
        reg.register_stub("tool-b", "b", vec![]);
        let mut names = reg.tool_names();
        names.sort();
        assert_eq!(names, vec!["tool-a", "tool-b"]);
    }
}
