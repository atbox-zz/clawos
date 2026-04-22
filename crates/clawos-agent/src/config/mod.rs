// crates/clawos-agent/src/config/mod.rs

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    /// cgroup path for this agent process
    #[serde(default = "default_cgroup_path")]
    pub cgroup_path: String,

    /// Profile name (matches resource-quotas.json profiles)
    #[serde(default = "default_profile")]
    pub profile: String,

    /// IPC socket path
    #[serde(default = "default_ipc_socket")]
    pub ipc_socket: String,

    pub clawfs: clawfs::ClawFsConfig,
    pub wasm: WasmConfig,
    pub llm: LlmConfig,
    pub security: SecurityConfig,
    
    #[serde(default)]
    pub channels: ChannelConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct WasmConfig {
    #[serde(default = "default_wasm_stack")]
    pub max_stack_bytes: u64,
    #[serde(default = "default_wasm_memory")]
    pub max_memory_bytes: u64,
    /// Directory where .wasm tool binaries are stored
    #[serde(default = "default_tools_dir")]
    pub tools_dir: String,
    /// cgroup path for WASM worker processes
    #[serde(default = "default_wasm_cgroup_path")]
    pub wasm_cgroup_path: String,
}

impl WasmConfig {
    /// Returns the configured WASM cgroup path (configurable, not hardcoded).
    pub fn wasm_cgroup_path(&self) -> &str {
        &self.wasm_cgroup_path
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct LlmConfig {
    pub backend: String, // "near_ai" | "openai_compatible"
    pub base_url: String,
    pub model: String,
    pub api_key_secret: String, // name in Secrets Vault, not the actual key
}

#[derive(Debug, Deserialize, Clone)]
pub struct SecurityConfig {
    /// Endpoint allowlist for WASM HTTP calls
    pub allowed_endpoints: Vec<AllowedEndpoint>,
    /// Paths WASM tools may read
    pub allowed_read_paths: Vec<String>,
    /// Paths WASM tools may write
    pub allowed_write_paths: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AllowedEndpoint {
    pub host: String,
    pub port: u16,
    pub paths: Vec<String>,   // glob patterns
    pub methods: Vec<String>, // GET, POST, etc.
}

#[derive(Default)]
#[derive(Debug, Deserialize, Clone)]
pub struct ChannelConfig {
    #[serde(default)]
    pub web_gateway: WebGatewayConfig,
    #[serde(default)]
    pub telegram: TelegramConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct WebGatewayConfig {
    #[serde(default = "default_gateway_enabled")]
    pub enabled: bool,
    #[serde(default = "default_gateway_bind")]
    pub bind: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TelegramConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_webhook_port")]
    pub webhook_port: u16,
}

impl Default for WebGatewayConfig {
    fn default() -> Self { Self { enabled: true, bind: default_gateway_bind() } }
}
impl Default for TelegramConfig {
    fn default() -> Self { Self { enabled: false, webhook_port: default_webhook_port() } }
}

fn default_gateway_enabled() -> bool { true }
fn default_gateway_bind()    -> String { "127.0.0.1:8080".into() }
fn default_webhook_port()    -> u16    { 8443 }

impl Config {
    pub async fn load() -> Result<Self> {
        // 1. Load .env bootstrap (DATABASE_URL, LLM_BACKEND, etc.)
        let env_path =
            std::env::var("CLAWOS_ENV").unwrap_or_else(|_| "/etc/clawos/.env".to_string());
        if Path::new(&env_path).exists() {
            dotenvy::from_path(&env_path)
                .with_context(|| format!("Failed to load env from {env_path}"))?;
        }

        // 2. Load config file (TOML)
        let config_path = std::env::var("CLAWOS_CONFIG")
            .unwrap_or_else(|_| "/etc/clawos/config.toml".to_string());

        let toml_str = tokio::fs::read_to_string(&config_path)
            .await
            .with_context(|| format!("Cannot read config: {config_path}"))?;

        let config: Config = toml::from_str(&toml_str).context("Failed to parse config TOML")?;

        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        // Verify frozen spec deps before engine starts
        if self.clawfs.vector_dims != 1536 && self.clawfs.vector_dims != 3072 {
            anyhow::bail!(
                "vector_dims must be 1536 or 3072 (P1.4 frozen spec). Got: {}",
                self.clawfs.vector_dims
            );
        }
        // Guard against accidental dev_random key in production (audit #7)
        if self.clawfs.key_source == "dev_random" && self.profile != "dev" {
            anyhow::bail!(
                "ClawFS key_source 'dev_random' is only permitted with profile='dev'. \
                 Current profile: '{}'. Use 'keyring' or 'env:CLAWFS_KEY' in production.",
                self.profile
            );
        }
        Ok(())
    }
}

fn default_cgroup_path() -> String {
    "/sys/fs/cgroup/clawos/agent".into()
}
fn default_profile() -> String {
    "agent_process".into()
}
fn default_ipc_socket() -> String {
    "/var/run/clawos/ipc/agent.sock".into()
}
fn default_wasm_stack() -> u64 {
    4 * 1024 * 1024
} // 4MB
fn default_wasm_memory() -> u64 {
    128 * 1024 * 1024
} // 128MB per worker
fn default_tools_dir() -> String {
    "/var/lib/clawos/tools".into()
}
fn default_wasm_cgroup_path() -> String {
    "/sys/fs/cgroup/clawos/wasm".into()
}
