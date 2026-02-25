// Phase 3 Configuration Schemas (P3.5, P3.6, P3.7, P3.8)
//
// This module defines configuration structures for:
// - P3.5: Prompt Injection defense (SQLite schema for pattern DB)
// - P3.6: Endpoint allowlist (LLM providers, rate limiting, TLS verification)
// - P3.7: LLM Provider configuration (NEAR AI/OpenRouter bridge)
// - P3.8: Secrets key init (kernel keyring, TPM 2.0 sealing, AES-256-GCM)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// P3.5: Prompt Injection Pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptInjectionPattern {
    pub pattern_id: String,
    pub regex: String,
    pub severity: PatternSeverity,
    pub description: String,
    pub false_positive_rate: f64,
    pub last_updated: String,
}

/// Pattern severity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PatternSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// P3.6: LLM Endpoint Allowlist Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowlistConfig {
    pub providers: HashMap<String, ProviderConfig>,
    pub global_settings: GlobalSettings,
}

/// Provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    pub name: String,
    pub base_url: String,
    pub allowed_endpoints: Vec<String>,
    pub tls_config: TlsConfig,
    pub rate_limit: Option<RateLimit>,
}

/// TLS verification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub verify_certificates: bool,
    pub min_tls_version: String,
    pub allowed_cert_pins: Vec<String>,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    pub requests_per_minute: u32,
    pub requests_per_hour: u32,
    pub burst_size: u32,
}

/// Global settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalSettings {
    pub enable_tls_verification: bool,
    pub max_concurrent_requests: u32,
    pub timeout_secs: u32,
}

/// P3.7: LLM Provider Bridge Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmProviderBridge {
    pub primary_provider: String,
    pub fallback_providers: Vec<String>,
    pub near_ai: NearAiConfig,
    pub openrouter: OpenRouterConfig,
}

/// NEAR AI configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NearAiConfig {
    pub api_key_path: String,
    pub model: String,
    pub temperature: f32,
    pub max_tokens: u32,
}

/// OpenRouter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenRouterConfig {
    pub api_key_path: String,
    pub models: Vec<String>,
    pub temperature: f32,
    pub max_tokens: u32,
}

/// P3.8: Secrets Management Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsConfig {
    pub keyring_config: KeyringConfig,
    pub tpm_config: Option<TpmConfig>,
    pub encryption_config: EncryptionConfig,
}

/// Keyring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyringConfig {
    pub keyring_name: String,
    pub key_type: KeyType,
    pub key_description: String,
}

/// Key type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    User,
    Session,
    Process,
    Thread,
}

/// TPM 2.0 configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmConfig {
    pub device_path: String,
    pub pcr_banks: Vec<String>,
    pub srk_password: Option<String>,
}

/// Encryption configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    pub algorithm: EncryptionAlgorithm,
    pub pbkdf2_iterations: u32,
    pub key_length_bits: u16,
}

/// Encryption algorithm
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionAlgorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            verify_certificates: true,
            min_tls_version: "1.3".to_string(),
            allowed_cert_pins: vec![],
        }
    }
}

impl Default for GlobalSettings {
    fn default() -> Self {
        Self {
            enable_tls_verification: true,
            max_concurrent_requests: 100,
            timeout_secs: 30,
        }
    }
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            algorithm: EncryptionAlgorithm::Aes256Gcm,
            pbkdf2_iterations: 600000,
            key_length_bits: 256,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prompt_injection_pattern_serialization() {
        let pattern = PromptInjectionPattern {
            pattern_id: "pi-001".to_string(),
            regex: ".*ignore previous.*".to_string(),
            severity: PatternSeverity::High,
            description: "Classic prompt injection attempt".to_string(),
            false_positive_rate: 0.01,
            last_updated: "2026-02-24".to_string(),
        };

        let json = serde_json::to_string(&pattern);
        assert!(json.is_ok());
    }

    #[test]
    fn test_tls_config_default() {
        let tls = TlsConfig::default();
        assert!(tls.verify_certificates);
        assert_eq!(tls.min_tls_version, "1.3");
    }

    #[test]
    fn test_global_settings_default() {
        let settings = GlobalSettings::default();
        assert_eq!(settings.max_concurrent_requests, 100);
        assert_eq!(settings.timeout_secs, 30);
    }

    #[test]
    fn test_encryption_config_default() {
        let enc = EncryptionConfig::default();
        assert_eq!(enc.key_length_bits, 256);
        assert_eq!(enc.pbkdf2_iterations, 600000);
    }
}
