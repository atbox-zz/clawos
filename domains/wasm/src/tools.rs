use crate::error::BridgeError;
use crate::resource::FileDescriptor;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::debug;
/// Tool registry for ClawOS
pub struct ToolRegistry {
    /// Path to ClawFS tools directory
    tools_path: PathBuf,
    /// Loaded tools cache
    tools_cache: HashMap<String, ToolDefinition>,
}

impl ToolRegistry {
    /// Create a new tool registry
    pub fn new(clawfs_root: &str) -> Result<Self, BridgeError> {
        let tools_path = PathBuf::from(clawfs_root).join("tools");
        Ok(Self {
            tools_path,
            tools_cache: HashMap::new(),
        })
    }

    /// Register a tool from a WASM binary
    pub fn register_tool(
        &mut self,
        tool_def: ToolDefinition,
        wasm_binary: &[u8],
    ) -> Result<(), BridgeError> {
        self.tools_cache.insert(tool_def.name.clone(), tool_def.clone());
        self.store_wasm_binary(&tool_def.name, wasm_binary)?;
        Ok(())
    }

    /// Get a tool definition by name
    pub fn get_tool(&self, name: &str) -> Option<&ToolDefinition> {
        self.tools_cache.get(name)
    }

    /// List all registered tools
    pub fn list_tools(&self) -> Vec<&ToolDefinition> {
        self.tools_cache.values().collect()
    }

    /// Store WASM binary for a tool
    fn store_wasm_binary(&self, tool_name: &str, binary: &[u8]) -> Result<(), BridgeError> {
        let tool_dir = self.tools_path.join(tool_name);
        let binary_path = tool_dir.join("tool.wasm");

        if tool_name.contains('/') || tool_name.contains("..") {
            return Err(BridgeError::InvalidInput(format!(
                "Invalid tool name: {}",
                tool_name
            )));
        }

        debug!("Storing WASM binary for tool {}", tool_name);
        Ok(())
    }
}

/// Tool definition structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    /// Unique tool identifier
    pub name: String,

    /// Tool version
    pub version: String,

    /// Tool description
    pub description: String,

    /// WIT interfaces required by this tool
    pub wit_interfaces: Vec<WitInterface>,

    /// Tool execution parameters
    pub parameters: ToolParameters,

    /// Tool capabilities (file access, network, etc.)
    pub capabilities: ToolCapabilities,

    /// Resource limits
    pub resource_limits: ToolResourceLimits,

    /// Tool metadata
    pub metadata: ToolMetadata,
}

/// WIT interface definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitInterface {
    /// Interface name
    pub name: String,

    /// Interface version
    pub version: String,

    /// Required functions
    pub functions: Vec<WitFunction>,
}

/// WIT function definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitFunction {
    /// Function name
    pub name: String,

    /// Input parameter types
    pub inputs: Vec<ParameterType>,

    /// Output parameter types
    pub outputs: Vec<ParameterType>,

    /// Function description
    pub description: Option<String>,
}

/// Parameter type in WIT interface
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParameterType {
    String,
    Number,
    Boolean,
    Array(Box<ParameterType>),
    Record(HashMap<String, ParameterType>),
    Result {
        ok: Option<Box<ParameterType>>,
        err: Option<Box<ParameterType>>,
    },
}

/// Tool execution parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolParameters {
    /// Required input parameters
    pub inputs: HashMap<String, ParameterDefinition>,

    /// Expected output structure
    pub outputs: HashMap<String, ParameterDefinition>,
}

/// Parameter definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterDefinition {
    /// Parameter type
    pub param_type: ParameterType,

    /// Whether parameter is required
    pub required: bool,

    /// Parameter description
    pub description: Option<String>,

    /// Default value (optional)
    pub default: Option<serde_json::Value>,
}

/// Tool capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCapabilities {
    /// File system access
    pub filesystem: FilesystemAccess,

    /// Network access
    pub network: NetworkAccess,

    /// System capabilities
    pub system: Vec<SystemCapability>,
}

/// File system access level
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemAccess {
    /// No file system access
    None,

    /// Read-only access to specific paths
    Readonly { paths: Vec<PathFilter> },

    /// Write access to specific paths
    ReadWrite { paths: Vec<PathFilter> },
}

/// Path filter for file system access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathFilter {
    /// Path pattern (supports glob patterns)
    pub pattern: String,

    /// Allowed permissions
    pub permissions: Vec<FilePermission>,
}

/// File permission
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilePermission {
    Read,
    Write,
    Execute,
}

/// Network access level
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkAccess {
    /// No network access
    None,

    /// HTTP/HTTPS access only
    Http { allowlist: Option<Vec<String>> },

    /// Custom TCP/UDP access
    TcpUdp { addresses: Vec<String>, ports: Vec<u16> },
}

/// System capability
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemCapability {
    /// Spawn processes
    ProcessSpawn,

    /// Environment variable access
    EnvironmentAccess,

    /// Clock/time access
    ClockAccess,

    /// Random number generation
    RandomAccess,
}

/// Tool resource limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResourceLimits {
    /// Memory limit in bytes
    pub memory_bytes: Option<u64>,

    /// CPU time limit in seconds
    pub cpu_time_secs: Option<u64>,

    /// Wall clock time limit in seconds
    pub wall_time_secs: Option<u64>,

    /// Maximum file descriptors
    pub max_fds: Option<u32>,

    /// Maximum number of spawned processes
    pub max_processes: Option<u32>,
}

/// Tool metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolMetadata {
    /// Tool author
    pub author: String,

    /// Tool license
    pub license: String,

    /// Source repository URL
    pub repository_url: Option<String>,

    /// Documentation URL
    pub documentation_url: Option<String>,

    /// Tool creation timestamp
    pub created_at: String,

    /// SHA-256 hash of the WASM binary
    pub wasm_sha256: String,

    /// Tags for categorization
    pub tags: Vec<String>,
}

/// Tool packaging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolPackage {
    /// Tool definition
    pub tool: ToolDefinition,

    /// WASM binary (base64 encoded)
    pub wasm_binary: String,

    /// Package metadata
    pub package_metadata: PackageMetadata,
}

/// Package metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageMetadata {
    /// Package version
    pub package_version: String,

    /// WIT specification version
    pub wit_version: String,

    /// ClawOS target version
    pub clawos_version: String,

    /// Package format version
    pub format_version: String,
}

impl Default for ToolResourceLimits {
    fn default() -> Self {
        Self {
            memory_bytes: Some(256 * 1024 * 1024),
            cpu_time_secs: None,
            wall_time_secs: None,
            max_fds: Some(32),
            max_processes: Some(1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_registry_creation() {
        let registry = ToolRegistry::new("/clawfs");
        assert!(registry.is_ok());
    }

    #[test]
    fn test_tool_definition_serialization() {
        let tool_def = ToolDefinition {
            name: "test-tool".to_string(),
            version: "1.0.0".to_string(),
            description: "A test tool".to_string(),
            wit_interfaces: vec![],
            parameters: ToolParameters {
                inputs: HashMap::new(),
                outputs: HashMap::new(),
            },
            capabilities: ToolCapabilities {
                filesystem: FilesystemAccess::None,
                network: NetworkAccess::None,
                system: vec![],
            },
            resource_limits: ToolResourceLimits::default(),
            metadata: ToolMetadata {
                author: "ClawOS".to_string(),
                license: "Apache-2.0".to_string(),
                repository_url: None,
                documentation_url: None,
                created_at: "2026-02-24".to_string(),
                wasm_sha256: "abc123".to_string(),
                tags: vec![],
            },
        };

        let json = serde_json::to_string(&tool_def);
        assert!(json.is_ok());
    }

    #[test]
    fn test_path_filter_validation() {
        let registry = ToolRegistry::new("/clawfs");
        assert!(registry.is_ok());

        let mut reg = registry.unwrap();
        let tool_def = ToolDefinition {
            name: "../../../evil".to_string(),
            version: "1.0.0".to_string(),
            description: "Evil tool".to_string(),
            wit_interfaces: vec![],
            parameters: ToolParameters {
                inputs: HashMap::new(),
                outputs: HashMap::new(),
            },
            capabilities: ToolCapabilities {
                filesystem: FilesystemAccess::None,
                network: NetworkAccess::None,
                system: vec![],
            },
            resource_limits: ToolResourceLimits::default(),
            metadata: ToolMetadata {
                author: "ClawOS".to_string(),
                license: "Apache-2.0".to_string(),
                repository_url: None,
                documentation_url: None,
                created_at: "2026-02-24".to_string(),
                wasm_sha256: "abc123".to_string(),
                tags: vec![],
            },
        };

        let result = reg.register_tool(tool_def, b"test wasm");
        assert!(result.is_err());
    }

    #[test]
    fn test_tool_resource_limits_default() {
        let limits = ToolResourceLimits::default();
        assert_eq!(limits.memory_bytes, Some(256 * 1024 * 1024));
        assert_eq!(limits.max_fds, Some(32));
        assert_eq!(limits.max_processes, Some(1));
    }
}
