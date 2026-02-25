use crate::error::{ClawFSError, Result};
use std::path::Path as StdPath;

pub const MAX_PATH_COMPONENT_LENGTH: usize = 255;
pub const MAX_WORKSPACE_NAME_LENGTH: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathNamespace {
    System,
    Agents,
    Tools,
    Workspaces,
    Vault,
    Specs,
}

impl PathNamespace {
    pub fn as_str(&self) -> &'static str {
        match self {
            PathNamespace::System => "system",
            PathNamespace::Agents => "agents",
            PathNamespace::Tools => "tools",
            PathNamespace::Workspaces => "workspaces",
            PathNamespace::Vault => "vault",
            PathNamespace::Specs => "specs",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "system" => Some(PathNamespace::System),
            "agents" => Some(PathNamespace::Agents),
            "tools" => Some(PathNamespace::Tools),
            "workspaces" => Some(PathNamespace::Workspaces),
            "vault" => Some(PathNamespace::Vault),
            "specs" => Some(PathNamespace::Specs),
            _ => None,
        }
    }
}

pub struct PathValidator;

impl PathValidator {
    pub fn validate_component(component: &str) -> Result<()> {
        if component.is_empty() {
            return Err(ClawFSError::PathValidation("Component cannot be empty".into()));
        }

        if component.len() > MAX_PATH_COMPONENT_LENGTH {
            return Err(ClawFSError::PathComponentTooLong(MAX_PATH_COMPONENT_LENGTH));
        }

        if !component.is_ascii() {
            return Err(ClawFSError::NonAscii(component.to_string()));
        }

        if !component.is_lowercase() {
            return Err(ClawFSError::NotLowercase(component.to_string()));
        }

        for c in component.chars() {
            if !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '-' && c != '.' {
                return Err(ClawFSError::InvalidCharacters(format!(
                    "Invalid character '{}' in '{}'",
                    c, component
                )));
            }
        }

        if component.contains('_') || component.contains(' ') {
            return Err(ClawFSError::InvalidSeparator(component.to_string()));
        }

        Ok(())
    }

    pub fn validate_workspace_name(name: &str) -> Result<()> {
        Self::validate_component(name)?;

        if name.len() > MAX_WORKSPACE_NAME_LENGTH {
            return Err(ClawFSError::InvalidConfig(format!(
                "Workspace name exceeds maximum length of {}",
                MAX_WORKSPACE_NAME_LENGTH
            )));
        }

        let reserved_names = ["default", "system", "vault"];
        if reserved_names.contains(&name) {
            return Err(ClawFSError::InvalidConfig(format!(
                "Workspace name '{}' is reserved",
                name
            )));
        }

        Ok(())
    }

    pub fn validate_tool_name(name: &str) -> Result<()> {
        Self::validate_component(name)?;
        Ok(())
    }

    pub fn validate_agent_name(name: &str) -> Result<()> {
        Self::validate_component(name)?;

        let valid_agents = [
            "kernel-engine",
            "ebpf-agent",
            "security-agent",
            "core-dev-agent",
            "wasm-agent",
            "fs-engine",
            "observability",
            "build-engine",
        ];

        if !valid_agents.contains(&name) {
            return Err(ClawFSError::InvalidConfig(format!(
                "Invalid agent name '{}'. Valid agents: {:?}",
                name, valid_agents
            )));
        }

        Ok(())
    }

    pub fn validate_clawfs_path(path: &str) -> Result<()> {
        let std_path = StdPath::new(path);

        if !std_path.starts_with("/clawfs/") {
            return Err(ClawFSError::PathValidation(
                "Path must start with /clawfs/".into(),
            ));
        }

        let components: Vec<&str> = std_path
            .components()
            .filter_map(|c| c.as_os_str().to_str())
            .collect();

        if components.len() < 3 {
            return Err(ClawFSError::PathValidation(
                "Path must have at least /clawfs/{namespace}/...".into(),
            ));
        }

        if let Some(namespace) = components.get(1) {
            if PathNamespace::from_str(namespace).is_none() {
                return Err(ClawFSError::PathValidation(format!(
                    "Invalid namespace '{}'",
                    namespace
                )));
            }
        }

        for component in &components[2..] {
            Self::validate_component(component)?;
        }

        Ok(())
    }

    pub fn build_path(namespace: PathNamespace, components: &[&str]) -> Result<String> {
        let mut path = format!("/clawfs/{}", namespace.as_str());

        for component in components {
            Self::validate_component(component)?;
            path.push('/');
            path.push_str(component);
        }

        Ok(path)
    }

    pub fn build_agent_path(agent_name: &str, components: &[&str]) -> Result<String> {
        Self::validate_agent_name(agent_name)?;
        Self::build_path(PathNamespace::Agents, &[agent_name])
            .map(|base| {
                let mut path = base;
                for component in components {
                    Self::validate_component(component).unwrap();
                    path.push('/');
                    path.push_str(component);
                }
                path
            })
    }

    pub fn build_workspace_path(workspace_name: &str, components: &[&str]) -> Result<String> {
        Self::validate_workspace_name(workspace_name)?;
        Self::build_path(PathNamespace::Workspaces, &[workspace_name])
            .map(|base| {
                let mut path = base;
                for component in components {
                    Self::validate_component(component).unwrap();
                    path.push('/');
                    path.push_str(component);
                }
                path
            })
    }

    pub fn build_tool_path(tool_name: &str, version: &str, components: &[&str]) -> Result<String> {
        Self::validate_tool_name(tool_name)?;
        Self::validate_component(version)?;

        let base = Self::build_path(PathNamespace::Tools, &[])?;
        let mut path = format!("{}/binaries/{}-v{}.wasm", base, tool_name, version);

        for component in components {
            Self::validate_component(component)?;
            path.push('/');
            path.push_str(component);
        }

        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_component_valid() {
        assert!(PathValidator::validate_component("valid-name").is_ok());
        assert!(PathValidator::validate_component("another-valid-name-123").is_ok());
        assert!(PathValidator::validate_component("tool-v1.0.0").is_ok());
    }

    #[test]
    fn test_validate_component_empty() {
        assert!(PathValidator::validate_component("").is_err());
    }

    #[test]
    fn test_validate_component_too_long() {
        let long_name = "a".repeat(256);
        assert!(PathValidator::validate_component(&long_name).is_err());
    }

    #[test]
    fn test_validate_component_non_ascii() {
        assert!(PathValidator::validate_component("café").is_err());
        assert!(PathValidator::validate_component("日本語").is_err());
    }

    #[test]
    fn test_validate_component_uppercase() {
        assert!(PathValidator::validate_component("InvalidName").is_err());
        assert!(PathValidator::validate_component("invalid-Name").is_err());
    }

    #[test]
    fn test_validate_component_underscore() {
        assert!(PathValidator::validate_component("invalid_name").is_err());
    }

    #[test]
    fn test_validate_component_space() {
        assert!(PathValidator::validate_component("invalid name").is_err());
    }

    #[test]
    fn test_validate_component_special_chars() {
        assert!(PathValidator::validate_component("invalid@name").is_err());
        assert!(PathValidator::validate_component("invalid#name").is_err());
    }

    #[test]
    fn test_validate_workspace_name_valid() {
        assert!(PathValidator::validate_workspace_name("my-workspace").is_ok());
        assert!(PathValidator::validate_workspace_name("project-alpha").is_ok());
    }

    #[test]
    fn test_validate_workspace_name_reserved() {
        assert!(PathValidator::validate_workspace_name("default").is_err());
        assert!(PathValidator::validate_workspace_name("system").is_err());
        assert!(PathValidator::validate_workspace_name("vault").is_err());
    }

    #[test]
    fn test_validate_workspace_name_too_long() {
        let long_name = "a".repeat(65);
        assert!(PathValidator::validate_workspace_name(&long_name).is_err());
    }

    #[test]
    fn test_validate_agent_name_valid() {
        assert!(PathValidator::validate_agent_name("kernel-engine").is_ok());
        assert!(PathValidator::validate_agent_name("ebpf-agent").is_ok());
        assert!(PathValidator::validate_agent_name("security-agent").is_ok());
    }

    #[test]
    fn test_validate_agent_name_invalid() {
        assert!(PathValidator::validate_agent_name("invalid-agent").is_err());
        assert!(PathValidator::validate_agent_name("kernel_engine").is_err());
    }

    #[test]
    fn test_validate_clawfs_path_valid() {
        assert!(PathValidator::validate_clawfs_path("/clawfs/system/kernel/config").is_ok());
        assert!(PathValidator::validate_clawfs_path("/clawfs/agents/kernel-engine/workspace.db").is_ok());
        assert!(PathValidator::validate_clawfs_path("/clawfs/workspaces/default/workspace.db").is_ok());
    }

    #[test]
    fn test_validate_clawfs_path_invalid_root() {
        assert!(PathValidator::validate_clawfs_path("/invalid/path").is_err());
        assert!(PathValidator::validate_clawfs_path("/clawfs-invalid/path").is_err());
    }

    #[test]
    fn test_validate_clawfs_path_invalid_namespace() {
        assert!(PathValidator::validate_clawfs_path("/clawfs/invalid/path").is_err());
    }

    #[test]
    fn test_build_path() {
        let path = PathValidator::build_path(PathNamespace::System, &["kernel", "config"]);
        assert_eq!(path, Ok("/clawfs/system/kernel/config".to_string()));
    }

    #[test]
    fn test_build_agent_path() {
        let path = PathValidator::build_agent_path("kernel-engine", &["workspace.db"]);
        assert_eq!(path, Ok("/clawfs/agents/kernel-engine/workspace.db".to_string()));
    }

    #[test]
    fn test_build_workspace_path() {
        let path = PathValidator::build_workspace_path("my-workspace", &["workspace.db"]);
        assert_eq!(path, Ok("/clawfs/workspaces/my-workspace/workspace.db".to_string()));
    }

    #[test]
    fn test_build_tool_path() {
        let path = PathValidator::build_tool_path("telegram-channel", "1.0.0", &[]);
        assert_eq!(path, Ok("/clawfs/tools/binaries/telegram-channel-v1.0.0.wasm".to_string()));
    }

    #[test]
    fn test_path_namespace_from_str() {
        assert_eq!(PathNamespace::from_str("system"), Some(PathNamespace::System));
        assert_eq!(PathNamespace::from_str("agents"), Some(PathNamespace::Agents));
        assert_eq!(PathNamespace::from_str("invalid"), None);
    }

    #[test]
    fn test_path_namespace_as_str() {
        assert_eq!(PathNamespace::System.as_str(), "system");
        assert_eq!(PathNamespace::Agents.as_str(), "agents");
        assert_eq!(PathNamespace::Tools.as_str(), "tools");
    }
}
