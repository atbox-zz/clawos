use crate::error::{ClawFSError, Result};
use crate::path::{PathNamespace, PathValidator};
use std::path::Path;

pub struct ClawFS {
    root_path: std::path::PathBuf,
}

impl ClawFS {
    pub fn new(root_path: &Path) -> Result<Self> {
        if !root_path.starts_with("/clawfs") {
            return Err(ClawFSError::PathValidation(
                "ClawFS root must start with /clawfs".to_string(),
            ));
        }

        Ok(Self {
            root_path: root_path.to_path_buf(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root_path
    }

    pub fn get_namespace_path(&self, namespace: PathNamespace) -> std::path::PathBuf {
        self.root_path.join(namespace.as_str())
    }

    pub fn get_system_path(&self) -> std::path::PathBuf {
        self.get_namespace_path(PathNamespace::System)
    }

    pub fn get_agents_path(&self) -> std::path::PathBuf {
        self.get_namespace_path(PathNamespace::Agents)
    }

    pub fn get_tools_path(&self) -> std::path::PathBuf {
        self.get_namespace_path(PathNamespace::Tools)
    }

    pub fn get_workspaces_path(&self) -> std::path::PathBuf {
        self.get_namespace_path(PathNamespace::Workspaces)
    }

    pub fn get_vault_path(&self) -> std::path::PathBuf {
        self.get_namespace_path(PathNamespace::Vault)
    }

    pub fn get_specs_path(&self) -> std::path::PathBuf {
        self.get_namespace_path(PathNamespace::Specs)
    }

    pub fn get_agent_path(&self, agent_name: &str) -> Result<std::path::PathBuf> {
        PathValidator::validate_agent_name(agent_name)?;
        Ok(self.get_agents_path().join(agent_name))
    }

    pub fn get_workspace_path(&self, workspace_name: &str) -> Result<std::path::PathBuf> {
        PathValidator::validate_workspace_name(workspace_name)?;
        Ok(self.get_workspaces_path().join(workspace_name))
    }

    pub fn get_tool_path(&self, tool_name: &str, version: &str) -> Result<std::path::PathBuf> {
        PathValidator::validate_tool_name(tool_name)?;
        PathValidator::validate_component(version)?;
        Ok(self.get_tools_path().join("binaries").join(format!(
            "{}-v{}.wasm",
            tool_name, version
        )))
    }

    pub fn initialize_structure(&self) -> Result<()> {
        std::fs::create_dir_all(self.get_system_path())?;
        std::fs::create_dir_all(self.get_agents_path())?;
        std::fs::create_dir_all(self.get_tools_path())?;
        std::fs::create_dir_all(self.get_workspaces_path())?;
        std::fs::create_dir_all(self.get_vault_path())?;
        std::fs::create_dir_all(self.get_specs_path())?;

        Ok(())
    }
}

pub struct WorkspaceDatabase {
    path: std::path::PathBuf,
    connection: Option<rusqlite::Connection>,
}

impl WorkspaceDatabase {
    pub fn new(path: &Path) -> Result<Self> {
        Ok(Self {
            path: path.to_path_buf(),
            connection: None,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn initialize_fts5_skeleton(&self) -> Result<()> {
        let conn = rusqlite::Connection::open(&self.path)?;

        conn.execute(
            "CREATE VIRTUAL TABLE IF NOT EXISTS documents USING fts5(
                id INTEGER PRIMARY KEY,
                workspace_id TEXT NOT NULL,
                content TEXT,
                metadata TEXT,
                tokenize = 'porter unicode61'
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS vectors (
                id INTEGER PRIMARY KEY,
                document_id INTEGER NOT NULL,
                embedding BLOB NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (document_id) REFERENCES documents(id)
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "INSERT OR IGNORE INTO metadata (key, value) VALUES ('vector_dimension', '1536')",
            [],
        )?;

        conn.execute(
            "INSERT OR IGNORE INTO metadata (key, value) VALUES ('hnsw_m', '16')",
            [],
        )?;

        conn.execute(
            "INSERT OR IGNORE INTO metadata (key, value) VALUES ('hnsw_ef_construction', '200')",
            [],
        )?;

        conn.execute(
            "INSERT OR IGNORE INTO metadata (key, value) VALUES ('hnsw_ef_search', '50')",
            [],
        )?;

        Ok(())
    }

    pub fn configure_sqlite(&self) -> Result<()> {
        let conn = rusqlite::Connection::open(&self.path)?;

        conn.execute("PRAGMA journal_mode = WAL", [])?;
        conn.execute("PRAGMA cache_size = -64000", [])?;
        conn.execute("PRAGMA mmap_size = 268435456", [])?;
        conn.execute("PRAGMA synchronous = NORMAL", [])?;
        conn.execute("PRAGMA temp_store = MEMORY", [])?;

        Ok(())
    }

    pub fn open(&mut self) -> Result<()> {
        self.connection = Some(rusqlite::Connection::open(&self.path)?);
        Ok(())
    }

    pub fn close(&mut self) -> Result<()> {
        self.connection = None;
        Ok(())
    }

    pub fn connection(&self) -> Result<&rusqlite::Connection> {
        self.connection
            .as_ref()
            .ok_or_else(|| ClawFSError::NotImplemented("Database not open".to_string()))
    }

    pub fn connection_mut(&mut self) -> Result<&mut rusqlite::Connection> {
        self.connection
            .as_mut()
            .ok_or_else(|| ClawFSError::NotImplemented("Database not open".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_clawfs_new() {
        let temp_dir = TempDir::new().unwrap();
        let clawfs_path = temp_dir.path().join("clawfs");
        let clawfs = ClawFS::new(&clawfs_path);
        assert!(clawfs.is_ok());
    }

    #[test]
    fn test_clawfs_new_invalid_root() {
        let clawfs = ClawFS::new(Path::new("/invalid/path"));
        assert!(clawfs.is_err());
    }

    #[test]
    fn test_clawfs_namespace_paths() {
        let temp_dir = TempDir::new().unwrap();
        let clawfs_path = temp_dir.path().join("clawfs");
        let clawfs = ClawFS::new(&clawfs_path).unwrap();

        assert_eq!(
            clawfs.get_system_path(),
            clawfs_path.join("system")
        );
        assert_eq!(
            clawfs.get_agents_path(),
            clawfs_path.join("agents")
        );
        assert_eq!(
            clawfs.get_tools_path(),
            clawfs_path.join("tools")
        );
        assert_eq!(
            clawfs.get_workspaces_path(),
            clawfs_path.join("workspaces")
        );
        assert_eq!(
            clawfs.get_vault_path(),
            clawfs_path.join("vault")
        );
        assert_eq!(
            clawfs.get_specs_path(),
            clawfs_path.join("specs")
        );
    }

    #[test]
    fn test_clawfs_get_agent_path() {
        let temp_dir = TempDir::new().unwrap();
        let clawfs_path = temp_dir.path().join("clawfs");
        let clawfs = ClawFS::new(&clawfs_path).unwrap();

        let path = clawfs.get_agent_path("kernel-engine").unwrap();
        assert_eq!(path, clawfs_path.join("agents/kernel-engine"));
    }

    #[test]
    fn test_clawfs_get_agent_path_invalid() {
        let temp_dir = TempDir::new().unwrap();
        let clawfs_path = temp_dir.path().join("clawfs");
        let clawfs = ClawFS::new(&clawfs_path).unwrap();

        let result = clawfs.get_agent_path("invalid-agent");
        assert!(result.is_err());
    }

    #[test]
    fn test_clawfs_get_workspace_path() {
        let temp_dir = TempDir::new().unwrap();
        let clawfs_path = temp_dir.path().join("clawfs");
        let clawfs = ClawFS::new(&clawfs_path).unwrap();

        let path = clawfs.get_workspace_path("my-workspace").unwrap();
        assert_eq!(path, clawfs_path.join("workspaces/my-workspace"));
    }

    #[test]
    fn test_clawfs_get_workspace_path_reserved() {
        let temp_dir = TempDir::new().unwrap();
        let clawfs_path = temp_dir.path().join("clawfs");
        let clawfs = ClawFS::new(&clawfs_path).unwrap();

        let result = clawfs.get_workspace_path("default");
        assert!(result.is_err());
    }

    #[test]
    fn test_clawfs_get_tool_path() {
        let temp_dir = TempDir::new().unwrap();
        let clawfs_path = temp_dir.path().join("clawfs");
        let clawfs = ClawFS::new(&clawfs_path).unwrap();

        let path = clawfs.get_tool_path("telegram-channel", "1.0.0").unwrap();
        assert_eq!(
            path,
            clawfs_path.join("tools/binaries/telegram-channel-v1.0.0.wasm")
        );
    }

    #[test]
    fn test_clawfs_initialize_structure() {
        let temp_dir = TempDir::new().unwrap();
        let clawfs_path = temp_dir.path().join("clawfs");
        let clawfs = ClawFS::new(&clawfs_path).unwrap();

        clawfs.initialize_structure().unwrap();

        assert!(clawfs.get_system_path().exists());
        assert!(clawfs.get_agents_path().exists());
        assert!(clawfs.get_tools_path().exists());
        assert!(clawfs.get_workspaces_path().exists());
        assert!(clawfs.get_vault_path().exists());
        assert!(clawfs.get_specs_path().exists());
    }

    #[test]
    fn test_workspace_database_new() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("workspace.db");
        let db = WorkspaceDatabase::new(&db_path);
        assert!(db.is_ok());
    }

    #[test]
    fn test_workspace_database_initialize_fts5() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("workspace.db");
        let db = WorkspaceDatabase::new(&db_path).unwrap();

        db.initialize_fts5_skeleton().unwrap();

        assert!(db_path.exists());
    }

    #[test]
    fn test_workspace_database_configure_sqlite() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("workspace.db");
        let db = WorkspaceDatabase::new(&db_path).unwrap();

        db.initialize_fts5_skeleton().unwrap();
        db.configure_sqlite().unwrap();

        assert!(db_path.exists());
    }
}
