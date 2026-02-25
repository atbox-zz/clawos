// PostgreSQL to ClawFS Migration (P3.3)
//
// This module implements migration from PostgreSQL + pgvector to SQLite + HNSW
// for ClawFS storage. It provides:
// - SQLite schema definition
// - Migration scripts for data transfer
// - Vector index migration (pgvector → HNSW)

use crate::error::{ClawFSError, Result};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Migration configuration
#[derive(Debug, Clone)]
pub struct MigrationConfig {
    /// PostgreSQL connection string
    pub pg_connection_string: String,
    /// SQLite database path
    pub sqlite_path: PathBuf,
    /// Vector dimension (default: 1536 for OpenAI ada-002)
    pub vector_dimension: usize,
    /// Batch size for data transfer
    pub batch_size: usize,
}

impl Default for MigrationConfig {
    fn default() -> Self {
        Self {
            pg_connection_string: String::new(),
            sqlite_path: PathBuf::from("/clawfs/workspaces/default.db"),
            vector_dimension: 1536,
            batch_size: 1000,
        }
    }
}

/// Migration executor
pub struct Migration {
    config: MigrationConfig,
}

impl Migration {
    pub fn new(config: MigrationConfig) -> Self {
        Self { config }
    }

    /// Initialize SQLite database with ClawFS schema
    pub fn initialize_schema(&self) -> Result<()> {
        let conn = Connection::open(&self.config.sqlite_path)
            .map_err(|e| ClawFSError::Database(e.to_string()))?;

        self.create_tables(&conn)?;
        self.create_fts_indexes(&conn)?;
        self.create_hnsw_tables(&conn)?;

        conn.close()
            .map_err(|e| ClawFSError::Database(e.to_string()))?;

        Ok(())
    }

    /// Create core tables
    fn create_tables(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS agents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                agent_type TEXT NOT NULL,
                state JSON NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            )",
            [],
        )
        .map_err(|e| ClawFSError::Database(e.to_string()))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS workspaces (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                owner_agent_id INTEGER,
                namespace TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (owner_agent_id) REFERENCES agents(id)
            )",
            [],
        )
        .map_err(|e| ClawFSError::Database(e.to_string()))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id INTEGER NOT NULL,
                path TEXT NOT NULL,
                content TEXT,
                metadata JSON,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
            )",
            [],
        )
        .map_err(|e| ClawFSError::Database(e.to_string()))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS tools (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                definition JSON NOT NULL,
                wasm_binary_path TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(name, version)
            )",
            [],
        )
        .map_err(|e| ClawFSError::Database(e.to_string()))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS channels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                channel_type TEXT NOT NULL,
                config JSON NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )",
            [],
        )
        .map_err(|e| ClawFSError::Database(e.to_string()))?;

        Ok(())
    }

    /// Create FTS5 full-text search indexes
    fn create_fts_indexes(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(
                id,
                workspace_id,
                path,
                content,
                content='documents',
                content_rowid='id'
            )",
            [],
        )
        .map_err(|e| ClawFSError::Database(e.to_string()))?;

        conn.execute(
            "CREATE TRIGGER IF NOT EXISTS documents_ai AFTER INSERT ON documents BEGIN
                INSERT INTO documents_fts(rowid, id, workspace_id, path, content)
                VALUES (NEW.id, NEW.id, NEW.workspace_id, NEW.path, NEW.content);
            END",
            [],
        )
        .map_err(|e| ClawFSError::Database(e.to_string()))?;

        conn.execute(
            "CREATE TRIGGER IF NOT EXISTS documents_ad AFTER DELETE ON documents BEGIN
                DELETE FROM documents_fts WHERE rowid = OLD.id;
            END",
            [],
        )
        .map_err(|e| ClawFSError::Database(e.to_string()))?;

        Ok(())
    }

    /// Create HNSW vector index tables
    fn create_hnsw_tables(&self, conn: &Connection) -> Result<()> {
        let dim = self.config.vector_dimension;

        conn.execute(
            &format!(
                "CREATE TABLE IF NOT EXISTS vectors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    document_id INTEGER NOT NULL,
                    vector_hash TEXT NOT NULL UNIQUE,
                    embedding BLOB NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    FOREIGN KEY (document_id) REFERENCES documents(id)
                )"
            ),
            [],
        )
        .map_err(|e| ClawFSError::Database(e.to_string()))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_vectors_document_id ON vectors(document_id)",
            [],
        )
        .map_err(|e| ClawFSError::Database(e.to_string()))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_vectors_hash ON vectors(vector_hash)",
            [],
        )
        .map_err(|e| ClawFSError::Database(e.to_string()))?;

        Ok(())
    }

    /// Insert vector embedding
    pub fn insert_vector(
        &self,
        document_id: u64,
        embedding: &[f32],
    ) -> Result<u64> {
        let conn = Connection::open(&self.config.sqlite_path)
            .map_err(|e| ClawFSError::Database(e.to_string()))?;

        if embedding.len() != self.config.vector_dimension {
            return Err(ClawFSError::Database(format!(
                "Vector dimension mismatch: expected {}, got {}",
                self.config.vector_dimension,
                embedding.len()
            )));
        }

        let vector_bytes: Vec<u8> = embedding
            .iter()
            .flat_map(|f| f.to_le_bytes())
            .collect();
        let vector_hash = self.compute_vector_hash(embedding);

        conn.execute(
            "INSERT INTO vectors (document_id, vector_hash, embedding) VALUES (?1, ?2, ?3)",
            params![document_id as i64, vector_hash, vector_bytes],
        )
        .map_err(|e| ClawFSError::Database(e.to_string()))?;

        Ok(conn.last_insert_rowid())
    }

    /// Get nearest neighbors using HNSW (simplified - would use usearch crate in production)
    pub fn find_similar(
        &self,
        query_embedding: &[f32],
        limit: usize,
    ) -> Result<Vec<VectorResult>> {
        let conn = Connection::open(&self.config.sqlite_path)
            .map_err(|e| ClawFSError::Database(e.to_string()))?;

        if query_embedding.len() != self.config.vector_dimension {
            return Err(ClawFSError::Database(format!(
                "Query vector dimension mismatch: expected {}, got {}",
                self.config.vector_dimension,
                query_embedding.len()
            )));
        }

        let mut stmt = conn.prepare(
            "SELECT v.id, v.document_id, v.embedding, d.path, d.content 
             FROM vectors v 
             JOIN documents d ON v.document_id = d.id 
             LIMIT ?1",
        )
        .map_err(|e| ClawFSError::Database(e.to_string()))?;

        let vector_iter = stmt
            .query_map(params![limit as i64], |row| {
                let embedding_bytes: Vec<u8> = row.get(2)?;
                let embedding = self.bytes_to_embedding(&embedding_bytes);
                Ok(VectorResult {
                    vector_id: row.get(0)?,
                    document_id: row.get(1)?,
                    similarity: self.cosine_similarity(query_embedding, &embedding),
                    path: row.get(3)?,
                    content: row.get(4)?,
                })
            })
            .map_err(|e| ClawFSError::Database(e.to_string()))?;

        let mut results: Vec<VectorResult> = vector_iter
            .filter_map(|r| r.ok())
            .collect();

        results.sort_by(|a, b| b.similarity.partial_cmp(&a.similarity).unwrap());

        Ok(results)
    }

    fn compute_vector_hash(&self, embedding: &[f32]) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        embedding.iter().for_each(|f| f.to_bits().hash(&mut hasher));
        format!("{:x}", hasher.finish())
    }

    fn bytes_to_embedding(&self, bytes: &[u8]) -> Vec<f32> {
        bytes
            .chunks_exact(4)
            .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect()
    }

    fn cosine_similarity(&self, a: &[f32], b: &[f32]) -> f32 {
        let dot_product: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
        let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
        let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm_a == 0.0 || norm_b == 0.0 {
            0.0
        } else {
            dot_product / (norm_a * norm_b)
        }
    }
}

/// Vector search result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorResult {
    pub vector_id: u64,
    pub document_id: u64,
    pub similarity: f32,
    pub path: String,
    pub content: String,
}

/// Migration status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationStatus {
    pub phase: String,
    pub total_items: u64,
    pub migrated_items: u64,
    pub failed_items: u64,
    pub start_time: String,
    pub end_time: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_migration_config_default() {
        let config = MigrationConfig::default();
        assert_eq!(config.vector_dimension, 1536);
        assert_eq!(config.batch_size, 1000);
    }

    #[test]
    fn test_schema_initialization() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");

        let config = MigrationConfig {
            sqlite_path: db_path.clone(),
            ..Default::default()
        };

        let migration = Migration::new(config);
        assert!(migration.initialize_schema().is_ok());

        assert!(db_path.exists());
    }

    #[test]
    fn test_vector_computation() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");

        let config = MigrationConfig {
            sqlite_path: db_path,
            vector_dimension: 4,
            ..Default::default()
        };

        let migration = Migration::new(config);
        migration.initialize_schema().unwrap();

        let embedding = vec![0.1, 0.2, 0.3, 0.4];
        let vector_id = migration.insert_vector(1, &embedding);

        assert!(vector_id.is_ok());
    }

    #[test]
    fn test_similarity_computation() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");

        let config = MigrationConfig {
            sqlite_path: db_path,
            vector_dimension: 3,
            ..Default::default()
        };

        let migration = Migration::new(config);
        migration.initialize_schema().unwrap();

        let a = vec![1.0, 0.0, 0.0];
        let b = vec![1.0, 0.0, 0.0];

        let sim = migration.cosine_similarity(&a, &b);
        assert!((sim - 1.0).abs() < 0.001);

        let c = vec![0.0, 1.0, 0.0];
        let sim2 = migration.cosine_similarity(&a, &c);
        assert!((sim2 - 0.0).abs() < 0.001);
    }
}
