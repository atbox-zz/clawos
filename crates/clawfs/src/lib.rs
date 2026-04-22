// clawfs -- ClawOS AI-Aware File System
// Implements P1.4 spec: vector index + AES-256-GCM + POSIX-compatible API.
// Backend: SQLite (FTS5 for text, custom vector table for embeddings).
//
// FIX (audit #8): rusqlite::Connection is !Send; it cannot be held across
// .await points in async code.  All SQLite operations are now dispatched via
// tokio::task::spawn_blocking onto a dedicated blocking thread.  The public
// API remains async for callers.  The Connection lives inside a
// tokio::sync::Mutex<DbConn> wrapper whose inner value is only accessed from
// spawn_blocking closures, keeping it on a single thread at a time.

#![allow(dead_code)]
use anyhow::{Context, Result};
//use serde::{Deserialize, Serialize};
use serde::{Deserialize};
use std::sync::Arc;
use tokio::sync::Mutex;

pub mod crypto;
pub mod hnsw;
pub mod search;
pub mod vault;

#[derive(Debug, Clone, Deserialize)]
pub struct ClawFsConfig {
    /// SQLite database path
    pub db_path: String,
    /// Encryption key source: "keyring" | "env:CLAWFS_KEY" | "file:/path"
    pub key_source: String,
    /// Vector embedding dimensions (FROZEN in P1.4 -- default 1536)
    pub vector_dims: usize,
    /// HNSW index parameters
    pub hnsw_m: usize,
    pub hnsw_ef_construction: usize,
}

impl Default for ClawFsConfig {
    fn default() -> Self {
        Self {
            db_path: "/var/lib/clawos/clawfs.db".into(),
            key_source: "keyring".into(),
            vector_dims: 1536,
            hnsw_m: 16,
            hnsw_ef_construction: 200,
        }
    }
}

// Inner synchronous handle -- lives only inside spawn_blocking closures.
struct DbInner {
    config: ClawFsConfig,
    db: rusqlite::Connection,
}

// Safety: DbInner is only accessed from spawn_blocking (blocking thread pool),
// never concurrently.  The Mutex ensures exclusive access.
unsafe impl Send for DbInner {}

/// Main ClawFS handle. All operations go through here.
/// Clone is cheap (Arc inside).
#[derive(Clone)]
pub struct ClawFs {
    inner: Arc<Mutex<DbInner>>,
}

impl ClawFs {
    /// Connect to (or create) the ClawFS database.
    pub async fn connect(config: &ClawFsConfig) -> Result<Self> {
        let cfg = config.clone();
        let inner = tokio::task::spawn_blocking(move || -> Result<DbInner> {
            let db = rusqlite::Connection::open(&cfg.db_path)
                .context("Failed to open ClawFS database")?;
            db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
            let mut inner = DbInner { config: cfg, db };
            inner.init_schema()?;
            Ok(inner)
        })
        .await
        .context("spawn_blocking panicked")??;

        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    // ---- File operations ----------------------------------------

    pub async fn read_file(&self, path: String) -> Result<Vec<u8>> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let guard = inner.blocking_lock();
            let encrypted: Vec<u8> = guard.db.query_row(
                "SELECT data FROM files WHERE path = ?1",
                rusqlite::params![path],
                |row| row.get(0),
            )?;
            crypto::decrypt(&guard.config.key_source, &encrypted)
        })
        .await
        .context("spawn_blocking panicked")?
    }

    pub async fn write_file(&self, path: String, data: Vec<u8>) -> Result<()> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let guard = inner.blocking_lock();
            let encrypted = crypto::encrypt(&guard.config.key_source, &data)?;
            let sha256 = compute_sha256(&data);
            let now = now_ms();

            guard.db.execute(
                "INSERT INTO files (path, data, created_at, updated_at, sha256)
                 VALUES (?1, ?2, ?3, ?3, ?4)
                 ON CONFLICT(path) DO UPDATE SET
                   data = excluded.data,
                   updated_at = excluded.updated_at,
                   sha256 = excluded.sha256",
                rusqlite::params![path, encrypted, now, sha256],
            )?;

            let text = String::from_utf8_lossy(&data).to_string();
            guard.db.execute(
                "INSERT OR REPLACE INTO files_fts(path, content) VALUES (?1, ?2)",
                rusqlite::params![path, text],
            )?;
            Ok(())
        })
        .await
        .context("spawn_blocking panicked")?
    }

    pub async fn delete_file(&self, path: String) -> Result<()> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let guard = inner.blocking_lock();
            guard
                .db
                .execute("DELETE FROM files WHERE path = ?1", rusqlite::params![path])?;
            guard.db.execute(
                "DELETE FROM files_fts WHERE path = ?1",
                rusqlite::params![path],
            )?;
            Ok(())
        })
        .await
        .context("spawn_blocking panicked")?
    }

    pub async fn list_dir(&self, prefix: String) -> Result<Vec<String>> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let guard = inner.blocking_lock();
            let pattern = format!("{}%", prefix.trim_end_matches('/'));
            let mut stmt = guard
                .db
                .prepare("SELECT path FROM files WHERE path LIKE ?1 ORDER BY path")?;
            let paths: Vec<String> = stmt
                .query_map(rusqlite::params![pattern], |row| row.get(0))?
                .filter_map(|r| r.ok())
                .collect();
            Ok(paths)
        })
        .await
        .context("spawn_blocking panicked")?
    }

    pub async fn hybrid_search(
        &self,
        text_query: Option<String>,
        embedding: Option<Vec<f32>>,
        top_k: usize,
    ) -> Result<Vec<search::SearchResult>> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let guard = inner.blocking_lock();
            let searcher = search::HybridSearch::new(&guard.db, guard.config.vector_dims);
            searcher.search(text_query.as_deref(), embedding.as_deref(), top_k)
        })
        .await
        .context("spawn_blocking panicked")?
    }

    pub async fn store_embedding(
        &self,
        path: String,
        chunk: String,
        embedding: Vec<f32>,
    ) -> Result<()> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let guard = inner.blocking_lock();
            let file_id: Option<i64> = guard
                .db
                .query_row(
                    "SELECT id FROM files WHERE path = ?1",
                    rusqlite::params![path],
                    |row| row.get(0),
                )
                .ok();

            let blob: Vec<u8> = embedding.iter().flat_map(|f| f.to_le_bytes()).collect();

            guard.db.execute(
                "INSERT INTO embeddings (file_id, chunk_text, embedding, created_at)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![file_id, chunk, blob, now_ms()],
            )?;
            Ok(())
        })
        .await
        .context("spawn_blocking panicked")?
    }

    // ---- Vault operations ---------------------------------------

    pub async fn vault_freeze(
        &self,
        spec_id: String,
        path: String,
        sha256: String,
        agent: String,
    ) -> Result<()> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let guard = inner.blocking_lock();
            guard.db.execute(
                "INSERT INTO vault (spec_id, path, sha256, frozen_at, signed_by)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(spec_id) DO NOTHING",
                rusqlite::params![spec_id, path, sha256, now_ms(), agent],
            )?;
            Ok(())
        })
        .await
        .context("spawn_blocking panicked")?
    }

    pub async fn vault_verify(&self, spec_id: String, sha256: String) -> Result<bool> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let guard = inner.blocking_lock();
            let stored: String = guard.db.query_row(
                "SELECT sha256 FROM vault WHERE spec_id = ?1",
                rusqlite::params![spec_id],
                |row| row.get(0),
            )?;
            Ok(stored == sha256)
        })
        .await
        .context("spawn_blocking panicked")?
    }
}

impl DbInner {
    fn init_schema(&mut self) -> Result<()> {
        self.db.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS files (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                path        TEXT NOT NULL UNIQUE,
                data        BLOB,
                created_at  INTEGER NOT NULL,
                updated_at  INTEGER NOT NULL,
                sha256      TEXT NOT NULL
            );

            CREATE VIRTUAL TABLE IF NOT EXISTS files_fts
            USING fts5(path, content, tokenize='unicode61');

            CREATE TABLE IF NOT EXISTS embeddings (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id     INTEGER REFERENCES files(id) ON DELETE CASCADE,
                chunk_text  TEXT NOT NULL,
                embedding   BLOB NOT NULL,
                created_at  INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS vault (
                spec_id     TEXT PRIMARY KEY,
                path        TEXT NOT NULL,
                sha256      TEXT NOT NULL,
                frozen_at   INTEGER NOT NULL,
                signed_by   TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS agent_logs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                agent       TEXT NOT NULL,
                task_id     TEXT,
                level       TEXT NOT NULL,
                message     TEXT NOT NULL,
                fields_json TEXT,
                timestamp   INTEGER NOT NULL
            );
        "#,
        )?;
        Ok(())
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn compute_sha256(data: &[u8]) -> String {
    use std::fmt::Write;
    let digest = ring::digest::digest(&ring::digest::SHA256, data);
    let mut hex = String::with_capacity(64);
    for byte in digest.as_ref() {
        write!(hex, "{:02x}", byte).unwrap();
    }
    hex
}
