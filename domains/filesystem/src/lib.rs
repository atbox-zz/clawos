//! ClawFS - AI-aware filesystem for ClawOS
//!
//! ClawFS provides:
//! - Vector-indexed storage for semantic search across workspaces
//! - AES-256-GCM encryption for secrets vault
//! - POSIX-compatible interface for seamless integration
//! - Identity Files as persistent kernel memory mechanism
//! - Hybrid search combining full-text (FTS5) and vector similarity (HNSW)
//!
//! # Path Namespace Hierarchy
//!
//! ```
//! /clawfs/
//! ├── system/          # OS-managed files (read-only)
//! ├── agents/          # Agent-specific workspaces
//! ├── tools/           # Tool definitions and WASM binaries
//! ├── workspaces/      # User workspaces with vector storage
//! ├── vault/           # Encrypted secrets storage
//! └── specs/           # Frozen specification documents (SHA256-signed)
//! ```
//!
//! # Path Naming Conventions
//!
//! - All path components must be lowercase
//! - Use hyphens, not underscores or spaces
//! - Max length: 255 characters per component
//! - ASCII only (no Unicode)
//!
//! # Vector Storage
//!
//! Default vector dimension: 1536 (OpenAI ada-002 compatible)
//! Alternative: 3072 dimensions (configurable)
//!
//! # Encryption
//!
//! - Algorithm: AES-256-GCM
//! - Key size: 256 bits
//! - IV size: 96 bits
//! - Auth tag size: 128 bits
//! - KDF: PBKDF2-HMAC-SHA256 with 600,000 iterations
//!
//! # PostgreSQL Migration Path
//!
//! Phase 3, Task E-02: PostgreSQL + pgvector → SQLite + HNSW
//! See migration module for details.

pub mod clawfs;
pub mod error;
pub mod path;
pub mod encryption;
pub mod vector;
pub mod identity;
pub mod migration;

pub use clawfs::ClawFS;
pub use error::{ClawFSError, Result};
pub use path::{PathValidator, PathNamespace};
pub use encryption::{SecretEncryptor, SecretMetadata};
pub use vector::{VectorIndex, VectorConfig};
pub use identity::{IdentityFile, IdentityState};
pub use migration::{Migration, MigrationConfig, MigrationStatus, VectorResult};

const CLAWFS_ROOT: &str = "/clawfs";
const DEFAULT_VECTOR_DIMENSION: usize = 1536;
const MAX_PATH_COMPONENT_LENGTH: usize = 255;
const MAX_WORKSPACE_NAME_LENGTH: usize = 64;
