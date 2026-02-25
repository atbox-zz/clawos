# ClawFS - AI-Aware Filesystem for ClawOS

ClawFS is an AI-aware filesystem designed for ClawOS, providing vector-indexed storage, encrypted secrets vault, and persistent kernel memory.

## Features

- **Vector-indexed storage** for semantic search across workspaces
- **AES-256-GCM encryption** for secrets vault
- **POSIX-compatible interface** for seamless integration
- **Identity Files** as persistent kernel memory mechanism
- **Hybrid search** combining full-text (FTS5) and vector similarity (HNSW)

## Path Namespace Hierarchy

```
/clawfs/
├── system/          # OS-managed files (read-only)
├── agents/          # Agent-specific workspaces
├── tools/           # Tool definitions and WASM binaries
├── workspaces/      # User workspaces with vector storage
├── vault/           # Encrypted secrets storage
└── specs/           # Frozen specification documents (SHA256-signed)
```

## Path Naming Conventions

- All path components must be lowercase
- Use hyphens, not underscores or spaces
- Max length: 255 characters per component
- ASCII only (no Unicode)

## Vector Storage

Default vector dimension: 1536 (OpenAI ada-002 compatible)
Alternative: 3072 dimensions (configurable)

## Encryption

- Algorithm: AES-256-GCM
- Key size: 256 bits
- IV size: 96 bits
- Auth tag size: 128 bits
- KDF: PBKDF2-HMAC-SHA256 with 600,000 iterations

## PostgreSQL Migration Path

### Overview

Phase 3, Task E-02: PostgreSQL + pgvector → SQLite + HNSW

This migration replaces IronClaw's PostgreSQL + pgvector setup with embedded SQLite + HNSW for minimal footprint and embedded deployment.

### Migration Strategy

**Source:** PostgreSQL 15+ with pgvector 0.7+
**Target:** SQLite 3.47+ with HNSW extension

### Schema Mapping

| PostgreSQL                 | SQLite                               |
| ---------------------------| -------------------------------------|
| `documents` table          | `documents` FTS5 virtual table       |
| `vectors` table (pgvector) | `vectors` table + HNSW virtual table |
| `metadata` JSONB column    | `metadata` TEXT column (JSON)        |
| `embedding` vector(1536)   | `embedding` BLOB (Float32 array)     |

### Migration Steps

#### Step 1: Export from PostgreSQL

```sql
-- Export documents
COPY (
    SELECT id, workspace_id, content, metadata::text
    FROM documents
) TO '/tmp/documents.csv' CSV HEADER;

-- Export vectors
COPY (
    SELECT id, document_id, embedding::bytea, created_at
    FROM vectors
) TO '/tmp/vectors.csv' CSV BINARY;
```

#### Step 2: Import to SQLite

```bash
# Import documents
sqlite3 workspace.db <<EOF
.mode csv
.import /tmp/documents.csv documents
EOF

# Import vectors (binary format)
sqlite3 workspace.db <<EOF
.import /tmp/vectors.csv vectors
EOF
```

#### Step 3: Rebuild HNSW Index

The HNSW index rebuilds automatically on INSERT. No manual rebuild required.

#### Step 4: Verification

```sql
-- Compare row counts
SELECT (SELECT COUNT(*) FROM documents) as pg_count,
       (SELECT COUNT(*) FROM documents) as sqlite_count;

-- Compare vector dimensions
SELECT array_length(embedding, 1) as dimension FROM vectors LIMIT 1;
```

### Migration Tool (Rust)

**Location:** `tools/migrate-pg-to-sqlite/`

**Usage:**
```bash
cargo run --bin migrate-pg-to-sqlite \
  --pg-url "postgresql://user:pass@localhost/ironclaw" \
  --sqlite-path "/clawfs/workspaces/default/workspace.db" \
  --workspace-id "default"
```

**Features:**
- Batch processing (1000 rows per transaction)
- Progress reporting
- Rollback on failure
- Checksum verification

### Rollback Plan

If migration fails:
1. Keep PostgreSQL running (dual-write mode)
2. Revert to PostgreSQL for affected workspaces
3. Log failure for investigation
4. Retry migration after fix

### Deprecation Timeline

| Phase     | Status                                         |
| ----------| -----------------------------------------------|
| P1-P2     | PostgreSQL still used (IronClaw compatibility) |
| P3 (E-02) | Migration to SQLite + HNSW                     |
| P3 (E-03) | PostgreSQL removed from codebase               |
| P4        | PostgreSQL dependency fully deprecated         |

## Usage

### Basic Setup

```rust
use clawfs::{ClawFS, PathNamespace};

let clawfs = ClawFS::new(Path::new("/clawfs"))?;
clawfs.initialize_structure()?;

let workspace_path = clawfs.get_workspace_path("my-workspace")?;
```

### Path Validation

```rust
use clawfs::PathValidator;

PathValidator::validate_component("valid-name")?;
PathValidator::validate_workspace_name("my-workspace")?;
PathValidator::validate_agent_name("kernel-engine")?;
```

### Encryption

```rust
use clawfs::SecretEncryptor;

let master_key = SecretEncryptor::generate_master_key();
let encryptor = SecretEncryptor::new(master_key);

let plaintext = b"my-secret-api-key";
let metadata = encryptor.encrypt("openai-api-key", plaintext)?;

let decrypted = encryptor.decrypt(&metadata)?;
```

### Vector Index

```rust
use clawfs::{VectorIndex, VectorConfig};

let config = VectorConfig::default();
let mut index = VectorIndex::new(config)?;

let vector = vec![0.1f32; 1536];
index.add_vector(1, &vector)?;

let results = index.search(&vector, 10)?;
```

### Identity Files

```rust
use clawfs::{IdentityFile, IdentityManager};

let manager = IdentityManager::new(Path::new("/clawfs/agents"));
let mut identity = manager.load_or_create("kernel-engine")?;

identity.record_task_completion("A-01", true);
identity.update_state("P2", "A-02", "in_progress");

manager.save_identity(&identity)?;
```

## Building

```bash
# Build with default features (includes HNSW)
cargo build

# Build without HNSW
cargo build --no-default-features

# Run tests
cargo test
```

## Dependencies

- `rusqlite` - SQLite database
- `usearch` - HNSW vector search (optional)
- `aes-gcm` - AES-256-GCM encryption
- `pbkdf2` - Key derivation
- `sha2` - SHA-256 hashing
- `serde` - Serialization

## License

MIT

## References

- P1.4 ClawFS Specification
- SQLite FTS5 Documentation
- HNSW Algorithm
- AES-GCM RFC 5116
- PBKDF2 RFC 2898
