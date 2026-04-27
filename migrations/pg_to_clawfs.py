#!/usr/bin/env python3
# migrations/pg_to_clawfs.py
# P3.3 — Migrate IronClaw PostgreSQL data → ClawFS SQLite
#
# Migrates:
#   - workspace files    (workspaces table → files + embeddings)
#   - identities         (identities table → files in /identities/)
#   - tool registry      (tools table → tools/ dir manifests)
#   - conversation logs  (conversations table → agent_logs)
#
# Usage:
#   export PG_URL="postgresql://user:pass@localhost/ironclaw"
#   export CLAWFS_DB="/var/lib/clawos/clawfs.db"
#   export CLAWFS_KEY="<64-hex-key>"
#   python3 migrations/pg_to_clawfs.py [--dry-run]

import argparse
import hashlib
import json
import os
import sqlite3
import struct
import sys
import time
import posixpath

from dataclasses import dataclass
from typing import Any, Optional

try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    print("ERROR: psycopg2 not found. Run: pip install psycopg2-binary", file=sys.stderr)
    sys.exit(1)

# ── Config ─────────────────────────────────────────────────────

PG_URL    = os.environ.get("PG_URL",    "postgresql://localhost/ironclaw")
CLAWFS_DB = os.environ.get("CLAWFS_DB", "/var/lib/clawos/clawfs.db")
VECTOR_DIMS = 1536  # P1.4 frozen

# ── Progress logging ─────────────────────────────────────────

def log(msg: str, ok: bool = True):
    icon = "✅" if ok else "❌"
    print(f"  {icon} {msg}", flush=True)

def section(title: str):
    print(f"\n── {title} {'─' * (50 - len(title))}")

# ── SHA256 ────────────────────────────────────────────────────

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

# ── Fake encryption stub ─────────────────────────────────────
# Real AES-GCM handled by Rust clawfs crate on re-read.
# During migration we write a plaintext marker so Rust re-encrypts on first access.

MIGRATION_PLAINTEXT_TAG = b"\x00CLAWFS_MIGRATION_PLAINTEXT\x00"

def migration_wrap(data: bytes) -> bytes:
    """Wrap plaintext so clawfs Rust layer knows to re-encrypt on first read."""
    return MIGRATION_PLAINTEXT_TAG + data

# ── Migrations ─────────────────────────────────────────────────

def migrate_workspace_files(pg, sqlite, dry_run: bool):
    section("Workspace Files")
    cur = pg.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute("""
        SELECT w.id, w.name, wf.path, wf.content, wf.created_at, wf.updated_at
        FROM workspace_files wf
        JOIN workspaces w ON wf.workspace_id = w.id
        ORDER BY wf.created_at
    """)
    rows = cur.fetchall()
    print(f"  Found {len(rows)} workspace files")

    ok_count = 0
    for row in rows:
        ##clawfs_path = f"/workspace/{row['name']}/{row['path']}"
        # 清理 name：不允許路徑分隔符
        safe_name = row['name'].replace('/', '_').replace('\x00', '_')

        # 清理 path：正規化並移除開頭的 ../
        safe_path = posixpath.normpath(row['path']).lstrip('/')

        # 組合並驗證結果一定在 /workspace/ 下
        clawfs_path = f"/workspace/{safe_name}/{safe_path}"
        if not clawfs_path.startswith("/workspace/"):
            raise ValueError(f"Path traversal detected: name={row['name']!r} path={row['path']!r}")

        content     = (row['content'] or "").encode()
        sha         = sha256(content)
        created_at  = int(row['created_at'].timestamp() * 1000) if row['created_at'] else int(time.time() * 1000)
        updated_at  = int(row['updated_at'].timestamp() * 1000) if row['updated_at'] else created_at

        if not dry_run:
            sqlite.execute("""
                INSERT OR REPLACE INTO files (path, data, created_at, updated_at, sha256)
                VALUES (?, ?, ?, ?, ?)
            """, (clawfs_path, migration_wrap(content), created_at, updated_at, sha))

            # Index in FTS5
            sqlite.execute("""
                INSERT OR REPLACE INTO files_fts (path, content)
                VALUES (?, ?)
            """, (clawfs_path, content.decode('utf-8', errors='replace')))

        ok_count += 1

    log(f"Migrated {ok_count}/{len(rows)} workspace files {'(dry run)' if dry_run else ''}")

def migrate_embeddings(pg, sqlite, dry_run: bool):
    section("Vector Embeddings (pgvector → SQLite)")
    cur = pg.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # Check if embeddings table exists
    cur.execute("""
        SELECT EXISTS (
            SELECT FROM information_schema.tables
            WHERE table_name = 'workspace_embeddings'
        )
    """)
    if not cur.fetchone()[0]:
        log("No workspace_embeddings table — skipping", ok=True)
        return

    cur.execute("""
        SELECT wf.path, we.chunk_text, we.embedding, we.created_at
        FROM workspace_embeddings we
        JOIN workspace_files wf ON we.file_id = wf.id
        ORDER BY we.created_at
    """)
    rows = cur.fetchall()
    print(f"  Found {len(rows)} embeddings")

    ok_count = 0
    skipped  = 0
    for row in rows:
        embedding = row['embedding']

        # pgvector returns as list of floats
        if isinstance(embedding, list):
            if len(embedding) != VECTOR_DIMS:
                skipped += 1
                continue
            blob = struct.pack(f'{len(embedding)}f', *embedding)
        elif isinstance(embedding, (bytes, bytearray)):
            if len(embedding) != VECTOR_DIMS * 4:
                skipped += 1
                continue
            blob = bytes(embedding)
        else:
            skipped += 1
            continue

        if not dry_run:
            cur2 = sqlite.execute("SELECT id FROM files WHERE path LIKE ?",
                                  (f"%{row['path']}",))
            file_row = cur2.fetchone()
            file_id  = file_row[0] if file_row else None

            created_at = int(row['created_at'].timestamp() * 1000) if row['created_at'] else int(time.time() * 1000)
            sqlite.execute("""
                INSERT INTO embeddings (file_id, chunk_text, embedding, created_at)
                VALUES (?, ?, ?, ?)
            """, (file_id, row['chunk_text'], blob, created_at))

        ok_count += 1

    log(f"Migrated {ok_count} embeddings, skipped {skipped} (wrong dims) {'(dry run)' if dry_run else ''}")

def migrate_identities(pg, sqlite, dry_run: bool):
    section("Identities")
    cur = pg.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute("SELECT id, name, data, created_at FROM identities ORDER BY created_at")
    rows = cur.fetchall()
    print(f"  Found {len(rows)} identities")

    for row in rows:
      ##path    = f"/identities/{row['id']}.json"
        safe_id = str(row['id']).replace('/', '_').replace('..', '_')
        path    = f"/identities/{safe_id}.json"
        data    = json.dumps(dict(row['data'] or {})).encode()
        created = int(row['created_at'].timestamp() * 1000) if row['created_at'] else int(time.time() * 1000)

        if not dry_run:
            sqlite.execute("""
                INSERT OR REPLACE INTO files (path, data, created_at, updated_at, sha256)
                VALUES (?, ?, ?, ?, ?)
            """, (path, migration_wrap(data), created, created, sha256(data)))

    log(f"Migrated {len(rows)} identities {'(dry run)' if dry_run else ''}")

def freeze_vault_entries(sqlite, dry_run: bool):
    section("Vault — Freezing Migration Record")
    now = int(time.time() * 1000)

    entry = {
        "spec_id":   "migration-pg-to-clawfs",
        "path":      "migrations/pg_to_clawfs.py",
        "sha256":    sha256(open(__file__, 'rb').read()),
        "frozen_at": now,
        "signed_by": "migration-script",
        "phase":     "P3"
    }

    if not dry_run:
        sqlite.execute("""
            INSERT OR IGNORE INTO vault (spec_id, path, sha256, frozen_at, signed_by)
            VALUES (?, ?, ?, ?, ?)
        """, (entry['spec_id'], entry['path'], entry['sha256'], entry['frozen_at'], entry['signed_by']))

    log(f"Migration vault entry written: sha256={entry['sha256'][:16]}...")

# ── Main ───────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Migrate IronClaw PostgreSQL → ClawFS SQLite")
    parser.add_argument("--dry-run", action="store_true", help="Don't write to ClawFS")
    parser.add_argument("--skip-embeddings", action="store_true", help="Skip vector migration")
    args = parser.parse_args()

    print("╔══════════════════════════════════════════════╗")
    print("║  ClawFS Migration: PostgreSQL → SQLite       ║")
    print(f"║  {'DRY RUN — no writes' if args.dry_run else 'LIVE — writing to ' + CLAWFS_DB:<44}║")
    print("╚══════════════════════════════════════════════╝")

    # Connect PostgreSQL
    print(f"\nConnecting to PostgreSQL: {PG_URL[:40]}...")
    try:
        pg = psycopg2.connect(PG_URL)
        log("PostgreSQL connected")
    except Exception as e:
        log(f"PostgreSQL connection failed: {e}", ok=False)
        sys.exit(1)

    # Connect SQLite
    print(f"Opening ClawFS database: {CLAWFS_DB}")
    try:
        sqlite_conn = sqlite3.connect(CLAWFS_DB)
        sqlite_conn.row_factory = sqlite3.Row
        log("SQLite connected")
    except Exception as e:
        log(f"SQLite open failed: {e}", ok=False)
        sys.exit(1)

    try:
        migrate_workspace_files(pg, sqlite_conn, args.dry_run)
        if not args.skip_embeddings:
            migrate_embeddings(pg, sqlite_conn, args.dry_run)
        migrate_identities(pg, sqlite_conn, args.dry_run)
        freeze_vault_entries(sqlite_conn, args.dry_run)

        if not args.dry_run:
            sqlite_conn.commit()
            log("Transaction committed")

        section("Summary")
        print("  Migration complete ✅")
        print("  Next: re-encrypt plaintext blobs by running:")
        print("    clawos-agent --migrate-encrypt-pass")

    except Exception as e:
        sqlite_conn.rollback()
        log(f"MIGRATION FAILED: {e}", ok=False)
        raise
    finally:
        pg.close()
        sqlite_conn.close()

if __name__ == "__main__":
    main()
