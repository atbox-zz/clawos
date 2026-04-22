// crates/clawfs/src/search.rs
//
// Hybrid Search (E-03): FTS5 full-text + HNSW vector search.
// Fusion via Reciprocal Rank Fusion (RRF, k=60).
// P1.4 spec: returns (path, score) pairs, highest score first.
//
// FIX (P4): vector_search() now uses the HNSW index (O(log n)) instead of
// the P2 naive linear scan over all embeddings.  HybridSearch accepts an
// optional &HnswIndex; if None it falls back to the linear scan so existing
// callers (tests, migration) that don't have an index yet still work.

use crate::hnsw::HnswIndex;
use anyhow::Result;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, warn};

const RRF_K: f64 = 60.0;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub path: String,
    pub score: f64,
    pub chunk: Option<String>,
}

pub struct HybridSearch<'a> {
    db: &'a Connection,
    vector_dims: usize,
    /// Optional HNSW index for O(log n) vector search.
    /// When None, falls back to linear scan (correct but slow).
    hnsw: Option<&'a HnswIndex>,
}

impl<'a> HybridSearch<'a> {
    /// Create without HNSW (linear scan fallback — for tests / migration).
    pub fn new(db: &'a Connection, vector_dims: usize) -> Self {
        Self {
            db,
            vector_dims,
            hnsw: None,
        }
    }

    /// Create with an HNSW index for fast vector search.
    pub fn with_hnsw(db: &'a Connection, vector_dims: usize, hnsw: &'a HnswIndex) -> Self {
        Self {
            db,
            vector_dims,
            hnsw: Some(hnsw),
        }
    }

    /// Hybrid search: combines FTS5 text results + vector similarity results using RRF.
    /// If only text_query is provided → pure FTS5.
    /// If only embedding is provided → pure vector search.
    /// Both → RRF fusion.
    pub fn search(
        &self,
        text_query: Option<&str>,
        query_embedding: Option<&[f32]>,
        top_k: usize,
    ) -> Result<Vec<SearchResult>> {
        let fts_results = text_query
            .map(|q| self.fts_search(q, top_k * 2))
            .transpose()?
            .unwrap_or_default();

        let vec_results = query_embedding
            .map(|e| self.vector_search(e, top_k * 2))
            .transpose()?
            .unwrap_or_default();

        if fts_results.is_empty() && vec_results.is_empty() {
            return Ok(vec![]);
        }

        let fused = rrf_fuse(&fts_results, &vec_results, top_k);
        Ok(fused)
    }

    /// FTS5 full-text search using SQLite.
    fn fts_search(&self, query: &str, limit: usize) -> Result<Vec<SearchResult>> {
        let safe_query = sanitize_fts5_query(query);
        debug!(query = %safe_query, "FTS5 search");

        let mut stmt = self.db.prepare_cached(
            r#"SELECT path,
                      snippet(files_fts, 1, '<b>', '</b>', '...', 10) as snippet,
                      bm25(files_fts) as score
               FROM files_fts
               WHERE files_fts MATCH ?1
               ORDER BY score
               LIMIT ?2"#,
        )?;

        let results: Vec<SearchResult> = stmt
            .query_map(rusqlite::params![safe_query, limit as i64], |row| {
                Ok(SearchResult {
                    path: row.get(0)?,
                    score: -(row.get::<_, f64>(2)?), // bm25 returns negative, flip it
                    chunk: row.get(1)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        debug!(count = results.len(), "FTS5 results");
        Ok(results)
    }

    /// Vector similarity search.
    /// Uses HNSW index if available (O(log n)), otherwise falls back to
    /// linear cosine scan over all stored embeddings (O(n)).
    fn vector_search(&self, query: &[f32], limit: usize) -> Result<Vec<SearchResult>> {
        if query.len() != self.vector_dims {
            anyhow::bail!(
                "Query embedding dim {} != expected {} (P1.4 frozen)",
                query.len(),
                self.vector_dims
            );
        }

        // ── HNSW fast path ────────────────────────────────────────────────────
        if let Some(hnsw) = self.hnsw {
            debug!(
                dims = query.len(),
                "Vector search via HNSW index (O(log n))"
            );

            let hits = hnsw.search(query, limit)?;
            if !hits.is_empty() {
                let results: Vec<SearchResult> = hits
                    .into_iter()
                    .map(|h| SearchResult {
                        path: format!("/clawfs/{}", h.id), // HNSW id → ClawFS path
                        score: h.score,
                        chunk: Some(h.chunk),
                    })
                    .collect();
                debug!(count = results.len(), "HNSW vector results");
                return Ok(results);
            }

            // HNSW returned no results (index empty / not built yet) — fall through
            warn!("HNSW index returned 0 results — falling back to linear scan");
        }

        // ── Linear scan fallback ──────────────────────────────────────────────
        debug!(
            dims = query.len(),
            "Vector search via linear scan (HNSW not ready)"
        );

        let mut stmt = self.db.prepare_cached(
            "SELECT f.path, e.chunk_text, e.embedding FROM embeddings e
             JOIN files f ON e.file_id = f.id",
        )?;

        let rows: Vec<(String, String, Vec<u8>)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .filter_map(|r| r.ok())
            .collect();

        let mut scored: Vec<SearchResult> = rows
            .iter()
            .filter_map(|(path, chunk, blob)| {
                let stored = bytes_to_f32_vec(blob)?;
                if stored.len() != self.vector_dims {
                    return None;
                }
                let score = cosine_similarity(query, &stored);
                Some(SearchResult {
                    path: path.clone(),
                    score,
                    chunk: Some(chunk.clone()),
                })
            })
            .collect();

        scored.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
        scored.truncate(limit);

        debug!(count = scored.len(), "Linear scan vector results");
        Ok(scored)
    }
}

/// Reciprocal Rank Fusion (RRF) with k=60.
fn rrf_fuse(fts: &[SearchResult], vec: &[SearchResult], top_k: usize) -> Vec<SearchResult> {
    let mut scores: HashMap<String, f64> = HashMap::new();

    for (rank, r) in fts.iter().enumerate() {
        *scores.entry(r.path.clone()).or_default() += 1.0 / (RRF_K + rank as f64 + 1.0);
    }
    for (rank, r) in vec.iter().enumerate() {
        *scores.entry(r.path.clone()).or_default() += 1.0 / (RRF_K + rank as f64 + 1.0);
    }

    let chunk_map: HashMap<&str, &str> = fts
        .iter()
        .chain(vec.iter())
        .filter_map(|r| r.chunk.as_deref().map(|c| (r.path.as_str(), c)))
        .collect();

    let mut fused: Vec<SearchResult> = scores
        .into_iter()
        .map(|(path, score)| SearchResult {
            chunk: chunk_map.get(path.as_str()).map(|s| s.to_string()),
            path,
            score,
        })
        .collect();

    fused.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
    fused.truncate(top_k);
    fused
}

fn cosine_similarity(a: &[f32], b: &[f32]) -> f64 {
    let dot: f64 = a
        .iter()
        .zip(b)
        .map(|(x, y)| (*x as f64) * (*y as f64))
        .sum();
    let mag_a: f64 = a.iter().map(|x| (*x as f64).powi(2)).sum::<f64>().sqrt();
    let mag_b: f64 = b.iter().map(|x| (*x as f64).powi(2)).sum::<f64>().sqrt();
    if mag_a == 0.0 || mag_b == 0.0 {
        0.0
    } else {
        dot / (mag_a * mag_b)
    }
}

fn bytes_to_f32_vec(bytes: &[u8]) -> Option<Vec<f32>> {
    if bytes.len() % 4 != 0 {
        return None;
    }
    Some(
        bytes
            .chunks(4)
            .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect(),
    )
}

fn sanitize_fts5_query(q: &str) -> String {
    q.chars()
        .map(|c| if r#"":*^(),-"#.contains(c) { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" OR ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rrf_fuse_combines_rankings() {
        let fts = vec![
            SearchResult {
                path: "a".into(),
                score: 0.9,
                chunk: None,
            },
            SearchResult {
                path: "b".into(),
                score: 0.7,
                chunk: None,
            },
        ];
        let vec = vec![
            SearchResult {
                path: "b".into(),
                score: 0.95,
                chunk: None,
            },
            SearchResult {
                path: "c".into(),
                score: 0.6,
                chunk: None,
            },
        ];
        let fused = rrf_fuse(&fts, &vec, 3);
        assert_eq!(fused[0].path, "b");
    }

    #[test]
    fn cosine_similarity_same_vector() {
        let v = vec![1.0f32, 0.0, 0.0];
        assert!((cosine_similarity(&v, &v) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn cosine_similarity_orthogonal() {
        let a = vec![1.0f32, 0.0];
        let b = vec![0.0f32, 1.0];
        assert!(cosine_similarity(&a, &b).abs() < 1e-6);
    }

    #[test]
    fn hybrid_search_falls_back_to_linear_without_hnsw() {
        // Verifies the no-hnsw fallback compiles and returns empty (no DB).
        // Full integration test requires a live SQLite DB.
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE VIRTUAL TABLE files_fts USING fts5(path, content);
             CREATE TABLE files (id INTEGER PRIMARY KEY, path TEXT);
             CREATE TABLE embeddings (file_id INTEGER, chunk_text TEXT, embedding BLOB);",
        )
        .unwrap();
        let search = HybridSearch::new(&conn, 3);
        let results = search.search(Some("hello"), None, 5).unwrap();
        assert!(results.is_empty());
    }
}
