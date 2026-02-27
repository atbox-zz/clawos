// crates/clawfs/src/search.rs
//
// Hybrid Search (E-03): FTS5 full-text + HNSW vector search.
// Fusion via Reciprocal Rank Fusion (RRF, k=60).
// P1.4 spec: returns (path, score) pairs, highest score first.

use anyhow::Result;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::debug;

const RRF_K: f64 = 60.0;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub path:  String,
    pub score: f64,
    pub chunk: Option<String>,
}

pub struct HybridSearch<'a> {
    db:          &'a Connection,
    vector_dims: usize,
}

impl<'a> HybridSearch<'a> {
    pub fn new(db: &'a Connection, vector_dims: usize) -> Self {
        Self { db, vector_dims }
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
        // Sanitize query for FTS5 (prevent syntax errors)
        let safe_query = sanitize_fts5_query(query);
        debug!(query = %safe_query, "FTS5 search");

        let mut stmt = self.db.prepare_cached(
            r#"SELECT path,
                      snippet(files_fts, 1, '<b>', '</b>', '...', 10) as snippet,
                      bm25(files_fts) as score
               FROM files_fts
               WHERE files_fts MATCH ?1
               ORDER BY score
               LIMIT ?2"#
        )?;

        let results: Vec<SearchResult> = stmt.query_map(
            rusqlite::params![safe_query, limit as i64],
            |row| Ok(SearchResult {
                path:  row.get(0)?,
                score: -(row.get::<_, f64>(2)?), // bm25 returns negative, flip it
                chunk: row.get(1)?,
            }),
        )?.filter_map(|r| r.ok()).collect();

        debug!(count = results.len(), "FTS5 results");
        Ok(results)
    }

    /// Vector similarity search using cosine distance.
    /// P2: naive linear scan (correct but slow).
    /// P4.5: replace with usearch HNSW for O(log n) performance.
    fn vector_search(&self, query: &[f32], limit: usize) -> Result<Vec<SearchResult>> {
        if query.len() != self.vector_dims {
            anyhow::bail!(
                "Query embedding dim {} != expected {} (P1.4 frozen)",
                query.len(), self.vector_dims
            );
        }

        debug!(dims = query.len(), "Vector search (linear scan — HNSW in P4.5)");

        // Load all embeddings
        let mut stmt = self.db.prepare_cached(
            "SELECT f.path, e.chunk_text, e.embedding FROM embeddings e
             JOIN files f ON e.file_id = f.id"
        )?;

        let rows: Vec<(String, String, Vec<u8>)> = stmt.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?.filter_map(|r| r.ok()).collect();

        let mut scored: Vec<SearchResult> = rows.iter().filter_map(|(path, chunk, blob)| {
            let stored = bytes_to_f32_vec(blob)?;
            if stored.len() != self.vector_dims { return None; }
            let score = cosine_similarity(query, &stored);
            Some(SearchResult { path: path.clone(), score, chunk: Some(chunk.clone()) })
        }).collect();

        scored.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
        scored.truncate(limit);

        debug!(count = scored.len(), "Vector results");
        Ok(scored)
    }
}

/// Reciprocal Rank Fusion (RRF) with k=60.
/// Merges two ranked lists into a single fused ranking.
fn rrf_fuse(fts: &[SearchResult], vec: &[SearchResult], top_k: usize) -> Vec<SearchResult> {
    let mut scores: HashMap<String, f64> = HashMap::new();

    for (rank, r) in fts.iter().enumerate() {
        *scores.entry(r.path.clone()).or_default() += 1.0 / (RRF_K + rank as f64 + 1.0);
    }
    for (rank, r) in vec.iter().enumerate() {
        *scores.entry(r.path.clone()).or_default() += 1.0 / (RRF_K + rank as f64 + 1.0);
    }

    // Build result list with chunks from whichever source found them
    let chunk_map: HashMap<&str, &str> = fts.iter()
        .chain(vec.iter())
        .filter_map(|r| r.chunk.as_deref().map(|c| (r.path.as_str(), c)))
        .collect();

    let mut fused: Vec<SearchResult> = scores.into_iter()
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
    let dot:  f64 = a.iter().zip(b).map(|(x, y)| (*x as f64) * (*y as f64)).sum();
    let mag_a: f64 = a.iter().map(|x| (*x as f64).powi(2)).sum::<f64>().sqrt();
    let mag_b: f64 = b.iter().map(|x| (*x as f64).powi(2)).sum::<f64>().sqrt();
    if mag_a == 0.0 || mag_b == 0.0 { 0.0 } else { dot / (mag_a * mag_b) }
}

fn bytes_to_f32_vec(bytes: &[u8]) -> Option<Vec<f32>> {
    if bytes.len() % 4 != 0 { return None; }
    Some(bytes.chunks(4).map(|c| {
        f32::from_le_bytes([c[0], c[1], c[2], c[3]])
    }).collect())
}

fn sanitize_fts5_query(q: &str) -> String {
    // Remove FTS5 special chars that could cause syntax errors
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
            SearchResult { path: "a".into(), score: 0.9, chunk: None },
            SearchResult { path: "b".into(), score: 0.7, chunk: None },
        ];
        let vec = vec![
            SearchResult { path: "b".into(), score: 0.95, chunk: None },
            SearchResult { path: "c".into(), score: 0.6,  chunk: None },
        ];
        let fused = rrf_fuse(&fts, &vec, 3);
        // "b" appears in both lists → should rank highest
        assert_eq!(fused[0].path, "b");
    }

    #[test]
    fn cosine_similarity_same_vector() {
        let v = vec![1.0f32, 0.0, 0.0];
        let sim = cosine_similarity(&v, &v);
        assert!((sim - 1.0).abs() < 1e-6);
    }

    #[test]
    fn cosine_similarity_orthogonal() {
        let a = vec![1.0f32, 0.0];
        let b = vec![0.0f32, 1.0];
        let sim = cosine_similarity(&a, &b);
        assert!(sim.abs() < 1e-6);
    }
}
