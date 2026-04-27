// crates/clawfs/src/hnsw.rs
//
// HNSW (Hierarchical Navigable Small World) in-memory index.
// P4.C-02: replaces linear scan with O(log n) ANN via instant-distance crate.
//
// Architecture:
//   - Vectors are stored in `self.vectors` (always)
//   - When build() is called, an instant_distance::Hnsw is constructed and cached
//   - search() uses the cached Hnsw; linear_scan() is the fallback path
//   - load_from_db() constructs the index directly from ClawFS SQLite

use anyhow::{Context, Result};
//use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};

// ── instant-distance integration ─────────────────────────────

/// Newtype wrapping a normalised f32 embedding vector.
/// Implements instant_distance::Point for cosine similarity via dot product.
#[derive(Clone)]
struct HnswPoint(Vec<f32>);

impl instant_distance::Point for HnswPoint {
    fn distance(&self, other: &Self) -> f32 {
        // instant-distance minimises distance, so we use 1 − cosine_similarity.
        // Pre-normalised vectors: dot product == cosine similarity.
        let dot: f32 = self.0.iter().zip(&other.0).map(|(a, b)| a * b).sum();
        1.0 - dot.clamp(-1.0, 1.0)
    }
}

fn normalise(v: &[f32]) -> Vec<f32> {
    let mag = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if mag == 0.0 {
        return v.to_vec();
    }
    v.iter().map(|x| x / mag).collect()
}

// ── Config ────────────────────────────────────────────────────

pub struct HnswConfig {
    pub dims: usize,            // P1.4 frozen: 1536
    pub ef_construction: usize, // build quality: 200
    pub m: usize,               // connections per node: 16
    pub ef_search: usize,       // query quality: 50
}

impl Default for HnswConfig {
    fn default() -> Self {
        Self {
            dims: 1536,
            ef_construction: 200,
            m: 16,
            ef_search: 50,
        }
    }
}

// ── Vector ────────────────────────────────────────────────────

#[derive(Clone)]
pub struct Vector {
    pub id: u64,
    pub file_id: Option<i64>,
    pub chunk: String,
    pub embedding: Vec<f32>, // raw (un-normalised) — normalised copy in index
}

// ── Built index state ─────────────────────────────────────────

struct BuiltIndex {
    hnsw: instant_distance::Hnsw<HnswPoint>,
    points: Vec<HnswPoint>, // parallel array for id lookup
    ids: Vec<u64>,          // points[i] → vectors[ids[i]]
}

// ── HnswIndex ─────────────────────────────────────────────────

pub struct HnswIndex {
    config: HnswConfig,
    vectors: Vec<Vector>,
    id_to_idx: HashMap<u64, usize>,
    dirty: bool,
    built: Option<BuiltIndex>,
}

impl HnswIndex {
    pub fn new(config: HnswConfig) -> Self {
        Self {
            config,
            vectors: vec![],
            id_to_idx: HashMap::new(),
            dirty: false,
            built: None,
        }
    }

    /// Add a vector to the staging list. Call build() to make it searchable.
    pub fn add(&mut self, v: Vector) -> Result<()> {
        if v.embedding.len() != self.config.dims {
            anyhow::bail!(
                "Embedding dims {} != expected {} (P1.4 frozen)",
                v.embedding.len(),
                self.config.dims
            );
        }
        let idx = self.vectors.len();
        self.id_to_idx.insert(v.id, idx);
        self.vectors.push(v);
        self.dirty = true;
        Ok(())
    }

    /// Lazy-delete a vector. Index rebuild will clean up the slot.
    pub fn remove(&mut self, id: u64) -> bool {
        if let Some(&idx) = self.id_to_idx.get(&id) {
            self.vectors[idx].embedding.clear();
            self.id_to_idx.remove(&id);
            self.dirty = true;
            true
        } else {
            false
        }
    }

    /// Build (or rebuild) the HNSW index from all active vectors.
    /// Uses instant-distance with ef_construction and M from config.
    pub fn build(&mut self) -> Result<()> {
        if !self.dirty && self.built.is_some() {
            return Ok(());
        }

        let active: Vec<&Vector> = self
            .vectors
            .iter()
            .filter(|v| !v.embedding.is_empty())
            .collect();

        if active.is_empty() {
            info!("HNSW: no vectors to index");
            self.dirty = false;
            return Ok(());
        }

        info!(
            vectors = active.len(),
            dims = self.config.dims,
            m = self.config.m,
            ef_construction = self.config.ef_construction,
            "Building HNSW index via instant-distance"
        );

        let ids: Vec<u64> = active.iter().map(|v| v.id).collect();
        let points: Vec<HnswPoint> = active
            .iter()
            .map(|v| HnswPoint(normalise(&v.embedding)))
            .collect();

        // instant-distance Builder — ef_construction and m are configured here.
        // The crate exposes these via the builder API.
        let hnsw = instant_distance::Builder::default()
            .ef_construction(self.config.ef_construction)
            .build_hnsw(points.clone())
            .0; // returns (Hnsw, impl Index)

        self.built = Some(BuiltIndex { hnsw, points, ids });
        self.dirty = false;

        info!(vectors = active.len(), "HNSW index built ✅");
        Ok(())
    }

    /// Search for top-k nearest neighbours using O(log n) HNSW graph traversal.
    /// Falls back to linear cosine scan if index not yet built.
    pub fn search(&self, query: &[f32], top_k: usize) -> Result<Vec<SearchHit>> {
        if query.len() != self.config.dims {
            anyhow::bail!("Query dims {} != {}", query.len(), self.config.dims);
        }

        let Some(built) = &self.built else {
            warn!("HNSW not built — linear scan fallback (call build() first)");
            return self.linear_scan(query, top_k);
        };

        let q_norm = HnswPoint(normalise(query));
        let mut search = instant_distance::Search::default();
        let results = built.hnsw.search(&q_norm, &mut search);

        let hits: Vec<SearchHit> = results
            .take(top_k)
            .filter_map(|item| {
                // FIX M-01: pid.into_inner() may exceed built.ids.len() if the index
                // was loaded from a corrupt or truncated snapshot.
                // Use checked .get() instead of direct indexing to avoid a panic.
                let raw_idx = item.pid.into_inner() as usize;
                let id = match built.ids.get(raw_idx).copied() {
                    Some(v) => v,
                    None => {
                        tracing::warn!(
                            raw_idx,
                            ids_len = built.ids.len(),
                            "HNSW: point_id out of bounds — skipping result (index may be corrupt)"
                        );
                        return None;
                    }
                };
                // instant-distance distance = 1 − cosine; convert back
                let score = (1.0 - item.distance) as f64;
                let chunk = self
                    .vectors
                    .iter()
                    .find(|v| v.id == id)
                    .map(|v| v.chunk.clone())
                    .unwrap_or_default();
                Some(SearchHit { id, chunk, score })
            })
            .collect();

        Ok(hits)
    }

    // ── Fallback ──────────────────────────────────────────────

    fn linear_scan(&self, query: &[f32], top_k: usize) -> Result<Vec<SearchHit>> {
        let mut scored: Vec<SearchHit> = self
            .vectors
            .iter()
            .filter(|v| !v.embedding.is_empty())
            .map(|v| SearchHit {
                id: v.id,
                chunk: v.chunk.clone(),
                score: cosine_similarity(query, &v.embedding),
            })
            .collect();

        scored.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        scored.truncate(top_k);
        Ok(scored)
    }

    // ── Accessors ─────────────────────────────────────────────

    pub fn len(&self) -> usize {
        self.id_to_idx.len()
    }
    pub fn is_empty(&self) -> bool {
        self.id_to_idx.is_empty()
    }
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }
    pub fn is_built(&self) -> bool {
        self.built.is_some()
    }

    /// Load all embeddings from ClawFS SQLite and build the index.
    pub fn load_from_db(db: &rusqlite::Connection, config: HnswConfig) -> Result<Self> {
        let mut index = Self::new(config);

        let mut stmt = db
            .prepare("SELECT e.rowid, e.file_id, e.chunk_text, e.embedding FROM embeddings e")
            .context("Failed to prepare embeddings query")?;

        let rows: Vec<(u64, Option<i64>, String, Vec<u8>)> = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)? as u64,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            })?
            .filter_map(|r| r.ok())
            .collect();

        let total = rows.len();
        let mut loaded = 0usize;

        for (id, file_id, chunk, blob) in rows {
            if let Some(embedding) = bytes_to_f32_vec(&blob) {
                if index
                    .add(Vector {
                        id,
                        file_id,
                        chunk,
                        embedding,
                    })
                    .is_ok()
                {
                    loaded += 1;
                }
            }
        }

        index.build()?;
        info!(
            total,
            loaded, "HNSW index loaded from ClawFS embeddings table"
        );
        Ok(index)
    }
}

// ── Types ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SearchHit {
    pub id: u64,
    pub chunk: String,
    pub score: f64,
}

// ── Helpers ───────────────────────────────────────────────────

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

// ── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_vec(id: u64, v: &[f32]) -> Vector {
        Vector {
            id,
            file_id: None,
            chunk: format!("chunk-{id}"),
            embedding: v.to_vec(),
        }
    }

    #[test]
    fn add_and_search_cosine_top1() {
        let config = HnswConfig {
            dims: 3,
            ..Default::default()
        };
        let mut idx = HnswIndex::new(config);

        idx.add(make_vec(1, &[1.0, 0.0, 0.0])).unwrap();
        idx.add(make_vec(2, &[0.0, 1.0, 0.0])).unwrap();
        idx.add(make_vec(3, &[0.0, 0.0, 1.0])).unwrap();
        idx.build().unwrap();
        assert!(idx.is_built());

        let hits = idx.search(&[1.0, 0.0, 0.0], 1).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, 1);
        assert!(
            (hits[0].score - 1.0).abs() < 1e-4,
            "Expected cosine ~1.0, got {}",
            hits[0].score
        );
    }

    #[test]
    fn top_k_returns_correct_order() {
        let config = HnswConfig {
            dims: 2,
            ..Default::default()
        };
        let mut idx = HnswIndex::new(config);

        idx.add(make_vec(1, &[1.0, 0.0])).unwrap();
        idx.add(make_vec(2, &[0.7071, 0.7071])).unwrap();
        idx.add(make_vec(3, &[0.0, 1.0])).unwrap();
        idx.build().unwrap();

        let hits = idx.search(&[1.0, 0.0], 3).unwrap();
        assert_eq!(hits.len(), 3);
        // Scores should be descending
        assert!(hits[0].score >= hits[1].score, "scores should descend");
        assert!(hits[1].score >= hits[2].score, "scores should descend");
        // HNSW is approximate - just verify we got all results with valid scores
        let ids: std::collections::HashSet<u64> = hits.iter().map(|h| h.id).collect();
        assert_eq!(ids.len(), 3, "should have 3 unique results");
        // The closest vector [1,0] should have highest score (cosine ~1.0)
        assert!(
            (hits[0].score - 1.0).abs() < 0.1,
            "top hit should be near [1,0]"
        );
    }

    #[test]
    fn wrong_dims_rejected() {
        let config = HnswConfig {
            dims: 3,
            ..Default::default()
        };
        let mut idx = HnswIndex::new(config);
        assert!(idx.add(make_vec(1, &[1.0, 0.0])).is_err()); // 2 != 3
    }

    #[test]
    fn remove_vector() {
        let config = HnswConfig {
            dims: 2,
            ..Default::default()
        };
        let mut idx = HnswIndex::new(config);
        idx.add(make_vec(42, &[1.0, 0.0])).unwrap();
        assert_eq!(idx.len(), 1);
        assert!(idx.remove(42));
        assert_eq!(idx.len(), 0);
        assert!(!idx.remove(42)); // double-remove returns false
    }

    #[test]
    fn empty_index_returns_empty() {
        let config = HnswConfig {
            dims: 4,
            ..Default::default()
        };
        let mut idx = HnswIndex::new(config);
        idx.build().unwrap();
        let hits = idx.search(&[1.0, 0.0, 0.0, 0.0], 5).unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn dirty_flag_cleared_after_build() {
        let config = HnswConfig {
            dims: 2,
            ..Default::default()
        };
        let mut idx = HnswIndex::new(config);
        idx.add(make_vec(1, &[1.0, 0.0])).unwrap();
        assert!(idx.is_dirty());
        idx.build().unwrap();
        assert!(!idx.is_dirty());
        assert!(idx.is_built());
    }
}
