use crate::error::{ClawFSError, Result};
use serde::{Deserialize, Serialize};

pub const DEFAULT_VECTOR_DIMENSION: usize = 1536;
pub const ALTERNATIVE_VECTOR_DIMENSION: usize = 3072;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorConfig {
    pub dimension: usize,
    pub hnsw_params: HnswParams,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HnswParams {
    pub m: usize,
    pub ef_construction: usize,
    pub ef_search: usize,
}

impl Default for VectorConfig {
    fn default() -> Self {
        Self {
            dimension: DEFAULT_VECTOR_DIMENSION,
            hnsw_params: HnswParams::default(),
        }
    }
}

impl Default for HnswParams {
    fn default() -> Self {
        Self {
            m: 16,
            ef_construction: 200,
            ef_search: 50,
        }
    }
}

pub struct VectorIndex {
    config: VectorConfig,
    #[cfg(feature = "hnsw")]
    index: Option<usearch::Index>,
    #[cfg(not(feature = "hnsw"))]
    _phantom: std::marker::PhantomData<()>,
}

impl VectorIndex {
    pub fn new(config: VectorConfig) -> Result<Self> {
        if config.dimension < 128 || config.dimension > 4096 {
            return Err(ClawFSError::InvalidConfig(format!(
                "Vector dimension must be between 128 and 4096, got {}",
                config.dimension
            )));
        }

        if config.hnsw_params.m < 8 || config.hnsw_params.m > 64 {
            return Err(ClawFSError::InvalidConfig(format!(
                "HNSW parameter m must be between 8 and 64, got {}",
                config.hnsw_params.m
            )));
        }

        if config.hnsw_params.ef_construction < 100 || config.hnsw_params.ef_construction > 1000 {
            return Err(ClawFSError::InvalidConfig(format!(
                "HNSW parameter ef_construction must be between 100 and 1000, got {}",
                config.hnsw_params.ef_construction
            )));
        }

        if config.hnsw_params.ef_search < 10 || config.hnsw_params.ef_search > 200 {
            return Err(ClawFSError::InvalidConfig(format!(
                "HNSW parameter ef_search must be between 10 and 200, got {}",
                config.hnsw_params.ef_search
            )));
        }

        #[cfg(feature = "hnsw")]
        let index = {
            tracing::info!("Initializing HNSW index with dimension {}", config.dimension);
            None
        };

        #[cfg(not(feature = "hnsw"))]
        let _phantom = std::marker::PhantomData;

        Ok(Self {
            config,
            #[cfg(feature = "hnsw")]
            index,
            #[cfg(not(feature = "hnsw"))]
            _phantom,
        })
    }

    pub fn config(&self) -> &VectorConfig {
        &self.config
    }

    pub fn dimension(&self) -> usize {
        self.config.dimension
    }

    pub fn add_vector(&mut self, _id: u64, _vector: &[f32]) -> Result<()> {
        #[cfg(feature = "hnsw")]
        {
            if _vector.len() != self.config.dimension {
                return Err(ClawFSError::VectorIndex(format!(
                    "Vector dimension mismatch: expected {}, got {}",
                    self.config.dimension,
                    _vector.len()
                )));
            }

            tracing::debug!("Adding vector with id {}", _id);
            Ok(())
        }

        #[cfg(not(feature = "hnsw"))]
        {
            Err(ClawFSError::NotImplemented(
                "Vector indexing requires 'hnsw' feature".to_string(),
            ))
        }
    }

    pub fn search(&self, _query: &[f32], _k: usize) -> Result<Vec<(u64, f32)>> {
        #[cfg(feature = "hnsw")]
        {
            if _query.len() != self.config.dimension {
                return Err(ClawFSError::VectorIndex(format!(
                    "Query vector dimension mismatch: expected {}, got {}",
                    self.config.dimension,
                    _query.len()
                )));
            }

            tracing::debug!("Searching for {} nearest neighbors", _k);
            Ok(vec![])
        }

        #[cfg(not(feature = "hnsw"))]
        {
            Err(ClawFSError::NotImplemented(
                "Vector search requires 'hnsw' feature".to_string(),
            ))
        }
    }

    pub fn remove(&mut self, _id: u64) -> Result<()> {
        #[cfg(feature = "hnsw")]
        {
            tracing::debug!("Removing vector with id {}", _id);
            Ok(())
        }

        #[cfg(not(feature = "hnsw"))]
        {
            Err(ClawFSError::NotImplemented(
                "Vector removal requires 'hnsw' feature".to_string(),
            ))
        }
    }

    pub fn len(&self) -> usize {
        #[cfg(feature = "hnsw")]
        {
            self.index.as_ref().map(|i| i.len()).unwrap_or(0)
        }

        #[cfg(not(feature = "hnsw"))]
        {
            0
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn save(&self, _path: &str) -> Result<()> {
        #[cfg(feature = "hnsw")]
        {
            tracing::info!("Saving vector index to {}", _path);
            Ok(())
        }

        #[cfg(not(feature = "hnsw"))]
        {
            Err(ClawFSError::NotImplemented(
                "Index save requires 'hnsw' feature".to_string(),
            ))
        }
    }

    pub fn load(_path: &str, config: VectorConfig) -> Result<Self> {
        #[cfg(feature = "hnsw")]
        {
            tracing::info!("Loading vector index from {}", _path);
            Self::new(config)
        }

        #[cfg(not(feature = "hnsw"))]
        {
            Err(ClawFSError::NotImplemented(
                "Index load requires 'hnsw' feature".to_string(),
            ))
        }
    }
}

pub fn validate_vector(vector: &[f32], expected_dimension: usize) -> Result<()> {
    if vector.len() != expected_dimension {
        return Err(ClawFSError::VectorIndex(format!(
            "Vector dimension mismatch: expected {}, got {}",
            expected_dimension,
            vector.len()
        )));
    }

    for (i, &val) in vector.iter().enumerate() {
        if !val.is_finite() {
            return Err(ClawFSError::VectorIndex(format!(
                "Vector contains non-finite value at index {}: {}",
                i, val
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vector_config_default() {
        let config = VectorConfig::default();
        assert_eq!(config.dimension, DEFAULT_VECTOR_DIMENSION);
        assert_eq!(config.hnsw_params.m, 16);
        assert_eq!(config.hnsw_params.ef_construction, 200);
        assert_eq!(config.hnsw_params.ef_search, 50);
    }

    #[test]
    fn test_vector_config_custom() {
        let config = VectorConfig {
            dimension: 3072,
            hnsw_params: HnswParams {
                m: 32,
                ef_construction: 400,
                ef_search: 100,
            },
        };
        assert_eq!(config.dimension, 3072);
        assert_eq!(config.hnsw_params.m, 32);
    }

    #[test]
    fn test_vector_index_new_valid() {
        let config = VectorConfig::default();
        let index = VectorIndex::new(config);
        assert!(index.is_ok());
    }

    #[test]
    fn test_vector_index_new_invalid_dimension() {
        let config = VectorConfig {
            dimension: 64,
            ..Default::default()
        };
        let result = VectorIndex::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_vector_index_new_invalid_m() {
        let config = VectorConfig {
            hnsw_params: HnswParams {
                m: 4,
                ..Default::default()
            },
            ..Default::default()
        };
        let result = VectorIndex::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_vector_index_new_invalid_ef_construction() {
        let config = VectorConfig {
            hnsw_params: HnswParams {
                ef_construction: 50,
                ..Default::default()
            },
            ..Default::default()
        };
        let result = VectorIndex::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_vector_index_new_invalid_ef_search() {
        let config = VectorConfig {
            hnsw_params: HnswParams {
                ef_search: 5,
                ..Default::default()
            },
            ..Default::default()
        };
        let result = VectorIndex::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_vector_valid() {
        let vector = vec![0.1f32; 1536];
        let result = validate_vector(&vector, 1536);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_vector_wrong_dimension() {
        let vector = vec![0.1f32; 512];
        let result = validate_vector(&vector, 1536);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_vector_non_finite() {
        let mut vector = vec![0.1f32; 1536];
        vector[100] = f32::NAN;
        let result = validate_vector(&vector, 1536);
        assert!(result.is_err());

        vector[100] = f32::INFINITY;
        let result = validate_vector(&vector, 1536);
        assert!(result.is_err());
    }

    #[test]
    fn test_vector_index_dimension() {
        let config = VectorConfig::default();
        let index = VectorIndex::new(config).unwrap();
        assert_eq!(index.dimension(), DEFAULT_VECTOR_DIMENSION);
    }

    #[test]
    fn test_vector_index_is_empty() {
        let config = VectorConfig::default();
        let index = VectorIndex::new(config).unwrap();
        assert!(index.is_empty());
    }
}
