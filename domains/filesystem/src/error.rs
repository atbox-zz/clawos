use thiserror::Error;

pub type Result<T> = std::result::Result<T, ClawFSError>;

#[derive(Error, Debug)]
pub enum ClawFSError {
    #[error("Path validation failed: {0}")]
    PathValidation(String),

    #[error("Path component exceeds maximum length of {0} characters")]
    PathComponentTooLong(usize),

    #[error("Path contains invalid characters: {0}")]
    InvalidCharacters(String),

    #[error("Path must be lowercase: {0}")]
    NotLowercase(String),

    #[error("Path must use hyphens, not underscores or spaces: {0}")]
    InvalidSeparator(String),

    #[error("Path contains non-ASCII characters: {0}")]
    NonAscii(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("Key derivation error: {0}")]
    KeyDerivation(String),

    #[error("SQLite error: {0}")]
    SQLite(#[from] rusqlite::Error),

    #[error("Vector index error: {0}")]
    VectorIndex(String),

    #[error("Identity file error: {0}")]
    IdentityFile(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Not implemented: {0}")]
    NotImplemented(String),
}
