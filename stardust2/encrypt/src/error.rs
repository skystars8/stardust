use std::path::PathBuf;
use thiserror::Error;

/// Application-level errors with clear, actionable messages.
#[derive(Debug, Error)]
pub enum AppError {
    #[error("{0}")]
    Msg(String),

    #[error("refusing to overwrite existing file: {0}")]
    RefuseOverwrite(PathBuf),

    #[error("input file not found: {0}")]
    InputNotFound(PathBuf),

    #[error("key file not found: {0}")]
    KeyNotFound(PathBuf),

    #[error("key file too short: {path} has {got} bytes, need at least {need}")]
    KeyTooShort {
        path: PathBuf,
        got: u64,
        need: u64,
    },

    #[error("passwords do not match")]
    PasswordMismatch,

    #[error("empty password is not allowed")]
    EmptyPassword,

    #[error("invalid key size: {0} (allowed range: 1 byte .. 20 GiB inclusive)")]
    InvalidKeySize(u64),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("authentication failed: wrong key or corrupted ciphertext")]
    AuthFailed,

    #[error("invalid or truncated ciphertext")]
    InvalidCiphertext,

    #[error("crypto error: {0}")]
    Crypto(String),
}

pub type Result<T> = std::result::Result<T, AppError>;

impl AppError {
    pub fn msg(s: impl Into<String>) -> Self {
        Self::Msg(s.into())
    }
}
