use thiserror::Error;

#[derive(Error, Debug)]
pub enum ExporterError {
    #[error("Configuration not found. Run setup first.")]
    ConfigNotFound,

    #[allow(dead_code)]
    #[error("Password not found. Run setup again.")]
    PasswordNotFound,

    #[allow(dead_code)]
    #[error("Export failed: {0}")]
    ExportFailed(String),

    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("Curl not found. Please install curl.")]
    CurlNotFound,

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Data encoding error: {0}")]
    DataEncodingError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Network error: {0}")]
    NetworkError(String),
}