mod manager;

pub use manager::ConfigManager;

use serde::{Deserialize, Serialize};
use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};
use data_encoding::HEXUPPER;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub server: String,
    pub report_path: String,
    pub username: String,
    pub password_encrypted: String,
    pub password_hash: String,
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.server.is_empty() {
            return Err(anyhow!("Server URL cannot be empty"));
        }
        if self.report_path.is_empty() {
            return Err(anyhow!("Report path cannot be empty"));
        }
        if self.username.is_empty() {
            return Err(anyhow!("Username cannot be empty"));
        }
        Ok(())
    }

    pub fn compute_password_hash(password: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let result = hasher.finalize();
        HEXUPPER.encode(&result)
    }
}