use anyhow::{anyhow, Result};
use dirs::home_dir;
use std::fs;
use std::path::{Path, PathBuf};

use super::Config;
use crate::encryption::EncryptionManager;

pub struct ConfigManager {
    config_dir: PathBuf,
    config_file: PathBuf,
    encryption: EncryptionManager,
}

impl ConfigManager {
    pub fn new() -> Result<Self> {
        let home = home_dir().ok_or_else(|| anyhow!("Could not find home directory"))?;
        let config_dir = home.join(".config").join("rustkpcli");
        let config_file = config_dir.join("config.json");
        let encryption = EncryptionManager::new()?;

        Ok(Self {
            config_dir,
            config_file,
            encryption,
        })
    }

    fn ensure_config_dir(&self) -> Result<()> {
        if !self.config_dir.exists() {
            fs::create_dir_all(&self.config_dir)?;
        }
        Ok(())
    }

    pub fn load(&self) -> Result<Option<Config>> {
        if !self.config_file.exists() {
            return Ok(None);
        }
        let content = fs::read_to_string(&self.config_file)?;
        let config: Config = serde_json::from_str(&content)?;
        Ok(Some(config))
    }

    pub fn save_with_password(&self, config: &mut Config, password: &str) -> Result<()> {
        self.ensure_config_dir()?;
        config.password_encrypted = self.encryption.encrypt(password)?;
        config.password_hash = Config::compute_password_hash(password);
        let content = serde_json::to_string_pretty(config)?;
        fs::write(&self.config_file, content)?;
        Ok(())
    }

    pub fn verify_password(&self, config: &Config, password: &str) -> bool {
        let provided_hash = Config::compute_password_hash(password);
        provided_hash == config.password_hash
    }

    pub fn get_decrypted_password(&self, config: &Config) -> Result<String> {
        self.encryption.decrypt(&config.password_encrypted)
    }

    pub fn clear(&self) -> Result<()> {
        if self.config_file.exists() {
            fs::remove_file(&self.config_file)?;
        }
        let key_file = self.config_dir.join(".master_key.asc");
        if key_file.exists() {
            fs::remove_file(key_file)?;
        }
        Ok(())
    }

    pub fn get_path(&self) -> &Path {
        &self.config_file
    }
}