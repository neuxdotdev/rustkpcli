use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{anyhow, Context, Result};
use data_encoding::HEXUPPER;
use dirs::home_dir;
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs;
use std::path::PathBuf;

use crate::errors::ExporterError;

pub struct EncryptionManager {
    key_path: PathBuf,
}

impl EncryptionManager {
    pub fn new() -> Result<Self> {
        let home = home_dir().ok_or_else(|| anyhow!("Could not find home directory"))?;
        let config_dir = home.join(".config/rustkpcli");
        let key_path = config_dir.join(".master_key.asc");

        if !config_dir.exists() {
            fs::create_dir_all(&config_dir)?;
        }

        Ok(Self { key_path })
    }

    fn get_or_create_key(&self) -> Result<[u8; 32]> {
        if self.key_path.exists() {
            let key_hex = fs::read_to_string(&self.key_path)
                .context("Failed to read key file")?;
            let key_bytes = HEXUPPER.decode(key_hex.trim().as_bytes())
                .map_err(|e| anyhow!("Failed to decode hex: {}", e))?;

            if key_bytes.len() < 32 {
                return Err(anyhow!("Stored key length is too short"));
            }

            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes[..32]);
            Ok(key)
        } else {
            let mut key = [0u8; 32];
            let mut rng = OsRng;
            rng.try_fill_bytes(&mut key)
                .map_err(|e| anyhow!("Failed to generate random key: {}", e))?;

            let key_hex = HEXUPPER.encode(&key);
            fs::write(&self.key_path, key_hex)
                .context("Failed to write key file")?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(&self.key_path)
                    .context("Failed to get key file metadata")?
                    .permissions();
                perms.set_mode(0o600);
                fs::set_permissions(&self.key_path, perms)
                    .context("Failed to set key file permissions")?;
            }

            Ok(key)
        }
    }

    pub fn encrypt(&self, plaintext: &str) -> Result<String> {
        let key_bytes = self.get_or_create_key()?;
        let key = GenericArray::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);

        let mut rng = OsRng;
        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut nonce_bytes);

        let nonce = GenericArray::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| ExporterError::EncryptionError(format!("Encryption failed: {}", e)))?;

        let mut result = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(HEXUPPER.encode(&result))
    }

    pub fn decrypt(&self, ciphertext_hex: &str) -> Result<String> {
        let key_bytes = self.get_or_create_key()?;
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);

        let data = HEXUPPER.decode(ciphertext_hex.as_bytes())
            .map_err(|e| ExporterError::DataEncodingError(format!("Hex decode failed: {}", e)))?;

        if data.len() < 12 {
            return Err(anyhow::Error::new(
                ExporterError::EncryptionError("Invalid ciphertext length".to_string())
            ));
        }

        let nonce_bytes = &data[..12];
        let ciphertext = &data[12..];
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| ExporterError::EncryptionError(format!("Decryption failed: {}", e)))?;

        String::from_utf8(plaintext)
            .map_err(|e| anyhow!("UTF-8 decode failed: {}", e))
    }
}