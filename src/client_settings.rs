use anyhow::{Context, Result};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead, AeadCore};
use rand::{rngs::OsRng, Rng};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const SETTINGS_FILENAME: &str = "client_settings.dat";
const MAX_LOG_ENTRIES: usize = 100;

/// Client settings structure containing all configurable parameters
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ClientSettings {
    // GUI settings
    pub window_width: u32,
    pub window_height: u32,
    pub dark_mode: bool,
    pub font_size: u8,
    pub auto_connect: bool,

    // Network settings
    pub server_ip: String,
    pub server_port: u16,
    pub tls_enabled: bool,
    pub connection_timeout_seconds: u32,
    pub retry_attempts: u8,

    // Logging settings
    pub log_level: LogLevel,
    pub log_to_file: bool,
    pub log_file_path: String,
    pub recent_operations: Vec<LogEntry>,

    // Backup settings
    pub backup_paths: Vec<BackupPathEntry>,

    // Additional settings
    pub auto_update: bool,
    pub default_download_path: String,
    pub upload_chunk_size: usize,
    pub download_chunk_size: usize,
    pub max_concurrent_transfers: u8,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BackupPathEntry {
    pub path: String,
    pub is_directory: bool,
    pub include_subdirectories: bool,
    pub file_pattern: Option<String>, // For filtering files in directories
    pub last_backup_time: Option<u64>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LogEntry {
    pub timestamp: u64,  // Unix timestamp
    pub operation: String,
    pub status: OperationStatus,
    pub details: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum OperationStatus {
    Success,
    Failure,
    InProgress,
}

impl Default for ClientSettings {
    fn default() -> Self {
        ClientSettings {
            // Default GUI settings
            window_width: 1200,
            window_height: 1200,
            dark_mode: true,
            font_size: 12,
            auto_connect: true,

            // Default Network settings
            server_ip: "127.0.0.1".to_string(),
            server_port: 7878,
            tls_enabled: true,
            connection_timeout_seconds: 30,
            retry_attempts: 3,

            // Default Logging settings
            log_level: LogLevel::Info,
            log_to_file: true,
            log_file_path: "./logs/client.log".to_string(),
            recent_operations: Vec::new(),

            // Backup settings
            backup_paths: Vec::new(),

            // Additional settings
            auto_update: true,
            default_download_path: "./downloads".to_string(),
            upload_chunk_size: 1024 * 1024, // 1MB
            download_chunk_size: 1024 * 1024, // 1MB
            max_concurrent_transfers: 3,
        }
    }
}

impl ClientSettings {
    /// Create a new settings instance with default values
    pub fn new() -> Self {
        Default::default()
    }

    /// Load settings from the specified path, decrypt with the provided key
    pub fn load(path: &Path, encryption_key: &[u8; 32]) -> Result<Self> {
        let mut file = File::open(path)
            .with_context(|| format!("Failed to open settings file at {:?}", path))?;

        let mut encrypted_data = Vec::new();
        file.read_to_end(&mut encrypted_data)
            .context("Failed to read settings file")?;

        Self::decrypt(&encrypted_data, encryption_key)
    }

    /// Save settings to the specified path, encrypt with the provided key
    pub fn save(&self, path: &Path, encryption_key: &[u8; 32]) -> Result<()> {
        let encrypted_data = self.encrypt(encryption_key)?;

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .context("Failed to create settings directory")?;
        }

        let mut file = File::create(path)
            .with_context(|| format!("Failed to create settings file at {:?}", path))?;

        file.write_all(&encrypted_data)
            .context("Failed to write encrypted settings to file")?;

        Ok(())
    }

    /// Get the default local path for settings
    pub fn default_local_path() -> PathBuf {
        let home_dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        home_dir.join(".llamapak").join(SETTINGS_FILENAME)
    }

    /// Add a new operation to the recent operations log
    pub fn add_log_entry(&mut self, operation: String, status: OperationStatus, details: String) {
        let entry = LogEntry {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            operation,
            status,
            details,
        };

        self.recent_operations.push(entry);

        // Trim if exceeds maximum
        if self.recent_operations.len() > MAX_LOG_ENTRIES {
            self.recent_operations = self.recent_operations.split_off(
                self.recent_operations.len() - MAX_LOG_ENTRIES
            );
        }
    }

    /// Encrypt the settings using ChaCha20Poly1305
    fn encrypt(&self, key: &[u8; 32]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(key.into());
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let serialized = serde_json::to_vec(self)
            .context("Failed to serialize settings")?;
    
    let encrypted = cipher.encrypt(&nonce, serialized.as_ref())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;
    
    // Combine nonce and encrypted data for storage
    let mut result = Vec::with_capacity(nonce.len() + encrypted.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&encrypted);
    Ok(result)
}

    /// Decrypt and deserialize settings using ChaCha20Poly1305
    fn decrypt(encrypted_data: &[u8], key: &[u8; 32]) -> Result<Self> {
        if encrypted_data.len() < 12 {
            return Err(anyhow::anyhow!("Encrypted data too short"));
        }
    
    // Use the same initialization method as in encrypt for consistency
    let cipher = ChaCha20Poly1305::new(key.into());
    
    // Split nonce and ciphertext
    let nonce = chacha20poly1305::Nonce::from_slice(&encrypted_data[..12]);
    let ciphertext = &encrypted_data[12..];
    
    let decrypted = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))?;
    
    serde_json::from_slice(&decrypted)
        .context("Failed to deserialize settings after decryption")
}

    /// Synchronize settings with server
    pub fn sync_with_server(&mut self, server_url: &str, encryption_key: &[u8; 32]) -> Result<()> {
        // This would use tls_client.rs to communicate with the server
        // First attempt to fetch settings from server
        // If successful, merge with local settings (giving preference to server settings)
        // Then upload merged settings back to server

        // Placeholder implementation - to be expanded
        #[allow(unused_variables)]
        let local_path = Self::default_local_path();

        // TODO: Implement actual server communication using tls_client.rs
        // For now, just save locally
        self.save(&local_path, encryption_key)?;

        Ok(())
    }

    /// Generate a new random encryption key
    pub fn generate_encryption_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        let mut rng = OsRng;
        rng.fill(&mut key);
        key
    }
    /// Add a new backup path to the settings
    pub fn add_backup_path(&mut self, path: String, is_directory: bool) -> Result<()> {
        // Validate the path exists
        let path_obj = Path::new(&path);
        if !path_obj.exists() {
            return Err(anyhow::anyhow!("Path does not exist: {}", path));
        }

        // Add to the list
        self.backup_paths.push(BackupPathEntry {
            path,
            is_directory,
            include_subdirectories: true, // Default to including subdirectories
            file_pattern: None,
            last_backup_time: None,
        });

        Ok(())
    }

    /// Update the last backup time for a path
    pub fn update_backup_time(&mut self, path: &str, timestamp: u64) {
        if let Some(entry) = self.backup_paths.iter_mut().find(|e| e.path == path) {
            entry.last_backup_time = Some(timestamp);
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_encryption_decryption() {
        // Generate a random key
        let key = ClientSettings::generate_encryption_key();

        // Create settings
        let mut settings = ClientSettings::new();
        settings.server_ip = "192.168.1.1".to_string();
        settings.log_level = LogLevel::Debug;

        // Encrypt
        let encrypted = settings.encrypt(&key).unwrap();

        // Decrypt
        let decrypted = ClientSettings::decrypt(&encrypted, &key).unwrap();

        // Verify
        assert_eq!(decrypted.server_ip, "192.168.1.1");
        assert_eq!(decrypted.log_level, LogLevel::Debug);
    }

    #[test]
    fn test_save_load() {
        // Generate a random key
        let key = ClientSettings::generate_encryption_key();

        // Create temporary directory
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test_settings.dat");

        // Create settings
        let mut settings = ClientSettings::new();
        settings.server_port = 9999;
        settings.dark_mode = false;

        // Save settings
        settings.save(&file_path, &key).unwrap();

        // Load settings
        let loaded = ClientSettings::load(&file_path, &key).unwrap();

        // Verify
        assert_eq!(loaded.server_port, 9999);
        assert_eq!(loaded.dark_mode, false);
    }
}