pub mod logger;
pub mod tls_client;
pub mod client_settings;

use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;
use std::io::SeekFrom;
use std::path::PathBuf;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tracing::{debug, warn};

pub const MIN_CHUNK_SIZE: u64 = 64 * 1024; // 64KB
pub const MAX_CHUNK_SIZE: u64 = 10 * 1024 * 1024; // 10MB
pub const OPTIMAL_CHUNK_SIZE: u64 = 1 * 1024 * 1024; // 1MB default
pub const DEFAULT_CHUNK_SIZE: u64 = 1024 * 1024; // 1MB
pub const DEFAULT_PORT: u16 = 3000;

pub struct ConnectionConfig {
    pub server_address: String,
    pub server_port: u16,
}
impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            server_address: "localhost".to_string(),
            server_port: DEFAULT_PORT,
        }
    }
}

/// Sends a serializable message to a TLS stream
pub async fn send_message<T: Serialize, S>(stream: &mut S, message: &T) -> Result<()>
where
    S: AsyncWriteExt + Unpin,
{
    let data = serde_json::to_vec(message).context("Failed to serialize message")?;
    let len = data.len() as u32;

    debug!("Sending message with length: {}", len);

    // Send message length first
    stream
        .write_all(&len.to_be_bytes())
        .await
        .context("Failed to write message length")?;

    // Then send the actual message
    stream
        .write_all(&data)
        .await
        .context("Failed to write message data")?;
    stream.flush().await.context("Failed to flush stream")?;

    Ok(())
}

pub async fn receive_message<T: DeserializeOwned, S>(stream: &mut S) -> Result<T>
where
    S: AsyncReadExt + Unpin,
{
    // Read message length
    let mut len_bytes = [0u8; 4];
    debug!("Waiting to read message length");
    
    match stream.read_exact(&mut len_bytes).await {
        Ok(_) => {
            let len = u32::from_be_bytes(len_bytes);
            debug!("Received message length: {}", len);
            
            // Read message data
            let mut buffer = vec![0u8; len as usize];
            stream
                .read_exact(&mut buffer)
                .await
                .context("Failed to read message data")?;

            // Deserialize response
            let message: T = serde_json::from_slice(&buffer).context("Failed to deserialize message")?;
            Ok(message)
        },
        Err(e) => {
            warn!("Failed to read message length: {}", e);
            Err(anyhow::anyhow!("Failed to read message length: {}", e))
        }
    }
}

/// Calculate SHA-256 hash of data
pub fn calculate_hash(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

// Common messages used by both client and server
#[derive(Serialize, Deserialize)]
pub enum BackupMessage {
    InitBackup(BackupRequest),
    ChunkData {
        offset: u64,
        data: Vec<u8>,
        chunk_hash: String,
    },
    Complete {
        hash: String,
        chunks_count: u64,
    },
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ServerResponse {
    Ready {
        negotiated_chunk_size: u64,
    },
    ChunkReceived {
        offset: u64,
        verified: bool,
    },
    BackupComplete {
        verified: bool,
    },
    FileChunk {
        offset: u64,
        data: Vec<u8>,
        chunk_hash: String,
    },
    FileComplete {
        hash: String,
        chunks_count: u64,
    },
    Error(String),
}
#[derive(Serialize, Deserialize, Clone)]
pub struct BackupRequest {
    pub file_info: FileInfo,
    pub chunk_size: u64,
}

#[derive(Debug)]
pub struct ChunkInfo {
    pub hash: String,
    pub verified: bool,
    pub data: Vec<u8>,
}

// Make FileInfo and other common structs public
#[derive(Serialize, Deserialize, Clone)]
pub struct FileInfo {
    pub path: PathBuf,
    pub hash: String,
    pub size: u64,
}
// Custom error handling
#[derive(Debug)]
pub enum AppError {
    Runtime(std::io::Error),
    Server(anyhow::Error),
    Iced(iced::Error),
    // Other variants as needed
}
impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::Server(err) => write!(f, "Server error: {}", err),
            AppError::Runtime(err) => write!(f, "{:?}", err),
            AppError::Iced(err) => write!(f, "{:?}", err),
            // Handle other variants
        }
    }
}
impl std::error::Error for AppError {}
impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        AppError::Runtime(err)
    }
}
impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        AppError::Server(err)
    }
}
impl From<iced::Error> for AppError {
    fn from(err: iced::Error) -> Self {
        AppError::Iced(err)
    }
}

pub struct BackupSession {
    pub file_path: PathBuf,
    pub expected_hash: String,
    pub expected_size: u64,
    pub chunks: HashMap<u64, ChunkInfo>,
    pub chunk_size: u64,
}

impl BackupSession {
    pub fn new(
        file_path: PathBuf,
        expected_hash: String,
        expected_size: u64,
        chunk_size: u64,
    ) -> Self {
        Self {
            file_path,
            expected_hash,
            expected_size,
            chunks: HashMap::new(),
            chunk_size,
        }
    }

    pub fn verify_complete(&self) -> bool {
        let mut current_offset = 0u64;
        let mut total_size = 0u64;

        while let Some(chunk) = self.chunks.get(&current_offset) {
            if !chunk.verified {
                return false;
            }
            total_size += chunk.data.len() as u64;
            current_offset += chunk.data.len() as u64;
        }

        total_size == self.expected_size
    }

    pub fn calculate_chunk_hash(data: &[u8]) -> String {
        calculate_hash(data)
    }

    // Use chunk_size for validating chunk offsets
    pub fn validate_chunk_offset(&self, offset: u64) -> bool {
        offset % self.chunk_size == 0
    }
}
pub fn negotiate_chunk_size(requested_size: u64) -> u64 {
    if requested_size < MIN_CHUNK_SIZE {
        MIN_CHUNK_SIZE
    } else if requested_size > MAX_CHUNK_SIZE {
        MAX_CHUNK_SIZE
    } else {
        // Round to nearest power of 2 for optimal memory alignment
        let mut size = MIN_CHUNK_SIZE;
        while size < requested_size && size < MAX_CHUNK_SIZE {
            size *= 2;
        }
        size
    }
}
/// Represents a chunked file operation (read or write)
pub struct ChunkedFileOperation {
    pub file_path: PathBuf,
    pub expected_hash: String,
    pub expected_size: u64,
    pub chunk_size: u64,
    pub chunks: HashMap<u64, ChunkInfo>,
}

impl ChunkedFileOperation {
    pub fn new(
        file_path: PathBuf,
        expected_hash: String,
        expected_size: u64,
        chunk_size: u64,
    ) -> Self {
        Self {
            file_path,
            expected_hash,
            expected_size,
            chunks: HashMap::new(),
            chunk_size,
        }
    }

    /// Verify that all chunks have been received and are verified
    pub fn verify_complete(&self) -> bool {
        let mut current_offset = 0u64;
        let mut total_size = 0u64;

        while let Some(chunk) = self.chunks.get(&current_offset) {
            if !chunk.verified {
                return false;
            }
            total_size += chunk.data.len() as u64;
            current_offset += chunk.data.len() as u64;
        }

        total_size == self.expected_size
    }

    /// Validate that a chunk offset aligns with chunk boundaries
    pub fn validate_chunk_offset(&self, offset: u64) -> bool {
        // Allow offset 0 and offsets that align with chunk_size
        offset == 0 || offset % self.chunk_size == 0
    }

    /// Add a chunk to the operation after verifying it
    pub fn add_chunk(&mut self, offset: u64, data: Vec<u8>, chunk_hash: String) -> bool {
        // Verify the chunk
        let calculated_hash = calculate_hash(&data);
        let verified = calculated_hash == chunk_hash;

        if verified {
            self.chunks.insert(
                offset,
                ChunkInfo {
                    hash: chunk_hash,
                    verified: true,
                    data,
                },
            );
        }

        verified
    }

    /// Save all chunks to a file
    pub async fn save_to_file(&self) -> Result<bool> {
        if !self.verify_complete() {
            return Ok(false);
        }

        // Ensure the directory exists
        if let Some(parent) = self.file_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // Create the file
        let mut file = File::create(&self.file_path).await?;
        let mut current_offset = 0u64;

        // Write chunks in order
        while let Some(chunk) = self.chunks.get(&current_offset) {
            file.write_all(&chunk.data).await?;
            current_offset += chunk.data.len() as u64;
        }

        // Flush to ensure all data is written
        file.flush().await?;

        // Verify final file hash
        let final_hash = self.calculate_file_hash().await?;
        Ok(final_hash == self.expected_hash)
    }

    /// Calculate the hash of the saved file
    pub async fn calculate_file_hash(&self) -> Result<String> {
        let file_content = tokio::fs::read(&self.file_path).await.context(format!(
            "Failed to read file for hash calculation: {}",
            self.file_path.display()
        ))?;

        Ok(calculate_hash(&file_content))
    }

    /// Read a file in chunks for sending
    pub async fn read_file_in_chunks<F>(&self, callback: F) -> Result<(u64, String)>
    where
        F: FnMut(u64, &[u8], &str) -> Result<()>,
    {
        let mut callback = callback;
        let file_content = tokio::fs::read(&self.file_path)
            .await
            .context(format!("Failed to read file: {}", self.file_path.display()))?;

        // Calculate overall file hash
        let file_hash = calculate_hash(&file_content);
        let mut chunks_count = 0;

        // Split into chunks and process each
        for (i, chunk) in file_content.chunks(self.chunk_size as usize).enumerate() {
            let offset = i as u64 * self.chunk_size;
            let chunk_hash = calculate_hash(chunk);

            callback(offset, chunk, &chunk_hash)?;
            chunks_count += 1;
        }

        Ok((chunks_count, file_hash))
    }

    /// Read a specific chunk from the file
    pub async fn read_chunk(&self, offset: u64, size: usize) -> Result<(Vec<u8>, String)> {
        if offset > self.expected_size {
            return Err(anyhow::anyhow!("Offset beyond end of file"));
        }

        // Limit the chunk size
        let max_size = (self.expected_size - offset).min(self.chunk_size) as usize;
        let size = size.min(max_size);

        let mut file = File::open(&self.file_path).await?;
        file.seek(SeekFrom::Start(offset)).await?;

        let mut buffer = vec![0u8; size];
        file.read_exact(&mut buffer).await?;

        let chunk_hash = calculate_hash(&buffer);
        Ok((buffer, chunk_hash))
    }
}