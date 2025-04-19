// src/backup_server.rs
use anyhow::Result;
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn, error};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
enum BackupMessage {
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

#[derive(Serialize, Deserialize)]
enum ServerResponse {
    Ready,
    ChunkReceived {
        offset: u64,
        verified: bool,
    },
    BackupComplete {
        verified: bool,
    },
    Error(String),
}

#[derive(Serialize, Deserialize)]
struct BackupRequest {
    file_info: FileInfo,
    chunk_size: u64,
}

// Add FileInfo struct as well since it's used in BackupRequest
#[derive(Serialize, Deserialize, Clone)]
struct FileInfo {
    path: PathBuf,
    hash: String,
    size: u64,
}

#[derive(Debug)]
struct ChunkInfo {
    hash: String,
    verified: bool,
    data: Vec<u8>,
}

struct BackupSession {
    file_path: PathBuf,
    expected_hash: String,
    expected_size: u64,
    chunks: HashMap<u64, ChunkInfo>,
    chunk_size: u64,
}

impl BackupSession {
    fn new(file_path: PathBuf, expected_hash: String, expected_size: u64, chunk_size: u64) -> Self {
        Self {
            file_path,
            expected_hash,
            expected_size,
            chunks: HashMap::new(),
            chunk_size,
        }
    }

    fn calculate_chunk_hash(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }

    fn verify_chunk(&mut self, offset: u64, data: Vec<u8>, chunk_hash: String) -> bool {
        let calculated_hash = Self::calculate_chunk_hash(&data);
        let verified = calculated_hash == chunk_hash;
        
        if verified {
            self.chunks.insert(offset, ChunkInfo {
                hash: chunk_hash,
                verified: true,
                data,
            });
        } else {
            warn!("Chunk hash mismatch at offset {}. Expected: {}, Got: {}", 
                  offset, chunk_hash, calculated_hash);
        }
        
        verified
    }

    async fn save_file(&self) -> Result<bool> {
        if !self.verify_complete() {
            return Ok(false);
        }

        // Ensure the directory exists
        if let Some(parent) = self.file_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let mut file = tokio::fs::File::create(&self.file_path).await?;
        let mut current_offset = 0u64;

        // Write chunks in order
        while let Some(chunk) = self.chunks.get(&current_offset) {
            file.write_all(&chunk.data).await?;
            current_offset += chunk.data.len() as u64;
        }

        // Verify final file
        let final_hash = self.calculate_file_hash().await?;
        Ok(final_hash == self.expected_hash)
    }

    async fn calculate_file_hash(&self) -> Result<String> {
        let mut hasher = Sha256::new();
        let mut file = tokio::fs::File::open(&self.file_path).await?;
        let mut buffer = vec![0u8; 8192];

        loop {
            let bytes_read = file.read(&mut buffer).await?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        Ok(format!("{:x}", hasher.finalize()))
    }

    fn verify_complete(&self) -> bool {
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
}

pub struct BackupServer {
    storage_path: PathBuf,
    acceptor: TlsAcceptor,
}

impl BackupServer {
    pub async fn new(storage_path: impl Into<PathBuf>, cert_path: &Path, key_path: &Path) -> Result<Self> {
        let certs = load_certs(cert_path)?;
        let key = load_private_key(key_path)?;
        
        let config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
            
        let acceptor = TlsAcceptor::from(std::sync::Arc::new(config));
        
        Ok(Self {
            storage_path: storage_path.into(),
            acceptor,
        })
    }

    pub async fn run(&self, addr: &str) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        info!("Backup server listening on {}", addr);

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            info!("New connection from {}", peer_addr);

            let acceptor = self.acceptor.clone();
            let storage_path = self.storage_path.clone();

            tokio::spawn(async move {
                match acceptor.accept(stream).await {
                    Ok(stream) => {
                        if let Err(e) = Self::handle_client(stream, storage_path).await {
                            error!("Error handling client {}: {}", peer_addr, e);
                        }
                    }
                    Err(e) => error!("TLS error from {}: {}", peer_addr, e),
                }
            });
        }
    }

    async fn handle_client(
        mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        storage_path: PathBuf,
    ) -> Result<()> {
        let mut session: Option<BackupSession> = None;

        loop {
            // Read message length
            let mut len_bytes = [0u8; 4];
            if stream.read_exact(&mut len_bytes).await.is_err() {
                break; // Client disconnected
            }
            let len = u32::from_be_bytes(len_bytes);

            // Read message
            let mut buffer = vec![0u8; len as usize];
            stream.read_exact(&mut buffer).await?;

            let message: BackupMessage = serde_json::from_slice(&buffer)?;
            
            match message {
                BackupMessage::InitBackup(request) => {
                    let file_path = storage_path.join(&request.file_info.path);
                    session = Some(BackupSession::new(
                        file_path,
                        request.file_info.hash,
                        request.file_info.size,
                        request.chunk_size,
                    ));
                    Self::send_response(&mut stream, ServerResponse::Ready).await?;
                }

                BackupMessage::ChunkData { offset, data, chunk_hash } => {
                    if let Some(session) = session.as_mut() {
                        let verified = session.verify_chunk(offset, data, chunk_hash);
                        Self::send_response(&mut stream, ServerResponse::ChunkReceived { 
                            offset,
                            verified,
                        }).await?;
                    } else {
                        Self::send_response(&mut stream, ServerResponse::Error(
                            "No active backup session".to_string()
                        )).await?;
                    }
                }

                BackupMessage::Complete { hash, chunks_count } => {
                    if let Some(session) = session.take() {
                        if session.chunks.len() as u64 != chunks_count {
                            Self::send_response(&mut stream, ServerResponse::Error(
                                format!("Expected {} chunks, got {}", chunks_count, session.chunks.len())
                            )).await?;
                            continue;
                        }

                        match session.save_file().await {
                            Ok(verified) => {
                                Self::send_response(&mut stream, ServerResponse::BackupComplete { 
                                    verified 
                                }).await?;
                            }
                            Err(e) => {
                                Self::send_response(&mut stream, ServerResponse::Error(
                                    format!("Failed to save file: {}", e)
                                )).await?;
                            }
                        }
                    } else {
                        Self::send_response(&mut stream, ServerResponse::Error(
                            "No active backup session".to_string()
                        )).await?;
                    }
                }
            }
        }

        Ok(())
    }

    async fn send_response(
        stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        response: ServerResponse,
    ) -> Result<()> {
        let data = serde_json::to_vec(&response)?;
        let len = data.len() as u32;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(&data).await?;
        stream.flush().await?;
        Ok(())
    }
}

// Helper functions for loading TLS certificates
fn load_certs(path: &Path) -> Result<Vec<rustls::Certificate>> {
    // Implementation depends on your certificate format
    // This is a placeholder - you'll need to implement actual cert loading
    unimplemented!("Certificate loading needs to be implemented")
}

fn load_private_key(path: &Path) -> Result<rustls::PrivateKey> {
    // Implementation depends on your key format
    // This is a placeholder - you'll need to implement actual key loading
    unimplemented!("Private key loading needs to be implemented")
}