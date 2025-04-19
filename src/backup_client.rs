use anyhow::Result;
use std::path::Path;
use walkdir::WalkDir;
use crate::file_manager::FileInfo;
use tracing::{info, warn, debug, error};
use serde::{Serialize, Deserialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use sha2::{Sha256, Digest};
use tokio_rustls::client::TlsStream;
use crate::tls_client::TlsClient;

#[derive(Serialize, Deserialize)]
enum BackupMessage {
    InitBackup(BackupRequest),
    ChunkData {
        offset: u64,
        data: Vec<u8>,
        chunk_hash: String,  // SHA-256 hash of the chunk
    },
    Complete {
        hash: String,
        chunks_count: u64,  // Total number of chunks for final verification
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

#[derive(Serialize, Deserialize, Clone)]
struct BackupRequest {
    file_info: FileInfo,
    chunk_size: u64,
}

// In backup_client.rs
pub struct BackupClient {
    server_name: String,
    server_port: u16,
    tls_client: TlsClient,
}

impl BackupClient {
    pub fn new(server_name: String) -> Result<Self> {
        Ok(BackupClient {
            server_name,
            server_port: 3000,  // Match server port
            tls_client: TlsClient::new()?,
        })
    }

    pub async fn process_directory(&self, dir: &Path) -> Result<()> {
        info!("Starting directory processing: {}", dir.display());
        let mut processed_files = 0;
        let mut failed_files = 0;

        for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                match self.process_file(entry.path()).await {
                    Ok(_) => {
                        processed_files += 1;
                        debug!("Successfully processed file: {}", entry.path().display());
                    }
                    Err(e) => {
                        failed_files += 1;
                        error!("Failed to process file {}: {}", entry.path().display(), e);
                    }
                }
            }
        }

        info!(
            "Directory processing completed. Processed: {}, Failed: {}",
            processed_files, failed_files
        );
        Ok(())
    }

    async fn send_message(&self, stream: &mut TlsStream<TcpStream>, msg: &BackupMessage) -> Result<()> {
        let data = serde_json::to_vec(msg)?;
        let len = data.len() as u32;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(&data).await?;
        stream.flush().await?;
        Ok(())
    }

    async fn receive_response(&self, stream: &mut TlsStream<TcpStream>) -> Result<ServerResponse> {
        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes).await?;
        let len = u32::from_be_bytes(len_bytes);
        
        let mut buffer = vec![0u8; len as usize];
        stream.read_exact(&mut buffer).await?;
        
        let response: ServerResponse = serde_json::from_slice(&buffer)?;
        Ok(response)
    }

    

    async fn with_retry<F, Fut, T>(&self, operation: F, max_retries: u32) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let mut retries = 0;
        let mut last_error = None;

        while retries < max_retries {
            match operation().await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    warn!("Operation failed (attempt {}/{}): {}", retries + 1, max_retries, e);
                    last_error = Some(e);
                    retries += 1;
                    
                    if retries < max_retries {
                        let delay = std::time::Duration::from_secs(2u64.pow(retries));
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Operation failed after {} retries", max_retries)))
    }
}
impl BackupClient {
    fn calculate_chunk_hash(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }

    async fn process_file(&self, path: &Path) -> Result<()> {
        debug!("Processing file: {}", path.display());

        let file_info = FileInfo::from_path(path)?;
        debug!("File hash: {}, size: {}", file_info.hash, file_info.size);

        info!("Connecting to server for file: {}", path.display());
        let addr = format!("{}:{}", self.server_name, self.server_port);
        let mut stream = self.tls_client.connect(
            &self.server_name,
            &addr
        ).await?;

        debug!("Sending file info to server");
        let request = BackupRequest {
            file_info: file_info.clone(),
            chunk_size: 1024 * 1024, // 1MB chunks
        };

        // Initialize backup
        self.send_message(&mut stream, &BackupMessage::InitBackup(request.clone())).await?;
        
        match self.receive_response(&mut stream).await? {
            ServerResponse::Ready => {
                debug!("Server ready to receive file data");
            }
            ServerResponse::Error(e) => {
                return Err(anyhow::anyhow!("Server rejected backup request: {}", e));
            }
            _ => return Err(anyhow::anyhow!("Unexpected server response")),
        }

        // Send file chunks with verification
        let mut offset = 0u64;
        let mut chunks_count = 0u64;
        let file = tokio::fs::File::open(path).await?;
        let mut reader = tokio::io::BufReader::new(file);
        let mut buffer = vec![0u8; request.chunk_size as usize];

        loop {
            let bytes_read = reader.read(&mut buffer).await?;
            if bytes_read == 0 {
                break;
            }

            let chunk_data = &buffer[..bytes_read];
            let chunk_hash = Self::calculate_chunk_hash(chunk_data);
            
            let chunk = BackupMessage::ChunkData {
                offset,
                data: chunk_data.to_vec(),
                chunk_hash: chunk_hash.clone(),
            };

            // Send chunk and verify receipt
            let max_chunk_retries = 3;
            let mut chunk_retry_count = 0;
            
            loop {
                self.send_message(&mut stream, &chunk).await?;

                match self.receive_response(&mut stream).await? {
                    ServerResponse::ChunkReceived { offset: recv_offset, verified } => {
                        if recv_offset != offset {
                            return Err(anyhow::anyhow!(
                                "Server acknowledged wrong chunk offset: expected {}, got {}", 
                                offset, 
                                recv_offset
                            ));
                        }
                        
                        if verified {
                            debug!("Chunk at offset {} verified by server", offset);
                            break;
                        } else {
                            chunk_retry_count += 1;
                            if chunk_retry_count >= max_chunk_retries {
                                return Err(anyhow::anyhow!(
                                    "Failed to verify chunk at offset {} after {} attempts", 
                                    offset,
                                    max_chunk_retries
                                ));
                            }
                            warn!(
                                "Chunk verification failed at offset {}. Retrying ({}/{})", 
                                offset,
                                chunk_retry_count,
                                max_chunk_retries
                            );
                            continue;
                        }
                    }
                    ServerResponse::Error(e) => {
                        return Err(anyhow::anyhow!("Error sending chunk at offset {}: {}", offset, e));
                    }
                    _ => return Err(anyhow::anyhow!("Unexpected server response for chunk")),
                }
            }

            offset += bytes_read as u64;
            chunks_count += 1;
            debug!("Progress: {}/{} bytes", offset, file_info.size);
        }

        // Send completion message with total chunks for verification
        self.send_message(&mut stream, &BackupMessage::Complete {
            hash: file_info.hash.clone(),
            chunks_count,
        }).await?;

        match self.receive_response(&mut stream).await? {
            ServerResponse::BackupComplete { verified } => {
                if verified {
                    info!("File backup completed and verified: {}", path.display());
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("Final backup verification failed"))
                }
            }
            ServerResponse::Error(e) => {
                Err(anyhow::anyhow!("Backup completion error: {}", e))
            }
            _ => Err(anyhow::anyhow!("Unexpected server response at completion")),
        }
    }
}