use crate::{BackupMessage, BackupRequest, FileInfo, ServerResponse};
use anyhow::{Context, Result};
use rustls::{ClientConfig, RootCertStore};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{rustls, TlsConnector};
use tracing::{debug, info, warn};

pub struct TlsClient {
    connector: TlsConnector,
}

impl TlsClient {
    pub fn new() -> Result<Self> {
        let mut root_store = RootCertStore::empty();
        root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));

        let config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        // Note: TLS 1.3 is enabled by default with safe_defaults()
        let connector = TlsConnector::from(Arc::new(config));

        Ok(TlsClient { connector })
    }

    pub async fn connect(
        &self,
        server_name: &str,
        addr: &str,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let stream = TcpStream::connect(addr).await?;
        let domain = rustls::ServerName::try_from(server_name)?;

        let stream = self.connector.connect(domain, stream).await?;
        Ok(stream)
    }
}

pub async fn connect_to_server(
    server_addr: &str,
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    // Load root certificates
    let mut root_store = RootCertStore::empty();

    // For development, you might want to accept self-signed certs
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(std::sync::Arc::new(config));
    let server_name = rustls::ServerName::try_from("localhost")?;

    let stream = tokio::net::TcpStream::connect(server_addr).await?;
    let stream = connector.connect(server_name, stream).await?;

    Ok(stream)
}

pub async fn backup_file(file_path: PathBuf, server_addr: &str, chunk_size: u64) -> Result<bool> {
    // Connect to server
    let mut stream = connect_to_server(server_addr).await?;

    // Read the file and get metadata
    let file_content = tokio::fs::read(&file_path)
        .await
        .context(format!("Failed to read file: {:?}", file_path))?;
    let file_size = file_content.len() as u64;

    // Calculate the file hash
    let file_hash = {
        let mut hasher = Sha256::new();
        hasher.update(&file_content);
        format!("{:x}", hasher.finalize())
    };

    debug!(
        "Backing up file: {:?}, size: {}, hash: {}",
        file_path, file_size, file_hash
    );

    // Create backup request
    let request = BackupRequest {
        file_info: FileInfo {
            path: file_path.clone(),
            hash: file_hash.clone(),
            size: file_size,
        },
        chunk_size,
    };

    // Send init backup message
    let init_message = BackupMessage::InitBackup(request);
    send_message(&mut stream, &init_message)
        .await
        .context("Failed to send backup initialization message")?;

    // Wait for server ready response
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        receive_response(&mut stream),
    )
    .await
    .context("Timed out waiting for server response")?
    .context("Failed to receive server response")?;

    match response {
        ServerResponse::Ready => {
            info!("Server ready to receive backup");
        }
        ServerResponse::Error(msg) => {
            return Err(anyhow::anyhow!("Server error: {}", msg));
        }
        _ => {
            return Err(anyhow::anyhow!("Unexpected server response"));
        }
    }

    // Split file into chunks and send each chunk
    let mut chunks_count = 0;
    for (i, chunk) in file_content.chunks(chunk_size as usize).enumerate() {
        let offset = i as u64 * chunk_size;

        // Calculate chunk hash
        let chunk_hash = {
            let mut hasher = Sha256::new();
            hasher.update(chunk);
            format!("{:x}", hasher.finalize())
        };

        // Send chunk
        let chunk_message = BackupMessage::ChunkData {
            offset,
            data: chunk.to_vec(),
            chunk_hash: chunk_hash.clone(),
        };

        send_message(&mut stream, &chunk_message)
            .await
            .context(format!("Failed to send chunk at offset {}", offset))?;

        // Wait for chunk receipt confirmation
        let response = receive_response(&mut stream).await.context(format!(
            "Failed to receive response for chunk at offset {}",
            offset
        ))?;

        match response {
            ServerResponse::ChunkReceived {
                offset: resp_offset,
                verified,
            } => {
                if resp_offset != offset {
                    return Err(anyhow::anyhow!(
                        "Server acknowledged wrong chunk offset: {} (expected {})",
                        resp_offset,
                        offset
                    ));
                }

                if !verified {
                    return Err(anyhow::anyhow!(
                        "Chunk verification failed at offset {}",
                        offset
                    ));
                }

                debug!("Chunk at offset {} verified successfully", offset);
            }
            ServerResponse::Error(msg) => {
                return Err(anyhow::anyhow!("Server error: {}", msg));
            }
            _ => {
                return Err(anyhow::anyhow!("Unexpected server response"));
            }
        }

        chunks_count += 1;
    }

    // Send completion message
    let complete_message = BackupMessage::Complete {
        hash: file_hash,
        chunks_count,
    };

    send_message(&mut stream, &complete_message)
        .await
        .context("Failed to send backup completion message")?;

    // Wait for completion confirmation
    let response = receive_response(&mut stream)
        .await
        .context("Failed to receive backup completion response")?;

    match response {
        ServerResponse::BackupComplete { verified } => {
            if verified {
                info!(
                    "Backup of {:?} completed and verified successfully",
                    file_path
                );
                Ok(true)
            } else {
                warn!(
                    "Backup of {:?} completed but verification failed",
                    file_path
                );
                Ok(false)
            }
        }
        ServerResponse::Error(msg) => Err(anyhow::anyhow!("Server error: {}", msg)),
        _ => Err(anyhow::anyhow!("Unexpected server response")),
    }
}

/// Sends a serializable message to the TLS stream
///
/// This function serializes the message to JSON, prepends the length as a 4-byte
/// big-endian integer, and writes the data to the stream.
async fn send_message<T: serde::Serialize>(
    stream: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    message: &T,
) -> Result<()> {
    // Serialize the message to JSON
    let data = serde_json::to_vec(message).context("Failed to serialize message")?;

    // Get the length as u32 and convert to big-endian bytes
    let len = data.len() as u32;
    let len_bytes = len.to_be_bytes();

    // Write the length header
    stream
        .write_all(&len_bytes)
        .await
        .context("Failed to write message length")?;

    // Write the actual message data
    stream
        .write_all(&data)
        .await
        .context("Failed to write message data")?;

    // Ensure all data is sent
    stream.flush().await.context("Failed to flush stream")?;

    Ok(())
}
/// Receives a response from the TLS stream
///
/// This function reads a 4-byte length header, then reads the corresponding
/// number of bytes and deserializes them from JSON to a ServerResponse.
async fn receive_response(
    stream: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
) -> Result<ServerResponse> {
    // Read message length (4 bytes)
    let mut len_bytes = [0u8; 4];
    stream
        .read_exact(&mut len_bytes)
        .await
        .context("Failed to read message length")?;

    // Convert bytes to u32 length
    let len = u32::from_be_bytes(len_bytes);

    // Read the message data
    let mut buffer = vec![0u8; len as usize];
    stream
        .read_exact(&mut buffer)
        .await
        .context("Failed to read message data")?;

    // Deserialize the message
    let response: ServerResponse =
        serde_json::from_slice(&buffer).context("Failed to deserialize server response")?;

    Ok(response)
}
