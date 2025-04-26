use crate::{
    calculate_hash, receive_message, send_message, BackupMessage, BackupRequest, ConnectionConfig,
    FileInfo, ServerResponse, DEFAULT_CHUNK_SIZE,
};
use anyhow::Result;
use rustls::ServerName;
use rustls::{Certificate, ClientConfig, RootCertStore};
use rustls_pemfile;
use sha2::Digest;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::{rustls, TlsConnector};
use tracing::{debug, info, warn};

/// A client for secure file operations over TLS
pub struct TlsClient {
    connector: TlsConnector,
    config: ClientConfig,
    connection_config: ConnectionConfig,
}

impl TlsClient {
    /// Create a new TLS client with the given configuration
    pub fn new(connection_config: ConnectionConfig) -> Self {
        let config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        
        let connector = TlsConnector::from(Arc::new(config.clone()));
        
        Self {
            connector,
            connection_config,
            config,
        }
    }
    /// Initialize the TLS client with the required certificates
    pub async fn initialize(&mut self, cert_path: Option<&Path>) -> Result<()> {
        let mut root_store = RootCertStore::empty();

        // Add system root certificates
        root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));
        info!("Added system root certificates to trust store");

        // Add custom certificate if provided
        if let Some(path) = cert_path {
            info!("Loading custom certificate from path: {:?}", path);
            match tokio::fs::read(path).await {
                Ok(server_cert) => {
                    let certs_result = rustls_pemfile::certs(&mut server_cert.as_slice())
                        .collect::<Result<Vec<_>, _>>();
                    
                    match certs_result {
                        Ok(certs) => {
                            info!("Found {} certificates in provided cert file", certs.len());
                            for (i, cert) in certs.iter().enumerate() {
                                match root_store.add(&Certificate(cert.to_vec())) {
                                    Ok(_) => info!("Successfully added certificate #{} to trust store", i+1),
                                    Err(e) => warn!("Failed to add certificate #{} to trust store: {}", i+1, e),
                                }
                            }
                        },
                        Err(e) => warn!("Failed to parse certificates from file: {:?}", e),
                    }
                },
                Err(e) => warn!("Failed to read certificate file: {:?}", e),
            }
        } else {
            info!("No custom certificate provided, using only system certificates");
        }

        let config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        self.connector = TlsConnector::from(Arc::new(config));
        info!("TLS client initialized with configuration");
        Ok(())
    }

    /// Connect to the server
    pub async fn connect(&self) -> Result<TlsStream<TcpStream>> {
        let server_addr = format!(
            "{}:{}",
            self.connection_config.server_address, self.connection_config.server_port
        );

        info!("Attempting to connect to server at {}", server_addr);

        match TcpStream::connect(&server_addr).await {
            Ok(stream) => {
                info!("TCP connection established to {}", server_addr);
                
                // Determine the appropriate ServerName based on whether address is IP or hostname
                let domain_str = self.connection_config.server_address.as_str();
                info!("Using server name '{}' for TLS validation", domain_str);
                
                let server_name = if domain_str.parse::<std::net::IpAddr>().is_ok() {
                    // For IP addresses, use "localhost" as a DNS name (which should be in the cert)
                    ServerName::try_from("localhost")?
                } else {
                    // For hostnames, use as-is
                    ServerName::try_from(domain_str)?
                };
                
                debug!("ServerName successfully parsed for TLS validation");
                
                match self.connector.connect(server_name, stream).await {
                    Ok(tls_stream) => {
                        info!("TLS handshake successful with {}", server_addr);
                        Ok(tls_stream)
                    },
                    Err(e) => {
                        // Detailed error logging for TLS failure
                        let error_details = format!("{:?}", e);
                        warn!("TLS handshake failed: {}", error_details);
                        if error_details.contains("BadCertificate") {
                            warn!("Certificate was rejected by peer (BadCertificate)");
                        } else if error_details.contains("UnknownCA") {
                            warn!("Server certificate not trusted (UnknownCA)");
                        }
                        Err(anyhow::anyhow!("TLS connection failed: {}", e))
                    }
                }
            },
            Err(e) => {
                warn!("TCP connection to {} failed: {}", server_addr, e);
                Err(anyhow::anyhow!("Failed to connect to server: {}", e))
            }
        }
    }
    /// Send a file to the server
    pub async fn send_file(
        &self,
        file_path: &Path,
        preferred_chunk_size: Option<u64>,
    ) -> Result<bool> {
        let mut stream = self.connect().await?;

        // Get file metadata instead of reading the whole file
        let file_metadata = tokio::fs::metadata(file_path).await?;
        let file_size = file_metadata.len();

        // Request chunk size (use default if not specified)
        let requested_chunk_size = preferred_chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE);

        // We'll calculate the file hash during chunking
        // Read a small portion of the file to verify it exists and is readable
        let _ = tokio::fs::File::open(file_path).await?;

        // Create backup request
        let request = BackupRequest {
            file_info: FileInfo {
                path: file_path.to_path_buf(),
                hash: String::new(), // We'll calculate the real hash during chunking
                size: file_size,
            },
            chunk_size: requested_chunk_size,
        };

        // Send initialization request
        let init_message = BackupMessage::InitBackup(request);
        send_message(&mut stream, &init_message).await?;

        // Get negotiated chunk size from server
        let response = receive_message::<ServerResponse, _>(&mut stream).await?;
        let actual_chunk_size = match response {
            ServerResponse::Ready {
                negotiated_chunk_size,
            } => {
                info!(
                    "Server ready to receive file '{}' with chunk size: {} bytes",
                    file_path.display(),
                    negotiated_chunk_size
                );
                negotiated_chunk_size
            }
            ServerResponse::Error(msg) => {
                return Err(anyhow::anyhow!("Server error: {}", msg));
            }
            _ => {
                return Err(anyhow::anyhow!("Unexpected server response"));
            }
        };

        // Process file in chunks
        let mut file = tokio::fs::File::open(file_path).await?;
        let mut buffer = vec![0u8; actual_chunk_size as usize];
        let mut offset = 0u64;
        let mut hasher = sha2::Sha256::new();
        let mut chunks_count = 0u64;

        // Read and process each chunk
        loop {
            let bytes_read = file.read(&mut buffer).await?;
            if bytes_read == 0 {
                break; // End of file
            }

            // Update the file hash
            hasher.update(&buffer[..bytes_read]);

            // Calculate chunk hash
            let chunk_hash = calculate_hash(&buffer[..bytes_read]);

            // Send chunk
            let chunk_message = BackupMessage::ChunkData {
                offset,
                data: buffer[..bytes_read].to_vec(),
                chunk_hash: chunk_hash.clone(),
            };
            send_message(&mut stream, &chunk_message).await?;

            // Wait for chunk receipt confirmation
            let response = receive_message::<ServerResponse, _>(&mut stream).await?;
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
                    // Log only at specific intervals to avoid excessive logging
                    if offset % (actual_chunk_size * 10) == 0 || offset == 0 {
                        info!(
                            "Chunk at offset {} verified successfully ({} bytes)",
                            offset, bytes_read
                        );
                    }
                }
                ServerResponse::Error(msg) => {
                    return Err(anyhow::anyhow!("Server error: {}", msg));
                }
                _ => {
                    return Err(anyhow::anyhow!("Unexpected server response"));
                }
            }

            offset += bytes_read as u64;
            chunks_count += 1;
        }

        // Get the final file hash
        let file_hash = format!("{:x}", hasher.finalize());

        // Send completion message
        let complete_message = BackupMessage::Complete {
            hash: file_hash.clone(),
            chunks_count,
        };
        send_message(&mut stream, &complete_message).await?;

        // Wait for completion confirmation
        let response = receive_message::<ServerResponse, _>(&mut stream).await?;
        match response {
            ServerResponse::BackupComplete { verified } => {
                if verified {
                    info!(
                        "File '{}' sent and verified successfully",
                        file_path.display()
                    );
                    Ok(true)
                } else {
                    warn!(
                        "File '{}' sent but verification failed",
                        file_path.display()
                    );
                    Ok(false)
                }
            }
            ServerResponse::Error(msg) => {
                Err(anyhow::anyhow!("Server error during completion: {}", msg))
            }
            _ => Err(anyhow::anyhow!(
                "Unexpected server response during completion"
            )),
        }
    }
    /// Send multiple files to the server in a single session
    pub async fn send_multiple_files(
        &self,
        file_paths: &Vec<PathBuf>,
        preferred_chunk_size: Option<u64>,
    ) -> Result<Vec<(PathBuf, bool)>> {
        // Connect once for all files
        let mut stream = self.connect().await?;
        let mut results = Vec::new();

        info!("Starting multi-file backup session with {} files", file_paths.len());

        // Process each file
        for file_path in file_paths {
            match self.send_file_over_existing_connection(&mut stream, file_path, preferred_chunk_size).await {
                Ok(verified) => {
                    info!("File '{}' transfer completed, verified: {}", file_path.display(), verified);
                    results.push((file_path.clone(), verified));
                },
                Err(e) => {
                    warn!("Failed to transfer file '{}': {}", file_path.display(), e);
                    results.push((file_path.clone(), false));
                }
            }
        }

        // Send disconnect message
        info!("All files processed, sending disconnect message");
        let disconnect_msg = BackupMessage::Disconnect {
            reason: "Backup session complete".to_string(),
        };

        if let Err(e) = send_message(&mut stream, &disconnect_msg).await {
            warn!("Failed to send disconnect message: {}", e);
        } else {
            // Wait for disconnect acknowledgment from server
            match receive_message::<ServerResponse, _>(&mut stream).await {
                Ok(ServerResponse::DisconnectAck) => {
                    info!("Server acknowledged disconnect request");
                },
                Ok(other) => {
                    warn!("Unexpected response to disconnect request: {:?}", other);
                },
                Err(e) => {
                    warn!("Error receiving disconnect acknowledgment: {}", e);
                }
            }
        }

        Ok(results)
    }

    /// Send a file over an existing connection
    async fn send_file_over_existing_connection(
        &self,
        stream: &mut TlsStream<TcpStream>,
        file_path: &Path,
        preferred_chunk_size: Option<u64>,
    ) -> Result<bool> {
        // Get file metadata
        let file_metadata = tokio::fs::metadata(file_path).await?;
        let file_size = file_metadata.len();

        info!("Sending file '{}' ({} bytes) to server", file_path.display(), file_size);

        // Request chunk size (use default if not specified)
        let requested_chunk_size = preferred_chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE);

        // Create backup request
        let request = BackupRequest {
            file_info: FileInfo {
                path: file_path.to_path_buf(),
                hash: String::new(), // We'll calculate during chunking
                size: file_size,
            },
            chunk_size: requested_chunk_size,
        };

        // Send initialization request
        let init_message = BackupMessage::InitBackup(request);
        send_message(stream, &init_message).await?;

        // Get negotiated chunk size from server
        let response = receive_message::<ServerResponse, _>(stream).await?;
        let actual_chunk_size = match response {
            ServerResponse::Ready { negotiated_chunk_size } => {
                info!(
                    "Server ready to receive file '{}' with chunk size: {} bytes",
                    file_path.display(),
                    negotiated_chunk_size
                );
                negotiated_chunk_size
            }
            ServerResponse::Error(msg) => {
                return Err(anyhow::anyhow!("Server error: {}", msg));
            }
            _ => {
                return Err(anyhow::anyhow!("Unexpected server response"));
            }
        };

        // Process file in chunks
        let mut file = tokio::fs::File::open(file_path).await?;
        let mut buffer = vec![0u8; actual_chunk_size as usize];
        let mut offset = 0u64;
        let mut hasher = sha2::Sha256::new();
        let mut chunks_count = 0u64;

        // Read and process each chunk
        loop {
            let bytes_read = file.read(&mut buffer).await?;
            if bytes_read == 0 {
                break; // End of file
            }

            // Update the file hash
            hasher.update(&buffer[..bytes_read]);

            // Calculate chunk hash
            let chunk_hash = calculate_hash(&buffer[..bytes_read]);

            // Send chunk
            let chunk_message = BackupMessage::ChunkData {
                offset,
                data: buffer[..bytes_read].to_vec(),
                chunk_hash: chunk_hash.clone(),
            };
            send_message(stream, &chunk_message).await?;

            // Wait for chunk receipt confirmation
            let response = receive_message::<ServerResponse, _>(stream).await?;
            match response {
                ServerResponse::ChunkReceived { offset: resp_offset, verified } => {
                    if resp_offset != offset {
                        return Err(anyhow::anyhow!(
                            "Server acknowledged wrong chunk offset: {} (expected {})",
                            resp_offset,
                            offset
                        ));
                    }
                    if !verified {
                        return Err(anyhow::anyhow!("Chunk verification failed at offset {}", offset));
                    }
                    // Log only occasionally to avoid excessive logging
                    if chunks_count % 100 == 0 || chunks_count == 0 {
                        info!(
                            "Chunk {} at offset {} verified successfully ({} bytes)",
                            chunks_count, offset, bytes_read
                        );
                    }
                }
                ServerResponse::Error(msg) => {
                    return Err(anyhow::anyhow!("Server error: {}", msg));
                }
                _ => {
                    return Err(anyhow::anyhow!("Unexpected server response"));
                }
            }

            offset += bytes_read as u64;
            chunks_count += 1;
        }

        // Get the final file hash
        let file_hash = format!("{:x}", hasher.finalize());

        // Send completion message
        info!("File '{}' transfer complete, sending completion message", file_path.display());
        let complete_message = BackupMessage::Complete {
            hash: file_hash.clone(),
            chunks_count,
        };
        send_message(stream, &complete_message).await?;

        // Wait for completion confirmation
        let response = receive_message::<ServerResponse, _>(stream).await?;
        match response {
            ServerResponse::BackupComplete { verified } => {
                if verified {
                    info!("File '{}' sent and verified successfully", file_path.display());
                    Ok(true)
                } else {
                    warn!("File '{}' sent but verification failed", file_path.display());
                    Ok(false)
                }
            }
            ServerResponse::Error(msg) => {
                Err(anyhow::anyhow!("Server error during completion: {}", msg))
            }
            _ => Err(anyhow::anyhow!("Unexpected server response during completion")),
        }
    }

    /// Send a directory to the server
    pub async fn send_directory(
        &self,
        dir_path: &Path,
        include_subdirectories: bool,
        file_pattern: Option<&str>,
        preferred_chunk_size: Option<u64>,
    ) -> Result<Vec<(PathBuf, bool)>> {
        info!("Preparing to backup directory: {}", dir_path.display());

        // Collect all files from the directory
        let files = self.collect_files_from_directory(dir_path, include_subdirectories, file_pattern)?;

        if files.is_empty() {
            info!("No files found in directory {} matching pattern", dir_path.display());
            return Ok(Vec::new());
        }

        info!("Found {} files to backup in directory {}", files.len(), dir_path.display());

        // Send all files in one session
        self.send_multiple_files(&files, preferred_chunk_size).await
    }

    /// Collect files from a directory, optionally including subdirectories and filtering by pattern
    fn collect_files_from_directory(
        &self,
        dir_path: &Path,
        include_subdirectories: bool,
        file_pattern: Option<&str>,
    ) -> Result<Vec<PathBuf>> {
        use walkdir::{WalkDir, Error as WalkDirError};
        use std::io::Error as IoError;

        if !dir_path.exists() {
            return Err(anyhow::anyhow!("Directory does not exist: {}", dir_path.display()));
        }

        if !dir_path.is_dir() {
            return Err(anyhow::anyhow!("Path is not a directory: {}", dir_path.display()));
        }

        let mut files = Vec::new();
        let mut skipped_count = 0;
        let mut filtered_count = 0;

        // Configure directory traversal
        let walkdir = if include_subdirectories {
            WalkDir::new(dir_path)
        } else {
            WalkDir::new(dir_path).max_depth(1)
        };

        // Compile regex if pattern is provided
        let pattern = if let Some(pattern_str) = file_pattern {
            use regex::Regex;
            match Regex::new(pattern_str) {
                Ok(re) => {
                    info!("Using file pattern filter: '{}'", pattern_str);
                    Some(re)
                },
                Err(e) => {
                    warn!("Invalid file pattern '{}': {}", pattern_str, e);
                    return Err(anyhow::anyhow!("Invalid file pattern '{}': {}", pattern_str, e));
                }
            }
        } else {
            None
        };

        // Process all entries
        for entry_result in walkdir.into_iter() {
            match entry_result {
                Ok(entry) => {
                    let path = entry.path();
                    
                    // Skip directories
                    if path.is_dir() {
                        continue;
                    }

                    // Apply pattern filter if one exists
                    if let Some(ref regex) = pattern {
                        if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                            if !regex.is_match(file_name) {
                                filtered_count += 1;
                                continue;
                            }
                        }
                    }

                    // Add to our file list
                    files.push(path.to_path_buf());
                },
                Err(e) => {
                    // Log access errors but continue
                    warn!("Error accessing path during directory scan: {}", e);
                    skipped_count += 1;
                }
            }
        }

        // Log summary
        if filtered_count > 0 {
            info!("Filtered out {} files not matching pattern", filtered_count);
        }
        
        if skipped_count > 0 {
            warn!("Skipped {} inaccessible entries", skipped_count);
        }

        info!("Found {} files in directory {}", files.len(), dir_path.display());
        
        if files.is_empty() && (filtered_count > 0 || skipped_count > 0) {
            warn!("No files found after filtering - check your pattern or permissions");
        }

        Ok(files)
    }


    /// Get the TLS connector
    pub fn get_connector(&self) -> TlsConnector {
        self.connector.clone()
    }


}

// Convenience function to create and initialize a client with defaults
pub async fn create_default_client(
    server_address: String,
    server_port: Option<u16>,
    cert_path: Option<&Path>,
) -> Result<TlsClient> {
    let connection_config = ConnectionConfig {
        server_address,
        server_port: server_port.unwrap_or(crate::DEFAULT_PORT),
    };

    let mut client = TlsClient::new(connection_config);
    client.initialize(cert_path).await?;

    Ok(client)
}