use anyhow::{Context, Result};
use fs2::FileExt;
use rcgen::{Certificate, CertificateParams, CertifiedKey, DistinguishedName, DnType, Ia5String, SanType, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::PrivateKeyDer;
use std::time::Duration;
use std::fs::File;
use std::io::Write;
use std::io::{BufReader, Seek};
use std::path::{Path, PathBuf};
use serde::Serialize;
use tempfile::tempfile_in;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

// Import from the library crate
use llamapak::{
    logger::{initialize_logging, LoggerConfig},
    negotiate_chunk_size, receive_message, send_message, BackupMessage, ChunkedFileOperation,
    ServerResponse,
};

struct BackupSession {
    file_operation: ChunkedFileOperation,
}

impl BackupSession {
    fn new(file_path: PathBuf, expected_hash: String, expected_size: u64, chunk_size: u64) -> Self {
        Self {
            file_operation: ChunkedFileOperation::new(
                file_path,
                expected_hash,
                expected_size,
                chunk_size,
            ),
        }
    }

    fn verify_chunk(&mut self, offset: u64, data: Vec<u8>, chunk_hash: String) -> bool {
        // Validate offset
        if !self.file_operation.validate_chunk_offset(offset) {
            warn!(
                "Chunk offset {} is not aligned with negotiated chunk size {}",
                offset, self.file_operation.chunk_size
            );
            return false;
        }

        // Add the chunk
        let verified = self
            .file_operation
            .add_chunk(offset, data, chunk_hash.clone());

        if !verified {
            warn!(
                "Chunk verification failed: offset={}, hash={}",
                offset, chunk_hash
            );
        }

        verified
    }

    async fn save_file(&self) -> Result<bool> {
        // Use the common implementation
        match self.file_operation.save_to_file().await {
            Ok(verified) => {
                if verified {
                    info!(
                        "File saved successfully at '{}' and hash verified",
                        self.file_operation.file_path.display()
                    );
                } else {
                    warn!(
                        "File hash verification FAILED for '{}'",
                        self.file_operation.file_path.display()
                    );
                }
                Ok(verified)
            }
            Err(e) => {
                error!(
                    "Error saving file '{}': {}",
                    self.file_operation.file_path.display(),
                    e
                );
                Err(e)
            }
        }
    }
}

pub struct BackupServer {
    storage_path: PathBuf,
    acceptor: TlsAcceptor,
}

impl BackupServer {
    pub async fn new(
        storage_path: impl Into<PathBuf>,
        cert_path: &Path,
        key_path: &Path,
    ) -> Result<Self> {
        let storage_path = storage_path.into();

        // Create storage directory if it doesn't exist
        if !storage_path.exists() {
            info!("Creating storage directory: {}", storage_path.display());
            std::fs::create_dir_all(&storage_path).context("Failed to create storage directory")?;
        }

        // Verify the storage directory is writable
        let _ = tempfile_in(&storage_path)
            .context(format!("Storage directory {} is not writable", storage_path.display()))?;

        // Use a file lock to prevent race conditions during certificate generation
        if !cert_path.exists() || !key_path.exists() {
            warn!("Certificate or key file not found, generating self-signed certificate");
            warn!("For production use, it is recommended to use a properly signed certificate");

            // Create a lock file
            let lock_path = cert_path.with_file_name(".cert_generation.lock");
            let lock_file = std::fs::File::create(&lock_path)
                .context("Failed to create lock file for certificate generation")?;

            if lock_file.try_lock_exclusive().is_ok() {
                // We got the lock, generate certificates
                let result = generate_self_signed_cert(cert_path, key_path)
                    .with_context(|| "Failed to generate self-signed certificate");

                // Always try to unlock and remove the lock file
                let unlock_result = fs2::FileExt::unlock(&lock_file);
                let _ = std::fs::remove_file(&lock_path);

                // Now handle the original error if there was one
                result?;

                if let Err(e) = unlock_result {
                    warn!("Failed to unlock certificate generation lock file: {}", e);
                }

            } else {
                // Wait for the process to generate a certificate
                let mut attempt = 0;
                let max_attempts = 10;
                let wait_time = std::time::Duration::from_secs(1);

                while attempt < max_attempts {
                    std::thread::sleep(wait_time);
                    attempt += 1;

                    if cert_path.exists() && key_path.exists() {
                        info!("Certificates found after waiting {} seconds", attempt);
                        break;
                    }

                    debug!(
                        "Waiting for certificates to be created... ({}/{})",
                        attempt, max_attempts
                    );
                }

                // Verify the certificates were actually created after waiting
                if !cert_path.exists() || !key_path.exists() {
                    return Err(anyhow::anyhow!(
                        "Certificates not created after waiting {} seconds",
                        max_attempts
                    ));
                }
            }

            let _ = std::fs::remove_file(lock_path);
        }

        let certs = load_certs(cert_path)
            .with_context(|| format!("Failed to load certificates from {}", cert_path.display()))?;
        let key = load_private_key(key_path)
            .with_context(|| format!("Failed to load private key from {}", key_path.display()))?;

        // Check if there are any certificates
        if certs.is_empty() {
            return Err(anyhow::anyhow!(
                "No certificates found in {}",
                cert_path.display()
            ));
        }

        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .with_context(|| "Failed to create TLS server configuration")?;
        let acceptor = TlsAcceptor::from(std::sync::Arc::new(config));

        Ok(Self {
            storage_path,
            acceptor,
        })
    }

    pub async fn run(&self, addr: &str) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        info!("Backup server listening on {}", addr);

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
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
                            Err(e) => {
                                error!("TLS error from {}: {}", peer_addr, e);
                            }
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }

    async fn handle_client(
        mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        storage_path: PathBuf,
    ) -> Result<()> {
        info!("Starting client session");

        loop {
            // Read message using the existing receive_message function
            let message = match receive_message::<BackupMessage, _>(&mut stream).await {
                Ok(msg) => msg,
                Err(e) => {
                    if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
                        if io_err.kind() == std::io::ErrorKind::UnexpectedEof
                            || io_err.kind() == std::io::ErrorKind::ConnectionReset
                            || io_err.kind() == std::io::ErrorKind::ConnectionAborted
                        {
                            info!("Client disconnected unexpectedly");
                            break;
                        }
                    }
                    return Err(e);
                }
            };

            match message {
                BackupMessage::InitBackup(request) => {
                    let file_path = storage_path.join(&request.file_info.path);
                    // Negotiate the chunk size
                    let requested_chunk_size = request.chunk_size;
                    let negotiated_chunk_size = negotiate_chunk_size(requested_chunk_size);

                    info!(
                    "Received backup request: file '{}', size: {} bytes, hash: {}, chunk size: {} bytes",
                    format!("{}", file_path.display()),
                    request.file_info.size,
                    request.file_info.hash,
                    negotiated_chunk_size, // Use negotiated size in log
                );

                    // Send ready response with negotiated chunk size
                    let response = ServerResponse::Ready {
                        negotiated_chunk_size: negotiated_chunk_size,
                    };
                    send_message(&mut stream, &response).await?;

                    // Create a new backup session
                    let mut session = BackupSession::new(
                        file_path,
                        request.file_info.hash.clone(),
                        request.file_info.size,
                        negotiated_chunk_size,
                    );

                    // Process file chunks
                    loop {
                        let message = receive_message::<BackupMessage, _>(&mut stream).await?;

                        match message {
                            BackupMessage::ChunkData {
                                offset,
                                data,
                                chunk_hash,
                            } => {
                                // Check if the offset is at a negotiated_chunk_size interval
                                // Use the session's actual chunk size from file_operation
                                if offset % session.file_operation.chunk_size == 0 {
                                    info!(
                                        "Received chunk at offset={}, size={} bytes, hash={}",
                                        offset,
                                        data.len(),
                                        chunk_hash
                                    );
                                }
                                let verified = session.verify_chunk(offset, data, chunk_hash);

                                send_message(
                                    &mut stream,
                                    &ServerResponse::ChunkReceived { offset, verified },
                                )
                                .await?;
                            }
                            BackupMessage::Complete { hash, chunks_count } => {
                                // Verify the client-provided hash matches what we expect
                                if hash != session.file_operation.expected_hash {
                                    warn!(
                                        "File hash mismatch: client reported {}, but expected {}",
                                        hash, session.file_operation.expected_hash
                                    );
                                    send_message(
                                        &mut stream,
                                        &ServerResponse::Error(format!(
                                            "Hash mismatch: expected {}, got {}",
                                            session.file_operation.expected_hash, hash
                                        )),
                                    )
                                    .await?;
                                }

                                if session.file_operation.chunks.len() as u64 != chunks_count {
                                    warn!(
                                            "Chunks count mismatch: client reported {} chunks, but server received {}",
                                            chunks_count,
                                            session.file_operation.chunks.len()
                                        );
                                    send_message(
                                        &mut stream,
                                        &ServerResponse::Error(format!(
                                            "Expected {} chunks, got {}",
                                            chunks_count,
                                            session.file_operation.chunks.len()
                                        )),
                                    )
                                    .await?;
                                    break;
                                }
                                match session.save_file().await {
                                    Ok(verified) => {
                                        if verified {
                                            info!(
                                                    "Backup completed successfully: file hash verified for '{}'",
                                                    session.file_operation.file_path.display()
                                                );
                                        } else {
                                            warn!(
                                                "Backup hash verification failed for '{}'",
                                                session.file_operation.file_path.display()
                                            );
                                        }
                                        send_message(
                                            &mut stream,
                                            &ServerResponse::BackupComplete { verified },
                                        )
                                        .await?;
                                    }
                                    Err(e) => {
                                        error!("Failed to save file: {}", e);
                                        send_message(
                                            &mut stream,
                                            &ServerResponse::Error(format!(
                                                "Failed to save file: {}",
                                                e
                                            )),
                                        )
                                        .await?;
                                    }
                                }
                                break;
                            }
                            BackupMessage::Disconnect { reason } => {
                                info!("Client requested disconnect: {}", reason);
                                let response = ServerResponse::DisconnectAck;
                                send_message(&mut stream, &response).await?;
                                return Ok(());
                            }
                            _ => {
                                let error_msg = "Unexpected message type received".to_string();
                                let response = ServerResponse::Error(error_msg.clone());
                                send_message(&mut stream, &response).await?;
                                return Err(anyhow::anyhow!(error_msg));
                            }
                        }
                    }
                }
                BackupMessage::Disconnect { reason } => {
                    info!("Client requested disconnect: {}", reason);
                    let response = ServerResponse::DisconnectAck;
                    send_message(&mut stream, &response).await?;
                    return Ok(());
                }
                _ => {
                    let error_msg = "Expected InitBackup or Disconnect message".to_string();
                    let response = ServerResponse::Error(error_msg.clone());
                    send_message(&mut stream, &response).await?;
                    return Err(anyhow::anyhow!(error_msg));
                }
            }
        }
        Ok(())
    }
}
#[tokio::main]
async fn main() -> Result<()> {
    // Ensure the logs directory exists
    let log_dir = PathBuf::from("logs");
    std::fs::create_dir_all(&log_dir).context("Failed to create log directory")?;

    // Initialize logging with both file and console output
    let log_config = LoggerConfig {
        log_dir,
        log_file: String::from("llamapak-server.log"),
        max_files: 7,
        log_level: tracing::Level::INFO,
        json_format: false,
    };

    initialize_logging(log_config).context("Failed to initialize logging")?;
    info!("Server application starting");

    // Setup signal handling for graceful shutdown
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigint = signal(SignalKind::interrupt())?;
        let mut sigterm = signal(SignalKind::terminate())?;

        tokio::spawn(async move {
            tokio::select! {
                _ = sigint.recv() => info!("Received SIGINT"),
                _ = sigterm.recv() => info!("Received SIGTERM"),
            }
            let _ = shutdown_tx.send(());
        });
    }

    // Create and run server
    let server = BackupServer::new(
        "backup_storage",
        Path::new("cert.pem"),
        Path::new("key.pem"),
    )
    .await?;

    info!("Starting server on 0.0.0.0:3000");

    tokio::select! {
        result = server.run("0.0.0.0:3000") => {
            match result {
                Ok(_) => {
                    info!("Server terminated gracefully");
                    Ok(())
                },
                Err(e) => {
                    error!("Server error: {:#}", e);
                    Err(e)
                }
            }
        }
        _ = shutdown_rx => {
            info!("Shutting down server gracefully");
            Ok(())
        }
    }
}

// Helper functions for loading TLS certificates
fn load_certs(path: &Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let cert_file = std::fs::File::open(path)
        .with_context(|| format!("Failed to open certificate file: {}", path.display()))?;
    let mut reader = BufReader::new(cert_file);

    // Use rustls-pemfile to parse PEM certificates
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::io::Result<Vec<_>>>()? // First collect IO errors
        .into_iter()
        .map(|v| v.to_owned())
        .collect();

    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    // Open key file
    let key_file = std::fs::File::open(path)
        .with_context(|| format!("Failed to open private key file: {}", path.display()))?;
    let mut reader = BufReader::new(key_file);

    // Try to parse as PKCS8 private keys
    let pkcs8_keys = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("Failed to parse PKCS8 private keys")?;

    if !pkcs8_keys.is_empty() {
        // Convert to PrivateKeyDer
        return Ok(pkcs8_keys[0].clone_key().into());
    }

    // If no PKCS8 keys found, rewind the reader and try RSA keys
    reader
        .seek(std::io::SeekFrom::Start(0))
        .context("Failed to rewind file for RSA key parsing")?;

    let rsa_keys = rustls_pemfile::rsa_private_keys(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("Failed to parse RSA private keys")?;

    if rsa_keys.is_empty() {
        return Err(anyhow::anyhow!(
            "No private keys found in {}",
            path.display()
        ));
    }

    // Return the RSA key
    Ok(rsa_keys[0].clone_key().into())
}

fn generate_self_signed_cert(cert_path: &Path, key_path: &Path) -> Result<()> {
    info!(
        "Generating self-signed certificate at {}",
        cert_path.display()
    );

    // Create directories if they don't exist
    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Configure certificate parameters
    let mut params = CertificateParams::default();

    // Set the distinguished name
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "llamapak-server");
    distinguished_name.push(DnType::OrganizationName, "LlamaPak Backup");
    distinguished_name.push(DnType::CountryName, "US");
    params.distinguished_name = distinguished_name;

    // Set subject alternative names
    params.subject_alt_names.push(SanType::DnsName("localhost".to_string().parse()?));
    params.subject_alt_names.push(SanType::IpAddress("127.0.0.1".parse()?));

    // Set expiration
    params.not_before = std::time::SystemTime::now().into();
    params.not_after = std::time::SystemTime::now()
        .checked_add(std::time::Duration::from_secs(365 * 24 * 60 * 60))
        .unwrap()
        .into();

    // Generate key and certificate
    let key_pair = rcgen::KeyPair::generate()?;
    let certified_key = params.self_signed(&key_pair)?;

    
    let key_pem = key_pair.serialize_pem();
    let cert_pem = certified_key.pem();

    // Write the certificate to file
    let mut cert_file = File::create(cert_path).with_context(|| {
        format!(
            "Failed to create certificate file at {}",
            cert_path.display()
        )
    })?;
    cert_file
        .write_all(cert_pem.as_bytes())
        .context("Failed to write certificate to file")?;

    // Write the private key to file
    let mut key_file = File::create(key_path)
        .with_context(|| format!("Failed to create key file at {}", key_path.display()))?;
    key_file
        .write_all(key_pem.as_bytes())
        .context("Failed to write private key to file")?;

    info!("Self-signed certificate and key generated successfully");
    Ok(())
}
