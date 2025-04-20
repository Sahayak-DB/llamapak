use anyhow::{Context, Result};
use rcgen::{
    Certificate, CertificateParams, DistinguishedName, DnType, KeyPair, SanType,
    PKCS_ECDSA_P256_SHA256,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::io::{BufReader, Seek};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

// Import from the library crate
use llamapak::{
    logger::{initialize_logging, LoggerConfig},
    BackupMessage, ChunkInfo, ServerResponse,
};

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
            self.chunks.insert(
                offset,
                ChunkInfo {
                    hash: chunk_hash,
                    verified: true,
                    data,
                },
            );
        } else {
            warn!(
                "Chunk hash mismatch at offset {}. Expected: {}, Got: {}",
                offset, chunk_hash, calculated_hash
            );
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
        let hash_matches = final_hash == self.expected_hash;

        // Add detailed logging about file verification
        if hash_matches {
            info!(
                "File saved successfully at '{}' and hash verified: {} (size: {} bytes)",
                self.file_path.display(),
                final_hash,
                self.expected_size
            );
        } else {
            warn!(
                "File hash verification FAILED for '{}'. Expected: {}, Got: {}",
                self.file_path.display(),
                self.expected_hash,
                final_hash
            );
        }

        Ok(hash_matches)
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
    pub async fn new(
        storage_path: impl Into<PathBuf>,
        cert_path: &Path,
        key_path: &Path,
    ) -> Result<Self> {
        // Check if certificate and key files exist, generate them if they don't
        if !cert_path.exists() || !key_path.exists() {
            warn!("Certificate or key file not found, generating self-signed certificate");
            warn!("For production use, it is recommended to use a properly signed certificate");
            generate_self_signed_cert(cert_path, key_path)?;
        }

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
                        file_path.clone(),
                        request.file_info.hash.clone(),
                        request.file_info.size,
                        request.chunk_size,
                    ));
                    info!(
                        "Received backup request: file '{}', size: {} bytes, hash: {}, chunk size: {} bytes",
                        format!("{}", file_path.display()),
                        request.file_info.size,
                        request.file_info.hash,
                        request.chunk_size,
                    );

                    Self::send_response(&mut stream, ServerResponse::Ready).await?;
                }

                BackupMessage::ChunkData {
                    offset,
                    data,
                    chunk_hash,
                } => {
                    if let Some(session) = session.as_mut() {
                        // Check if the offset is at a 1MB interval
                        if (offset % 1048576 == 0) {
                            info!(
                                "Received chunk at offset={}, size={} bytes, hash={}",
                                offset,
                                data.len(),
                                chunk_hash
                            );
                        }

                        let verified = session.verify_chunk(offset, data, chunk_hash);
                        Self::send_response(
                            &mut stream,
                            ServerResponse::ChunkReceived { offset, verified },
                        )
                        .await?;
                    } else {
                        Self::send_response(
                            &mut stream,
                            ServerResponse::Error("No active backup session".to_string()),
                        )
                        .await?;
                    }
                }

                BackupMessage::Complete { hash, chunks_count } => {
                    if let Some(session) = session.take() {
                        if session.chunks.len() as u64 != chunks_count {
                            warn!(
                                "Chunks count mismatch: client reported {} chunks, but server received {}",
                                chunks_count,
                                session.chunks.len()
                            );

                            Self::send_response(
                                &mut stream,
                                ServerResponse::Error(format!(
                                    "Expected {} chunks, got {}",
                                    chunks_count,
                                    session.chunks.len()
                                )),
                            )
                            .await?;
                            continue;
                        }

                        match session.save_file().await {
                            Ok(verified) => {
                                if verified {
                                    info!(
                                        "Backup completed successfully: file hash verified for '{}'",
                                        session.file_path.display()
                                    );
                                } else {
                                    warn!(
                                        "Backup hash verification failed for '{}'",
                                        session.file_path.display()
                                    );
                                }
                                Self::send_response(
                                    &mut stream,
                                    ServerResponse::BackupComplete { verified },
                                )
                                .await?;
                            }
                            Err(e) => {
                                Self::send_response(
                                    &mut stream,
                                    ServerResponse::Error(format!("Failed to save file: {}", e)),
                                )
                                .await?;
                            }
                            Err(e) => {
                                error!("Failed to save file: {}", e);
                                Self::send_response(
                                    &mut stream,
                                    ServerResponse::Error(format!("Failed to save file: {}", e)),
                                )
                                    .await?;
                            }
                        }
                    } else {
                        Self::send_response(
                            &mut stream,
                            ServerResponse::Error("No active backup session".to_string()),
                        )
                        .await?;
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
fn load_certs(path: &Path) -> Result<Vec<rustls::Certificate>> {
    let cert_file = std::fs::File::open(path)
        .with_context(|| format!("Failed to open certificate file: {}", path.display()))?;
    let mut reader = BufReader::new(cert_file);

    // Use rustls-pemfile to parse PEM certificates
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::io::Result<Vec<_>>>()? // First collect IO errors
        .into_iter()
        .map(|v| rustls::Certificate(v.into_owned().to_vec()))
        .collect();

    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<rustls::PrivateKey> {
    // Open key file
    let key_file = std::fs::File::open(path)
        .with_context(|| format!("Failed to open private key file: {}", path.display()))?;
    let mut reader = BufReader::new(key_file);

    // Try to parse as PKCS8 private keys
    let pkcs8_keys = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("Failed to parse PKCS8 private keys")?;

    if !pkcs8_keys.is_empty() {
        // Get the bytes from the PKCS8 key
        let key_data = pkcs8_keys[0].secret_pkcs8_der();
        return Ok(rustls::PrivateKey(key_data.to_vec()));
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

    // Get the bytes from the RSA key
    let key_data = rsa_keys[0].secret_pkcs1_der();
    Ok(rustls::PrivateKey(key_data.to_vec()))
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
    params.alg = &PKCS_ECDSA_P256_SHA256;

    // Set the distinguished name
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "llamapak-server");
    distinguished_name.push(DnType::OrganizationName, "LlamaPak Backup");
    distinguished_name.push(DnType::CountryName, "US");
    params.distinguished_name = distinguished_name;

    // Set subject alternative names
    params.subject_alt_names = vec![
        SanType::DnsName("localhost".to_string()),
        SanType::DnsName("127.0.0.1".to_string()),
    ];

    // Generate the certificate
    let cert = Certificate::from_params(params).context("Failed to generate certificate")?;

    // Write the certificate to file
    let pem_cert = cert
        .serialize_pem()
        .context("Failed to serialize certificate to PEM")?;
    let mut cert_file = File::create(cert_path).with_context(|| {
        format!(
            "Failed to create certificate file at {}",
            cert_path.display()
        )
    })?;
    cert_file
        .write_all(pem_cert.as_bytes())
        .context("Failed to write certificate to file")?;

    // Write the private key to file
    let pem_key = cert.serialize_private_key_pem();
    let mut key_file = File::create(key_path)
        .with_context(|| format!("Failed to create key file at {}", key_path.display()))?;
    key_file
        .write_all(pem_key.as_bytes())
        .context("Failed to write private key to file")?;

    info!("Self-signed certificate and key generated successfully");
    Ok(())
}
