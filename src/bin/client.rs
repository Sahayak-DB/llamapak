use anyhow::{Context, Result};
use iced::theme::Theme::{SolarizedDark, SolarizedLight};
use iced::widget::{button, column, container, row, text};
use iced::window::Position;
use iced::{Application, Command, Element, Length, Settings, Size, Theme};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::{rustls, TlsConnector};

use tracing::{debug, error, info, warn};

use llamapak::{
    calculate_hash,
    logger::{initialize_logging, LoggerConfig},
    receive_message, send_message, BackupMessage, BackupRequest, ChunkedFileOperation,
    ConnectionConfig, FileInfo, ServerResponse, DEFAULT_CHUNK_SIZE,
};

#[derive(Debug, Clone)]
enum Message {
    SetBackupPath(String),
    StartBackup,
    StopBackup,
    OpenSettings,
    Quit,
    BackupFailed(String),
    BackupInitiated(Result<(), String>),
    ChunkSent(Result<(), String>),
    BackupCompleted(Result<bool, String>),
    ConnectionError(String),
}
// TODO: Pseudo-code for future client implementation
struct FileDownloadOperation {
    file_operation: ChunkedFileOperation,
}

impl FileDownloadOperation {
    async fn receive_chunk(&mut self, offset: u64, data: Vec<u8>, chunk_hash: String) -> bool {
        self.file_operation.add_chunk(offset, data, chunk_hash)
    }

    async fn complete_download(&self) -> Result<bool> {
        self.file_operation.save_to_file().await
    }
}

#[derive(Default, Clone)]
struct BackupClient {
    backup_path: String,
    status: String,
    is_running: bool,
    operations: Vec<OperationLog>,
    space_used: u64,
    space_available: u64,
    schedule: String,
    should_exit: bool,
    server_address: String,
    server_port: u16,
    connector: Option<TlsConnector>,
}
impl BackupClient {
    pub fn new(server_address: String, server_port: u16) -> Self {
        let config = ConnectionConfig {
            server_address,
            server_port,
        };

        let example_operations = vec![
            OperationLog {
                timestamp: "2024-03-20 12:00".to_string(),
                cpu_usage: 15.2,
                size_transferred: 1024000,
            },
            OperationLog {
                timestamp: "2024-03-19 09:00".to_string(),
                cpu_usage: 8.1,
                size_transferred: 512000,
            },
            OperationLog {
                timestamp: "2024-03-18 14:00".to_string(),
                cpu_usage: 9.8,
                size_transferred: 896000,
            },
            OperationLog {
                timestamp: "2024-03-17 13:00".to_string(),
                cpu_usage: 14.7,
                size_transferred: 247138,
            },
            OperationLog {
                timestamp: "2024-03-16 07:00".to_string(),
                cpu_usage: 47.1,
                size_transferred: 1316090,
            },
        ];
        Self {
            backup_path: String::new(),
            status: String::new(),
            is_running: false,
            operations: example_operations,
            space_used: 1024 * 1024 * 100,
            space_available: 1024 * 1024 * 1000,
            schedule: "Daily at 11:30".to_string(),
            should_exit: false, // Initialize the new field
            server_address: config.server_address,
            server_port: config.server_port,
            connector: None,
        }
    }
    pub fn should_exit(&self) -> bool {
        self.should_exit
    }

    pub async fn initialize(&mut self) -> Result<()> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));

        let server_cert_from_file = tokio::fs::read("cert.pem").await?;
        let server_cert = rustls_pemfile::certs(&mut server_cert_from_file.as_slice())
            .collect::<Result<Vec<_>, _>>()?;

        // Add the server certificate to the root store
        for cert in server_cert {
            root_store.add(&rustls::Certificate(cert.to_vec()))?;
        }

        let config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        self.connector = Some(TlsConnector::from(Arc::new(config)));
        Ok(())
    }
    pub async fn connect(&self) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let connector = self
            .connector
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("TLS connector not initialized"))?;

        let server_addr = format!("{}:{}", self.server_address, self.server_port);
        info!("Connecting to server at {}", server_addr);

        let stream = TcpStream::connect(&server_addr).await?;
        let domain = rustls::ServerName::try_from(self.server_address.as_str())?;

        let tls_stream = connector.connect(domain, stream).await?;
        info!("TLS connection established");

        Ok(tls_stream)
    }
    pub async fn start_backup(&self, file_path: &Path) -> Result<()> {
        let mut stream = self.connect().await?;

        // Read the file and get metadata
        let file_content = tokio::fs::read(file_path).await?;
        let file_size = file_content.len() as u64;

        // Calculate the file hash
        let file_hash = calculate_hash(&file_content);

        let requested_chunk_size = DEFAULT_CHUNK_SIZE;

        // Create backup request
        let request = BackupRequest {
            file_info: FileInfo {
                path: file_path.to_path_buf(),
                hash: file_hash.clone(),
                size: file_size,
            },
            chunk_size: requested_chunk_size,
        };

        // Send init backup message
        let init_message = BackupMessage::InitBackup(request);
        send_message(&mut stream, &init_message).await?;

        // Wait for server ready response with negotiated chunk size
        let response = receive_message::<ServerResponse, _>(&mut stream).await?;
        let actual_chunk_size = match response {
            ServerResponse::Ready {
                negotiated_chunk_size,
            } => {
                info!(
                    "Server ready to receive backup with chunk size: {} bytes",
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

        // Split file into chunks and send each chunk
        let mut chunks_count = 0;
        for (i, chunk) in file_content.chunks(actual_chunk_size as usize).enumerate() {
            let offset = i as u64 * actual_chunk_size;

            // Calculate chunk hash
            let chunk_hash = calculate_hash(chunk);

            // Send chunk
            let chunk_message = BackupMessage::ChunkData {
                offset,
                data: chunk.to_vec(),
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

                    info!("Chunk at offset {} verified successfully", offset);
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

        send_message(&mut stream, &complete_message).await?;

        // Wait for completion confirmation
        let response = receive_message::<ServerResponse, _>(&mut stream).await?;
        match response {
            ServerResponse::BackupComplete { verified } => {
                if verified {
                    info!("Backup completed and verified successfully");
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("Backup completed but verification failed"))
                }
            }
            ServerResponse::Error(msg) => Err(anyhow::anyhow!("Server error: {}", msg)),
            _ => Err(anyhow::anyhow!("Unexpected server response")),
        }
    }
}
impl Application for BackupClient {
    type Executor = iced::executor::Default;
    type Message = Message;
    type Theme = Theme;
    type Flags = ();
    fn new(_flags: Self::Flags) -> (Self, iced::Command<Message>) {
        (
            BackupClient::new(String::from("localhost"), 3000),
            iced::Command::none(),
        )
    }
    fn title(&self) -> String {
        String::from("Llamapak: Fast, light, no stragglers.")
    }
    fn update(&mut self, message: Message) -> iced::Command<Message> {
        match message {
            Message::SetBackupPath(path) => {
                self.backup_path = path;
                iced::Command::none()
            }
            Message::StartBackup => {
                self.status = "Initializing backup...".to_string();
                // Use the command to run the backup asynchronously
                self.backup_path = String::from("./test_send/key.pem"); //TODO: REMOVE ME
                Command::perform(
                    start_backup_async(
                        PathBuf::from(self.backup_path.clone()),
                        self.server_address.clone(),
                    ),
                    |result| match result {
                        Ok(()) => Message::BackupInitiated(Ok(())),
                        Err(e) => Message::BackupInitiated(Err(e.to_string())),
                    },
                )
            }
            Message::StopBackup => {
                self.is_running = false;
                self.status = "Backup was stopped".to_string();
                iced::Command::none()
            }
            Message::OpenSettings => {
                self.should_exit = true;
                iced::Command::none()
            }
            Message::BackupFailed(error) => {
                self.is_running = false;
                self.status = format!("Backup failed: {}", error);
                iced::Command::none()
            }
            Message::Quit => {
                self.should_exit = true;
                iced::Command::none()
            }
            Message::ConnectionError(error) => {
                self.status = format!("Connection error: {}", error);
                iced::Command::none()
            }
            Message::BackupInitiated(result) => {
                match result {
                    Ok(_) => {
                        self.is_running = true;
                        self.status = "Backup initiated".to_string();
                    }
                    Err(error) => {
                        self.is_running = false;
                        self.status = format!("Backup failed: {}", error);
                    }
                }
                iced::Command::none()
            }
            Message::ChunkSent(result) => {
                match result {
                    Ok(_) => {
                        self.status = "Chunk sent".to_string();
                    }
                    Err(error) => {
                        self.status = format!("Chunk sending failed: {}", error);
                    }
                }
                iced::Command::none()
            }
            Message::BackupCompleted(result) => {
                match result {
                    Ok(_) => {
                        self.is_running = false;
                        self.status = "Backup completed".to_string();
                    }
                    Err(error) => {
                        self.is_running = false;
                        self.status = format!("Backup failed: {}", error);
                    }
                }
                iced::Command::none()
            }
        }
    }
    fn view(&self) -> Element<Message> {
        let header_height = Length::FillPortion(2);
        let content_height = Length::FillPortion(9);
        // Top row (header)
        let header = row![
            // Left side with text
            text("Llamapak").size(24),
            // Spacer that pushes the buttons to the right
            container(row![]) // Empty container
                .width(Length::Fill),
            // Right side with buttons
            row![
                button(text(if self.is_running { "Stop" } else { "Start" })).on_press(
                    if self.is_running {
                        Message::StopBackup
                    } else {
                        Message::StartBackup
                    }
                ),
                button(text("Settings")).on_press(Message::OpenSettings),
            ]
            .spacing(10)
        ]
        .padding(10)
        .width(Length::Fill)
        .height(header_height);

        // Operations list
        let operations_list = column(
            self.operations
                .iter()
                .take(5)
                .map(|op| {
                    text(format!(
                        "{}: {:.1}% CPU / {} bytes",
                        op.timestamp, op.cpu_usage, op.size_transferred
                    ))
                    .size(16)
                    .into()
                })
                .collect::<Vec<_>>(),
        )
        .spacing(5)
        .width(Length::Fill);

        // Main content
        let content = column![
            // Second row
            text("Last operations:").size(18),
            // Third row
            operations_list,
            // Fourth row
            text(format!(
                "Space used/available: {} / {} bytes",
                self.space_used, self.space_available
            ))
            .size(16),
            // Fifth row
            text(format!("Schedule: {}", self.schedule)).size(16),
            // Sixth row - Status
            text(&self.status).size(16),
        ]
        .spacing(20)
        .padding(10)
        .width(Length::Fill)
        .height(content_height);

        // Combine all elements
        container(column![header, content,])
            .height(Length::Fill)
            .width(Length::Fill)
            .into()
    }
    fn theme(&self) -> Theme {
        SolarizedDark
    }
}
#[derive(Debug, Default, Clone)]
struct OperationLog {
    timestamp: String,
    cpu_usage: f32,
    size_transferred: u64,
}

async fn start_backup_async(file_path: PathBuf, server_addr: String) -> Result<(), anyhow::Error> {
    // Create a new client instance
    let mut client = BackupClient::new(server_addr, 3000); // Using default port 3000

    // Initialize TLS components
    client
        .initialize()
        .await
        .context("Failed to initialize TLS client")?;

    // Start the actual backup process
    client
        .start_backup(&file_path)
        .await
        .context("Backup operation failed")?;

    info!("Backup completed successfully for file: {:?}", file_path);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Ensure the logs directory exists
    let log_dir = PathBuf::from("logs");
    std::fs::create_dir_all(&log_dir).context("Failed to create log directory")?;

    // Initialize logging with both file and console output
    let log_config = LoggerConfig {
        log_dir,
        log_file: String::from("llamapak-client.log"),
        max_files: 7,
        log_level: tracing::Level::INFO,
        json_format: false,
    };

    initialize_logging(log_config).context("Failed to initialize logging")?;
    info!("Client application starting");
    let mut settings = Settings::default();
    settings.window.size = Size::new(800.0, 600.0);

    settings.window.position = Position::Centered;

    BackupClient::run(settings).map_err(|e| anyhow::anyhow!("GUI error: {}", e))?;

    info!("Client application completed successfully");
    Ok(())
}
