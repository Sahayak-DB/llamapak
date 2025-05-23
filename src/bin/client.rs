use anyhow::{Context, Result};
use iced::alignment::Horizontal;
use iced::widget::{button, column, container, horizontal_rule, horizontal_space, progress_bar, row, text, text_input, ProgressBar};
use iced::window::Position;
use iced::{Alignment, Background};
use iced::{Application, Color, Command, Element, Length, Settings, Size, Theme};
use iced_style::progress_bar::Appearance;
use iced_style::theme;
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::{rustls, TlsConnector};
use tracing::{debug, error, info, warn};

use llamapak::client_settings::BackupPathEntry;
use llamapak::tls_client::TlsClient;
use llamapak::{
    calculate_hash,
    client_settings::{ClientSettings, LogLevel, OperationStatus},
    format_storage,
    logger::{initialize_logging, LoggerConfig},
    receive_message, send_message, BackupMessage, BackupRequest, ChunkedFileOperation,
    ConnectionConfig, FileInfo, ServerResponse,
};

#[derive(Debug)]
struct AtomicF32 {
    inner: AtomicU32,
}

impl AtomicF32 {
    fn new(value: f32) -> Self {
        let bits = value.to_bits();
        Self {
            inner: AtomicU32::new(bits),
        }
    }

    fn store(&self, value: f32, ordering: Ordering) {
        let bits = value.to_bits();
        self.inner.store(bits, ordering);
    }

    fn load(&self, ordering: Ordering) -> f32 {
        let bits = self.inner.load(ordering);
        f32::from_bits(bits)
    }
}

#[derive(Debug, Clone)]
enum Message {
    SetBackupPath(String),
    BrowseForBackupFile,
    StartBackup,
    StopBackup,
    OpenSettings,
    SaveSettings,
    ToggleDarkMode,
    SetServerIP(String),
    SetServerPort(String),
    SetLogLevel(LogLevel),
    Quit,
    BackupFailed(String),
    BackupInitiated(Result<(), String>),
    ChunkSent(Result<(), String>),
    BackupCompleted(Result<bool, String>),
    ConnectionError(String),
    SettingsLoaded(Result<ClientSettings, String>),
    SettingsSaved(Result<(), String>),
    SyncSettings,
    AddBackupPath,
    RemoveBackupPath(usize),    // Index of the path to remove
    SelectBackupPathType(bool), // true for directory, false for file
    SetBackupPathIncludeSubdirs(bool),
    SetBackupPathPattern(String),
    SetNewBackupPath(String), // For storing the path being edited before adding
}

// TODO: Pseudo-code for future client implementation
struct FileDownloadOperation {
    file_operation: ChunkedFileOperation,
}

impl FileDownloadOperation {}

#[derive(Clone)]
struct BackupClient {
    backup_path: String,
    status: String,
    is_running: bool,
    operations: Vec<OperationLog>,
    space_used: u64,
    space_available: u64,
    schedule: String,
    server_address: String,
    server_port: u16,
    connector: Option<TlsConnector>,
    settings: ClientSettings,
    encryption_key: [u8; 32],
    show_settings: bool,
    new_server_ip: String,
    new_server_port: String,
    new_backup_path: String,
    is_directory_backup: bool,
    include_subdirectories: bool,
    file_pattern: String,
    cancel_token: Arc<AtomicBool>,
    percent_complete: Arc<AtomicF32>,
}

impl BackupClient {
    pub fn new(server_address: String, server_port: u16) -> Self {
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

        // Create a default settings object
        let settings = ClientSettings::new();

        // Generate a persistent encryption key - in production this should be stored securely
        // For demo purposes, we'll use a static key
        let encryption_key = [42u8; 32]; // Fixed key for demo

        Self {
            backup_path: String::new(),
            status: String::new(),
            is_running: false,
            operations: example_operations,
            space_used: 112198210,
            space_available: 1048576000,
            schedule: "Daily at 11:30".to_string(),
            server_address: server_address.clone(),
            server_port,
            connector: None,
            settings,
            encryption_key,
            show_settings: false,
            new_server_ip: server_address,
            new_server_port: server_port.to_string(),
            new_backup_path: String::new(),
            is_directory_backup: true, // Default to directory backup
            include_subdirectories: true,
            file_pattern: String::new(),
            cancel_token: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            percent_complete: Arc::new(AtomicF32::new(0.0)),
        }
    }
    pub fn get_percent_complete(&self) -> f32 {
        self.percent_complete.load(Ordering::SeqCst)
    }

    fn view_backup_paths(&self) -> Element<Message> {
        let paths: Vec<Element<_>> = self
            .settings
            .backup_paths
            .iter()
            .enumerate()
            .map(|(index, entry)| {
                row![
                    // Path type icon (folder or file)
                    text(if entry.is_directory { "D:" } else { "F:" }).size(16),
                    // Path details
                    column![
                        horizontal_rule(1),
                        text(&entry.path).size(16),
                        if entry.is_directory {
                            text(format!(
                                "Include subdirs: {}{}",
                                if entry.include_subdirectories {
                                    "Yes"
                                } else {
                                    "No"
                                },
                                entry
                                    .file_pattern
                                    .as_ref()
                                    .map_or("".to_string(), |p| format!(", Pattern: {}", p))
                            ))
                            .size(14)
                        } else {
                            text("").size(14)
                        },
                        if let Some(time) = entry.last_backup_time {
                            text(format!(
                                "Last backup: {}",
                                chrono::DateTime::from_timestamp(time as i64, 0)
                                    .map_or("Invalid time".to_string(), |dt| dt
                                        .format("%Y-%m-%d %H:%M")
                                        .to_string())
                            ))
                            .size(14)
                        } else {
                            text("Never backed up").size(14)
                        },
                    ]
                    .width(Length::Fill),
                    // Remove button
                    button(text("Delete").horizontal_alignment(Horizontal::Center))
                        .on_press(Message::RemoveBackupPath(index))
                        .style(iced::theme::Button::Destructive),
                    text("").size(16),
                ]
                .spacing(10)
                .width(Length::Fill)
                .into()
            })
            .collect();

        if paths.is_empty() {
            // Show message when no paths are configured
            container(text("No backup paths configured. Add one below.").size(16))
                .width(Length::Fill)
                .center_x()
                .padding(10)
                .into()
        } else {
            // Show scrollable list of paths
            iced::widget::scrollable(column(paths).spacing(5).width(Length::Fill))
                .height(Length::from(200))
                .into()
        }
    }

    pub async fn initialize(&mut self) -> Result<()> {
        // Load settings first
        self.load_settings().await?;

        // Use settings for configuration
        self.server_address = self.settings.server_ip.clone();
        self.server_port = self.settings.server_port;
        self.new_server_ip = self.settings.server_ip.clone();
        self.new_server_port = self.settings.server_port.to_string();

        // Initialize TLS only if enabled in settings
        if self.settings.tls_enabled {
            // Ensure we have the server certificate
            let cert_path = Path::new("cert.pem");
            let cert_option = if cert_path.exists() {
                Some(cert_path)
            } else {
                warn!(
                    "Server certificate not found at {}. Using system certificates only.",
                    cert_path.display()
                );
                None
            };

            // Create a TLS connector with the server's certificate
            let connection_config = ConnectionConfig {
                server_address: self.server_address.clone(),
                server_port: self.server_port,
            };

            // Create and initialize TLS client
            let mut tls_client = TlsClient::new(connection_config);

            match tls_client.initialize(cert_option).await {
                Ok(_) => {
                    info!("TLS connection initialized successfully");
                    // Add a getter method to TlsClient to access the connector
                    self.connector = Some(tls_client.get_connector());
                }
                Err(e) => {
                    warn!("Failed to initialize TLS connection: {}", e);
                    return Err(anyhow::anyhow!("TLS initialization failed: {}", e));
                }
            }
        } else {
            info!("TLS is disabled in settings, connections will not be encrypted");
            self.connector = None;
        }

        Ok(())
    }

    pub async fn load_settings(&mut self) -> Result<()> {
        let settings_path = ClientSettings::default_local_path();

        if settings_path.exists() {
            // Try to load existing settings
            match ClientSettings::load(&settings_path, &self.encryption_key) {
                Ok(loaded_settings) => {
                    info!("Loaded settings from {}", settings_path.display());
                    self.settings = loaded_settings;
                }
                Err(e) => {
                    warn!("Could not load settings: {}", e);
                    // Use defaults but save them
                    self.settings = ClientSettings::new();
                    self.settings.save(&settings_path, &self.encryption_key)?;
                }
            }
        } else {
            // Create and save default settings
            info!("Creating default settings at {}", settings_path.display());
            self.settings = ClientSettings::new();
            self.settings.save(&settings_path, &self.encryption_key)?;
        }

        Ok(())
    }

    pub async fn save_settings(&self) -> Result<()> {
        let settings_path = ClientSettings::default_local_path();
        self.settings.save(&settings_path, &self.encryption_key)?;
        info!("Settings saved to {}", settings_path.display());
        Ok(())
    }

    pub async fn sync_settings_with_server(&mut self) -> Result<()> {
        // Sync settings with server
        self.settings.sync_with_server(
            &format!("{}:{}", self.settings.server_ip, self.settings.server_port),
            &self.encryption_key,
        )?;

        // Add a log entry for this operation
        self.settings.add_log_entry(
            "Settings Sync".to_string(),
            OperationStatus::Success,
            "Synchronized settings with server".to_string(),
        );

        // Save updated settings with the new log entry
        self.save_settings().await?;

        Ok(())
    }

    pub async fn connect(&self) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let connector = self
            .connector
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("TLS connector not initialized"))?
            .clone();

        let server_addr = format!("{}:{}", self.server_address, self.server_port);
        info!("Connecting to server at {}", server_addr);

        let stream = TcpStream::connect(&server_addr).await?;
        let domain_string = self.server_address.clone();
        let domain = rustls::pki_types::ServerName::try_from(domain_string)?;

        let tls_stream = connector.connect(domain, stream).await?;
        info!("TLS connection established");

        Ok(tls_stream)
    }

    pub async fn start_backup(&self, paths: Vec<PathBuf>) -> Result<bool> {
        info!("Starting backup for {} paths", paths.len());

        // Reset progress at the start
        self.percent_complete.store(0.0, Ordering::SeqCst);

        // Reset the cancellation token before starting a new backup
        self.cancel_token.store(false, Ordering::SeqCst);

        // Clone the cancellation token for the connect operation
        let cancel_token = self.cancel_token.clone();

        // Connect to the server
        let mut stream = match self.connect().await {
            Ok(stream) => stream,
            Err(e) => {
                error!("Failed to connect to server: {}", e);
                return Err(anyhow::anyhow!("Failed to connect to server: {}", e));
            }
        };

        let mut all_files: Vec<PathBuf> = Vec::new();

        for path in &paths {
            if path.is_dir() && self.is_directory_backup {
                // Process directory backup
                let pattern = if !self.file_pattern.is_empty() {
                    Some(self.file_pattern.as_str())
                } else {
                    None
                };

                match self.collect_files_from_directory(path, self.include_subdirectories, pattern)
                {
                    Ok(files) => all_files.extend(files),
                    Err(e) => {
                        error!(
                            "Failed to collect files from directory {}: {}",
                            path.display(),
                            e
                        );
                        return Err(anyhow::anyhow!("Failed to collect files: {}", e));
                    }
                };
            } else if path.is_file() {
                all_files.push(path.clone());
            }
        }

        let total_files = all_files.len();
        if total_files == 0 {
            self.percent_complete.store(100.0, Ordering::SeqCst);
            return Ok(true);
        }

        for (file_index, file_path) in all_files.iter().enumerate() {
            // Check if the backup has been cancelled
            if cancel_token.load(Ordering::SeqCst) {
                info!("Backup operation cancelled");
                // Optionally notify server about cancellation
                return Ok(false);
            }

            // Backup the file
            if let Err(e) = self
                .backup_file_with_cancellation(&mut stream, file_path, &cancel_token)
                .await
            {
                error!("Failed to backup file {}: {}", file_path.display(), e);
                return Err(e);
            }

            // Update progress after each file
            let progress = ((file_index + 1) as f32 / total_files as f32) * 100.0;
            self.percent_complete.store(progress, Ordering::SeqCst);
        }

        info!("Backup completed successfully");
        self.percent_complete.store(100.0, Ordering::SeqCst);
        Ok(true)
    }
    /// Backup a file using an existing connection with cancellation support
    async fn backup_file_with_cancellation(
        &self,
        stream: &mut TlsStream<TcpStream>,
        file_path: &Path,
        cancel_token: &Arc<AtomicBool>,
    ) -> Result<()> {
        // Check if cancelled before starting file
        if cancel_token.load(Ordering::SeqCst) {
            return Ok(());
        }

        info!(
            "Starting backup for file using existing connection: {}",
            file_path.display()
        );

        // Read the file and get metadata
        let file_content = tokio::fs::read(file_path).await?;
        let file_size = file_content.len() as u64;

        // Calculate the file hash
        let file_hash = calculate_hash(&file_content);

        // Use chunk size from settings if available
        let requested_chunk_size = self.settings.upload_chunk_size as u64;

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
        send_message(stream, &init_message).await?;

        // Wait for server ready response with negotiated chunk size
        let response = receive_message::<ServerResponse, _>(stream).await?;
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

        // Split file into chunks and send each chunk
        let mut chunks_count = 0;
        for (i, chunk) in file_content.chunks(actual_chunk_size as usize).enumerate() {
            // Check for cancellation before sending each chunk
            if cancel_token.load(Ordering::SeqCst) {
                // Optionally notify server about cancellation
                info!(
                    "Backup cancelled during file transfer: {}",
                    file_path.display()
                );
                return Ok(());
            }

            let offset = i as u64 * actual_chunk_size;

            // Calculate chunk hash
            let chunk_hash = calculate_hash(chunk);

            // Send chunk
            let chunk_message = BackupMessage::ChunkData {
                offset,
                data: chunk.to_vec(),
                chunk_hash: chunk_hash.clone(),
            };

            send_message(stream, &chunk_message).await?;

            // Wait for chunk receipt confirmation
            let response = receive_message::<ServerResponse, _>(stream).await?;
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

                    // Log only occasionally for large files
                    if chunks_count % 20 == 0 || chunks_count == 0 {
                        info!(
                            "Chunk {} at offset {} verified successfully",
                            chunks_count, offset
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

            chunks_count += 1;
        }

        // Check for cancellation before sending completion
        if cancel_token.load(Ordering::SeqCst) {
            info!(
                "Backup cancelled after sending all chunks: {}",
                file_path.display()
            );
            return Ok(());
        }

        // Send completion message
        info!(
            "All chunks sent for file '{}', sending completion message",
            file_path.display()
        );
        let complete_message = BackupMessage::Complete {
            hash: file_hash,
            chunks_count,
        };

        send_message(stream, &complete_message).await?;

        // Wait for completion confirmation
        let response = receive_message::<ServerResponse, _>(stream).await?;
        match response {
            ServerResponse::BackupComplete { verified } => {
                if verified {
                    info!(
                        "File '{}' backup completed and verified successfully",
                        file_path.display()
                    );
                    Ok(())
                } else {
                    Err(anyhow::anyhow!(
                        "File '{}' backup completed but verification failed",
                        file_path.display()
                    ))
                }
            }
            ServerResponse::Error(msg) => Err(anyhow::anyhow!(
                "Server error for file '{}': {}",
                file_path.display(),
                msg
            )),
            _ => Err(anyhow::anyhow!(
                "Unexpected server response for file '{}'",
                file_path.display()
            )),
        }
    }

    /// Backup a file using an existing connection
    async fn backup_file_with_existing_connection(
        &self,
        stream: &mut TlsStream<TcpStream>,
        file_path: &Path,
    ) -> Result<()> {
        info!(
            "Starting backup for file using existing connection: {}",
            file_path.display()
        );

        // Read the file and get metadata
        let file_content = tokio::fs::read(file_path).await?;
        let file_size = file_content.len() as u64;

        // Calculate the file hash
        let file_hash = calculate_hash(&file_content);

        // Use chunk size from settings if available
        let requested_chunk_size = self.settings.upload_chunk_size as u64;

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
        send_message(stream, &init_message).await?;

        // Wait for server ready response with negotiated chunk size
        let response = receive_message::<ServerResponse, _>(stream).await?;
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

            send_message(stream, &chunk_message).await?;

            // Wait for chunk receipt confirmation
            let response = receive_message::<ServerResponse, _>(stream).await?;
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

                    // Log only occasionally for large files
                    if chunks_count % 20 == 0 || chunks_count == 0 {
                        info!(
                            "Chunk {} at offset {} verified successfully",
                            chunks_count, offset
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

            chunks_count += 1;
        }

        // Send completion message
        info!(
            "All chunks sent for file '{}', sending completion message",
            file_path.display()
        );
        let complete_message = BackupMessage::Complete {
            hash: file_hash,
            chunks_count,
        };

        send_message(stream, &complete_message).await?;

        // Wait for completion confirmation
        let response = receive_message::<ServerResponse, _>(stream).await?;
        match response {
            ServerResponse::BackupComplete { verified } => {
                if verified {
                    info!(
                        "File '{}' backup completed and verified successfully",
                        file_path.display()
                    );
                    Ok(())
                } else {
                    Err(anyhow::anyhow!(
                        "File '{}' backup completed but verification failed",
                        file_path.display()
                    ))
                }
            }
            ServerResponse::Error(msg) => Err(anyhow::anyhow!(
                "Server error for file '{}': {}",
                file_path.display(),
                msg
            )),
            _ => Err(anyhow::anyhow!(
                "Unexpected server response for file '{}'",
                file_path.display()
            )),
        }
    }

    /// Collect files from a directory with optional pattern matching
    fn collect_files_from_directory(
        &self,
        dir_path: &Path,
        include_subdirectories: bool,
        file_pattern: Option<&str>,
    ) -> Result<Vec<PathBuf>> {
        use regex::Regex;
        use walkdir::WalkDir;

        let mut files = Vec::new();

        // Create WalkDir with appropriate depth
        let walkdir = if include_subdirectories {
            WalkDir::new(dir_path)
        } else {
            WalkDir::new(dir_path).max_depth(1)
        };

        // Compile regex if pattern is provided
        let pattern = if let Some(pattern_str) = file_pattern {
            match Regex::new(pattern_str) {
                Ok(re) => Some(re),
                Err(e) => {
                    warn!("Invalid file pattern '{}': {}", pattern_str, e);
                    None
                }
            }
        } else {
            None
        };

        // Walk directory and collect files
        for entry in walkdir.into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();

            // Skip directories
            if path.is_dir() {
                continue;
            }

            // Apply pattern filter if one exists
            if let Some(ref regex) = pattern {
                if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                    if !regex.is_match(file_name) {
                        continue;
                    }
                }
            }

            debug!("Adding file to backup list: {}", path.display());
            files.push(path.to_path_buf());
        }

        Ok(files)
    }
}

impl Application for BackupClient {
    type Executor = iced::executor::Default;
    type Message = Message;
    type Theme = Theme;
    type Flags = ();

    fn new(_flags: Self::Flags) -> (Self, iced::Command<Message>) {
        let client = BackupClient::new(String::from("localhost"), 3000);

        // Load settings on startup
        (
            client,
            Command::perform(
                async {
                    let mut client = BackupClient::new(String::from("localhost"), 3000);
                    client.initialize().await.map(|_| client)
                },
                |result| match result {
                    Ok(client) => Message::SettingsLoaded(Ok(client.settings)),
                    Err(e) => Message::SettingsLoaded(Err(e.to_string())),
                },
            ),
        )
    }

    fn title(&self) -> String {
        String::from("Llamapak: Fast, light, no stragglers.")
    }

    fn update(&mut self, message: Message) -> iced::Command<Message> {
        match message {
            Message::SetBackupPath(path) => {
                self.backup_path = path.clone();
                // Update or add to backup_paths in settings
                if let Some(_) = self
                    .settings
                    .backup_paths
                    .iter_mut()
                    .find(|e| e.path == path)
                {
                    self.status = "Backup path already exists".to_string();
                } else {
                    self.settings.backup_paths.push(BackupPathEntry {
                        path,
                        is_directory: false,
                        include_subdirectories: true, // Default to including subdirectories
                        file_pattern: None,           // No file pattern by default
                        last_backup_time: None,
                    });
                    self.status = "Backup path added".to_string();
                }

                iced::Command::none()
            }
            Message::StartBackup => {
                if !self.is_running {
                    // Check if there are any active backup paths
                    if self.settings.backup_paths.is_empty() {
                        self.status = "Error: No backup paths specified".to_string();
                        return iced::Command::none();
                    }

                    self.is_running = true;
                    self.status = "Initializing backup...".to_string();

                    // Reset cancellation token before starting
                    self.cancel_token.store(false, Ordering::SeqCst);

                    // Clone data needed for the background task
                    let backup_paths = self.settings.backup_paths.clone();
                    let server_address = self.server_address.clone();
                    let server_port = self.server_port;
                    let settings = self.settings.clone();
                    let encryption_key = self.encryption_key;
                    let cancel_token = self.cancel_token.clone();

                    let mut backup_op_paths: Vec<PathBuf> = Vec::new();

                    for path_entry in backup_paths {
                        let path = PathBuf::from(path_entry.path);

                        if path.is_dir() && path_entry.is_directory {
                            let files_to_add = self
                                .collect_files_from_directory(
                                    &path,
                                    path_entry.include_subdirectories,
                                    path_entry.file_pattern.as_deref(),
                                )
                                .expect("Unable to extract a file list.");

                            backup_op_paths.extend(files_to_add)
                        } else {
                            backup_op_paths.extend(Vec::from([path]));
                        }
                    }

                    // Log this in settings
                    self.settings.add_log_entry(
                        "Backup".to_string(),
                        OperationStatus::InProgress,
                        format!(
                            "Starting backup with {} active paths",
                            self.settings.backup_paths.iter().count()
                        ),
                    );

                    return Command::perform(
                        async move {
                            // Here we create a method that checks cancellation during the process
                            let client_result = setup_backup_client(
                                server_address,
                                server_port,
                                settings.clone(),
                                encryption_key,
                                cancel_token.clone(),
                            )
                            .await;

                            match client_result {
                                Ok(client) => {
                                    // Now use the client to perform the backup
                                    if cancel_token.load(Ordering::SeqCst) {
                                        return Ok(false); // Cancelled before starting
                                    }

                                    match client.start_backup(backup_op_paths).await {
                                        Ok(true) => Ok(true),   // Successful completion
                                        Ok(false) => Ok(false), // Cancelled
                                        Err(e) => Err(e.to_string()),
                                    }
                                }
                                Err(e) => Err(e.to_string()), // Error setting up client
                            }
                        },
                        |result| match result {
                            Ok(true) => Message::BackupCompleted(Ok(true)),
                            Ok(false) => Message::BackupCompleted(Ok(false)), // Cancelled
                            Err(msg) => Message::BackupFailed(msg),
                        },
                    );
                }
                iced::Command::none()
            }
            Message::StopBackup => {
                if self.is_running {
                    // Set the cancellation flag
                    self.cancel_token.store(true, Ordering::SeqCst);
                    self.is_running = false;
                    self.status = "Backup cancelled".to_string();

                    info!("Backup operation cancellation requested");
                }

                // Log this in settings
                self.settings.add_log_entry(
                    "Backup".to_string(),
                    OperationStatus::Failure,
                    "Backup was manually stopped".to_string(),
                );

                // Create a copy of the necessary data
                let settings_copy = self.settings.clone();
                let encryption_key = self.encryption_key;

                Command::perform(
                    async move {
                        let settings_path = ClientSettings::default_local_path();
                        settings_copy.save(&settings_path, &encryption_key)
                    },
                    |result| match result {
                        Ok(()) => Message::SettingsSaved(Ok(())),
                        Err(e) => Message::SettingsSaved(Err(e.to_string())),
                    },
                )
            }
            Message::SaveSettings => {
                // Update settings with UI values
                self.settings.server_ip = self.new_server_ip.clone();
                if let Ok(port) = self.new_server_port.parse() {
                    self.settings.server_port = port;
                } else {
                    self.status = format!("Invalid port number: {}", self.new_server_port);
                    // Maybe return early or set a flag
                }

                // Save updated settings
                self.show_settings = false; // Close settings panel

                // Create a copy of the necessary data
                let settings_copy = self.settings.clone();
                let encryption_key = self.encryption_key;

                Command::perform(
                    async move {
                        let settings_path = ClientSettings::default_local_path();
                        settings_copy.save(&settings_path, &encryption_key)
                    },
                    |result| match result {
                        Ok(()) => Message::SettingsSaved(Ok(())),
                        Err(e) => Message::SettingsSaved(Err(e.to_string())),
                    },
                )
            }
            Message::BackupFailed(error) => {
                self.is_running = false;
                self.status = format!("Backup failed: {}", error);

                // Log this in settings
                self.settings.add_log_entry(
                    "Backup".to_string(),
                    OperationStatus::Failure,
                    format!("Backup failed: {}", error),
                );

                // Create a copy of the necessary data
                let settings_copy = self.settings.clone();
                let encryption_key = self.encryption_key;

                Command::perform(
                    async move {
                        let settings_path = ClientSettings::default_local_path();
                        settings_copy.save(&settings_path, &encryption_key)
                    },
                    |result| match result {
                        Ok(()) => Message::SettingsSaved(Ok(())),
                        Err(e) => Message::SettingsSaved(Err(e.to_string())),
                    },
                )
            }
            Message::BackupCompleted(result) => {
                self.is_running = false;

                match result {
                    Ok(true) => {
                        self.status = "Backup completed".to_string();

                        // Log successful backup in settings
                        self.settings.add_log_entry(
                            "Backup".to_string(),
                            OperationStatus::Success,
                            format!("Backup of {} completed successfully", self.backup_path),
                        );
                    }
                    Ok(false) => {
                        self.status = "Backup cancelled".to_string();

                        // Add cancelled operation to log
                        self.settings.add_log_entry(
                            "Backup".to_string(),
                            OperationStatus::Cancelled, // You may need to add this variant to your enum
                            "Backup operation was cancelled by user".to_string(),
                        );
                    }
                    Err(error) => {
                        self.is_running = false;
                        self.status = format!("Backup failed: {}", error);

                        // Log failed backup in settings
                        self.settings.add_log_entry(
                            "Backup".to_string(),
                            OperationStatus::Failure,
                            format!("Backup failed: {}", error),
                        );
                    }
                }

                // Create a copy of the necessary data
                let settings_copy = self.settings.clone();
                let encryption_key = self.encryption_key;

                Command::perform(
                    async move {
                        let settings_path = ClientSettings::default_local_path();
                        settings_copy.save(&settings_path, &encryption_key)
                    },
                    |result| match result {
                        Ok(()) => Message::SettingsSaved(Ok(())),
                        Err(e) => Message::SettingsSaved(Err(e.to_string())),
                    },
                )
            }
            Message::SyncSettings => {
                self.status = "Syncing settings with server...".to_string();

                // Create copies of the needed data
                let mut settings_copy = self.settings.clone();
                let encryption_key = self.encryption_key;
                let server_ip = self.settings.server_ip.clone();
                let server_port = self.settings.server_port;

                Command::perform(
                    async move {
                        // First sync the settings with server
                        settings_copy.sync_with_server(
                            &format!("{}:{}", server_ip, server_port),
                            &encryption_key,
                        )?;

                        // Then save the updated settings
                        let settings_path = ClientSettings::default_local_path();
                        settings_copy.save(&settings_path, &encryption_key)?;

                        Ok::<(), anyhow::Error>(())
                    },
                    |result| match result {
                        Ok(()) => Message::SettingsSaved(Ok(())),
                        Err(e) => Message::SettingsSaved(Err(e.to_string())),
                    },
                )
            }
            // Other message handlers remain unchanged...
            Message::OpenSettings => {
                self.show_settings = true;
                iced::Command::none()
            }
            Message::ToggleDarkMode => {
                self.settings.dark_mode = !self.settings.dark_mode;
                iced::Command::none()
            }
            Message::SetServerIP(ip) => {
                self.new_server_ip = ip;
                iced::Command::none()
            }
            Message::SetServerPort(port) => {
                self.new_server_port = port;
                iced::Command::none()
            }
            Message::SetLogLevel(level) => {
                self.settings.log_level = level;
                iced::Command::none()
            }
            Message::Quit => iced::Command::none(),
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

                        // Log this in settings
                        self.settings.add_log_entry(
                            "Backup".to_string(),
                            OperationStatus::Failure,
                            format!("Backup initiation failed: {}", error),
                        );
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
            Message::SettingsLoaded(result) => {
                match result {
                    Ok(settings) => {
                        self.settings = settings;
                        self.server_address = self.settings.server_ip.clone();
                        self.server_port = self.settings.server_port;
                        self.new_server_ip = self.settings.server_ip.clone();
                        self.new_server_port = self.settings.server_port.to_string();
                        self.status = "Settings loaded successfully".to_string();
                    }
                    Err(e) => {
                        self.status = format!("Failed to load settings: {}", e);
                    }
                }
                iced::Command::none()
            }
            Message::SettingsSaved(result) => {
                match result {
                    Ok(_) => {
                        self.status = "Synchronized with server".to_string();
                    }
                    Err(e) => {
                        self.status = format!("Failed to save settings: {}", e);
                    }
                }
                iced::Command::none()
            }
            Message::BrowseForBackupFile => {
                // TODO: This is a placeholder. In a real implementation, you would:
                // 1. Use a native file dialog library like rfd
                // 2. Get the selected file path
                // 3. Update self.settings.backup_file_path

                // For now, just set a test file path
                let test_path = String::from("./backups/");

                // Add to backup paths if not already present
                if !self
                    .settings
                    .backup_paths
                    .iter()
                    .any(|e| e.path == test_path)
                {
                    self.settings.backup_paths.push(BackupPathEntry {
                        path: test_path.clone(),
                        is_directory: true,
                        include_subdirectories: false, // For a file, this doesn't apply
                        file_pattern: None,
                        last_backup_time: None,
                    });
                }

                iced::Command::none()
            }
            // New message handlers for backup paths
            Message::SetNewBackupPath(path) => {
                self.new_backup_path = path;
                Command::none()
            }
            Message::SelectBackupPathType(is_directory) => {
                debug!(
                    "SelectBackupPathType: is_directory_backup={}",
                    self.is_directory_backup
                );
                self.is_directory_backup = is_directory;
                debug!(
                    "SelectBackupPathType: is_directory_backup={}",
                    self.is_directory_backup
                );
                Command::none()
            }
            Message::SetBackupPathIncludeSubdirs(include) => {
                self.include_subdirectories = include;
                Command::none()
            }
            Message::SetBackupPathPattern(pattern) => {
                self.file_pattern = pattern;
                Command::none()
            }
            Message::AddBackupPath => {
                // Validate path exists
                let path = Path::new(&self.new_backup_path);
                if !path.exists() {
                    self.status = format!("Path does not exist: {}", self.new_backup_path);
                    return Command::none();
                }

                // Add to settings
                self.settings.backup_paths.push(BackupPathEntry {
                    path: self.new_backup_path.clone(),
                    is_directory: self.is_directory_backup,
                    include_subdirectories: self.include_subdirectories,
                    file_pattern: if self.file_pattern.is_empty() {
                        None
                    } else {
                        Some(self.file_pattern.clone())
                    },
                    last_backup_time: None,
                });

                // Reset form
                self.new_backup_path = String::new();
                self.file_pattern = String::new();
                self.status = "Backup path added.".to_string();

                Command::none()
            }
            Message::RemoveBackupPath(index) => {
                if index < self.settings.backup_paths.len() {
                    let path = self.settings.backup_paths[index].path.clone();
                    self.settings.backup_paths.remove(index);
                    self.status = format!("Removed backup path: {}", path);
                }
                Command::none()
            }
        }
    }

    fn view(&self) -> Element<Message> {
        let header_background_color;
        let header_border_bar;
        let status_border_bar;
        let prog_bar_theme;

        if self.settings.dark_mode {
            // Dark mode
            header_background_color = iced::Color::from_rgb8(13, 22, 38);
            header_border_bar =
                container(text("").size(1))
                    .width(Length::Fill)
                    .style(container::Appearance {
                        text_color: None,
                        background: Some(iced::Background::Color(Color::from_rgb8(0, 119, 182))),
                        border: Default::default(),
                        shadow: Default::default(),
                    });
            status_border_bar =
                container(text("").size(1))
                    .width(Length::Fill)
                    .style(container::Appearance {
                        text_color: None,
                        background: Some(iced::Background::Color(Color::from_rgb8(0, 119, 182))),
                        border: Default::default(),
                        shadow: Default::default(),
                    });
            prog_bar_theme = progress_bar::Appearance {
                background: Background::Color([0.2, 0.2, 0.2].into()),
                bar: Background::Color(Color::from_rgb8(13, 22, 38)),
                border_radius: Default::default(),
            };
        } else {
            // Light mode
            header_background_color = iced::Color::from_rgb8(0, 119, 182);
            header_border_bar =
                container(text("").size(1))
                    .width(Length::Fill)
                    .style(container::Appearance {
                        text_color: None,
                        background: Some(iced::Background::Color(Color::from_rgb8(13, 22, 38))),
                        border: Default::default(),
                        shadow: Default::default(),
                    });
            status_border_bar =
                container(text("").size(1))
                    .width(Length::Fill)
                    .style(container::Appearance {
                        text_color: None,
                        background: Some(iced::Background::Color(Color::from_rgb8(13, 22, 38))),
                        border: Default::default(),
                        shadow: Default::default(),
                    });
            prog_bar_theme = progress_bar::Appearance {
                background: Background::Color([0.2, 0.2, 0.2].into()),
                bar: Background::Color(Color::from_rgb8(0, 119, 182)),
                border_radius: Default::default(),
            };
        }

        let mut operation_progress_bar = progress_bar::ProgressBar::new(0.0..=100.0, 0.0);
        if self.is_running {
            operation_progress_bar = progress_bar::ProgressBar::new(
                0.0..=100.0,
                self.get_percent_complete(),
            )
            .height(iced::Length::from(20))
                .style(move |theme: &Theme| {prog_bar_theme});
        }

        let header_height = Length::from(65);
        if self.show_settings {
            // Settings view
            let content_height = Length::FillPortion(9);

            let settings_header = column![
                container(
                    row![
                        // Left side with text
                        text("Llamapak Settings")
                            .size(26)
                            .width(Length::FillPortion(2)),
                        // Spacer that pushes the buttons to the right
                        horizontal_space().width(Length::Fill),
                        // Right side with theme toggle
                        row![
                            container(
                                iced::widget::toggler(
                                    "Dark Mode".to_string(),
                                    self.settings.dark_mode,
                                    |_| { Message::ToggleDarkMode }
                                )
                                .size(16)
                            )
                            .width(Length::from(140))
                            .padding(5),
                            button(
                                text("Sync with Server").horizontal_alignment(Horizontal::Center)
                            )
                            .on_press(Message::SyncSettings),
                            button(text("Save Settings").horizontal_alignment(Horizontal::Center))
                                .on_press(Message::SaveSettings),
                        ]
                        .spacing(10)
                        .align_items(Alignment::Center)
                    ]
                    .padding(10)
                    .width(Length::Fill)
                    .height(header_height)
                    .align_items(Alignment::Center),
                )
                .style(iced::widget::container::Appearance {
                    text_color: Some(iced::Color::WHITE),
                    background: Some(iced::Background::Color(header_background_color)),
                    border: Default::default(),
                    shadow: Default::default(),
                }),
                header_border_bar
            ];

            let settings_form = iced::widget::scrollable(
                column![
                    // Backup Paths section
                    self.view_backup_paths(),
                    // Add new backup path form
                    row![
                        // Left side with text
                        text("Add New Backup Path").size(16),
                        // Spacer that pushes the buttons to the right
                        container(row![]).width(Length::FillPortion(6)),
                        // Right side with theme toggle
                        button(text("Add Backup Path").horizontal_alignment(Horizontal::Center))
                            .on_press(Message::AddBackupPath)
                            .width(Length::FillPortion(2))
                    ],
                    row![
                        text_input("Enter file path...", &self.new_backup_path)
                            .on_input(Message::SetNewBackupPath)
                            .width(Length::FillPortion(7)),
                        button(text("Browse...").horizontal_alignment(Horizontal::Center))
                            .on_press(Message::BrowseForBackupFile)
                            .width(Length::FillPortion(1)),
                    ]
                    .spacing(10),
                    // Backup type controls

                    // Subdirectory controls (only visible for directory backups)
                    if self.is_directory_backup {
                        row![
                            iced::widget::toggler(
                                if self.is_directory_backup {
                                    String::from("Directory")
                                } else {
                                    String::from("File")
                                },
                                self.is_directory_backup,
                                |_| Message::SelectBackupPathType(!self.is_directory_backup)
                            )
                            .size(16)
                            .width(Length::FillPortion(2)),
                            column![
                                iced::widget::toggler(
                                    "Include Subdirectories".to_string(),
                                    self.include_subdirectories,
                                    |_| Message::SetBackupPathIncludeSubdirs(
                                        !self.include_subdirectories
                                    )
                                )
                                .size(16),
                                row![
                                    text("File Pattern:").size(16),
                                    text_input("e.g., *.txt,*.md", &self.file_pattern)
                                        .on_input(Message::SetBackupPathPattern)
                                        .width(Length::FillPortion(6)),
                                ]
                                .spacing(10)
                            ]
                            .spacing(10)
                            .width(Length::FillPortion(7))
                        ]
                        .spacing(10)
                    } else {
                        row![iced::widget::toggler(
                            if self.is_directory_backup {
                                String::from("Directory")
                            } else {
                                String::from("File")
                            },
                            self.is_directory_backup,
                            |_| Message::SelectBackupPathType(!self.is_directory_backup)
                        )
                        .size(16)]
                        .spacing(10)
                    },
                    // Server settings
                    horizontal_rule(1),
                    row![
                        text("Server:").size(16),
                        text_input("127.0.0.1", &self.new_server_ip)
                            .size(14)
                            .on_input(Message::SetServerIP)
                            .width(Length::from(300)),
                        text("Port:").size(16),
                        text_input("3000", &self.new_server_port)
                            .size(14)
                            .on_input(Message::SetServerPort)
                            .width(Length::from(100))
                    ]
                    .spacing(10),
                    // Save and cancel buttons
                    horizontal_rule(1),
                ]
                .spacing(20)
                .padding(20),
            )
            .height(content_height);

            let status_bar = column![
                status_border_bar,
                container(text(&self.status).size(16))
                    .padding(5)
                    .style(container::Appearance {
                        text_color: Some(iced::Color::WHITE),
                        background: Some(iced::Background::Color(header_background_color)),
                        border: Default::default(),
                        shadow: Default::default(),
                    })
                    .width(Length::Fill)
            ];

            container(column![settings_header, settings_form, status_bar])
                .width(Length::Fill)
                .height(Length::Fill)
                .center_x()
                .center_y()
                .into()
        } else {
            // Main application view
            let content_height = Length::FillPortion(9);

            // Top row (header)
            let header = column![
                container(
                    row![
                        // Left side with text
                        text("Llamapak").size(26),
                        // Spacer that pushes the buttons to the right
                        container(row![]).width(Length::Fill),
                        // Right side with buttons
                        row![
                            button(
                                text(if self.is_running { "Stop" } else { "Start" })
                                    .horizontal_alignment(Horizontal::Center)
                            )
                            .on_press(if self.is_running {
                                Message::StopBackup
                            } else {
                                Message::StartBackup
                            }),
                            button(text("Settings").horizontal_alignment(Horizontal::Center))
                                .on_press(Message::OpenSettings),
                        ]
                        .spacing(10)
                    ]
                    .padding(10)
                    .width(Length::Fill)
                    .height(header_height)
                    .align_items(Alignment::Center),
                )
                .style(container::Appearance {
                    text_color: Some(iced::Color::WHITE),
                    background: Some(iced::Background::Color(header_background_color)),
                    border: Default::default(),
                    shadow: Default::default(),
                }),
                header_border_bar
            ];

            // Recent operations from settings
            let operations_list = if !self.settings.recent_operations.is_empty() {
                column(
                    self.settings
                        .recent_operations
                        .iter()
                        .rev()
                        .take(100)
                        .map(|entry| {
                            let status_text = match entry.status {
                                OperationStatus::Success => "Success",
                                OperationStatus::Failure => "Failed",
                                OperationStatus::InProgress => "In Progress",
                                OperationStatus::Cancelled => "Canceled",
                            };

                            // Use unwrap_or_else for better error handling
                            let formatted_time =
                                chrono::DateTime::from_timestamp(entry.timestamp as i64, 0)
                                    .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
                                    .unwrap_or_else(|| "Unknown time".to_string());

                            text(format!(
                                "{}: {} - {} - {}",
                                formatted_time, entry.operation, status_text, entry.details
                            ))
                            .size(16)
                            .into()
                        })
                        .collect::<Vec<_>>(),
                )
                .spacing(5)
                .width(Length::Fill)
            } else {
                // Fall back to example operations if no real operations exist yet
                column(
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
                .width(Length::Fill)
            };

            // Main content
            let content = iced::widget::scrollable(container(
                column![
                    text(format!(
                        "Space used ({} %): {} / {}",
                        (self.space_used * 100 / self.space_available) as u16,
                        format_storage(self.space_used),
                        format_storage(self.space_available)
                    ))
                    .size(16),
                    text(format!("Schedule: {}", self.schedule)).size(16),
                    text("Last operations:").size(18),
                    operations_list
                ]
                .spacing(20)
                .padding(10)
                .width(Length::Fill),
            ))
            .height(Length::from(200))
            .height(content_height);

            let status_bar = column![
                status_border_bar,
                container(text(&self.status).size(16))
                    .padding(5)
                    .style(container::Appearance {
                        text_color: Some(iced::Color::WHITE),
                        background: Some(iced::Background::Color(header_background_color)),
                        border: Default::default(),
                        shadow: Default::default(),
                    })
                    .width(Length::Fill)
            ];

            // Combine all elements
            if self.is_running {
                // asdfasdfasdf
                container(column![header, content, operation_progress_bar, status_bar])
                    .height(Length::Fill)
                    .width(Length::Fill)
                    .into()
            } else {
                container(column![header, content, status_bar])
                    .height(Length::Fill)
                    .width(Length::Fill)
                    .into()
            }
        }
    }

    fn theme(&self) -> Theme {
        if self.settings.dark_mode {
            info!("Using Dark theme");
            Theme::Custom(
                Box::new(iced::theme::Custom::new(
                    String::from("Llamapak Dark"),
                    iced::theme::Palette {
                        background: Color::from_rgb8(19, 33, 68),
                        text: Color::from_rgb8(230, 230, 230),
                        primary: Color::from_rgb8(0, 119, 182),
                        success: Color::from_rgb8(18, 102, 79),
                        danger: Color::from_rgb8(174, 32, 18),
                    },
                ))
                .into(),
            )
            //iced::Theme::Dark
        } else {
            info!("Using Light theme");
            Theme::Custom(
                Box::new(iced::theme::Custom::new(
                    String::from("Llamapak Light"),
                    iced::theme::Palette {
                        background: Color::from_rgb8(237, 246, 249),
                        text: Color::from_rgb8(0, 0, 0),
                        primary: Color::from_rgb8(19, 33, 68),
                        success: Color::from_rgb8(106, 153, 78),
                        danger: Color::from_rgb8(195, 66, 63),
                    },
                ))
                .into(),
            )
            // iced::Theme::Light
        }
    }
}

#[derive(Debug, Default, Clone)]
struct OperationLog {
    timestamp: String,
    cpu_usage: f32,
    size_transferred: u64,
}

// Helper function to set up a backup client with cancellation support
async fn setup_backup_client(
    server_address: String,
    server_port: u16,
    settings: ClientSettings,
    encryption_key: [u8; 32],
    cancel_token: Arc<AtomicBool>,
) -> Result<BackupClient> {
    // Check cancellation
    if cancel_token.load(Ordering::SeqCst) {
        return Err(anyhow::anyhow!("Setup cancelled"));
    }

    // Create a new client
    let mut client = BackupClient::new(server_address, server_port);
    client.settings = settings;
    client.encryption_key = encryption_key;
    client.cancel_token = cancel_token;

    // Initialize client
    client.initialize().await?;

    Ok(client)
}
async fn start_backup_async(
    file_paths: Vec<PathBuf>,
    server_addr: String,
    settings: ClientSettings,
    encryption_key: [u8; 32],
) -> Result<(), anyhow::Error> {
    // Create a new client instance
    let mut client = BackupClient::new(server_addr, settings.server_port);
    client.settings = settings;
    client.encryption_key = encryption_key;

    // Initialize TLS components
    client
        .initialize()
        .await
        .context("Failed to initialize TLS client")?;

    // Start the actual backup process
    client
        .start_backup(file_paths.clone())
        .await
        .context("Backup operation failed")?;

    // Add the successful operation to settings
    client.settings.add_log_entry(
        "Backup".to_string(),
        OperationStatus::Success,
        format!("Completed backup of {:?} paths.", file_paths.len()),
    );

    // Save updated settings
    client.save_settings().await?;

    info!("Backup completed successfully.");
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
        log_level: tracing::Level::DEBUG,
        json_format: false,
    };

    initialize_logging(log_config).context("Failed to initialize logging")?;
    info!("Client application starting");

    // Ensure settings directory exists
    if let Some(parent) = ClientSettings::default_local_path().parent() {
        std::fs::create_dir_all(parent).context("Failed to create settings directory")?;
    }

    let mut settings = Settings::default();
    settings.window.min_size = Some(Size::new(900.0, 560.0));
    settings.window.size = Size::new(900.0, 560.0);
    settings.window.position = Position::Centered;

    BackupClient::run(settings).map_err(|e| anyhow::anyhow!("GUI error: {}", e))?;

    info!("Client application completed successfully");
    Ok(())
}
