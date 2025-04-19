use iced::theme::Container;
use iced::font::Style;
use std::io::IntoInnerError;
use anyhow::{Context, Result};
use iced::widget::{button, column, container, row, text};
use iced::{Application, Border, Element, Length, Sandbox, Settings, Shadow, Theme, Vector};
use std::path::Path;
use iced::theme::Theme::{SolarizedLight, SolarizedDark};
use tracing::{info, debug, error, warn};
use crate::logger::{LoggerConfig, initialize_logging};
use std::path::PathBuf;
use iced::window::Position;

mod backup_server;
mod logger;
mod tests;
mod file_manager;
mod backup_client;
mod tls_client;

// First, implement the required traits for AppError
// Ensure AppError can be converted to anyhow::Error
#[derive(Debug)]
enum AppError {
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


// Keep your existing run_server function
async fn run_server() -> Result<()> {
    let server = backup_server::BackupServer::new(
        "backup_storage",
        Path::new("cert.pem"),
        Path::new("key.pem")
    ).await?;
    
    server.run("0.0.0.0:3000").await
}

// Modify run_server_mode to not create a new runtime
async fn run_server_mode() -> Result<(), AppError> {
    run_server().await.map_err(|e| AppError::Server(e))
}

#[derive(Debug, Clone)]
enum Message {
    SetBackupPath(String),
    StartBackup,
    StopBackup,
    OpenSettings,
    Quit,  // Add this variant
}

#[derive(Debug, Default)]
struct BackupApp {
    backup_path: String,
    status: String,
    is_running: bool,
    operations: Vec<OperationLog>,
    space_used: u64,
    space_available: u64,
    schedule: String,
    should_exit: bool,  // Add this field
}

#[derive(Debug, Default)]
struct OperationLog {
    timestamp: String,
    cpu_usage: f32,
    size_transferred: u64,
}

impl BackupApp {
    fn new() -> Self {
        // Example data - replace with real data in your implementation
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
            },OperationLog {
                timestamp: "2024-03-17 13:00".to_string(),
                cpu_usage: 14.7,
                size_transferred: 247138,
            },OperationLog {
                timestamp: "2024-03-16 07:00".to_string(),
                cpu_usage: 47.1,
                size_transferred: 1316090,
            },
        ];

        BackupApp {
            backup_path: String::new(),
            status: String::new(),
            is_running: false,
            operations: example_operations,
            space_used: 1024 * 1024 * 100,
            space_available: 1024 * 1024 * 1000,
            schedule: "Daily at 11:30".to_string(),
            should_exit: false,  // Initialize the new field
        }
    }

    pub fn should_exit(&self) -> bool {
        self.should_exit
    }

}

impl Application for BackupApp {
    type Executor = iced::executor::Default;
    type Message = Message;
    type Theme = Theme;
    type Flags = ();

    fn new(_flags: Self::Flags) -> (Self, iced::Command<Message>) {
        (BackupApp::new(), iced::Command::none())
    }

    fn title(&self) -> String {
        String::from("Llamapak: Fast, light, no stragglers.")
    }

    fn update(&mut self, message: Message) -> iced::Command<Message> {
        match message {
            // Your existing message handling
            Message::SetBackupPath(path) => self.backup_path = path,
            Message::StartBackup => {
                self.is_running = true;
                self.status = "Backup is running...".to_string();
            },
            Message::StopBackup => {
                self.is_running = false;
                self.status = "Backup was stopped".to_string();
            },
            Message::OpenSettings => {
                self.should_exit = true;
            },
            Message::Quit => {
                self.should_exit = true;
            }
        }
        iced::Command::none()
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
                button(
                    text(if self.is_running { "Stop" } else { "Start" })
                ).on_press(
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
                .collect::<Vec<_>>()
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
            container(
            column![
                header,
                content,
            ]
        )
        .height(Length::Fill)
        .width(Length::Fill)
        .into()
    }

    fn theme(&self) -> Theme {
        SolarizedDark
    }
}
const SERVER_MODE_FLAG: &str = "--server";

// Then modify the main function to handle errors consistently
#[tokio::main]
async fn main() -> Result<()> {
    // Ensure the logs directory exists
    let log_dir = PathBuf::from("logs");
    std::fs::create_dir_all(&log_dir).context("Failed to create log directory")?;
    
    // Initialize logging with both file and console output
    let log_config = LoggerConfig {
        log_dir,
        log_file: String::from("llamapak.log"),
        max_files: 7,
        log_level: tracing::Level::INFO,
        json_format: false,
    };
    
    initialize_logging(log_config).context("Failed to initialize logging")?;
    info!("Application starting");
    
    // Setup signal handling for graceful shutdown
    // Instead of cloning
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

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

    #[cfg(windows)]
    {
        let shutdown_tx = shutdown_tx;
        tokio::spawn(async move {
            if let Ok(()) = tokio::signal::ctrl_c().await {
                info!("Received Ctrl+C");
                let _ = shutdown_tx.send(());
            }
        });
    }
    
    match parse_command_line_args() {
        AppMode::Server => {
            info!("Starting in server mode");
            tokio::select! {
                result = run_server_mode() => {
                    match result {
                        Ok(_) => {
                            info!("Server terminated gracefully");
                            Ok(())
                        },
                        Err(e) => {
                            error!("Server error: {:#}", e);
                            Err(e.into())
                        }
                    }
                }
                _ = shutdown_rx => {
                    info!("Shutting down server gracefully");
                    Ok(())
                }
            }
        }
        AppMode::Client => {
            info!("Starting in client mode");
            let settings = Settings {
                window: iced::window::Settings {
                    min_size: Some(iced::Size::new(640.0, 480.0)), // Less restrictive
                    max_size: None, // Allow maximizing
                    resizable: true,
                    decorations: true,
                    position: Position::Centered,
                    ..Default::default()
                },
                ..Default::default()
            };
            
            debug!("Initializing UI with settings: {:?}", settings);
            match BackupApp::run(settings) {
                Ok(_) => {
                    info!("UI application terminated gracefully");
                    Ok(())
                },
                Err(e) => {
                    error!("UI application error: {:#}", e);
                    Err(anyhow::anyhow!("UI application error: {}", e))
                }
            }
        }
    }
}

enum AppMode {
    Server,
    Client,
}

fn parse_command_line_args() -> AppMode {
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 && args[1] == SERVER_MODE_FLAG {
        AppMode::Server
    } else {
        AppMode::Client
    }
}