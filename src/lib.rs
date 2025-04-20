pub mod file_manager;
pub mod logger;
pub mod tls_client;

use iced::Application;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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
    Ready,
    ChunkReceived { offset: u64, verified: bool },
    BackupComplete { verified: bool },
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

#[derive(Debug, Clone)]
enum Message {
    SetBackupPath(String),
    StartBackup,
    StopBackup,
    OpenSettings,
    Quit, // Add this variant
}

#[derive(Debug, Default)]
struct OperationLog {
    timestamp: String,
    cpu_usage: f32,
    size_transferred: u64,
}
