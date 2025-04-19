use tracing::{debug, error};
use anyhow::{Result, Context};
use sha2::{Sha256, Digest};
use std::path::Path;
use std::fs::File;
use std::io::{Read, Seek};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct FileInfo {
    pub path: String,
    pub hash: String,
    pub size: u64,
}

impl FileInfo {
    pub fn from_path(path: &Path) -> Result<Self> {
        let mut file = File::open(path)?;
        let metadata = file.metadata()?;
        let size = metadata.len();
        
        // Calculate SHA-256 hash
        let mut hasher = Sha256::new();
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        hasher.update(&buffer);
        let hash = format!("{:x}", hasher.finalize());
        
        Ok(FileInfo {
            path: path.to_string_lossy().into_owned(),
            hash,
            size,
        })
    }
}

pub fn read_file_chunk(path: &Path, start: u64, size: usize) -> Result<Vec<u8>> {
    const MAX_CHUNK_SIZE: usize = 10 * 1024 * 1024; // 10MB limit

    if size > MAX_CHUNK_SIZE {
        return Err(anyhow::anyhow!("Requested chunk size too large"));
    }

    let mut file = File::open(path).context("Failed to open file")?;
    let file_size = file.metadata()?.len();

    if start >= file_size {
        return Err(anyhow::anyhow!("Start position beyond end of file"));
    }

    let size = size.min((file_size - start) as usize);
    file.seek(std::io::SeekFrom::Start(start))?;

    let mut buffer = vec![0u8; size];
    file.read_exact(&mut buffer).context("Failed to read file chunk")?;

    Ok(buffer)
}