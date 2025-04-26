use lazy_static::lazy_static;
use std::path::PathBuf;
use std::sync::Mutex;
use tracing_appender::non_blocking::WorkerGuard;

// Properly define the global guard to store the worker guard
lazy_static! {
    static ref GLOBAL_GUARD: Mutex<Option<WorkerGuard>> = Mutex::new(None);
}

pub struct LoggerConfig {
    pub log_level: tracing::Level,
    pub log_dir: PathBuf,
    pub log_file: String,
    pub max_files: i8,
    pub json_format: bool,
}

fn validate_config(config: &LoggerConfig) -> anyhow::Result<()> {
    if config.max_files <= 0 {
        return Err(anyhow::anyhow!("max_files must be positive"));
    }

    Ok(())
}

pub fn initialize_logging(config: LoggerConfig) -> anyhow::Result<()> {
    validate_config(&config)?;

    use tracing_appender::{
        non_blocking,
        rolling::{RollingFileAppender, Rotation},
    };
    use tracing_subscriber::filter::LevelFilter;
    use tracing_subscriber::{fmt, prelude::*, Registry};

    // Ensure log directory exists
    std::fs::create_dir_all(&config.log_dir)?;

    // Use the log_file directly as it's already a String
    let filename = config.log_file;

    let file_appender = RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix(filename)
        .max_log_files(config.max_files as usize)
        .build(config.log_dir)?;

    // Use a non-blocking writer for file output
    let (non_blocking, guard) = non_blocking(file_appender);

    // Store the guard globally
    *GLOBAL_GUARD
        .lock()
        .map_err(|e| anyhow::anyhow!("Failed to lock global guard: {}", e))? = Some(guard);

    // Create a filter that excludes noisy modules
    let target_filter = tracing_subscriber::filter::Targets::new()
        // Set default level to debug or your desired level
        .with_default(config.log_level)
        // Filter out noisy crates
        .with_target("cosmic_text", LevelFilter::WARN)
        .with_target("wgpu", LevelFilter::WARN)
        .with_target("winit", LevelFilter::WARN)
        .with_target("naga", LevelFilter::WARN)
        .with_target("iced", LevelFilter::WARN);

    // Create the file logging layer
    let file_layer = if config.json_format {
        fmt::layer()
            .json()
            .with_current_span(true)
            // Other formatting options
            .with_writer(non_blocking)
            .with_ansi(false)
            .boxed()
    } else {
        fmt::layer()
            .with_timer(fmt::time::LocalTime::rfc_3339())
            // Other formatting options
            .with_writer(non_blocking)
            .with_ansi(false)
            .boxed()
    };

    // Create a separate console layer
    let stdout_layer = fmt::layer()
        .compact()
        .with_ansi(true)
        .with_writer(std::io::stdout);

    // Combine layers with a Registry subscriber
    Registry::default()
        .with(file_layer.with_filter(target_filter.clone()))
        .with(stdout_layer.with_filter(target_filter))
        .try_init()
        .map_err(|e| anyhow::anyhow!("Failed to initialize logger: {}", e))?;

    Ok(())
}

pub fn shutdown_logging() -> anyhow::Result<()> {
    // Take ownership of the guard to drop it
    let _guard = GLOBAL_GUARD
        .lock()
        .map_err(|e| anyhow::anyhow!("Failed to lock global guard: {}", e))?
        .take();

    Ok(())
}
