use crate::logger::LoggerConfig;
use tempfile;
#[cfg(test)]
mod tests {
    use crate::logger::initialize_logging;
    use tempfile::TempDir;

    #[test]
    fn test_logger_initialization() {
        let temp_dir = TempDir::new().unwrap();
        let config = LoggerConfig {
            log_level: tracing::Level::DEBUG,
            log_dir: temp_dir.path().to_path_buf(),
            log_file: "test.log".to_string(),
            max_files: 5,
            json_format: false,
        };

        let result = initialize_logging(config);
        assert!(result.is_ok());

        // Add assertions to verify log files are created
    }

    #[test]
    fn test_logger_initialization_empty_max_files() {
        let temp_dir = TempDir::new().unwrap();
        let config = LoggerConfig {
            log_level: tracing::Level::DEBUG,
            log_dir: temp_dir.path().to_path_buf(),
            log_file: "test_empty_max_files.log".to_string(),
            max_files: 0,
            json_format: false,
        };

        let result = initialize_logging(config);
        assert!(result.is_err());

        // Add assertions to verify log files are created
    }
}
