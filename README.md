[package]
name = "file-backup"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio = { version = "1.32", features = ["full"] }
sha2 = "0.10.8"
walkdir = "2.3"
rustls = "0.23.26"
tokio-rustls = "0.26.2"
webpki-roots = "0.26.8"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0.140"
anyhow = "1.0.98"