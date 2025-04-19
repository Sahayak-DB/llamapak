use anyhow::Result;
use std::sync::Arc;
use rustls::RootCertStore;
use tokio_rustls::{TlsConnector, rustls};
use tokio::net::TcpStream;

pub struct TlsClient {
    connector: TlsConnector,
}

impl TlsClient {
    pub fn new() -> Result<Self> {
        let mut root_store = RootCertStore::empty();
        root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));

        let config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        // Note: TLS 1.3 is enabled by default with safe_defaults()
        let connector = TlsConnector::from(Arc::new(config));

        Ok(TlsClient { connector })
    }


    pub async fn connect(&self, server_name: &str, addr: &str) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let stream = TcpStream::connect(addr).await?;
        let domain = rustls::ServerName::try_from(server_name)?;
        
        let stream = self.connector.connect(domain, stream).await?;
        Ok(stream)
    }
}