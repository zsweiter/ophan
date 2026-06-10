use tokio::net::TcpStream;

use crate::tls::TlsStream;
use crate::tls::error::{Error, ErrorKind, Result};

/// A TLS connector for outbound connections to upstream servers.
///
/// Wraps `s2n_tls_tokio::TlsConnector` with a default config.
/// Used by `Client` when the URL scheme is `https://`.
pub struct TlsConnector {
    inner: s2n_tls_tokio::TlsConnector,
}

impl TlsConnector {
    pub fn new() -> Result<Self> {
        let config = s2n_tls::config::Config::builder();
        let config = config.build().map_err(|e| Error::new(ErrorKind::HandshakeFailed(e.to_string())))?;
        let inner = s2n_tls_tokio::TlsConnector::new(config);
        Ok(Self { inner })
    }

    pub async fn connect(self, host: &str, stream: TcpStream) -> Result<TlsStream<TcpStream>> {
        self.inner
            .connect(host, stream)
            .await
            .map_err(|e| Error::new(ErrorKind::HandshakeFailed(e.to_string())).with_peer(host))
    }
}
