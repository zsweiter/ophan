use tokio::net::TcpStream;

use crate::tls::TlsStream;
use crate::tls::error::{Error, ErrorKind, Result};

/// A TLS acceptor for terminating inbound TLS connections.
///
/// Wraps `s2n_tls_tokio::TlsAcceptor`.  For server-side use in
/// the ingress / proxy pipeline.
pub struct TlsAcceptor {
    inner: s2n_tls_tokio::TlsAcceptor,
}

impl TlsAcceptor {
    pub fn new() -> Result<Self> {
        let config = s2n_tls::config::Config::builder();
        let config = config.build().map_err(|e| Error::new(ErrorKind::HandshakeFailed(e.to_string())))?;
        let inner = s2n_tls_tokio::TlsAcceptor::new(config);

        Ok(Self { inner })
    }

    pub async fn accept(&self, stream: TcpStream) -> Result<TlsStream<TcpStream>> {
        self.inner.accept(stream).await.map_err(|e| Error::new(ErrorKind::HandshakeFailed(e.to_string())))
    }
}
