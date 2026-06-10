mod error;
mod tcp;

#[cfg(unix)]
mod unix;

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub use error::{Error, Result};

pub use tcp::connect_tcp;

#[cfg(unix)]
pub use unix::connect_unix;

/// A raw transport connection: TCP or Unix socket.
///
/// Implements `AsyncRead` + `AsyncWrite` by delegating to the
/// underlying stream.  TLS wrapping is handled by `tls::TlsStream`.
pub enum Transport {
    Tcp(tokio::net::TcpStream),
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
}

impl Transport {
    pub fn set_nodelay(&self) -> Result<()> {
        match self {
            Transport::Tcp(s) => Ok(s.set_nodelay(true)?),
            #[cfg(unix)]
            Transport::Unix(_) => Ok(()),
        }
    }
}

impl AsyncRead for Transport {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Transport::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(unix)]
            Transport::Unix(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Transport {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Transport::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(unix)]
            Transport::Unix(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Transport::Tcp(s) => Pin::new(s).poll_flush(cx),
            #[cfg(unix)]
            Transport::Unix(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Transport::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(unix)]
            Transport::Unix(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}
