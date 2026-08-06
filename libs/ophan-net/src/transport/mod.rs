mod error;
mod tcp;

#[cfg(unix)]
mod unix;

use std::pin::Pin;
use std::task::{Context, Poll};

use s2n_tls_tokio::TlsStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

pub use error::{Error, Result};

pub use tcp::connect_tcp;

#[cfg(unix)]
pub use unix::connect_unix;

/// A raw transport connection: TCP, Unix socket, or TLS over TCP.
///
/// Implements `AsyncRead` + `AsyncWrite` by delegating to the
/// underlying stream.
pub enum RawStream {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
    Tls(TlsStream<TcpStream>),
}

impl RawStream {
    pub fn set_nodelay(&self) -> Result<()> {
        match self {
            RawStream::Tcp(s) => Ok(s.set_nodelay(true)?),
            #[cfg(unix)]
            RawStream::Unix(_) => Ok(()),
            RawStream::Tls(s) => Ok(s.get_ref().set_nodelay(true)?),
        }
    }
}

impl AsyncRead for RawStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            RawStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(unix)]
            RawStream::Unix(s) => Pin::new(s).poll_read(cx, buf),
            RawStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for RawStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            RawStream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(unix)]
            RawStream::Unix(s) => Pin::new(s).poll_write(cx, buf),
            RawStream::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            RawStream::Tcp(s) => Pin::new(s).poll_flush(cx),
            #[cfg(unix)]
            RawStream::Unix(s) => Pin::new(s).poll_flush(cx),
            RawStream::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            RawStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(unix)]
            RawStream::Unix(s) => Pin::new(s).poll_shutdown(cx),
            RawStream::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}
