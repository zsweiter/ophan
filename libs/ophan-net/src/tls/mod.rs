#![allow(dead_code)]

pub use s2n_tls_tokio::TlsStream;

pub mod acceptor;
mod alpn;
pub mod connector;
pub mod error;
mod version;

pub use alpn::ALPN;
pub use version::{TlsParseError, TlsVersion};
