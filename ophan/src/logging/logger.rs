use std::fs::OpenOptions;
use std::path::Path;

use tracing_appender::non_blocking::{NonBlocking, NonBlockingBuilder, WorkerGuard};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use crate::sys::error::ExitCode;

/// Process-wide logging to stderr and the error log file.
///
/// Both sinks are written by background threads; keep the value alive until shutdown so
/// buffered lines are flushed.
pub struct Logger {
    _stderr: WorkerGuard,
    _file: WorkerGuard,
}

impl Logger {
    /// Log lines buffered per sink before new lines are dropped.
    const BUFFERED_LINES: usize = 16 * 1024;

    pub fn init(error_log: &str) -> Result<Self, ExitCode> {
        if let Some(parent) = Path::new(error_log).parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|e| {
                eprintln!("failed to create error log directory '{}': {e}", parent.display());
                ExitCode::Config
            })?;
        }

        let file = OpenOptions::new().create(true).append(true).open(error_log).map_err(|e| {
            eprintln!("failed to create error log file: {e}");
            ExitCode::Config
        })?;

        let (stderr_writer, stderr_guard) = Self::non_blocking(std::io::stderr());
        let (file_writer, file_guard) = Self::non_blocking(file);

        let stderr_layer = fmt::layer()
            .with_writer(stderr_writer)
            .with_thread_ids(true)
            .with_thread_names(true)
            .with_target(false);

        let file_layer = fmt::layer()
            .with_writer(file_writer)
            .with_ansi(false)
            .with_thread_ids(true)
            .with_thread_names(true)
            .with_target(false);

        // `RUST_LOG` overrides the default level.
        let filter = EnvFilter::builder().with_default_directive(LevelFilter::WARN.into()).from_env_lossy();

        let subscriber = tracing_subscriber::registry().with(filter).with(stderr_layer).with(file_layer);

        tracing::subscriber::set_global_default(subscriber).map_err(|e| {
            eprintln!("failed to initialize tracing subscriber: {e}");
            ExitCode::Software
        })?;

        Ok(Self { _stderr: stderr_guard, _file: file_guard })
    }

    fn non_blocking<W>(writer: W) -> (NonBlocking, WorkerGuard)
    where
        W: std::io::Write + Send + 'static,
    {
        NonBlockingBuilder::default().buffered_lines_limit(Self::BUFFERED_LINES).finish(writer)
    }
}
