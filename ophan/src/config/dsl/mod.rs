mod blocks;
pub mod compile;
pub mod errors;
pub mod loader;
pub mod parser;

// pub use crate::config::domain::*;
pub use loader::*;

use std::{fs, io, path::PathBuf, sync::OnceLock, time::SystemTime};

use crate::config::dsl::errors::ConfigError;

pub const MAX_CONFIG_FILE_SIZE: u64 = 2 * 1024 * 1024; // 2MB
pub const MAX_ROUTES: usize = 5000;
pub const MAX_LISTENERS: usize = 100;
pub const MAX_UPSTREAMS: usize = 500;
pub const MAX_POLICIES: usize = 500;

static CONFIG_PATH_CELL: OnceLock<PathBuf> = OnceLock::new();

pub fn set_config_path(path: &str) -> Result<(), PathBuf> {
    CONFIG_PATH_CELL.set(PathBuf::from(path))
}

pub fn get_config_path() -> &'static PathBuf {
    CONFIG_PATH_CELL.get_or_init(|| {
        if let Ok(cfg) = std::env::var("CONFIG_PATH") {
            return PathBuf::from(cfg);
        }

        if cfg!(debug_assertions) {
            PathBuf::from(".config/master.conf")
        } else if cfg!(target_os = "windows") {
            PathBuf::from("C:\\ophan-gateway\\conf\\master.conf")
        } else if cfg!(target_os = "macos") {
            let homebrew = PathBuf::from("/opt/homebrew/etc/ophan/master.conf");
            if homebrew.exists() {
                homebrew
            } else {
                PathBuf::from("/usr/local/etc/ophan/master.conf")
            }
        } else {
            PathBuf::from("/etc/ophan/master.conf")
        }
    })
}

pub fn get_max_thread_size() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

fn read_config_file(path: &PathBuf) -> Result<String, ConfigError> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_CONFIG_FILE_SIZE {
        let message = format!(
            "Config file too large: {} ({} bytes, max: {} bytes)",
            path.display(),
            metadata.len(),
            MAX_CONFIG_FILE_SIZE
        );

        return Err(ConfigError::Io {
            source: io::Error::from(io::ErrorKind::FileTooLarge),
            path: Some(path.into()),
            message: Some(message),
        });
    }

    fs::read_to_string(path).map_err(|e| ConfigError::from(e).with_file(path))
}

#[derive(Debug, Clone)]
pub struct ConfigFileTracker {
    pub path: PathBuf,
    pub last_mtime: SystemTime,
}

impl ConfigFileTracker {
    pub fn new(path: PathBuf) -> Result<Self, ConfigError> {
        let mtime = fs::metadata(&path)?.modified()?;
        Ok(Self { path, last_mtime: mtime })
    }

    pub fn has_changed(&self) -> Result<bool, ConfigError> {
        let current = fs::metadata(&self.path)?.modified()?;
        Ok(current > self.last_mtime)
    }

    pub fn refresh_mtime(&mut self) -> Result<(), ConfigError> {
        self.last_mtime = fs::metadata(&self.path)?.modified()?;
        Ok(())
    }
}
