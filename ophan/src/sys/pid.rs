use std::path::PathBuf;

use crate::{
    config::{compile::get_config_pid, get_config_path},
    sys::error::ExitCode,
};

pub struct PidGuard {
    path: std::path::PathBuf,
}

impl PidGuard {
    pub fn create(path: std::path::PathBuf) -> Result<Self, String> {
        let current_pid = std::process::id();
        std::fs::write(&path, current_pid.to_string())
            .map_err(|e| format!("Failed to write PID file '{}': {}", path.display(), e))?;

        Ok(Self { path })
    }
}

impl Drop for PidGuard {
    fn drop(&mut self) {
        println!("pid deleted");
        let _ = std::fs::remove_file(&self.path);
    }
}

fn resolve_pid_path(config_path: Option<&PathBuf>) -> PathBuf {
    if let Some(path) = get_config_pid(config_path.unwrap_or(get_config_path()))
        && path.exists()
    {
        return path;
    }

    PathBuf::from("/run/ophan.pid")
}

pub fn read_pid(config_path: Option<&PathBuf>) -> Result<(i32, PathBuf), ExitCode> {
    let pid_path = resolve_pid_path(config_path);
    let pid_str = std::fs::read_to_string(&pid_path).map_err(|e| {
        eprintln!("Error: cannot read PID file '{}': {}", pid_path.display(), e);
        ExitCode::NoInput
    })?;

    let trimmed = pid_str.trim();
    let pid = trimmed.parse::<i32>().map_err(|e| {
        eprintln!("Error: invalid PID '{}' in '{}': {}", trimmed, pid_path.display(), e);
        ExitCode::DataErr
    })?;

    Ok((pid, pid_path))
}
