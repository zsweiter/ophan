use std::path::PathBuf;

use crate::{config::compile::get_config_pid, sys::error::ExitCode};

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

/// Resolve the effective PID file path.
///
/// Precedence (highest first):
/// 1. Explicit `--pid-file` CLI argument.
/// 2. `OPHAN_PID_FILE` environment variable (only honored in static/musl builds).
/// 3. `pid` directive from the master configuration file.
/// 4. Fallback `/run/ophan.pid`.
pub fn effective_pid_path(cli_pid: Option<&str>, config_path: Option<&PathBuf>) -> PathBuf {
    if let Some(pid) = cli_pid {
        let pid = pid.trim();
        if !pid.is_empty() {
            return PathBuf::from(pid);
        }
    }

    #[cfg(target_env = "musl")]
    {
        if let Ok(pid) = std::env::var("OPHAN_PID_FILE") {
            let pid = pid.trim();
            if !pid.is_empty() {
                return PathBuf::from(pid);
            }
        }
    }

    if let Some(path) = config_path
        && let Some(pid) = get_config_pid(path)
    {
        return pid;
    }

    if cfg!(unix) {
        PathBuf::from("/run/ophan.pid")
    } else {
        PathBuf::from(r"C:\ophan-gateway\ophan.pid")
    }
}

pub fn read_pid(cli_pid: Option<&str>, config_path: Option<&PathBuf>) -> Result<(i32, PathBuf), ExitCode> {
    let pid_path = effective_pid_path(cli_pid, config_path);
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write;

    fn write_temp_master(content: &str) -> (tempfile::NamedTempFile, PathBuf) {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        let path = file.path().to_path_buf();
        (file, path)
    }

    #[test]
    fn cli_pid_overrides_config() {
        let (_file, path) = write_temp_master(
            r#"master "ophan-01" {
    user = "www-data"
    workers = "auto"
    pid = "/run/ophan.pid"
    error_log = "/var/log/ophan/error.log"
    includes = "/etc/ophan/gateways/*.conf"
}
"#,
        );
        let result = effective_pid_path(Some("/tmp/cli.pid"), Some(&path));
        assert_eq!(result, PathBuf::from("/tmp/cli.pid"));
    }

    #[test]
    fn config_pid_used_when_no_cli() {
        let (_file, path) = write_temp_master(
            r#"master "ophan-01" {
    user = "www-data"
    workers = "auto"
    pid = "/var/run/ophan/ophan.pid"
    error_log = "/var/log/ophan/error.log"
    includes = "/etc/ophan/gateways/*.conf"
}
"#,
        );
        let result = effective_pid_path(None, Some(&path));
        assert_eq!(result, PathBuf::from("/var/run/ophan/ophan.pid"));
    }

    #[test]
    fn fallback_when_no_config() {
        let result = effective_pid_path(None, None);
        assert_eq!(result, PathBuf::from("/run/ophan.pid"));
    }
}
