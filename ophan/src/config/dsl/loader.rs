use std::path::{Path, PathBuf};
use std::{fs, io};

use ahash::AHashMap;
use flatkit::str::ImmerStr;

use crate::config::domain::OphanConfig;
use crate::config::dsl::compile::compile;

use super::blocks::RawConfig;
use super::errors::ConfigError;
use super::parser::{parse_raw_gateway, parse_raw_master};
use super::{ConfigFileTracker, get_config_path, read_config_file};

pub fn load_config() -> Result<OphanConfig, ConfigError> {
    let config_root = get_config_path(); // This is master config end in *.conf
    if !config_root.exists() {
        return Err(ConfigError::from(io::Error::from(io::ErrorKind::NotFound)).with_file(config_root));
    }

    let master_str = read_config_file(config_root)?;
    let master = parse_raw_master(&master_str).map_err(|e| e.with_file(config_root.display().to_string()))?;

    // Track master config file mtime
    let master_tracker = ConfigFileTracker::new(config_root.clone())?;

    let includes = master.includes.clone();

    // For now only support one gateway
    let config_dir = config_root.parent().unwrap_or(Path::new("."));
    let mut paths = Vec::with_capacity(master.includes.len());

    for include in &master.includes {
        paths.extend(resolve_include(config_dir, include)?);
    }

    paths.sort();
    paths.dedup();

    drop(includes);

    let mut gw_strs: Vec<(PathBuf, String)> = Vec::with_capacity(paths.len());
    for path in &paths {
        gw_strs.push((path.clone(), read_config_file(path)?));
    }

    drop(paths);

    let mut gateways = Vec::with_capacity(gw_strs.len());
    let mut gateway_paths: AHashMap<ImmerStr, PathBuf> = AHashMap::with_capacity(gw_strs.len());
    for (path, gw_str) in &gw_strs {
        let gateway = parse_raw_gateway(gw_str).map_err(|e| e.with_file(path.display().to_string()))?;

        gateway_paths.insert(gateway.name.into(), path.clone());
        gateways.push((gateway.name, gateway));
    }

    let raw = RawConfig { master, gateways };

    let mut config = compile(&raw).map_err(|errors| {
        let msg = errors.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("; ");
        ConfigError::validation("COMPILE", msg)
    })?;

    // Track each gateway config file mtime
    let mut gateway_trackers = AHashMap::with_capacity(gateway_paths.len());
    for (name, path) in &gateway_paths {
        if let Ok(tracker) = ConfigFileTracker::new(path.clone()) {
            gateway_trackers.insert(name.clone(), tracker);
        }
    }

    config.master_tracker = Some(master_tracker);
    config.gateway_trackers = gateway_trackers;

    Ok(config)
}

fn resolve_include(base: &Path, include: &str) -> Result<Vec<PathBuf>, ConfigError> {
    let path = PathBuf::from(include);
    let path = if path.is_relative() { base.join(path) } else { path };

    let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");

    match file_name {
        "*" => {
            let dir = path.parent().unwrap_or(Path::new("."));
            collect_matching(dir, |_| true)
        },

        "*.conf" => {
            let dir = path.parent().unwrap_or(Path::new("."));
            collect_matching(dir, |p| p.extension().and_then(|s| s.to_str()) == Some("conf"))
        },

        _ => {
            if !path.exists() {
                return Err(ConfigError::from(io::Error::from(io::ErrorKind::NotFound)).with_file(path));
            }

            Ok(vec![path])
        },
    }
}

fn collect_matching<F>(dir: &Path, filter: F) -> Result<Vec<PathBuf>, ConfigError>
where
    F: Fn(&Path) -> bool,
{
    let mut out = Vec::new();

    for entry in fs::read_dir(dir).map_err(|e| ConfigError::from(e).with_file(dir))? {
        let entry = entry.map_err(ConfigError::from)?;
        let path = entry.path();

        if !path.is_file() {
            continue;
        }

        if !filter(&path) {
            continue;
        }

        out.push(path);
    }

    out.sort();

    Ok(out)
}
