use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::SystemTime;

use crate::config::dsl_parser::{MasterConfig, parse_gateway_config, parse_master_config};
use crate::config::errors::ConfigError;
use crate::config::parts::{GatewayConfig, ListenerConfig, MAX_CONFIG_FILE_SIZE, PolicyConfig, RoutesConfig, UpstreamConfig};

fn read_config_file(path: &PathBuf) -> Result<String, ConfigError> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_CONFIG_FILE_SIZE {
        let message = format!(
            "Config file too large: {} ({} bytes, max: {} bytes)",
            path.display(),
            metadata.len(),
            MAX_CONFIG_FILE_SIZE
        );

        return Err(message.into());
    }

    Ok(fs::read_to_string(path)?)
}

#[derive(Clone)]
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

    #[allow(dead_code)]
    pub fn refresh_mtime(&mut self) -> Result<(), ConfigError> {
        self.last_mtime = fs::metadata(&self.path)?.modified()?;
        Ok(())
    }
}

#[derive(Clone)]
#[allow(unused)]
pub struct OphanConfig {
    pub master: MasterConfig,
    pub gateways: Vec<GatewayConfig>,
    pub policies: PolicyConfig,

    pub master_tracker: ConfigFileTracker,
    pub gateway_trackers: Vec<ConfigFileTracker>,

    pub listeners: Vec<Arc<ListenerConfig>>,
    pub routes: Vec<Arc<RoutesConfig>>,
    pub upstreams: Vec<Arc<UpstreamConfig>>,
    pub upstreams_index: HashMap<String, Arc<UpstreamConfig>>,
    pub routes_fast_match: Vec<(String, Arc<RoutesConfig>)>,
}

impl OphanConfig {
    pub fn parse() -> Result<Self, ConfigError> {
        let config_base = get_config_path();
        let master_path = config_base.join("master.conf");

        if !master_path.exists() {
            return Err(format!("Master config not found: {}", master_path.display()).into());
        }

        let master_str = read_config_file(&master_path)?;
        let master = parse_master_config(&master_str)?;
        let master_tracker = ConfigFileTracker::new(master_path)?;

        let mut gateways = Vec::with_capacity(master.includes.len());
        let mut gateway_trackers = Vec::with_capacity(master.includes.len());

        for include in &master.includes {
            let include_path = PathBuf::from(include);

            if include.ends_with("*.conf") || include.ends_with(".conf") {
                let parent = include_path.parent().unwrap_or(config_base);

                if parent.is_dir() && parent.exists() {
                    let entries = fs::read_dir(parent)?;
                    let mut paths: Vec<PathBuf> = entries
                        .filter_map(|e| e.ok())
                        .map(|e| e.path())
                        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("conf"))
                        .collect();

                    paths.sort();

                    for path in paths {
                        let content = read_config_file(&path)?;
                        let gateway =
                            parse_gateway_config(&content).map_err(|e| format!("Error parsing {}: {}", path.display(), e))?;
                        gateway_trackers.push(ConfigFileTracker::new(path.clone())?);
                        gateways.push(gateway);
                    }
                }
            }
        }

        let total_listeners: usize = gateways.iter().map(|gw| gw.listeners.len()).sum();
        let total_upstreams: usize = gateways.iter().map(|gw| gw.upstreams.len()).sum();
        let total_routes: usize = gateways.iter().map(|gw| gw.routes.len()).sum();

        let mut policies = PolicyConfig::default();
        let mut listeners = Vec::with_capacity(total_listeners);
        let mut routes = Vec::with_capacity(total_routes);
        let mut upstreams = Vec::with_capacity(total_upstreams);
        let mut upstreams_index = HashMap::with_capacity(total_upstreams);
        let mut routes_fast_match = Vec::with_capacity(total_routes);

        for gw in &gateways {
            policies.merge_all(gw.policies.clone());

            for listener in &gw.listeners {
                listeners.push(Arc::new(listener.clone()));
            }

            for upstream in &gw.upstreams {
                let shared_u = Arc::new(upstream.clone());
                upstreams.push(Arc::clone(&shared_u));
                upstreams_index.insert(upstream.name.clone(), shared_u);
            }

            for route in &gw.routes {
                let shared_r = Arc::new(route.clone());
                routes.push(Arc::clone(&shared_r));

                let match_path = route.path.trim_end_matches('*').to_string();
                routes_fast_match.push((match_path, shared_r));
            }
        }

        routes_fast_match.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

        Ok(OphanConfig {
            master,
            gateways,
            policies,
            master_tracker,
            gateway_trackers,
            listeners,
            routes,
            upstreams,
            upstreams_index,
            routes_fast_match,
        })
    }
}

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
            PathBuf::from(".config")
        } else if cfg!(target_os = "windows") {
            PathBuf::from("C:\\ophan-gateway\\conf")
        } else if cfg!(target_os = "macos") {
            let homebrew = PathBuf::from("/opt/homebrew/etc/ophan");
            if homebrew.exists() {
                homebrew
            } else {
                PathBuf::from("/usr/local/etc/ophan")
            }
        } else {
            PathBuf::from("/etc/ophan")
        }
    })
}
