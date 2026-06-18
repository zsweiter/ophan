use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;
use std::{env, fs};

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
#[allow(unused)] // For now 
pub struct ConfigFileTracker {
    pub path: PathBuf,
    pub last_mtime: SystemTime,
}

#[allow(unused)] // For now 
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

        let mut gateways = Vec::new();
        let mut gateway_trackers = Vec::new();

        for include in &master.includes {
            let include_path = PathBuf::from(include);

            if include.ends_with("*.conf") || include.ends_with(".conf") {
                let parent = include_path.parent().unwrap_or(&config_base);

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

        let mut policies = PolicyConfig::default();
        let mut listeners = Vec::new();
        let mut routes = Vec::new();
        let mut upstreams = Vec::new();
        let mut upstreams_index = HashMap::new();
        let mut routes_fast_match = Vec::new();

        for gw in &gateways {
            policies.merge_all(gw.policies.clone());

            for l in &gw.listeners {
                listeners.push(Arc::new(l.clone()));
            }

            for u in &gw.upstreams {
                let shared_u = Arc::new(u.clone());
                upstreams.push(shared_u.clone());
                upstreams_index.insert(u.name.clone(), shared_u);
            }

            for r in &gw.routes {
                let shared_r = Arc::new(r.clone());
                routes.push(shared_r.clone());
                let match_path = r.path.trim_end_matches('*').to_string();
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

    #[allow(unused)] // For now (gracefull reload)
    pub fn reload_if_changed(&mut self, force: bool) -> Result<bool, Box<dyn std::error::Error>> {
        if force || self.master_tracker.has_changed()? {
            let new = Self::parse()?;
            *self = new;
            return Ok(true);
        }

        let mut changed = false;
        let mut changed_indices = Vec::new();

        for (idx, tracker) in self.gateway_trackers.iter().enumerate() {
            if force || tracker.has_changed()? {
                changed_indices.push(idx);
            }
        }

        for idx in changed_indices {
            let tracker = &mut self.gateway_trackers[idx];
            let content = read_config_file(&tracker.path)?;
            let new_gw =
                parse_gateway_config(&content).map_err(|e| format!("Error parsing {}: {}", tracker.path.display(), e))?;

            self.gateways[idx] = new_gw.clone();
            tracker.refresh_mtime()?;
            self.rebuild_from_gateway(idx, &new_gw);
            changed = true;
        }

        if changed {
            self.policies = self.merge_all_policies();
        }

        Ok(changed)
    }

    #[allow(unused)] // For now (gracefull reload)
    fn rebuild_from_gateway(&mut self, idx: usize, gw: &GatewayConfig) {
        for l in &gw.listeners {
            self.listeners.push(Arc::new(l.clone()));
        }

        for u in &gw.upstreams {
            let name = u.name.clone();
            if let Some(existing) = self.upstreams.iter().position(|a| a.name == name) {
                let shared = Arc::new(u.clone());
                self.upstreams[existing] = shared.clone();
                self.upstreams_index.insert(name, shared);
            } else {
                let shared = Arc::new(u.clone());
                self.upstreams.push(shared.clone());
                self.upstreams_index.insert(name, shared);
            }
        }

        for r in &gw.routes {
            let path = r.path.clone();
            if let Some(existing) = self.routes.iter().position(|a| a.path == path) {
                let shared = Arc::new(r.clone());
                self.routes[existing] = shared.clone();
                if let Some(match_entry) = self.routes_fast_match.iter_mut().find(|(p, _)| *p == path.trim_end_matches('*')) {
                    match_entry.1 = shared;
                }
            } else {
                let shared = Arc::new(r.clone());
                self.routes.push(shared.clone());
                let match_path = r.path.trim_end_matches('*').to_string();
                self.routes_fast_match.push((match_path, shared));
            }
        }

        self.routes_fast_match.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
    }

    fn merge_all_policies(&self) -> PolicyConfig {
        let mut merged = PolicyConfig::default();
        for gw in &self.gateways {
            merged.merge_all(gw.policies.clone());
        }
        merged
    }
}

fn get_config_path() -> PathBuf {
    if let Ok(path) = env::var("CONFIG_PATH") {
        return PathBuf::from(path);
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
}
