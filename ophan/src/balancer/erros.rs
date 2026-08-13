#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BalancerError {
    /// The requested route points to an Upstream that is not registered in the system.
    /// (Critical configuration mismatch or synchronization bug).
    UpstreamNotFound,

    /// The Upstream exists, but its backend server list is completely empty.
    /// (Configuration error or all nodes were dynamically removed).
    UpstreamEmpty,

    /// All configured backend servers in the cluster are currently down or failing health checks.
    /// (Dynamic infrastructure failure / All Unhealthy).
    AllServersUnhealthy,
}

impl BalancerError {
    pub fn format(&self, name: &str) -> String {
        match self {
            BalancerError::UpstreamNotFound => {
                format!("Upstream cluster '{name}' not found in router registry")
            },
            BalancerError::UpstreamEmpty => {
                format!("Upstream cluster '{name}' has zero configured backends")
            },
            BalancerError::AllServersUnhealthy => {
                format!("All backends in the upstream cluster '{name}' are unhealthy")
            },
        }
    }
}

impl std::fmt::Display for BalancerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BalancerError::UpstreamNotFound => write!(f, "Upstream cluster not found in router registry"),
            BalancerError::UpstreamEmpty => write!(f, "Upstream cluster has zero configured backends"),
            BalancerError::AllServersUnhealthy => write!(f, "All backends in the upstream cluster are unhealthy"),
        }
    }
}
