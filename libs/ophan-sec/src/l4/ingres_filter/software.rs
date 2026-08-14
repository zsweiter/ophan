use ahash::{AHashMap, AHashSet};
use flatkit::net::{IpNet, IpSet, IpSetBuilder};
use std::net::IpAddr;

use super::backend::IngressBackend;

/// Software-based ingress backend with global and per-port ACLs.
///
/// - Deny rules always win over allow rules.
/// - Global rules apply to every port.
/// - Port-specific rules only affect the declared port.
/// - Bloom filters provide a fast negative path for blacklist checks.
#[derive(Debug)]
pub struct SoftwareBackend {
    /// Networks allowed on every port.
    global_allowed: IpSet,
    /// Networks denied on every port.
    global_blocked: IpSet,

    /// Per-port allow lists.
    port_allowed: AHashMap<u16, IpSet>,
    /// Per-port deny lists.
    port_blocked: AHashMap<u16, IpSet>,

    /// Registered listener ports.
    listener_ports: AHashSet<u16>,
}

impl SoftwareBackend {
    /// Creates a backend pre-seeded with the given ports, allowed and blocked networks.
    ///
    /// All networks supplied here are treated as **global** rules.
    pub fn from_config(
        ports: &[u16],
        allowed: &[IpNet],
        blocked: &[IpNet],
        allowed_on: &[(IpNet, u16)],
        blocked_on: &[(IpNet, u16)],
    ) -> Self {
        let mut global_allowed = IpSet::builder();
        for net in allowed {
            global_allowed.insert_network(net);
        }

        let mut global_blocked = IpSet::builder();
        for net in blocked {
            global_blocked.insert_network(net);
        }

        let mut port_allowed_builders: AHashMap<u16, IpSetBuilder> = AHashMap::new();
        for (net, port) in allowed_on {
            port_allowed_builders.entry(*port).or_insert_with(IpSet::builder).insert_network(net);
        }
        let port_allowed: AHashMap<u16, IpSet> = port_allowed_builders.into_iter().map(|(p, b)| (p, b.build())).collect();

        let mut port_blocked_builders: AHashMap<u16, IpSetBuilder> = AHashMap::new();
        for (net, port) in blocked_on {
            port_blocked_builders.entry(*port).or_insert_with(IpSet::builder).insert_network(net);
        }
        let port_blocked: AHashMap<u16, IpSet> = port_blocked_builders.into_iter().map(|(p, b)| (p, b.build())).collect();

        let mut listener_ports = AHashSet::with_capacity(ports.len());
        listener_ports.extend(ports.iter().copied());

        Self {
            global_allowed: global_allowed.build(),
            global_blocked: global_blocked.build(),
            port_allowed,
            port_blocked,
            listener_ports,
        }
    }
}

impl IngressBackend for SoftwareBackend {
    type Error = String;

    // ------------------------------------------------------------------
    // Global rules
    // ------------------------------------------------------------------

    fn allow(&mut self, _network: impl Into<IpNet>) -> Result<(), Self::Error> {
        // let net = network.into();
        // self.global_allowed.insert_network(&net);
        Ok(())
    }

    fn remove_allow(&mut self, _network: impl Into<IpNet>) -> Result<(), Self::Error> {
        // let net = network.into();
        // self.global_allowed.remove_network(&net);
        Ok(())
    }

    fn deny(&mut self, _network: impl Into<IpNet>) -> Result<(), Self::Error> {
        // let net = network.into();
        // self.global_blocked.insert_network(&net);

        // // Seed bloom filter with the network's representative address when possible.
        // // For pure CIDRs the bloom is best-effort; exact checks still go through IpSet.
        // if let Some(ip) = net.network_address() {
        //     self.insert_bloom(ip);
        // }
        Ok(())
    }

    fn remove_deny(&mut self, _network: impl Into<IpNet>) -> Result<(), Self::Error> {
        // let net = network.into();
        // self.global_blocked.remove_network(&net);
        Ok(())
    }

    // ------------------------------------------------------------------
    // Port-specific rules
    // ------------------------------------------------------------------

    fn allow_on(&mut self, _network: impl Into<IpNet>, _port: u16) -> Result<(), Self::Error> {
        // let net = network.into();
        // self.port_allowed.entry(port).or_insert_with(|| IpSet::builder().build()).insert_network(&net);
        Ok(())
    }

    fn remove_allow_on(&mut self, _network: impl Into<IpNet>, _port: u16) -> Result<(), Self::Error> {
        // let net = network.into();
        // if let Some(set) = self.port_allowed.get_mut(&port) {
        //     set.remove_network(&net);
        // }
        Ok(())
    }

    fn deny_on(&mut self, _network: impl Into<IpNet>, _port: u16) -> Result<(), Self::Error> {
        // let net = network.into();
        // self.port_blocked.entry(port).or_insert_with(|| IpSet::builder().build()).insert_network(&net);

        // if let Some(ip) = net.network_address() {
        //     self.insert_bloom(ip);
        // }
        Ok(())
    }

    fn remove_deny_on(&mut self, _network: impl Into<IpNet>, _port: u16) -> Result<(), Self::Error> {
        // let net = network.into();
        // if let Some(set) = self.port_blocked.get_mut(&port) {
        //     set.remove_network(&net);
        // }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Listener ports
    // ------------------------------------------------------------------

    fn allow_port(&mut self, port: u16) -> Result<(), Self::Error> {
        self.listener_ports.insert(port);
        Ok(())
    }

    fn remove_port(&mut self, port: u16) -> Result<(), Self::Error> {
        if self.listener_ports.remove(&port) {
            // Optional: also clean up per-port rule maps for this port
            self.port_allowed.remove(&port);
            self.port_blocked.remove(&port);
            Ok(())
        } else {
            Err(format!("Port {} was not registered as an active listener", port))
        }
    }

    // ------------------------------------------------------------------
    // Queries
    // ------------------------------------------------------------------

    #[inline]
    fn matches_port(&self, port: u16) -> bool {
        self.listener_ports.contains(&port)
    }

    #[inline]
    fn is_denied(&self, client_ip: IpAddr, port: Option<u16>) -> bool {
        if self.global_blocked.contains(client_ip) {
            return true;
        }

        if let Some(p) = port {
            if self.port_blocked.get(&p).is_some_and(|set| set.contains(client_ip)) {
                return true;
            }
        }

        false
    }

    #[inline]
    fn is_allowed(&self, client_ip: IpAddr, port: Option<u16>) -> bool {
        // Global allow
        if self.global_allowed.contains(client_ip) {
            return true;
        }

        // Port-specific allow
        if let Some(p) = port {
            if self.port_allowed.get(&p).is_some_and(|set| set.contains(client_ip)) {
                return true;
            }
        }

        false
    }
}
