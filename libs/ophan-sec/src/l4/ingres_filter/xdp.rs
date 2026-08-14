use aya::{
    Ebpf, Pod,
    maps::{HashMap, LpmTrie, MapData, lpm_trie::Key},
    programs::{Xdp, XdpMode, xdp::XdpLinkId},
};
use flatkit::net::{IpNet, Ipv4Net, Ipv6Net};
use std::net::IpAddr;

use super::backend::IngressBackend;

/// Compiled XDP binary embedded at build time.
const XDP_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ophan-bpf.o"));

// ---------------------------------------------------------------------------
// Map names (must match the names defined in the eBPF program)
// ---------------------------------------------------------------------------
/// Listener ports -> default firewall policy.
const MAP_LISTENER_POLICIES: &str = "LISTENER_POLICIES";
/// Per-port IPv4 IP/CIDR rules.
const MAP_PORT_RULES_V4: &str = "PORT_RULES_V4";
/// Per-port IPv6 IP/CIDR rules.
const MAP_PORT_RULES_V6: &str = "PORT_RULES_V6";

// ---------------------------------------------------------------------------
// Userspace mirrors of the eBPF map key/value types (must match `types.rs`
// byte-for-byte: same fields, same order, same `repr(C, packed)` layout).
// ---------------------------------------------------------------------------

/// Fallback policy assigned to a listener port.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListenerPolicy {
    /// `DefaultPolicy` byte: `ALLOW` (0) or `DENY` (1).
    pub default_action: u8,
}

/// Inner key payload for IPv4 per-port LPM lookups.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortRuleKeyV4 {
    /// Target destination port (same u16 representation used by the kernel).
    pub port: u16,
    /// Client IPv4 address (same u32 representation used by the kernel).
    pub client_ip: u32,
}

/// Inner key payload for IPv6 per-port LPM lookups.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortRuleKeyV6 {
    /// Target destination port (same u16 representation used by the kernel).
    pub port: u16,
    /// Client IPv6 address bytes (network byte order).
    pub client_ip: [u8; 16],
}

unsafe impl Pod for ListenerPolicy {}
unsafe impl Pod for PortRuleKeyV4 {}
unsafe impl Pod for PortRuleKeyV6 {}

/// Explicit rule action values (must match `types.rs::RuleAction`).
const RULE_ACTION_DROP: u8 = 1;
const RULE_ACTION_PASS: u8 = 2;

/// Default listener policy values (must match `types.rs::DefaultPolicy`).
const DEFAULT_POLICY_ALLOW: u8 = 0;

/// Prefix length for a `/32` IPv4 per-port rule: 16 bits port + 32 bits IP.
const V4_FULL_PREFIX_LEN: u8 = 32;
/// Prefix length for a `/128` IPv6 per-port rule: 16 bits port + 128 bits IP.
const V6_FULL_PREFIX_LEN: u8 = 128;

/// XDP-backed ingress filter.
///
/// Map loading uses `expect` because a missing map is a build-time / bytecode
/// error, not a recoverable runtime failure.
///
/// Decision logic lives entirely in the kernel. Userspace query methods
/// (`is_denied`, `is_allowed`, `matches_port`) are therefore no-ops.
#[derive(Debug)]
pub struct XdpBackend {
    ebpf: Ebpf,
    program_name: String,

    listener_policies: HashMap<MapData, u16, ListenerPolicy>,
    port_rules_v4: LpmTrie<MapData, PortRuleKeyV4, u8>,
    port_rules_v6: LpmTrie<MapData, PortRuleKeyV6, u8>,

    link: Option<XdpLinkId>,
}

impl XdpBackend {
    /// Creates an empty backend (no pre-seeded rules).
    #[allow(dead_code)]
    pub fn new(program_name: &str) -> Result<Self, String> {
        Self::from_config(program_name, &[], &[], &[], &[], &[])
    }

    /// Creates a backend and seeds it with the given ports + global rules.
    pub fn from_config(
        program_name: &str,
        ports: &[u16],
        allowed: &[IpNet],
        blocked: &[IpNet],
        allowed_on: &[(IpNet, u16)],
        blocked_on: &[(IpNet, u16)],
    ) -> Result<Self, String> {
        let mut ebpf = Ebpf::load(XDP_BYTES).map_err(|e| format!("Failed to load eBPF bytecode: {e}"))?;

        let listener_policies =
            HashMap::try_from(ebpf.take_map(MAP_LISTENER_POLICIES).expect("LISTENER_POLICIES map must exist in eBPF bytecode"))
                .expect("LISTENER_POLICIES must be a HashMap");

        let port_rules_v4 =
            LpmTrie::try_from(ebpf.take_map(MAP_PORT_RULES_V4).expect("PORT_RULES_V4 map must exist in eBPF bytecode"))
                .expect("PORT_RULES_V4 must be an LpmTrie");

        let port_rules_v6 =
            LpmTrie::try_from(ebpf.take_map(MAP_PORT_RULES_V6).expect("PORT_RULES_V6 map must exist in eBPF bytecode"))
                .expect("PORT_RULES_V6 must be an LpmTrie");

        ebpf.program(program_name).unwrap_or_else(|| {
            panic!("XDP program '{program_name}' not found in bytecode");
        });

        let mut backend = Self {
            ebpf,
            program_name: program_name.to_string(),
            listener_policies,
            port_rules_v4,
            port_rules_v6,
            link: None,
        };

        for &port in ports {
            backend.allow_port(port)?;
        }

        // Port-less global allow/deny rules have no backing map in the current
        // eBPF design. They are accepted for API compatibility but are no-ops.
        if !allowed.is_empty() || !blocked.is_empty() {
            eprintln!("[ophan-waf] Warning: port-less global allow/deny rules are not yet supported by the XDP backend");
        }

        for (network, port) in allowed_on {
            backend.allow_on(network.clone(), *port)?;
        }
        for (network, port) in blocked_on {
            backend.deny_on(network.clone(), *port)?;
        }

        Ok(backend)
    }

    /// Attaches the XDP program to the given interface.
    pub fn attach(&mut self, iface: &str, flags: XdpMode) -> Result<(), String> {
        if self.link.is_some() {
            return Ok(());
        }

        let program: &mut Xdp = self
            .ebpf
            .program_mut(&self.program_name)
            .expect("XDP program must exist")
            .try_into()
            .map_err(|e| format!("Failed to cast program to XDP: {e}"))?;

        let link_id = program.attach(iface, flags).map_err(|e| format!("Failed to attach XDP to {iface}: {e}"))?;

        self.link = Some(link_id);
        Ok(())
    }

    /// Detaches the XDP program if it is currently attached.
    #[allow(dead_code)]
    pub fn detach(&mut self) -> Result<(), String> {
        if let Some(link_id) = self.link.take() {
            let program: &mut Xdp = self
                .ebpf
                .program_mut(&self.program_name)
                .expect("XDP program must exist")
                .try_into()
                .map_err(|e| format!("Failed to cast program to XDP: {e}"))?;

            program.detach(link_id).map_err(|e| format!("Failed to detach XDP program: {e}"))?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn insert_port_rule_v4(&mut self, network: Ipv4Net, port: u16, action: u8) -> Result<(), String> {
        let prefix = 16 + network.prefix();
        if prefix > 16 + V4_FULL_PREFIX_LEN {
            return Err(format!("invalid IPv4 prefix length for per-port rule: {prefix}"));
        }
        let rule_key = PortRuleKeyV4 { port, client_ip: u32::from(network.ip()) };
        let key = Key::new(prefix as u32, rule_key);
        self.port_rules_v4
            .insert(&key, action, 0)
            .map_err(|e| format!("insert per-port IPv4 rule (port {port}, {network}): {e}"))
    }

    fn remove_port_rule_v4(&mut self, network: Ipv4Net, port: u16) -> Result<(), String> {
        let prefix = 16 + network.prefix();
        let rule_key = PortRuleKeyV4 { port, client_ip: u32::from(network.ip()) };
        let key = Key::new(prefix as u32, rule_key);
        self.port_rules_v4
            .remove(&key)
            .map_err(|e| format!("remove per-port IPv4 rule (port {port}, {network}): {e}"))
    }

    fn insert_port_rule_v6(&mut self, network: Ipv6Net, port: u16, action: u8) -> Result<(), String> {
        let prefix = 16 + network.prefix();
        if prefix > 16 + V6_FULL_PREFIX_LEN {
            return Err(format!("invalid IPv6 prefix length for per-port rule: {prefix}"));
        }
        let rule_key = PortRuleKeyV6 { port, client_ip: network.ip().octets() };
        let key = Key::new(prefix as u32, rule_key);
        self.port_rules_v6
            .insert(&key, action, 0)
            .map_err(|e| format!("insert per-port IPv6 rule (port {port}, {network}): {e}"))
    }

    fn remove_port_rule_v6(&mut self, network: Ipv6Net, port: u16) -> Result<(), String> {
        let prefix = 16 + network.prefix();
        let rule_key = PortRuleKeyV6 { port, client_ip: network.ip().octets() };
        let key = Key::new(prefix as u32, rule_key);
        self.port_rules_v6
            .remove(&key)
            .map_err(|e| format!("remove per-port IPv6 rule (port {port}, {network}): {e}"))
    }
}

impl IngressBackend for XdpBackend {
    type Error = String;

    // ------------------------------------------------------------------
    // Global rules
    // ------------------------------------------------------------------
    // The current eBPF maps only support per-port ACLs. Port-less global
    // allow/deny rules are accepted for API compatibility but are no-ops.

    fn allow(&mut self, network: impl Into<IpNet>) -> Result<(), Self::Error> {
        let network = network.into();
        eprintln!("[ophan-waf] Warning: global allow ({network}) is not supported by the XDP backend; ignored");
        Ok(())
    }

    fn remove_allow(&mut self, network: impl Into<IpNet>) -> Result<(), Self::Error> {
        let network = network.into();
        eprintln!("[ophan-waf] Warning: global remove_allow ({network}) is not supported by the XDP backend; ignored");
        Ok(())
    }

    fn deny(&mut self, network: impl Into<IpNet>) -> Result<(), Self::Error> {
        let network = network.into();
        eprintln!("[ophan-waf] Warning: global deny ({network}) is not supported by the XDP backend; ignored");
        Ok(())
    }

    fn remove_deny(&mut self, network: impl Into<IpNet>) -> Result<(), Self::Error> {
        let network = network.into();
        eprintln!("[ophan-waf] Warning: global remove_deny ({network}) is not supported by the XDP backend; ignored");
        Ok(())
    }

    // ------------------------------------------------------------------
    // Port-specific rules
    // ------------------------------------------------------------------

    fn allow_on(&mut self, network: impl Into<IpNet>, port: u16) -> Result<(), Self::Error> {
        match network.into() {
            IpNet::V4(v4) => self.insert_port_rule_v4(v4, port, RULE_ACTION_PASS),
            IpNet::V6(v6) => self.insert_port_rule_v6(v6, port, RULE_ACTION_PASS),
        }
    }

    fn remove_allow_on(&mut self, network: impl Into<IpNet>, port: u16) -> Result<(), Self::Error> {
        match network.into() {
            IpNet::V4(v4) => self.remove_port_rule_v4(v4, port),
            IpNet::V6(v6) => self.remove_port_rule_v6(v6, port),
        }
    }

    fn deny_on(&mut self, network: impl Into<IpNet>, port: u16) -> Result<(), Self::Error> {
        match network.into() {
            IpNet::V4(v4) => self.insert_port_rule_v4(v4, port, RULE_ACTION_DROP),
            IpNet::V6(v6) => self.insert_port_rule_v6(v6, port, RULE_ACTION_DROP),
        }
    }

    fn remove_deny_on(&mut self, network: impl Into<IpNet>, port: u16) -> Result<(), Self::Error> {
        match network.into() {
            IpNet::V4(v4) => self.remove_port_rule_v4(v4, port),
            IpNet::V6(v6) => self.remove_port_rule_v6(v6, port),
        }
    }

    // ------------------------------------------------------------------
    // Listener ports
    // ------------------------------------------------------------------

    fn allow_port(&mut self, port: u16) -> Result<(), Self::Error> {
        let policy = ListenerPolicy { default_action: DEFAULT_POLICY_ALLOW };
        self.listener_policies
            .insert(port, policy, 0)
            .map_err(|e| format!("insert listener policy for port {port}: {e}"))
    }

    fn remove_port(&mut self, port: u16) -> Result<(), Self::Error> {
        self.listener_policies
            .remove(&port)
            .map_err(|e| format!("remove listener policy for port {port}: {e}"))
    }

    // ------------------------------------------------------------------
    // Queries (no-ops — decision is made in-kernel)
    // ------------------------------------------------------------------

    fn matches_port(&self, _port: u16) -> bool {
        true
    }

    fn is_denied(&self, _client_ip: IpAddr, _port: Option<u16>) -> bool {
        false
    }

    fn is_allowed(&self, _client_ip: IpAddr, _port: Option<u16>) -> bool {
        true
    }
}
