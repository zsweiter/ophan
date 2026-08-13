/// Explicit action to take when a packet matches a port and IP/CIDR rule in the LPM Trie.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    /// Drop the incoming packet immediately at the XDP layer.
    DROP = 1,
    /// Allow the incoming packet to pass through to the kernel network stack.
    PASS = 2,
}

/// Fallback policy for a monitored listener port when no explicit rule matches.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum DefaultPolicy {
    /// Public port policy: Allow traffic by default unless an explicit `DROP` rule matches.
    #[default]
    ALLOW = 0,
    /// Strict/Private port policy: Drop traffic by default unless an explicit `PASS` rule matches.
    DENY = 1,
}

/// Base firewall policy configuration assigned to an exposed listener port.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct ListenerPolicy {
    /// Default action byte representing a [`DefaultPolicy`] variant (`ALLOW` or `DENY`).
    pub default_action: u8,
}

/// Inner key payload for IPv4 per-port Longest Prefix Match (LPM) lookups.
///
/// Must be wrapped inside an `aya_ebpf::maps::lpm_trie::Key` when performing map lookups.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct PortRuleKeyV4 {
    /// Target destination port in **Network Byte Order** (Big-Endian).
    pub port: u16,
    /// Source client IPv4 address in **Network Byte Order** (Big-Endian).
    pub client_ip: u32,
}

/// Inner key payload for IPv6 per-port Longest Prefix Match (LPM) lookups.
///
/// Must be wrapped inside an `aya_ebpf::maps::lpm_trie::Key` when performing map lookups.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct PortRuleKeyV6 {
    /// Target destination port in **Network Byte Order** (Big-Endian).
    pub port: u16,
    /// Source client IPv6 address bytes in **Network Byte Order** (Big-Endian).
    pub client_ip: [u8; 16],
}
