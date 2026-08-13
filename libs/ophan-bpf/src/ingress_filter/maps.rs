use aya_ebpf::{
    macros::map,
    maps::{HashMap, LpmTrie},
};

use crate::ingress_filter::types::{ListenerPolicy, PortRuleKeyV4, PortRuleKeyV6};

/// Map storing active listener ports and their default firewall policies.
///
/// Keys are destination ports in **Network Byte Order** (`u16`).
/// Values specify the default fallback action (`ALLOW` or `DENY`) if an incoming packet
/// does not match any explicit IP/CIDR rule in [`PORT_RULES_V4`] or [`PORT_RULES_V6`].
#[map]
pub static LISTENER_POLICIES: HashMap<u16, ListenerPolicy> = HashMap::with_max_entries(1024, 0);

/// Unified Longest Prefix Match (LPM) Trie map for IPv4 per-port firewall rules.
///
/// Stores explicit `PASS` or `DROP` rules for specific IPv4 addresses or CIDR subnets on a target port.
/// Lookups are evaluated using a composite key (`PortRuleKeyV4`) consisting of the destination port
/// and client IPv4 prefix.
#[map]
pub static PORT_RULES_V4: LpmTrie<PortRuleKeyV4, u8> = LpmTrie::with_max_entries(100_000, 0);

/// Unified Longest Prefix Match (LPM) Trie map for IPv6 per-port firewall rules.
///
/// Stores explicit `PASS` or `DROP` rules for specific IPv6 addresses or CIDR subnets on a target port.
/// Lookups are evaluated using a composite key (`PortRuleKeyV6`) consisting of the destination port
/// and client IPv6 prefix.
#[map]
pub static PORT_RULES_V6: LpmTrie<PortRuleKeyV6, u8> = LpmTrie::with_max_entries(100_000, 0);
