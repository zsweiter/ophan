use aya_ebpf::{bindings::xdp_action, maps::lpm_trie::Key};

use crate::ingress_filter::{
    maps::{LISTENER_POLICIES, PORT_RULES_V4, PORT_RULES_V6},
    types::{DefaultPolicy, ListenerPolicy, PortRuleKeyV4, PortRuleKeyV6, RuleAction},
};

impl ListenerPolicy {
    /// Maps the listener's default policy to the corresponding XDP action.
    #[inline(always)]
    pub fn into_xdp_action(&self) -> xdp_action::Type {
        if self.default_action == DefaultPolicy::DENY as u8 {
            xdp_action::XDP_DROP
        } else {
            xdp_action::XDP_PASS
        }
    }
}

#[inline(always)]
pub fn lookup_listener_port(dst_port_be: u16) -> Option<ListenerPolicy> {
    match unsafe { LISTENER_POLICIES.get(&dst_port_be) } {
        Some(p) => Some(*p),
        None => None,
    }
}

// -----------------------------------------------------------------------------
// Core Ingress Evaluation Pipeline
// -----------------------------------------------------------------------------

#[inline(always)]
pub fn evaluate_ingress_port(dst_port_be: u16) -> xdp_action::Type {
    match lookup_listener_port(dst_port_be) {
        Some(p) => p.into_xdp_action(),
        None => xdp_action::XDP_PASS,
    }
}

/// Evaluates incoming IPv4 network traffic directed toward a listener port.
#[inline(always)]
pub fn evaluate_ingress_v4(client_ip: u32, dst_port_be: u16) -> xdp_action::Type {
    // Lookup listener port policy
    let policy = match lookup_listener_port(dst_port_be) {
        Some(p) => p,
        None => return xdp_action::XDP_PASS,
    };

    let rule_data = PortRuleKeyV4 { port: dst_port_be, client_ip };
    // prefix_len = 16 bits (port) + 32 bits (IPv4 /32) = 48
    let rule_key = Key::new(48, rule_data);

    if let Some(action) = PORT_RULES_V4.get(&rule_key) {
        if *action == RuleAction::DROP as u8 {
            return xdp_action::XDP_DROP;
        } else if *action == RuleAction::PASS as u8 {
            return xdp_action::XDP_PASS;
        }
    }

    policy.into_xdp_action()
}

/// Evaluates incoming IPv6 network traffic directed toward a listener port.
#[inline(always)]
pub fn evaluate_ingress_v6(client_ip: &[u8; 16], dst_port_be: u16) -> xdp_action::Type {
    // Lookup listener port policy
    let policy = match unsafe { LISTENER_POLICIES.get(&dst_port_be) } {
        Some(p) => p,
        None => return xdp_action::XDP_PASS,
    };

    let rule_data = PortRuleKeyV6 { port: dst_port_be, client_ip: *client_ip };
    // prefix_len = 16 bits (port) + 128 bits (IPv6 /128) = 144
    let rule_key = Key::new(144, rule_data);

    if let Some(action) = PORT_RULES_V6.get(&rule_key) {
        if *action == RuleAction::DROP as u8 {
            return xdp_action::XDP_DROP;
        } else if *action == RuleAction::PASS as u8 {
            return xdp_action::XDP_PASS;
        }
    }

    policy.into_xdp_action()
}
