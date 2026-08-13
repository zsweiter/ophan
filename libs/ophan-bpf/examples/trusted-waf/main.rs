use anyhow::Context;
use aya::{
    Pod,
    maps::{HashMap, lpm_trie::Key},
    programs::{Xdp, XdpMode},
};
use log::info;
use std::net::Ipv4Addr;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    signal,
};

use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Map names (must match the names defined in the eBPF program)
// ---------------------------------------------------------------------------
/// Listener ports -> default firewall policy.
const MAP_LISTENER_POLICIES: &str = "LISTENER_POLICIES";
/// Per-port IPv4 IP/CIDR rules.
const MAP_PORT_RULES_V4: &str = "PORT_RULES_V4";

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
#[allow(unused)]
const RULE_ACTION_PASS: u8 = 2;

/// Default listener policy values (must match `types.rs::DefaultPolicy`).
const DEFAULT_POLICY_ALLOW: u8 = 0;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let iface = "wlp2s0";

    env_logger::init();

    let bpf_bytes = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../target/bpfel-unknown-none/release/ophan-bpf"
    ))
    .context("BPF program not found. Build it with: cargo build --target=bpfel-unknown-none --release -p ophan-bpf")?;
    let mut bpf = aya::Ebpf::load(&bpf_bytes)?;

    // if let Err(e) = EbpfLogger::init(&mut bpf) {
    //     warn!("failed to initialize eBPF logger: {e}");
    // }

    let mut trusted_v4 = HashMap::try_from(bpf.map_mut(&MAP_PORT_RULES_V4).unwrap())?;

    let rule_key = PortRuleKeyV4 { port: 80, client_ip: u32::from(Ipv4Addr::new(1, 1, 1, 1)) };
    let key = Key::new(32 + 16u32, rule_key);

    trusted_v4.insert(key, RULE_ACTION_DROP, 0)?;

    let mut listener_ports: HashMap<_, u16, ListenerPolicy> = HashMap::try_from(bpf.map_mut(&MAP_LISTENER_POLICIES).unwrap())?;
    for port in [22u16, 80, 443, 853, 3000, 8080, 8443] {
        let policy = ListenerPolicy { default_action: DEFAULT_POLICY_ALLOW };
        listener_ports.insert(port, policy, 0)?;
    }

    let program: &mut Xdp = bpf.program_mut("ingress_filter").unwrap().try_into()?;
    program.load()?;

    let mut link_id = Some(
        program
            .attach(&iface, XdpMode::default())
            .context("failed to attach the XDP program with default mode - try changing XdpMode::default() to XdpMode::Skb")?,
    );

    println!("Waiting for commands (disable/enable/Ctrl-C)...");

    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    tokio::spawn(async move {
        let stdin = BufReader::new(tokio::io::stdin());
        let mut lines = stdin.lines();

        while let Ok(Some(line)) = lines.next_line().await {
            let _ = tx.send(line);
        }
    });

    loop {
        tokio::select! {
            line = rx.recv() => {
                match line.as_deref() {
                    Some("disable") => {
                        if let Some(id) = link_id.take() {
                            program.detach(id)?;
                            info!("XDP detached");
                        }
                    }
                    Some("enable") => {
                        if link_id.is_none() {
                            link_id = Some(program.attach(&iface, XdpMode::default())?);
                            info!("XDP re-attached");
                        }
                    }
                    Some(cmd) => info!("unknown command: {cmd}"),
                    None => break,
                }
            },

            _ = signal::ctrl_c() => {
                println!("receive sigterm");

                if let Some(id) = link_id.take() {
                    let _ = program.detach(id);
                }
                break;
            }
        }
    }

    Ok(())
}
