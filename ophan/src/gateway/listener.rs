use ahash::AHashMap;
use arc_swap::ArcSwap;
use http::HeaderMap;
use ophan_sec::l4::ListenerFirewall;
use ophan_sec::{ClientAddress, TrustedProxies};
use pingora::listeners::PreTlsProcess;
use pingora::protocols::GetSocketDigest;
use pingora::protocols::l4::socket::SocketAddr;
use pingora::protocols::l4::stream::Stream as L4Stream;
use std::net::{IpAddr, SocketAddr as InetAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::config::{ListenerAddress, ListenerConfig};
use crate::state::AppContext;

/// Runtime settings of one listener.
#[derive(Debug, Default)]
pub struct ListenerRuntime {
    pub firewall: Option<Arc<ListenerFirewall>>,
    pub trusted_proxies: Option<Arc<TrustedProxies>>,
    pub keepalive: Option<Duration>,
    pub idle: Option<Duration>,
    pub max_request_size: Option<u64>,
}

impl ListenerRuntime {
    fn from_config(listener: &ListenerConfig) -> Self {
        Self {
            firewall: listener.firewall.clone(),
            trusted_proxies: listener.trusted_proxies.clone(),
            keepalive: listener.connection.keepalive_timeout,
            idle: listener.connection.idle_timeout,
            max_request_size: listener.connection.max_request_size.map(|size| size.as_u64()),
        }
    }

    /// Original client address. `peer` is `None` on Unix socket listeners, where the
    /// configuration guarantees a `real_ip_header`.
    pub fn client_address(&self, peer: Option<IpAddr>, headers: &HeaderMap) -> ClientAddress {
        match (&self.trusted_proxies, peer) {
            (Some(trusted_proxies), _) => trusted_proxies.resolve(peer, headers),
            (None, Some(ip)) => ClientAddress::Resolved(ip.to_canonical()),
            (None, None) => ClientAddress::MissingHeader,
        }
    }

    /// Whether the peer may supply forwarding headers.
    pub fn trusts(&self, peer: Option<IpAddr>) -> bool {
        self.trusted_proxies.as_ref().is_some_and(|tp| tp.trusts(peer))
    }

    /// Scheme the client used: TLS on this listener, or `X-Forwarded-Proto` from a trusted proxy.
    pub fn client_scheme(&self, tls: bool, peer: Option<IpAddr>, headers: &HeaderMap) -> &'static str {
        if tls {
            return "https";
        }

        self.trusted_proxies.as_ref().and_then(|tp| tp.forwarded_scheme(peer, headers)).unwrap_or("http")
    }

    /// Connection access: the firewall and, with `on_untrusted = reject`, the trusted proxies.
    #[inline]
    pub fn admits(&self, peer: IpAddr) -> bool {
        let peer = peer.to_canonical();

        self.firewall.as_ref().is_none_or(|fw| fw.admits(peer)) && self.trusted_proxies.as_ref().is_none_or(|tp| tp.admits(peer))
    }
}

/// Listeners of a gateway, identified by their full bind address.
#[derive(Debug, Default)]
pub struct ListenerTable {
    tcp: Vec<(InetAddr, Arc<ListenerRuntime>)>,
    unix: AHashMap<String, Arc<ListenerRuntime>>,
    /// Used when a connection matches no configured listener.
    unknown: Arc<ListenerRuntime>,
}

impl ListenerTable {
    pub fn from_config(listeners: &[Arc<ListenerConfig>]) -> Self {
        let mut table = Self::default();

        for listener in listeners {
            let runtime = Arc::new(ListenerRuntime::from_config(listener));

            match &listener.address {
                ListenerAddress::Tcp(addr) => {
                    let addr = InetAddr::new(addr.ip().to_canonical(), addr.port());
                    table.tcp.retain(|(bound, _)| *bound != addr);
                    table.tcp.push((addr, runtime));
                },
                #[cfg(unix)]
                ListenerAddress::Uds(path) => {
                    table.unix.insert(path.clone(), runtime);
                },
            }
        }

        table
    }

    /// Finds the listener that accepted a connection from its local address.
    pub fn lookup(&self, local: Option<&SocketAddr>) -> &Arc<ListenerRuntime> {
        let found = match local {
            Some(SocketAddr::Inet(addr)) => self.lookup_tcp(*addr),
            #[cfg(unix)]
            Some(SocketAddr::Unix(addr)) => addr.as_pathname().and_then(|p| p.to_str()).and_then(|p| self.unix.get(p)),
            None => None,
        };

        found.unwrap_or(&self.unknown)
    }

    /// Exact address first, then the wildcard listener of the same port, since a listener
    /// bound to `0.0.0.0` sees connections on the host's real addresses.
    fn lookup_tcp(&self, local: InetAddr) -> Option<&Arc<ListenerRuntime>> {
        let local = InetAddr::new(local.ip().to_canonical(), local.port());
        let mut wildcard = None;

        for (bound, runtime) in &self.tcp {
            if *bound == local {
                return Some(runtime);
            }
            if wildcard.is_none() && bound.port() == local.port() && bound.ip().is_unspecified() {
                wildcard = Some(runtime);
            }
        }

        wildcard
    }
}

/// Drops connections the listener does not admit, after accept and before the TLS handshake.
///
/// pingora runs this callback for TLS endpoints only; plaintext connections are checked when
/// their requests arrive.
pub struct ListenerGuard {
    context: Arc<ArcSwap<AppContext>>,
}

impl ListenerGuard {
    pub fn new(context: Arc<ArcSwap<AppContext>>) -> Self {
        Self { context }
    }
}

#[async_trait::async_trait]
impl PreTlsProcess for ListenerGuard {
    async fn process(&self, stream: &mut L4Stream) -> pingora::Result<()> {
        let Some(digest) = stream.get_socket_digest() else {
            return Ok(());
        };

        let Some(peer) = digest.peer_addr().and_then(SocketAddr::as_inet).map(|addr| addr.ip()) else {
            return Ok(());
        };

        let context = self.context.load();

        if context.listeners.lookup(digest.local_addr()).admits(peer) {
            Ok(())
        } else {
            Err(pingora::Error::explain(
                pingora::ErrorType::ConnectRefused,
                "connection rejected by listener access rules",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ophan_sec::OnUntrusted;

    fn listener(address: &str, firewall: Option<ListenerFirewall>) -> Arc<ListenerConfig> {
        let mut config = ListenerConfig::new(address.to_string(), address.parse().unwrap());
        config.firewall = firewall.map(Arc::new);
        Arc::new(config)
    }

    fn inet(addr: &str) -> SocketAddr {
        SocketAddr::Inet(addr.parse().unwrap())
    }

    #[test]
    fn exact_address_wins_over_wildcard() {
        let restricted = ListenerFirewall::new(&["10.0.0.0/8".parse().unwrap()], &[]);
        let table = ListenerTable::from_config(&[listener("0.0.0.0:8080", None), listener("192.0.2.10:8080", Some(restricted))]);

        let public = table.lookup(Some(&inet("198.51.100.1:8080")));
        let private = table.lookup(Some(&inet("192.0.2.10:8080")));

        assert!(public.admits("203.0.113.1".parse().unwrap()));
        assert!(!private.admits("203.0.113.1".parse().unwrap()));
    }

    #[test]
    fn mapped_local_address_matches_ipv4_listener() {
        let restricted = ListenerFirewall::new(&[], &["203.0.113.0/24".parse().unwrap()]);
        let table = ListenerTable::from_config(&[listener("127.0.0.1:9000", Some(restricted))]);

        assert!(!table.lookup(Some(&inet("[::ffff:127.0.0.1]:9000"))).admits("203.0.113.5".parse().unwrap()));
    }

    #[test]
    fn reject_mode_only_admits_trusted_proxies() {
        let runtime = ListenerRuntime {
            trusted_proxies: Some(Arc::new(TrustedProxies::new(
                &["173.245.48.0/20".parse().unwrap()],
                Some(http::HeaderName::from_static("cf-connecting-ip")),
                OnUntrusted::Reject,
            ))),
            ..Default::default()
        };

        assert!(runtime.admits("173.245.48.1".parse().unwrap()));
        assert!(!runtime.admits("203.0.113.1".parse().unwrap()));
    }

    #[test]
    fn unknown_listener_admits_everyone() {
        let table = ListenerTable::from_config(&[]);
        assert!(table.lookup(Some(&inet("127.0.0.1:1"))).admits("203.0.113.1".parse().unwrap()));
    }
}
