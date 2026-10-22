use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;
use flatkit::net::HostAddr;
use http::HeaderValue;
use pingora::protocols::TcpKeepalive;
use pingora::upstreams::peer::{ALPN, HttpPeer};

use crate::config::{NetworkProtocol, UpstreamAddress};

const EMPTY_HOST: &str = "one.one.one.one";

/// How long a resolved host backend address is reused before resolving again.
const DNS_TTL: Duration = Duration::from_secs(30);
const DNS_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackendAddr {
    Tcp(SocketAddr),
    Host(HostAddr),
    #[cfg(unix)]
    Uds(Arc<PathBuf>),
}

// Backend reprents a Server Backend, like clusters
#[allow(unused)] // for future use with dinamic routing
#[derive(Debug)]
pub struct Backend {
    pub addr: BackendAddr,
    pub protocol: NetworkProtocol,
    pub host_addr: Option<HostAddr>,

    active_conns: AtomicUsize,
    score: AtomicUsize,
    total_requests: AtomicU64,
    failed_requests: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    total_latency_ns: AtomicU64,
    latency_samples: AtomicU64,

    weight: AtomicU32,
    healthy: AtomicBool,
    check_successes: AtomicU32,
    check_failures: AtomicU32,

    /// Route-independent peer settings, cloned per request. Host backends expire it so
    /// DNS changes are picked up.
    pub peer_template: ArcSwapOption<PeerTemplate>,
    /// `Host` header for host backends, with the port when it is not the scheme default.
    pub host_header: Option<HeaderValue>,
}

#[derive(Debug)]
pub struct PeerTemplate {
    pub peer: HttpPeer,
    pub expires_at: Option<Instant>,
}

impl From<&UpstreamAddress> for BackendAddr {
    fn from(value: &UpstreamAddress) -> Self {
        match value {
            UpstreamAddress::Tcp(addr) => Self::Tcp(*addr),
            UpstreamAddress::Host(addr) => Self::Host(addr.to_owned()),
            #[cfg(unix)]
            UpstreamAddress::Uds(path) => Self::Uds(Arc::new(PathBuf::from(path))),
        }
    }
}

impl std::fmt::Display for BackendAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp(addr) => write!(f, "{addr}"),
            Self::Host(addr) => write!(f, "{}:{}", addr.host(), addr.into_parts().1),
            #[cfg(unix)]
            Self::Uds(path) => write!(f, "unix:{}", path.display()),
        }
    }
}

impl Backend {
    pub fn new(addr: BackendAddr, weight: u32) -> Self {
        Self {
            addr,
            protocol: NetworkProtocol::default(),
            active_conns: AtomicUsize::new(0),
            score: AtomicUsize::new(0),
            total_requests: AtomicU64::new(0),
            failed_requests: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            total_latency_ns: AtomicU64::new(0),
            latency_samples: AtomicU64::new(0),
            weight: AtomicU32::new(weight),
            healthy: AtomicBool::new(true),
            check_successes: AtomicU32::new(0),
            check_failures: AtomicU32::new(0),
            host_addr: None,
            peer_template: ArcSwapOption::empty(),
            host_header: None,
        }
    }

    pub fn from_tcp(addr: SocketAddr, weight: u32) -> Self {
        Self::new(BackendAddr::Tcp(addr), weight)
    }

    pub fn from_host(addr: &HostAddr, weight: u32) -> Self {
        let mut backend = Self::new(BackendAddr::Host(addr.to_owned()), weight);
        backend.host_addr = Some(addr.to_owned());

        let (host, port) = addr.into_parts();
        let default_port = if addr.is_https() { 443 } else { 80 };
        backend.host_header = match port == default_port {
            true => HeaderValue::from_str(host).ok(),
            false => HeaderValue::from_str(&format!("{host}:{port}")).ok(),
        };

        backend
    }

    #[cfg(unix)]
    pub fn from_uds(path: PathBuf, weight: u32) -> Self {
        Self::new(BackendAddr::Uds(Arc::new(path)), weight)
    }

    pub fn set_protocol(&mut self, protocol: NetworkProtocol) {
        self.protocol = protocol
    }
}

impl Backend {
    /// Returns the peer to connect to, rebuilding the cached template when it expired.
    pub async fn peer(&self) -> pingora::Result<HttpPeer> {
        let cached = self.peer_template.load_full();

        if let Some(template) = cached.as_ref()
            && template.expires_at.is_none_or(|at| at > Instant::now())
        {
            return Ok(template.peer.clone());
        }

        let (resolved, expires_at) = match &self.addr {
            BackendAddr::Host(host) => {
                let (name, port) = host.into_parts();
                let query = format!("{name}:{port}");
                let lookup = tokio::task::spawn_blocking(move || query.to_socket_addrs().map(|mut addrs| addrs.next()));

                match tokio::time::timeout(DNS_TIMEOUT, lookup).await {
                    Ok(Ok(Ok(Some(addr)))) => (Some(addr), Some(Instant::now() + DNS_TTL)),
                    result => {
                        // Keep serving with the last known address while DNS is failing.
                        if let Some(template) = cached.as_ref() {
                            tracing::warn!("failed to resolve upstream '{}', using the last address: {result:?}", name);
                            return Ok(template.peer.clone());
                        }

                        return Err(pingora::Error::explain(
                            pingora::ErrorType::ConnectNoRoute,
                            format!("failed to resolve upstream '{name}'"),
                        ));
                    },
                }
            },
            _ => (None, None),
        };

        let template = Arc::new(PeerTemplate { peer: self.build_peer(resolved)?, expires_at });
        self.peer_template.store(Some(Arc::clone(&template)));

        Ok(template.peer.clone())
    }

    /// Route-independent peer settings. `resolved` is the address of a host backend.
    fn build_peer(&self, resolved: Option<SocketAddr>) -> pingora::Result<HttpPeer> {
        let mut peer = match (&self.addr, resolved) {
            (BackendAddr::Tcp(addr), _) => HttpPeer::new(addr, false, EMPTY_HOST.to_string()),
            (BackendAddr::Host(host), Some(addr)) => HttpPeer::new(addr, host.is_https(), host.sni_name().to_string()),
            (BackendAddr::Host(host), None) => {
                return Err(pingora::Error::explain(
                    pingora::ErrorType::ConnectNoRoute,
                    format!("upstream '{}' is not resolved", host.host()),
                ));
            },
            #[cfg(unix)]
            (BackendAddr::Uds(path), _) => HttpPeer::new_uds(&path.to_string_lossy(), false, EMPTY_HOST.to_string())?,
        };

        let tls = matches!(&self.addr, BackendAddr::Host(host) if host.is_https());

        peer.options.connection_timeout = Some(Duration::from_secs(3));
        peer.options.total_connection_timeout = Some(Duration::from_secs(5));
        peer.options.read_timeout = Some(Duration::from_secs(30));
        peer.options.write_timeout = Some(Duration::from_secs(30));
        peer.options.idle_timeout = Some(Duration::from_secs(15));

        peer.options.alpn = ALPN::H1;

        peer.options.tcp_keepalive = Some(TcpKeepalive {
            idle: Duration::from_secs(60),
            interval: Duration::from_secs(10),
            count: 3,
            #[cfg(target_os = "linux")]
            user_timeout: Duration::from_secs(0),
        });

        if self.protocol.is_http2() || self.protocol.is_grpc() {
            peer.options.alpn = ALPN::H2;
            peer.options.max_h2_streams = 256;
            peer.options.h2_ping_interval = Some(Duration::from_secs(30));
        } else if tls && !self.protocol.allow_websocket_upgrade() {
            peer.options.alpn = ALPN::H2H1;
            peer.options.h2_ping_interval = Some(Duration::from_secs(30));
        }

        if self.protocol.allow_websocket_upgrade() {
            // For WebSocket upgrade, we must use HTTP/1.1 to support the Upgrade header.
            peer.options.alpn = ALPN::H1;

            peer.options.read_timeout = Some(Duration::from_secs(86400)); // 24h
            peer.options.write_timeout = Some(Duration::from_secs(86400));
            peer.options.idle_timeout = Some(Duration::from_secs(15));
        }

        Ok(peer)
    }
}

#[allow(unused)] // for future use with dinamic routing
impl Backend {
    pub fn weight(&self) -> u32 {
        self.weight.load(Ordering::Relaxed)
    }

    pub fn set_weight(&self, weight: u32) {
        self.weight.store(weight, Ordering::Relaxed);
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    pub fn set_healthy(&self, status: bool) {
        let prev = self.healthy.load(Ordering::Relaxed);
        if prev != status {
            self.healthy.store(status, Ordering::Relaxed);
        }
    }

    /// Applies an active health check result. The backend only changes state after
    /// `healthy_threshold` consecutive successes or `unhealthy_threshold` consecutive failures.
    pub fn report_check(&self, ok: bool, healthy_threshold: u32, unhealthy_threshold: u32) {
        if ok {
            self.check_failures.store(0, Ordering::Relaxed);
            let streak = self.check_successes.fetch_add(1, Ordering::Relaxed).saturating_add(1);
            if streak >= healthy_threshold.max(1) {
                self.set_healthy(true);
            }
        } else {
            self.check_successes.store(0, Ordering::Relaxed);
            let streak = self.check_failures.fetch_add(1, Ordering::Relaxed).saturating_add(1);
            if streak >= unhealthy_threshold.max(1) {
                self.set_healthy(false);
            }
        }
    }

    pub fn active_conns(&self) -> usize {
        self.active_conns.load(Ordering::Relaxed)
    }

    pub fn acquire(&self) {
        self.active_conns.fetch_add(1, Ordering::Relaxed);
    }

    pub fn release(&self) {
        let old = self.active_conns.fetch_sub(1, Ordering::Relaxed);
        debug_assert!(old > 0);
    }

    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    pub fn failed_requests(&self) -> u64 {
        self.failed_requests.load(Ordering::Relaxed)
    }

    pub fn record_request(&self) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_failure(&self) {
        self.failed_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_bytes_in(&self, n: u64) {
        self.bytes_in.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_bytes_out(&self, n: u64) {
        self.bytes_out.fetch_add(n, Ordering::Relaxed);
    }

    pub fn record_latency_ns(&self, ns: u64) {
        self.total_latency_ns.fetch_add(ns, Ordering::Relaxed);
        self.latency_samples.fetch_add(1, Ordering::Relaxed);
    }

    pub fn avg_latency_ns(&self) -> Option<u64> {
        let samples = self.latency_samples.load(Ordering::Relaxed);
        if samples == 0 {
            return None;
        }

        let total = self.total_latency_ns.load(Ordering::Relaxed);
        Some(total / samples)
    }

    pub fn score(&self) -> usize {
        self.score.load(Ordering::Relaxed)
    }

    pub fn update_score(&self) {
        let conns = self.active_conns.load(Ordering::Acquire);
        let failures = self.failed_requests.load(Ordering::Acquire);
        let latency = self.avg_latency_ns().unwrap_or(0);

        let computed = (conns * 10) + (failures as usize * 50) + (latency as usize / 1_000_000);

        self.score.store(computed, Ordering::Release);
    }

    pub fn load_factor(&self) -> usize {
        let conns = self.active_conns.load(Ordering::Acquire);
        let failures = self.failed_requests.load(Ordering::Acquire) as usize;
        let latency = self.avg_latency_ns().unwrap_or(0) as usize;

        conns + failures * 2 + latency / 1_000_000
    }

    pub fn is_overloaded(&self, threshold: usize) -> bool {
        self.load_factor() > threshold
    }
}
