use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use ahash::AHashMap;
use flatkit::net::HostAddr;
use flatkit::sizes::ByteSize;
use flatkit::str::ImmerStr;
use http::{HeaderName, HeaderValue};
use ophan_net::http::HttpMethodSet;
use ophan_net::tls::{ALPN, TlsVersion};
use ophan_sec::NetPolicy;
use ophan_sec::l7::WafConfig;

use crate::balancer::BalanceStrategy;
use crate::config::dsl::ConfigFileTracker;
use crate::middlewares::auth::AuthConfig;
use crate::middlewares::cors::CorsConfig;
use crate::middlewares::limiter::LimiterConfig;
use crate::middlewares::rewrites::TrailingSlashAction;

/// Top-level configuration for an Ophan gateway instance.
#[derive(Debug, Clone)]
pub struct OphanConfig {
    pub master: MasterConfig,
    pub gateways: AHashMap<ImmerStr, GatewayConfig>,

    pub listeners: Box<[Arc<ListenerConfig>]>,
    pub upstreams: Box<[Arc<UpstreamConfig>]>,

    pub master_tracker: Option<ConfigFileTracker>,
    pub gateway_trackers: AHashMap<ImmerStr, ConfigFileTracker>,
}

/// Master process configuration (process name, user, workers, logging).
#[derive(Debug, Clone)]
pub struct MasterConfig {
    pub name: ImmerStr,
    pub user: String,
    pub workers: usize,
    pub pid: String,
    pub error_log: String,
    pub includes: Box<[String]>,
}

/// Configuration for a single gateway instance with its listeners, upstreams, routes and trusted proxies.
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub name: ImmerStr,
    pub listeners: Box<[Arc<ListenerConfig>]>,
    pub upstreams: Box<[Arc<UpstreamConfig>]>,
    pub routes: Box<[Arc<RoutesConfig>]>,
    pub net_policy: Option<Arc<NetPolicy>>,
}

// ============================================================================
// TLS / SECURITY
// ============================================================================

/// Listener security mode: plaintext TCP or TLS with certificate configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum SecurityConfig {
    #[default]
    Plaintext,
    Tls {
        certs: TlsCerts,
        alpn_protocols: Option<ALPN>,
        min_version: TlsVersion,
    },
}

impl From<SecurityConfig> for Option<pingora::listeners::tls::TlsSettings> {
    fn from(config: SecurityConfig) -> Self {
        match config {
            SecurityConfig::Plaintext => None,
            SecurityConfig::Tls { certs, alpn_protocols, min_version } => {
                let mut tls_settings = pingora::listeners::tls::TlsSettings::new();
                if alpn_protocols.is_some_and(|proto| proto == ALPN::H2H1) {
                    tls_settings.enable_h2();
                }

                tls_settings.set_cert(&certs.cert, &certs.key);
                tls_settings.set_policy(pingora::tls::S2NPolicy::from_version(min_version.to_s2n_policy()).unwrap()); // safety unwrap

                if let Some(ca) = certs.client_ca {
                    tls_settings.set_ca(pingora::protocols::tls::CaType::new(ca));
                }

                Some(tls_settings)
            },
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsCerts {
    pub cert: String,
    pub key: String,
    pub client_ca: Option<Vec<u8>>, // CLIENT PEM bytes
}

// ============================================================================
// TRANSPORT / PROTOCOL
// ============================================================================

/// ### Supported Input Syntaxes (`from -> to`):
///
/// | Input Format (`&str`) | Identified Type | Internal Behavior / Destination |
/// | :--- | :--- | :--- |
/// | `unix:/path/to/socket` | `NetworkTransport::Uds` | Unix Domain Sockets (Unix platforms only). |
/// | `:8080` / `:443` | `NetworkTransport::Tcp` | Short syntax. Maps to `0.0.0.0:PORT` (All interfaces). |
/// | `127.0.0.1:8080` | `NetworkTransport::Tcp` | Classic IP:Port pair (Supports structured IPv4 and IPv6). |
/// | `127.0.1.0` | `NetworkTransport::Tcp` | Raw IP without port. Assigns default port `80`. |
/// | `azure.com:443` | `NetworkTransport::Host` | DNS Domain name (Delegated to `HostAddr`). |
///
/// ### Constraints and Errors:
/// - Empty strings or strings consisting only of whitespace will return an error.
/// - Ports outside the mathematical 16-bit range ($1 \leq \text{port} \leq 65535$) will fail parsing.
/// - Port `0` is explicitly forbidden to prevent unpredictable dynamic Kernel assignments.
/// - Using the `unix:` prefix on unsupported operating systems (e.g., Windows) will return a compilation/runtime error.
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkTransport {
    Tcp(SocketAddr),
    Host(HostAddr),
    #[cfg(unix)] // only available in unix systems
    Uds(String),
}

impl FromStr for NetworkTransport {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        if value.is_empty() {
            return Err("network transport cannot be empty".to_string());
        }

        if let Some(path) = value.strip_prefix("unix:") {
            if path.is_empty() {
                return Err("invalid unix domain socket path, expected unix:/path/to/socket".to_string());
            }

            #[cfg(unix)]
            {
                return Ok(Self::Uds(path.into()));
            }

            #[cfg(not(unix))]
            {
                return Err(format!("unix domain sockets are not supported on this platform: '{value}'"));
            }
        }

        if let Some(port_str) = value.strip_prefix(':') {
            let port = port_str
                .parse::<u16>()
                .map_err(|_| format!("invalid port syntax or out of range (0-65535): '{value}'"))?;

            if port == 0 {
                return Err("port 0 is reserved and cannot be used for explicit routing".to_string());
            }

            return Ok(Self::Tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)));
        }

        if let Ok(addr) = value.parse::<SocketAddr>() {
            return Ok(Self::Tcp(addr));
        }

        if let Ok(ip) = value.parse::<IpAddr>() {
            return Ok(Self::Tcp(SocketAddr::new(ip, 80)));
        }

        let host = value.parse::<HostAddr>().map_err(|e| format!("invalid network address '{value}': {e}"))?;

        Ok(Self::Host(host))
    }
}

impl TryFrom<&str> for NetworkTransport {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl NetworkTransport {
    pub fn port(&self) -> Option<u16> {
        match self {
            Self::Tcp(addr) => Some(addr.port()),
            Self::Host(addr) => Some(addr.port),
            #[cfg(unix)]
            Self::Uds(_) => None,
        }
    }

    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            Self::Tcp(addr) => Some(addr.ip()),
            _ => None,
        }
    }

    pub fn host_str(&self) -> Option<&str> {
        match self {
            Self::Tcp(_) => None,
            Self::Host(addr) => Some(addr.host()),
            #[cfg(unix)]
            Self::Uds(path) => Some(path.as_str()),
        }
    }

    pub fn is_uds(&self) -> bool {
        #[cfg(unix)]
        {
            matches!(self, Self::Uds(_))
        }
        #[cfg(not(unix))]
        {
            false
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListenerAddress {
    Tcp(SocketAddr),
    #[cfg(unix)] // only available in unix systems
    Uds(String),
}

impl TryFrom<NetworkTransport> for ListenerAddress {
    type Error = String;

    fn try_from(value: NetworkTransport) -> Result<Self, Self::Error> {
        match value {
            NetworkTransport::Tcp(addr) => Ok(Self::Tcp(addr)),

            #[cfg(unix)]
            NetworkTransport::Uds(path) => Ok(Self::Uds(path)),
            NetworkTransport::Host(host) => Err(format!("listener addresses must use an IP address, got hostname '{}'", host)),
        }
    }
}

impl FromStr for ListenerAddress {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        ListenerAddress::try_from(NetworkTransport::from_str(value)?)
    }
}

impl TryFrom<&str> for ListenerAddress {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkProtocol {
    Http1 { allow_websocket_upgrade: bool },
    Http2 { mode: Http2Mode },
}

impl Default for NetworkProtocol {
    fn default() -> Self {
        Self::Http1 { allow_websocket_upgrade: false }
    }
}

impl NetworkProtocol {
    #[inline]
    pub const fn is_http1(&self) -> bool {
        matches!(self, Self::Http1 { .. })
    }

    #[inline]
    pub const fn is_http2(&self) -> bool {
        matches!(self, Self::Http2 { .. })
    }

    #[inline]
    pub const fn is_websocket(&self) -> bool {
        matches!(self, Self::Http1 { allow_websocket_upgrade: true })
    }

    #[inline]
    pub const fn is_grpc(&self) -> bool {
        matches!(self, Self::Http2 { mode: Http2Mode::Grpc })
    }

    #[inline]
    pub const fn http2_mode(&self) -> Option<Http2Mode> {
        match self {
            Self::Http2 { mode } => Some(*mode),
            _ => None,
        }
    }

    #[inline]
    pub const fn allow_websocket_upgrade(&self) -> bool {
        match self {
            Self::Http1 { allow_websocket_upgrade } => *allow_websocket_upgrade,
            _ => false,
        }
    }
}

impl FromStr for NetworkProtocol {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "http1" | "h1" => Ok(NetworkProtocol::Http1 { allow_websocket_upgrade: false }),
            "websocket" | "ws" => Ok(NetworkProtocol::Http1 { allow_websocket_upgrade: true }),
            "http2" | "h2" => Ok(NetworkProtocol::Http2 { mode: Http2Mode::Standard }),
            "grpc" => Ok(NetworkProtocol::Http2 { mode: Http2Mode::Grpc }),
            _ => Err(format!("invalid protocol '{s}': expected http1, http2, websocket, or grpc")),
        }
    }
}

impl TryFrom<&str> for NetworkProtocol {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Http2Mode {
    #[default]
    Standard,
    Grpc,
}

impl Http2Mode {
    pub const fn is_standard(self) -> bool {
        matches!(self, Self::Standard)
    }

    pub const fn is_grpc(self) -> bool {
        matches!(self, Self::Grpc)
    }
}

// ============================================================================
// LISTENER
// ============================================================================

#[derive(Debug, Clone)]
pub struct ListenerConfig {
    pub name: ImmerStr,
    pub address: ListenerAddress,
    pub protocols: Box<[NetworkProtocol]>,
    pub security: SecurityConfig,
    pub connection: ConnectionConfig,
    pub policy: Option<Arc<NetPolicy>>,
}

impl ListenerConfig {
    pub fn new(name: String, address: ListenerAddress) -> Self {
        Self {
            name: name.into(),
            address,
            protocols: vec![NetworkProtocol::default()].into_boxed_slice(),
            security: SecurityConfig::default(),
            connection: ConnectionConfig::default(),
            policy: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ConnectionConfig {
    pub max_connections: Option<u32>,
    pub max_request_size: Option<ByteSize>,

    pub idle_timeout: Option<Duration>,
    pub keepalive_timeout: Option<Duration>,
}

// ============================================================================
// UPSTREAM
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub struct UpstreamId(pub usize);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamAddress {
    Tcp(SocketAddr),
    Host(HostAddr),

    #[cfg(unix)] // only available in unix systems
    Uds(String),
}

impl From<NetworkTransport> for UpstreamAddress {
    fn from(value: NetworkTransport) -> Self {
        match value {
            NetworkTransport::Tcp(addr) => Self::Tcp(addr),
            NetworkTransport::Host(host) => Self::Host(host),

            #[cfg(unix)]
            NetworkTransport::Uds(path) => Self::Uds(path),
        }
    }
}

impl TryFrom<&str> for UpstreamAddress {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(UpstreamAddress::from(NetworkTransport::from_str(value)?))
    }
}

#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    pub id: UpstreamId,
    pub name: ImmerStr,
    pub servers: Box<[UpstreamServer]>,
    pub tls: Option<UpstreamTlsConfig>,
    pub balance_strategy: BalanceStrategy,
    pub health_check: Option<HealthCheckConfig>, // Onlly when server list is greather than 1
    pub circuit_breaker: Option<CircuitBreakerConfig>, // Promoted from planned
    pub discovery: Option<DiscoveryConfig>,
}

#[derive(Debug, Clone)]
pub struct UpstreamServer {
    pub address: UpstreamAddress,
    pub protocol: NetworkProtocol,
    pub weight: u32,
}

impl UpstreamServer {
    pub fn new(address: UpstreamAddress) -> Self {
        Self { address, protocol: NetworkProtocol::default(), weight: 1 }
    }
}

#[derive(Debug, Clone, Default)]
pub struct UpstreamTlsConfig {
    pub insecure_skip_verify: bool,
    pub hosts: Option<Box<[String]>>,
    pub ca_cert: Option<Box<[u8]>>,
    pub client_cert: Option<Box<[u8]>>,
    pub client_key: Option<Box<[u8]>>,
}

/// Health check configuration for upstream servers (path, interval, thresholds).
#[derive(Debug, Clone)]
pub struct HealthCheckConfig {
    pub path: String,
    pub interval: Duration,
    pub timeout: Duration,
    pub unhealthy_threshold: u32,
    pub healthy_threshold: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct CircuitBreakerConfig {
    pub consecutive_failures: u32,
    pub ejection_time: Duration,
    pub max_ejection_percent: u32,
}

#[derive(Debug, Clone)]
pub enum DiscoveryDriver {
    Dns {
        nameserver: Option<String>,
        refresh_interval: Duration,
    },
    Consul {
        endpoint: String,
        datacenter: Option<String>,
        refresh_interval: Duration,
    },
    Etcd {
        endpoints: Box<[String]>,
        refresh_interval: Duration,
    },
    Custom(ImmerStr),
}

#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    pub driver: DiscoveryDriver,
    pub security: Option<RegistrySecurityConfig>,
}

#[derive(Debug, Clone)]
pub enum RegistrySecurityConfig {
    Mtls { cert: Box<[u8]>, key: Box<[u8]>, client_ca: Box<[u8]> },
    ApiKey { key: String, algo: String },
}

// ============================================================================
// STATIC BACKEND
// ============================================================================

#[derive(Debug, Clone)]
pub enum StaticUpstream {
    Local(ophan_static::ServeConfig),
}

// ============================================================================
// BACKEND TARGET
// ============================================================================

#[derive(Debug, Clone)]
pub enum BackendTarget {
    Static(Arc<StaticUpstream>),
    Upstream(Arc<UpstreamConfig>),
}

// ============================================================================
// ROUTE
// ============================================================================

#[derive(Debug, Clone)]
pub struct RoutesConfig {
    pub path: String,
    pub hosts: Box<[String]>,
    pub methods: HttpMethodSet,
    pub protocols: Box<[NetworkProtocol]>,
    pub backend: BackendTarget,

    // resolved policy configs
    pub auth: Option<Arc<AuthConfig>>,
    pub waf: Option<Arc<WafConfig>>,
    pub cors: Option<Arc<CorsConfig>>,
    pub limiter: Option<Arc<LimiterConfig>>,

    pub rewrite: Option<RouteRewrites>,
    pub headers: Option<HeaderMutations>,
    pub timeouts: Option<RouteTimeouts>,
    pub streaming: Option<RouteStreaming>,
}

#[derive(Debug, Clone)]
pub struct RouteRewrites {
    pub strip_prefix: Option<String>,
    pub strip_suffix: Option<String>,
    pub replaces: Vec<(String, String)>,
    pub trailing_slash: Option<TrailingSlashAction>,
}

#[derive(Debug, Clone, Default)]
pub struct RouteTimeouts {
    pub connect: Option<Duration>,
    pub read: Option<Duration>,
    pub send: Option<Duration>,
    pub idle: Option<Duration>,
    pub total_connect: Option<Duration>,
}

#[derive(Debug, Clone, Copy)]
pub struct RouteStreaming {
    pub buffering: bool,
    pub chunked: bool,
}

#[derive(Debug, Clone, Default)]
pub struct HeaderMutations {
    pub inbound: InboundHeaderMutations,
    pub outbound: OutboundHeaderMutations,
}

#[derive(Debug, Clone, Default)]
pub struct InboundHeaderMutations {
    pub client_set: AHashMap<HeaderName, HeaderValue>,
    pub client_remove: Box<[HeaderName]>,

    pub to_upstream_set: AHashMap<HeaderName, HeaderValue>,
    pub to_upstream_remove: Box<[HeaderName]>,
}

#[derive(Debug, Clone, Default)]
pub struct OutboundHeaderMutations {
    pub from_upstream_set: AHashMap<HeaderName, HeaderValue>,
    pub from_upstream_remove: Box<[HeaderName]>,

    pub client_set: AHashMap<HeaderName, HeaderValue>,
    pub client_remove: Box<[HeaderName]>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------------
    // NetworkTransport
    // ---------------------------------------------------------------------------

    #[test]
    fn test_transport_short_port() {
        let t = NetworkTransport::try_from(":8080").unwrap();
        assert_eq!(
            t,
            NetworkTransport::Tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080))
        );
    }

    #[test]
    fn test_transport_ip_port() {
        let t = NetworkTransport::try_from("127.0.0.1:9090").unwrap();
        assert_eq!(
            t,
            NetworkTransport::Tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9090))
        );
    }

    #[test]
    fn test_transport_raw_ip_default_port() {
        let t = NetworkTransport::try_from("192.168.1.1").unwrap();
        assert_eq!(
            t,
            NetworkTransport::Tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 80))
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_transport_uds() {
        let t = NetworkTransport::try_from("unix:/tmp/foo.sock").unwrap();
        assert_eq!(t, NetworkTransport::Uds("/tmp/foo.sock".into()));
    }

    #[cfg(not(unix))]
    #[test]
    fn test_transport_uds_not_supported() {
        let err = NetworkTransport::try_from("unix:/tmp/foo.sock").unwrap_err();
        assert!(err.contains("not supported"));
    }

    #[test]
    fn test_transport_host() {
        let t = NetworkTransport::try_from("example.com:443").unwrap();
        assert_eq!(t, NetworkTransport::Host("example.com:443".parse::<HostAddr>().unwrap()));
    }

    #[test]
    fn test_transport_port_zero_rejected() {
        let err = NetworkTransport::try_from(":0").unwrap_err();
        assert!(err.contains("port 0"));
    }

    #[test]
    fn test_transport_empty_rejected() {
        let err = NetworkTransport::try_from("").unwrap_err();
        assert!(err.contains("cannot be empty"));
    }

    #[test]
    fn test_transport_invalid_port() {
        let err = NetworkTransport::try_from(":abc").unwrap_err();
        assert!(err.contains("invalid port"));
    }

    #[test]
    fn test_transport_empty_uds_path() {
        let err = NetworkTransport::try_from("unix:").unwrap_err();
        assert!(err.contains("invalid unix domain socket path"));
    }

    // ---------------------------------------------------------------------------
    // ListenerAddress
    // ---------------------------------------------------------------------------

    #[test]
    fn test_listener_address_from_tcp() {
        let nt = NetworkTransport::try_from("0.0.0.0:443").unwrap();
        let addr = ListenerAddress::try_from(nt).unwrap();
        assert_eq!(
            addr,
            ListenerAddress::Tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 443))
        );
    }

    #[test]
    fn test_listener_address_rejects_hostname() {
        let nt = NetworkTransport::try_from("example.com:80").unwrap();
        let err = ListenerAddress::try_from(nt).unwrap_err();
        assert!(err.contains("hostname"));
    }

    #[cfg(unix)]
    #[test]
    fn test_listener_address_from_uds() {
        let nt = NetworkTransport::try_from("unix:/run/ophan.sock").unwrap();
        let addr = ListenerAddress::try_from(nt).unwrap();
        assert_eq!(addr, ListenerAddress::Uds("/run/ophan.sock".into()));
    }

    #[test]
    fn test_listener_address_from_str_tcp() {
        let addr = ListenerAddress::try_from("127.0.0.1:3000").unwrap();
        assert_eq!(
            addr,
            ListenerAddress::Tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 3000))
        );
    }

    // ---------------------------------------------------------------------------
    // NetworkProtocol
    // ---------------------------------------------------------------------------

    #[test]
    fn test_protocol_http1() {
        let p = NetworkProtocol::try_from("http1").unwrap();
        assert_eq!(p, NetworkProtocol::Http1 { allow_websocket_upgrade: false });
    }

    #[test]
    fn test_protocol_h1() {
        let p = NetworkProtocol::try_from("h1").unwrap();
        assert_eq!(p, NetworkProtocol::Http1 { allow_websocket_upgrade: false });
    }

    #[test]
    fn test_protocol_websocket() {
        let p = NetworkProtocol::try_from("websocket").unwrap();
        assert_eq!(p, NetworkProtocol::Http1 { allow_websocket_upgrade: true });
    }

    #[test]
    fn test_protocol_ws() {
        let p = NetworkProtocol::try_from("ws").unwrap();
        assert_eq!(p, NetworkProtocol::Http1 { allow_websocket_upgrade: true });
    }

    #[test]
    fn test_protocol_http2() {
        let p = NetworkProtocol::try_from("http2").unwrap();
        assert_eq!(p, NetworkProtocol::Http2 { mode: Http2Mode::Standard });
    }

    #[test]
    fn test_protocol_h2() {
        let p = NetworkProtocol::try_from("h2").unwrap();
        assert_eq!(p, NetworkProtocol::Http2 { mode: Http2Mode::Standard });
    }

    #[test]
    fn test_protocol_grpc() {
        let p = NetworkProtocol::try_from("grpc").unwrap();
        assert_eq!(p, NetworkProtocol::Http2 { mode: Http2Mode::Grpc });
    }

    #[test]
    fn test_protocol_invalid() {
        let err = NetworkProtocol::try_from("quic").unwrap_err();
        assert!(err.contains("invalid protocol"));
    }

    // ---------------------------------------------------------------------------
    // UpstreamAddress
    // ---------------------------------------------------------------------------

    #[test]
    fn test_upstream_address_tcp() {
        let ua = UpstreamAddress::try_from("10.0.0.1:3000").unwrap();
        assert_eq!(
            ua,
            UpstreamAddress::Tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 3000))
        );
    }

    #[test]
    fn test_upstream_address_host() {
        let ua = UpstreamAddress::try_from("upstream.example.com:8080").unwrap();
        assert_eq!(
            ua,
            UpstreamAddress::Host("upstream.example.com:8080".parse::<HostAddr>().unwrap())
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_upstream_address_uds() {
        let ua = UpstreamAddress::try_from("unix:/var/run/upstream.sock").unwrap();
        assert_eq!(ua, UpstreamAddress::Uds("/var/run/upstream.sock".into()));
    }

    // ---------------------------------------------------------------------------
    // Defaults
    // ---------------------------------------------------------------------------

    #[test]
    fn test_network_protocol_default() {
        let p = NetworkProtocol::default();
        assert_eq!(p, NetworkProtocol::Http1 { allow_websocket_upgrade: false });
    }

    #[test]
    fn test_security_config_default() {
        assert_eq!(SecurityConfig::default(), SecurityConfig::Plaintext);
    }

    #[test]
    fn test_balance_strategy_default() {
        assert_eq!(BalanceStrategy::default(), BalanceStrategy::RoundRobin);
    }

    #[test]
    fn test_tls_version_default() {
        assert_eq!(TlsVersion::default(), TlsVersion::Tls12);
    }
}
