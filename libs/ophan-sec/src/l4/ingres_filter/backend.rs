use flatkit::net::IpNet;
use std::net::IpAddr;

/// Backend responsible for storing and evaluating ingress ACL rules.
///
/// Implementations must treat **deny** rules as highest priority.
/// A global rule (no port) applies to every port. A port-specific rule
/// only affects the given port.
pub trait IngressBackend {
    type Error;

    // ------------------------------------------------------------------
    // Global rules (apply to all ports)
    // ------------------------------------------------------------------

    /// Allow the given network/CIDR/IP for every port.
    fn allow(&mut self, network: impl Into<IpNet>) -> Result<(), Self::Error>;

    /// Remove a previously allowed global network.
    fn remove_allow(&mut self, network: impl Into<IpNet>) -> Result<(), Self::Error>;

    /// Deny the given network/CIDR/IP for every port.
    /// Deny always takes precedence over any allow rule.
    fn deny(&mut self, network: impl Into<IpNet>) -> Result<(), Self::Error>;

    /// Remove a previously denied global network.
    fn remove_deny(&mut self, network: impl Into<IpNet>) -> Result<(), Self::Error>;

    // ------------------------------------------------------------------
    // Port-specific rules
    // ------------------------------------------------------------------

    /// Allow the given network only on the specified port.
    fn allow_on(&mut self, network: impl Into<IpNet>, port: u16) -> Result<(), Self::Error>;

    /// Remove a previously allowed port-specific network.
    fn remove_allow_on(&mut self, network: impl Into<IpNet>, port: u16) -> Result<(), Self::Error>;

    /// Deny the given network only on the specified port.
    fn deny_on(&mut self, network: impl Into<IpNet>, port: u16) -> Result<(), Self::Error>;

    /// Remove a previously denied port-specific network.
    fn remove_deny_on(&mut self, network: impl Into<IpNet>, port: u16) -> Result<(), Self::Error>;

    // ------------------------------------------------------------------
    // Listener ports
    // ------------------------------------------------------------------

    /// Register a port that this filter should accept traffic on.
    fn allow_port(&mut self, port: u16) -> Result<(), Self::Error>;

    /// Unregister a previously allowed listener port.
    fn remove_port(&mut self, port: u16) -> Result<(), Self::Error>;

    // ------------------------------------------------------------------
    // Queries (hot path)
    // ------------------------------------------------------------------

    /// Returns `true` if the port is registered as an active listener.
    fn matches_port(&self, port: u16) -> bool;

    /// Returns `true` if the IP is denied (globally or on the given port).
    ///
    /// `port = None` only checks global deny rules.
    fn is_denied(&self, client_ip: IpAddr, port: Option<u16>) -> bool;

    /// Returns `true` if the IP is allowed (globally or on the given port).
    ///
    /// `port = None` only checks global allow rules.
    /// Does **not** consult deny lists; callers must check `is_denied` first.
    fn is_allowed(&self, client_ip: IpAddr, port: Option<u16>) -> bool;
}
