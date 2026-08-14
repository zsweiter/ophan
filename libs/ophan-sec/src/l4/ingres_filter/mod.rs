use ahash::AHashSet;
use flatkit::net::IpNet;
use std::net::IpAddr;

use backend::IngressBackend;

mod backend;
mod software;

#[cfg(all(target_os = "linux", feature = "xdp"))]
mod xdp;

/// Final decision returned by the filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketAction {
    PASS,
    DROP,
}

impl PacketAction {
    #[inline]
    pub const fn is_pass(self) -> bool {
        matches!(self, Self::PASS)
    }
}

/// Current operational status of the filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    #[cfg(all(target_os = "linux", feature = "xdp"))]
    XdpActive {
        iface: String,
    },
    // Because firt option is xdp
    SoftwareFallback {
        reason: String,
    },
}

#[derive(Debug)]
enum Backend {
    #[cfg(all(target_os = "linux", feature = "xdp"))]
    Xdp(Box<xdp::XdpBackend>),
    Software(Box<software::SoftwareBackend>),
}

/// High-level ingress filter that can run on top of a software backend
/// or an XDP backend (when available).
#[derive(Debug)]
pub struct IngressFilter {
    backend: Backend,
    #[cfg(all(target_os = "linux", feature = "xdp"))]
    iface: Option<String>,
}

impl IngressFilter {
    /// Returns a new builder.
    pub fn builder() -> IngressFilterBuilder {
        IngressFilterBuilder {
            #[cfg(all(target_os = "linux", feature = "xdp"))]
            iface: None,
            ports: AHashSet::default(),
            allowed: Vec::new(),
            blocked: Vec::new(),
            allowed_on: Vec::new(),
            blocked_on: Vec::new(),
        }
    }

    /// Returns the current status of the filter.
    pub fn status(&self) -> Status {
        match &self.backend {
            #[cfg(all(target_os = "linux", feature = "xdp"))]
            Backend::Xdp(_) => Status::XdpActive { iface: self.iface.clone().unwrap_or_default() },
            Backend::Software(_) => Status::SoftwareFallback { reason: "XDP not available or failed to load".into() },
        }
    }

    /// Evaluates a packet. `port = None` only applies global rules.
    #[inline]
    pub fn filter(&self, ip: IpAddr, port: Option<u16>) -> PacketAction {
        match &self.backend {
            Backend::Software(b) => {
                if b.is_denied(ip, port) {
                    return PacketAction::DROP;
                }

                if port.is_some_and(|p| b.matches_port(p)) {
                    return PacketAction::DROP;
                }

                if b.is_allowed(ip, port) {
                    PacketAction::PASS
                } else {
                    PacketAction::DROP
                }
            },
            #[cfg(all(target_os = "linux", feature = "xdp"))]
            Backend::Xdp(_) => PacketAction::PASS, // XDP decides in-kernel
        }
    }

    // ------------------------------------------------------------------
    // Runtime mutation API
    // ------------------------------------------------------------------

    /// Allow a network globally (all ports).
    pub fn allow(&mut self, network: impl Into<IpNet>) -> Result<(), String> {
        let net = network.into();
        match &mut self.backend {
            Backend::Software(b) => b.allow(net),
            #[cfg(all(target_os = "linux", feature = "xdp"))]
            Backend::Xdp(b) => b.allow(net),
        }
    }

    /// Allow a network only on the given port.
    pub fn allow_on(&mut self, network: impl Into<IpNet>, port: u16) -> Result<(), String> {
        let net = network.into();
        match &mut self.backend {
            Backend::Software(b) => b.allow_on(net, port),
            #[cfg(all(target_os = "linux", feature = "xdp"))]
            Backend::Xdp(b) => b.allow_on(net, port),
        }
    }

    /// Deny a network globally.
    pub fn deny(&mut self, network: impl Into<IpNet>) -> Result<(), String> {
        let net = network.into();
        match &mut self.backend {
            Backend::Software(b) => b.deny(net),
            #[cfg(all(target_os = "linux", feature = "xdp"))]
            Backend::Xdp(b) => b.deny(net),
        }
    }

    /// Deny a network only on the given port.
    pub fn deny_on(&mut self, network: impl Into<IpNet>, port: u16) -> Result<(), String> {
        let net = network.into();
        match &mut self.backend {
            Backend::Software(b) => b.deny_on(net, port),
            #[cfg(all(target_os = "linux", feature = "xdp"))]
            Backend::Xdp(b) => b.deny_on(net, port),
        }
    }

    pub fn remove_allow(&mut self, network: impl Into<IpNet>) -> Result<(), String> {
        let net = network.into();
        match &mut self.backend {
            Backend::Software(b) => b.remove_allow(net),
            #[cfg(all(target_os = "linux", feature = "xdp"))]
            Backend::Xdp(b) => b.remove_allow(net),
        }
    }

    pub fn remove_allow_on(&mut self, network: impl Into<IpNet>, port: u16) -> Result<(), String> {
        let net = network.into();
        match &mut self.backend {
            Backend::Software(b) => b.remove_allow_on(net, port),
            #[cfg(all(target_os = "linux", feature = "xdp"))]
            Backend::Xdp(b) => b.remove_allow_on(net, port),
        }
    }

    pub fn remove_deny(&mut self, network: impl Into<IpNet>) -> Result<(), String> {
        let net = network.into();
        match &mut self.backend {
            Backend::Software(b) => b.remove_deny(net),
            #[cfg(all(target_os = "linux", feature = "xdp"))]
            Backend::Xdp(b) => b.remove_deny(net),
        }
    }

    pub fn remove_deny_on(&mut self, network: impl Into<IpNet>, port: u16) -> Result<(), String> {
        let net = network.into();
        match &mut self.backend {
            Backend::Software(b) => b.remove_deny_on(net, port),
            #[cfg(all(target_os = "linux", feature = "xdp"))]
            Backend::Xdp(b) => b.remove_deny_on(net, port),
        }
    }

    pub fn add_port(&mut self, port: u16) -> Result<(), String> {
        match &mut self.backend {
            Backend::Software(b) => b.allow_port(port),
            #[cfg(all(target_os = "linux", feature = "xdp"))]
            Backend::Xdp(b) => b.allow_port(port),
        }
    }

    pub fn remove_port(&mut self, port: u16) -> Result<(), String> {
        match &mut self.backend {
            Backend::Software(b) => b.remove_port(port),
            #[cfg(all(target_os = "linux", feature = "xdp"))]
            Backend::Xdp(b) => b.remove_port(port),
        }
    }
}

/// Builder for [`IngressFilter`].
///
/// Provides a fluent API to configure the filter with ports, allowed and
/// blocked networks before constructing it.
///
/// ```ignore
/// let filter = IngressFilter::builder()
///     .iface("eth0")
///     .port(443)
///     .port(80)
///     .allow("10.0.0.0/8")
///     .block("192.168.1.1")
///     .build();
/// ```
pub struct IngressFilterBuilder {
    #[cfg(all(target_os = "linux", feature = "xdp"))]
    iface: Option<String>,
    ports: AHashSet<u16>,
    allowed: Vec<IpNet>,
    blocked: Vec<IpNet>,
    /// (network, port)
    allowed_on: Vec<(IpNet, u16)>,
    blocked_on: Vec<(IpNet, u16)>,
}

impl IngressFilterBuilder {
    /// Sets the network interface for XDP attachment.
    ///
    /// When set, the builder will attempt XDP before falling back to software.
    #[cfg(all(target_os = "linux", feature = "xdp"))]
    pub fn iface(mut self, iface: &str) -> Self {
        self.iface = Some(iface.to_string());
        self
    }

    /// Registers a listener port.
    pub fn port(mut self, port: u16) -> Self {
        self.ports.insert(port);
        self
    }

    /// Registers multiple listener ports.
    pub fn ports(mut self, ports: &[u16]) -> Self {
        self.ports.extend(ports.iter().copied());
        self
    }

    /// Allows a network globally (all ports).
    pub fn allow(mut self, network: impl Into<IpNet>) -> Self {
        self.allowed.push(network.into());
        self
    }

    /// Allows multiple networks globally via an iterator of `(network, port)` pairs.
    pub fn allow_on_iter<I>(mut self, iter: I) -> Self
    where
        I: IntoIterator<Item = (IpNet, u16)>,
    {
        for (network, port) in iter {
            self.allowed_on.push((network, port));
        }
        self
    }

    /// Allows a network only on the given port.
    pub fn allow_on(mut self, network: impl Into<IpNet>, port: u16) -> Self {
        self.allowed_on.push((network.into(), port));
        self
    }

    /// Denies a network globally.
    pub fn deny(mut self, network: impl Into<IpNet>) -> Self {
        self.blocked.push(network.into());
        self
    }

    /// Denies multiple networks globally via an iterator of `(network, port)` pairs.
    pub fn deny_on_iter<I>(mut self, iter: I) -> Self
    where
        I: IntoIterator<Item = (IpNet, u16)>,
    {
        for (network, port) in iter {
            self.blocked_on.push((network, port));
        }
        self
    }

    /// Denies a network only on the given port.
    pub fn deny_on(mut self, network: impl Into<IpNet>, port: u16) -> Self {
        self.blocked_on.push((network.into(), port));
        self
    }

    /// Builds the [`IngressFilter`].
    ///
    /// If an interface was specified via [`iface`](Self::iface), an XDP
    /// program is loaded and attached. On failure the filter falls back
    /// to the software backend.
    pub fn build(self) -> Result<IngressFilter, String> {
        let ports: Vec<u16> = self.ports.into_iter().collect();
        let allowed = self.allowed;
        let blocked = self.blocked;
        let allowed_on = self.allowed_on;
        let blocked_on = self.blocked_on;

        #[cfg(all(target_os = "linux", feature = "xdp"))]
        if let Some(iface) = self.iface {
            return Self::try_xdp(&iface, ports, allowed, blocked, allowed_on, blocked_on);
        }

        Ok(Self::build_software_impl(ports, allowed, blocked, allowed_on, blocked_on))
    }

    #[cfg(all(target_os = "linux", feature = "xdp"))]
    fn try_xdp(
        iface: &str,
        ports: Vec<u16>,
        allowed: Vec<IpNet>,
        blocked: Vec<IpNet>,
        allowed_on: Vec<(IpNet, u16)>,
        blocked_on: Vec<(IpNet, u16)>,
    ) -> Result<IngressFilter, String> {
        use aya::programs::XdpMode;

        match xdp::XdpBackend::from_config("xdp_ingress", &ports, &allowed, &blocked, &allowed_on, &blocked_on) {
            Ok(mut xdp) => match xdp.attach(iface, XdpMode::default()) {
                Ok(()) => {
                    eprintln!("[ophan-waf] XDP attached to interface {}", iface);
                    Ok(IngressFilter {
                        backend: Backend::Xdp(Box::new(xdp)),
                        iface: Some(iface.to_string()),
                    })
                },
                Err(e) => {
                    eprintln!(
                        "[ophan-waf] XDP attach failed on {}: {} — falling back to software filter. \
                         To use XDP, run with elevated privileges.",
                        iface, e
                    );
                    Ok(Self::build_software_impl(ports, allowed, blocked, allowed_on, blocked_on))
                },
            },
            Err(e) => {
                eprintln!("[ophan-waf] XDP load failed: {} — falling back to software filter", e);
                Ok(Self::build_software_impl(ports, allowed, blocked, allowed_on, blocked_on))
            },
        }
    }

    fn build_software_impl(
        ports: Vec<u16>,
        allowed: Vec<IpNet>,
        blocked: Vec<IpNet>,
        allowed_on: Vec<(IpNet, u16)>,
        blocked_on: Vec<(IpNet, u16)>,
    ) -> IngressFilter {
        let backend = software::SoftwareBackend::from_config(&ports, &allowed, &blocked, &allowed_on, &blocked_on);
        eprintln!("[ophan-waf] Using software ingress filter");

        IngressFilter {
            backend: Backend::Software(Box::new(backend)),
            #[cfg(all(target_os = "linux", feature = "xdp"))]
            iface: None,
        }
    }
}
