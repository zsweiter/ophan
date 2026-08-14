mod backend;
mod erros;
mod healthcheck;
mod upstream;

use arc_swap::ArcSwap;
use std::{net::IpAddr, str::FromStr, sync::Arc};

pub use backend::{Backend, BackendAddr};
pub use erros::BalancerError;
pub use healthcheck::HealthScheduler;
pub use upstream::{HealthConfig, Upstream, UpstreamId};

/// Load balancing strategy for upstream server selection.
#[derive(Debug, Clone, Default, PartialEq, Eq, Copy)]
pub enum BalanceStrategy {
    #[default]
    RoundRobin,
    // WeightedRoundRobin,
    LeastConnections,
    IpHash,
}

impl FromStr for BalanceStrategy {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "round_robin" | "round-robin" => Ok(Self::RoundRobin),
            // "weighted_round_robin" | "weighted-round-robin" => Ok(Self::WeightedRoundRobin),
            "least_connections" | "least-connections" => Ok(Self::LeastConnections),
            "ip_hash" | "ip-hash" => Ok(Self::IpHash),
            _ => Err(format!(
                "invalid load_balance strategy '{value}', expected one of: round_robin, weighted_round_robin, least_connections, ip_hash"
            )),
        }
    }
}

impl TryFrom<&str> for BalanceStrategy {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<BalanceStrategy> for &'static str {
    fn from(value: BalanceStrategy) -> Self {
        match value {
            BalanceStrategy::RoundRobin => "round_robin",
            // BalanceStrategy::WeightedRoundRobin => "weighted_round_robin",
            BalanceStrategy::LeastConnections => "least_connections",
            BalanceStrategy::IpHash => "ip_hash",
        }
    }
}

#[derive(Debug)]
pub struct LoadBalancer {
    upstreams: ArcSwap<Vec<Upstream>>,
}

impl LoadBalancer {
    pub fn new(upstreams: Vec<Upstream>) -> Self {
        Self { upstreams: ArcSwap::new(Arc::new(upstreams)) }
    }

    // Updates the list of upstreams in the load balancer.
    // This method replaces the entire list of upstreams with a new one.
    // It is expected to be called when the configuration changes, and it should be called
    // infrequently, as it may be a relatively expensive operation.
    pub fn update_upstreams(&self, new_upstreams: Vec<Upstream>) {
        self.upstreams.store(Arc::new(new_upstreams));
    }

    #[inline]
    pub fn select_backend(&self, upstream_id: usize, client_ip: IpAddr) -> Result<Arc<Backend>, BalancerError> {
        let snapshot = self.upstreams.load();

        debug_assert!(
            upstream_id < snapshot.len(),
            "upstream_id {} is out of bounds for upstreams list of length {}",
            upstream_id,
            snapshot.len()
        );

        let upstream = &snapshot[upstream_id];
        let backends = upstream.servers.load();

        // Short circuit when backends is empty
        if backends.is_empty() {
            return Err(BalancerError::UpstreamEmpty);
        }

        match Self::next_backend(upstream, &backends, client_ip) {
            None => Err(BalancerError::AllServersUnhealthy),
            Some(backend) => {
                backend.acquire();
                backend.record_request();

                Ok(backend)
            },
        }
    }

    fn next_backend(upstream: &Upstream, backends: &[Arc<Backend>], client_ip: IpAddr) -> Option<Arc<Backend>> {
        let backend_len = backends.len();

        // Short circuit when there is only one backend, to avoid unnecessary hashing or iteration.
        if backend_len == 1 {
            let backend = &backends[0];
            if backend.is_healthy() {
                return Some(Arc::clone(backend));
            } else {
                return None;
            }
        }

        match upstream.balance_strategy {
            // Static loand balacing
            BalanceStrategy::IpHash => {
                let mut hash = flatkit::net::hash_ip(client_ip);

                for _ in 0..backend_len {
                    let idx = hash % backend_len;

                    // SAFETY: `idx` is guaranteed to be within bounds because the modulo
                    // operation limits its value to the range `0..backend_len`.
                    let candidate = unsafe { backends.get_unchecked(idx) };
                    if candidate.is_healthy() {
                        return Some(Arc::clone(candidate));
                    }

                    hash = hash.wrapping_add(1);
                }

                None
            },

            BalanceStrategy::RoundRobin => {
                let ticket = upstream.next_ticket();
                let start_idx = ticket % backend_len;

                // SAFETY: `start_idx` is guaranteed to be within bounds because it is
                // the result of a modulo operation by `backend_len`, which is strictly greater than 0.
                let candidate = unsafe { backends.get_unchecked(start_idx) };
                if candidate.is_healthy() {
                    return Some(Arc::clone(candidate));
                }

                for i in 1..backend_len {
                    let next_idx = (start_idx + i) % backend_len;

                    // SAFETY: `next_idx` is guaranteed to be within bounds because it is
                    // constrained by the modulo operation `% backend_len`.
                    let candidate = unsafe { backends.get_unchecked(next_idx) };
                    if candidate.is_healthy() {
                        return Some(Arc::clone(candidate));
                    }
                }

                None
            },

            // BalanceStrategy::WeightedRoundRobin => {
            //     let ticket = upstream.next_ticket();

            //     let total_weight: u32 = backends.iter().filter(|b| b.is_healthy()).map(|b| b.weight()).sum();

            //     if total_weight == 0 {
            //         return None;
            //     }

            //     let mut chosen = (ticket as u32) % total_weight;

            //     for backend in backends.iter() {
            //         if !backend.is_healthy() {
            //             continue;
            //         }
            //         let w = backend.weight();
            //         if chosen < w {
            //             return Some(Arc::clone(backend));
            //         }
            //         chosen -= w;
            //     }

            //     None
            // },

            // Dynamic load balancing
            BalanceStrategy::LeastConnections => {
                let ticket = upstream.next_ticket();

                // Both idx1 and idx2 are strictly bounded by modulo `len`.
                let idx1 = ticket % backend_len;
                let idx2 = (ticket + (backend_len / 2)) % backend_len;

                // SAFETY: We just enforced that idx1 and idx2 are strictly less than `backends.len()`
                // via the modulo operator.
                let (b1, b2) = unsafe { (backends.get_unchecked(idx1), backends.get_unchecked(idx2)) };

                let h1 = b1.is_healthy();
                let h2 = b2.is_healthy();

                match (h1, h2) {
                    (true, true) => {
                        if b1.active_conns() <= b2.active_conns() {
                            Some(Arc::clone(b1))
                        } else {
                            Some(Arc::clone(b2))
                        }
                    },
                    (true, false) => Some(Arc::clone(b1)),
                    (false, true) => Some(Arc::clone(b2)),
                    (false, false) => {
                        // Degraded Path: Iterators inherently skip bounds checks in Rust
                        backends.iter().find(|b| b.is_healthy()).map(Arc::clone)
                    },
                }
            },
        }
    }
}

#[cfg(test)]
mod lb_tests {
    use super::*;

    #[test]
    fn test_balance_strategy_round_robin() {
        for s in &["round_robin", "round-robin"] {
            assert_eq!(BalanceStrategy::from_str(s).unwrap(), BalanceStrategy::RoundRobin);
        }
    }

    #[test]
    fn test_balance_strategy_least_connections() {
        for s in &["least_connections", "least-connections"] {
            assert_eq!(BalanceStrategy::from_str(s).unwrap(), BalanceStrategy::LeastConnections);
        }
    }

    #[test]
    fn test_balance_strategy_ip_hash() {
        for s in &["ip_hash", "ip-hash"] {
            assert_eq!(BalanceStrategy::from_str(s).unwrap(), BalanceStrategy::IpHash);
        }
    }

    #[test]
    fn test_balance_strategy_invalid() {
        let err = BalanceStrategy::from_str("random").unwrap_err();
        assert!(err.contains("invalid load_balance strategy"));
    }

    #[test]
    fn test_balance_strategy_into_static_str() {
        let s: &'static str = BalanceStrategy::RoundRobin.into();
        assert_eq!(s, "round_robin");
        let s: &'static str = BalanceStrategy::LeastConnections.into();
        assert_eq!(s, "least_connections");
        let s: &'static str = BalanceStrategy::IpHash.into();
        assert_eq!(s, "ip_hash");
    }
}
