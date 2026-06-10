use pest::Parser;
use pest_derive::Parser;
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use ophan_net::http::{HttpMethod, HttpMethodSet};

use crate::config::parts::{
    BackendTarget, BalanceStrategy, CorsConfig, GatewayConfig, HealthCheckConfig, Http2Mode, LimiterConfig, LimiterIdentifier,
    LimiterRate, ListenerConfig, NetworkProtocol, NetworkTransport, OAuthConfig, PolicyConfig, RateLimitAlgorithm,
    RefreshTokenConfig, RouteAuthPolicy, RouteCorsPolicy, RouteLimiterPolicy, RouteRewrites, RouteStreaming, RouteTimeouts,
    RouteWafPolicy, RoutesConfig, SSLConfig, SecurityConfig, StaticUpstream, TlsVersion, TokenSource, UpstreamConfig,
    UpstreamServer,
};

use ophan_waf::config::{WafAction, WafCondition, WafConfig, WafMode, WafPhase, WafRule};

#[derive(Parser)]
#[grammar = "../ophan_grammar.pest"]
pub struct OphanConfigParser;

#[derive(Clone)]
pub struct MasterConfig {
    pub name: String,
    pub user: String,
    #[allow(unused)]
    pub workers: String,
    pub pid: String,
    pub error_log: String,
    pub includes: Vec<String>,
}

pub fn parse_master_config(input: &str) -> Result<MasterConfig, Box<dyn std::error::Error>> {
    let mut parsed = OphanConfigParser::parse(Rule::master_file, input)?;
    let root = parsed.next().unwrap();
    let master_block = root.into_inner().next().unwrap();
    let mut inner = master_block.into_inner();

    let name = extract_string(inner.next().unwrap());
    let mut user = String::from("www-data");
    let mut workers = String::from("auto");
    let mut pid = String::from("/run/ophan.pid");
    let mut error_log = String::from("/var/log/ophan/error.log");
    let mut includes = Vec::new();

    for entry in inner {
        match entry.as_rule() {
            Rule::master_user => {
                user = extract_string(entry.into_inner().next().ok_or("master: expected user value")?);
            },
            Rule::master_workers => {
                workers = extract_string(entry.into_inner().next().ok_or("master: expected workers value")?);
            },
            Rule::master_pid => {
                pid = extract_string(entry.into_inner().next().ok_or("master: expected pid value")?);
            },
            Rule::master_error_log => {
                error_log = extract_string(entry.into_inner().next().ok_or("master: expected error_log value")?);
            },
            Rule::master_includes => {
                includes.push(extract_string(
                    entry.into_inner().next().ok_or("master: expected includes value")?,
                ));
            },
            _ => return Err("unexpected entry in master block".into()),
        }
    }

    Ok(MasterConfig { name, user, workers, pid, error_log, includes })
}

pub fn parse_gateway_config(input: &str) -> Result<GatewayConfig, Box<dyn std::error::Error>> {
    let mut parsed = OphanConfigParser::parse(Rule::gateway_file, input)?;
    let root = parsed.next().unwrap();

    let mut config = GatewayConfig::new("");
    let mut global_auth: HashMap<String, OAuthConfig> = HashMap::new();
    let mut global_waf: HashMap<String, WafConfig> = HashMap::new();
    let mut global_cors: HashMap<String, CorsConfig> = HashMap::new();
    let mut global_limiter: HashMap<String, LimiterConfig> = HashMap::new();
    let mut routes_pair: Option<pest::iterators::Pair<Rule>> = None;

    for pair in root.into_inner() {
        match pair.as_rule() {
            Rule::name_assignment => {
                let val = pair.into_inner().next().unwrap();
                config.name = extract_string(val);
            },
            Rule::listeners_block => {
                config.listeners = parse_listeners(pair)?;
            },
            Rule::upstreams_block => {
                config.upstreams = parse_upstreams(pair)?;
            },
            Rule::routes_block => {
                routes_pair = Some(pair);
            },
            Rule::policy_block => {
                let (ptype, _pname, pconfig) = parse_policy_block(pair)?;
                match ptype.as_str() {
                    "auth" => {
                        if let Some(mut map) = pconfig.auth {
                            for (n, c) in map.drain() {
                                global_auth.insert(n, c);
                            }
                        }
                    },
                    "waf" => {
                        if let Some(mut map) = pconfig.waf {
                            for (n, c) in map.drain() {
                                global_waf.insert(n, c);
                            }
                        }
                    },
                    "cors" => {
                        if let Some(mut map) = pconfig.cors {
                            for (n, c) in map.drain() {
                                global_cors.insert(n, c);
                            }
                        }
                    },
                    "limiter" => {
                        if let Some(mut map) = pconfig.limiter {
                            for (n, c) in map.drain() {
                                global_limiter.insert(n, c);
                            }
                        }
                    },
                    _ => {},
                }
            },
            _ => {},
        }
    }

    if !global_auth.is_empty() {
        config.policies.auth = Some(global_auth);
    }
    if !global_waf.is_empty() {
        config.policies.waf = Some(global_waf);
    }
    if !global_cors.is_empty() {
        config.policies.cors = Some(global_cors);
    }
    if !global_limiter.is_empty() {
        config.policies.limiter = Some(global_limiter);
    }

    if let Some(routes) = routes_pair {
        config.routes = parse_routes(routes)?;
    }

    validate_limits(&config)?;

    Ok(config)
}

fn validate_limits(config: &GatewayConfig) -> Result<(), Box<dyn std::error::Error>> {
    use crate::config::parts::{MAX_LISTENERS, MAX_POLICIES, MAX_ROUTES, MAX_UPSTREAMS};

    if config.listeners.len() > MAX_LISTENERS {
        return Err(format!("Too many listeners: {} (max: {})", config.listeners.len(), MAX_LISTENERS).into());
    }
    if config.upstreams.len() > MAX_UPSTREAMS {
        return Err(format!("Too many upstreams: {} (max: {})", config.upstreams.len(), MAX_UPSTREAMS).into());
    }
    if config.routes.len() > MAX_ROUTES {
        return Err(format!("Too many routes: {} (max: {})", config.routes.len(), MAX_ROUTES).into());
    }

    let policy_count = [
        config.policies.auth.as_ref().map(|m| m.len()).unwrap_or(0),
        config.policies.waf.as_ref().map(|m| m.len()).unwrap_or(0),
        config.policies.cors.as_ref().map(|m| m.len()).unwrap_or(0),
        config.policies.limiter.as_ref().map(|m| m.len()).unwrap_or(0),
    ]
    .iter()
    .sum::<usize>();

    if policy_count > MAX_POLICIES {
        return Err(format!("Too many policies: {} (max: {})", policy_count, MAX_POLICIES).into());
    }

    Ok(())
}

fn extract_string(pair: pest::iterators::Pair<Rule>) -> String {
    match pair.as_rule() {
        Rule::string => pair.into_inner().next().unwrap().as_str().to_string(),
        _ => pair.as_str().to_string(),
    }
}

fn extract_bool(pair: pest::iterators::Pair<Rule>) -> bool {
    pair.as_str() == "true"
}

fn extract_number(pair: pest::iterators::Pair<Rule>) -> u64 {
    pair.as_str().parse().unwrap_or(0)
}

fn parse_duration_to_secs(pair: pest::iterators::Pair<Rule>) -> u64 {
    let s = pair.as_str();
    if let Some(val) = s.strip_suffix("ms") {
        val.parse::<u64>().unwrap_or(0) / 1000
    } else if let Some(val) = s.strip_suffix('s') {
        val.parse().unwrap_or(0)
    } else if let Some(val) = s.strip_suffix('m') {
        val.parse::<u64>().unwrap_or(0) * 60
    } else if let Some(val) = s.strip_suffix('h') {
        val.parse::<u64>().unwrap_or(0) * 3600
    } else {
        s.parse().unwrap_or(0)
    }
}

fn parse_size_to_bytes(pair: pest::iterators::Pair<Rule>) -> usize {
    let s = pair.as_str();
    if let Some(val) = s.strip_suffix("gb") {
        val.parse::<usize>().unwrap_or(0) * 1024 * 1024 * 1024
    } else if let Some(val) = s.strip_suffix("mb") {
        val.parse::<usize>().unwrap_or(0) * 1024 * 1024
    } else if let Some(val) = s.strip_suffix("kb") {
        val.parse::<usize>().unwrap_or(0) * 1024
    } else if let Some(val) = s.strip_suffix('b') {
        val.parse().unwrap_or(0)
    } else {
        s.parse().unwrap_or(0)
    }
}

fn parse_rate(pair: pest::iterators::Pair<Rule>) -> LimiterRate {
    let s = if pair.as_rule() == Rule::string {
        pair.into_inner().next().unwrap().as_str()
    } else {
        pair.as_str()
    };
    let s = s.trim();
    if let Some((num, period)) = s.split_once('/') {
        let requests = num.parse().unwrap_or(60);
        let per_seconds = match period {
            "s" => 1,
            "m" => 60,
            "h" => 3600,
            "d" => 86400,
            _ => 60,
        };
        LimiterRate { requests, per_seconds }
    } else {
        LimiterRate::default()
    }
}

fn parse_transport(addr: &str) -> Result<NetworkTransport, String> {
    if addr.starts_with("unix:") {
        let path = addr.strip_prefix("unix:").unwrap_or(addr).to_string();
        Ok(NetworkTransport::Uds(path))
    } else if let Ok(sa) = addr.parse::<SocketAddr>() {
        Ok(NetworkTransport::Tcp(sa))
    } else if let Some((host, port_str)) = addr.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            // Try DNS resolution for hostname
            if let Ok(mut addrs) = (host, port).to_socket_addrs()
                && let Some(sa) = addrs.find(|a| a.is_ipv4())
            {
                return Ok(NetworkTransport::Tcp(sa));
            }
            // Fallback: store as hostname:port, DNS resolved at connection time
            return Ok(NetworkTransport::Tcp(
                format!("{}:{}", host, port).parse().unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], port))),
            ));
        }
        Err(format!("invalid address '{}': invalid port", addr))
    } else {
        Err(format!("invalid address '{}': expected ip:port or unix:path", addr))
    }
}

fn parse_protocol(s: &str) -> Result<NetworkProtocol, String> {
    match s {
        "http1" | "h1" => Ok(NetworkProtocol::Http1 { allow_websocket_upgrade: false }),
        "websocket" | "ws" => Ok(NetworkProtocol::Http1 { allow_websocket_upgrade: true }),
        "http2" | "h2" => Ok(NetworkProtocol::Http2 { mode: Http2Mode::Standard }),
        "grpc" => Ok(NetworkProtocol::Http2 { mode: Http2Mode::Grpc }),
        _ => Err(format!("invalid protocol '{}': expected http1, http2, websocket, or grpc", s)),
    }
}

fn parse_balance_strategy(s: &str) -> Result<BalanceStrategy, String> {
    match s {
        "round_robin" => Ok(BalanceStrategy::RoundRobin),
        "least_connections" => Ok(BalanceStrategy::LeastConnections),
        "ip_hash" => Ok(BalanceStrategy::IpHash),
        "random" => Ok(BalanceStrategy::Random),
        _ => Err(format!(
            "invalid load_balance '{}': expected round_robin, least_connections, ip_hash, or random",
            s
        )),
    }
}

fn parse_listeners(pair: pest::iterators::Pair<Rule>) -> Result<Vec<ListenerConfig>, Box<dyn std::error::Error>> {
    let mut listeners = Vec::new();
    for def in pair.into_inner() {
        if def.as_rule() == Rule::listener_def {
            let mut inner = def.into_inner();
            let name = extract_string(inner.next().unwrap());

            let mut address = String::new();
            let mut transport = NetworkTransport::default();
            let mut protocols = vec![NetworkProtocol::Http1 { allow_websocket_upgrade: false }];
            let mut ssl: Option<SSLConfig> = None;

            for body in inner {
                match body.as_rule() {
                    Rule::listener_address => {
                        address = extract_string(body.into_inner().next().ok_or("listener: expected address value")?);
                        transport = parse_transport(&address).map_err(|e| format!("listener '{}': {}", name, e))?;
                    },
                    Rule::listener_protocols => {
                        let val = body.into_inner().next().ok_or("listener: expected protocols value")?;
                        protocols = extract_array(val)
                            .into_iter()
                            .map(|s| parse_protocol(&s).map_err(|e| format!("listener '{}': {}", name, e)))
                            .collect::<Result<Vec<_>, String>>()
                            .map_err(|e: String| e)?;
                    },
                    Rule::ssl_block => {
                        let mut cert = String::new();
                        let mut key_path = String::new();
                        let mut client_ca = None;
                        for kv in body.into_inner() {
                            match kv.as_rule() {
                                Rule::ssl_cert => {
                                    cert = extract_string(kv.into_inner().next().ok_or("ssl: expected cert value")?);
                                },
                                Rule::ssl_key => {
                                    key_path = extract_string(kv.into_inner().next().ok_or("ssl: expected key value")?);
                                },
                                Rule::ssl_client_ca => {
                                    client_ca =
                                        Some(extract_string(kv.into_inner().next().ok_or("ssl: expected client_ca value")?));
                                },
                                _ => return Err("unexpected entry in ssl block".into()),
                            }
                        }
                        ssl = Some(SSLConfig { cert, key: key_path, client_ca });
                    },
                    _ => return Err(format!("unexpected entry in listener '{}'", name).into()),
                }
            }

            let security = if let Some(certs) = ssl {
                SecurityConfig::Tls {
                    certs,
                    alpn_protocols: vec!["h2".into(), "http/1.1".into()],
                    min_version: TlsVersion::Tls13,
                }
            } else {
                SecurityConfig::Plaintext
            };

            listeners.push(ListenerConfig { name, listen: vec![address], transport, security, protocols });
        }
    }
    Ok(listeners)
}

fn extract_route_methods(pair: pest::iterators::Pair<Rule>) -> HttpMethodSet {
    let methods = pair
        .into_inner()
        .filter_map(|v| {
            let inner = v.into_inner().next()?;
            Some(HttpMethod::from(extract_string(inner)))
        })
        .collect::<HttpMethod>();

    HttpMethodSet::new(methods)
}

fn extract_array(pair: pest::iterators::Pair<Rule>) -> Vec<String> {
    pair.into_inner()
        .filter_map(|v| {
            let inner = v.into_inner().next()?;
            Some(extract_string(inner))
        })
        .collect()
}

fn parse_upstreams(pair: pest::iterators::Pair<Rule>) -> Result<Vec<UpstreamConfig>, Box<dyn std::error::Error>> {
    let mut upstreams = Vec::new();
    for def in pair.into_inner() {
        if def.as_rule() == Rule::upstream_def {
            let mut inner = def.into_inner();
            let name = extract_string(inner.next().unwrap());

            let mut servers: Vec<UpstreamServer> = Vec::new();
            let mut balance_strategy = BalanceStrategy::LeastConnections;
            let mut health_check: Option<HealthCheckConfig> = None;

            for body in inner {
                match body.as_rule() {
                    Rule::servers_assignment => {
                        let mut sa = body.into_inner();
                        let sv = sa.next().unwrap();
                        servers = parse_servers_value(sv)?;
                    },
                    Rule::load_balance_assignment => {
                        let val = body.into_inner().next().ok_or("upstream: expected load_balance value")?;
                        let name_str = extract_string(val);
                        balance_strategy =
                            parse_balance_strategy(&name_str).map_err(|e| format!("upstream '{}': {}", name, e))?;
                    },
                    Rule::health_check_assignment => {
                        let obj = body.into_inner().next().unwrap();
                        health_check = Some(parse_health_check(obj)?);
                    },
                    _ => {},
                }
            }

            upstreams.push(UpstreamConfig { name, servers, balance_strategy, health_check });
        }
    }
    Ok(upstreams)
}

fn parse_servers_value(pair: pest::iterators::Pair<Rule>) -> Result<Vec<UpstreamServer>, Box<dyn std::error::Error>> {
    let mut servers = Vec::new();
    let inner = pair.into_inner().next().ok_or("servers: expected value")?;

    match inner.as_rule() {
        Rule::string => {
            let addr = extract_string(inner);
            servers.push(make_upstream_server(&addr, 1, None)?);
        },
        Rule::inline_object => {
            servers.push(parse_inline_server(inner)?);
        },
        Rule::array => {
            for item in inner.into_inner() {
                let obj = item.into_inner().next().ok_or("servers: expected inline object")?;
                servers.push(parse_inline_server(obj)?);
            }
        },
        _ => return Err("unexpected servers value format".to_string().into()),
    }
    Ok(servers)
}

fn parse_inline_server(pair: pest::iterators::Pair<Rule>) -> Result<UpstreamServer, Box<dyn std::error::Error>> {
    let mut endpoint = String::new();
    let mut weight = 1u32;
    let mut protocol: Option<NetworkProtocol> = None;

    for kv in pair.into_inner() {
        if kv.as_rule() == Rule::inline_kv {
            let mut kv_inner = kv.into_inner();
            let key = kv_inner.next().ok_or("server: expected key")?.as_str().to_string();
            let val_inner = kv_inner.next().ok_or("server: expected value")?;
            let val = val_inner.into_inner().next().ok_or("server: expected value inner")?;
            match key.as_str() {
                "endpoint" => endpoint = extract_string(val),
                "weight" => weight = extract_number(val) as u32,
                "protocol" => {
                    let proto_str = extract_string(val);
                    protocol = Some(parse_protocol(&proto_str).map_err(|e| format!("server endpoint '{}': {}", endpoint, e))?);
                },
                _ => return Err(format!("unexpected key '{}' in server definition", key).into()),
            }
        }
    }

    Ok(make_upstream_server(&endpoint, weight, protocol)?)
}

fn make_upstream_server(addr: &str, weight: u32, protocol: Option<NetworkProtocol>) -> Result<UpstreamServer, String> {
    let transport = parse_transport(addr)?;
    Ok(UpstreamServer {
        protocol: protocol.unwrap_or(NetworkProtocol::Http1 { allow_websocket_upgrade: false }),
        address: addr.to_string(),
        transport,
        ssl: None,
        weight,
        is_healthy: true,
    })
}

fn parse_health_check(pair: pest::iterators::Pair<Rule>) -> Result<HealthCheckConfig, Box<dyn std::error::Error>> {
    let mut path = "/".to_string();
    let mut interval = 10u64;
    let mut timeout = 5u64;
    let mut unhealthy_threshold = 3u32;
    let mut healthy_threshold = 2u32;

    for kv in pair.into_inner() {
        if kv.as_rule() == Rule::inline_kv {
            let mut kv_inner = kv.into_inner();
            let key = kv_inner.next().ok_or("health_check: expected key")?.as_str().to_string();
            let val_inner = kv_inner.next().ok_or("health_check: expected value")?;
            let val = val_inner.into_inner().next().ok_or("health_check: expected value inner")?;
            match key.as_str() {
                "path" => path = extract_string(val),
                "interval" => interval = parse_duration_to_secs(val),
                "timeout" => timeout = parse_duration_to_secs(val),
                "unhealthy_threshold" => unhealthy_threshold = extract_number(val) as u32,
                "healthy_threshold" => healthy_threshold = extract_number(val) as u32,
                _ => return Err(format!("unexpected key '{}' in health_check block", key).into()),
            }
        }
    }

    Ok(HealthCheckConfig {
        path,
        interval,
        timeout,
        unhealthy_threshold,
        healthy_threshold,
    })
}

fn parse_routes(pair: pest::iterators::Pair<Rule>) -> Result<Vec<RoutesConfig>, Box<dyn std::error::Error>> {
    let mut routes = Vec::new();
    for def in pair.into_inner() {
        if def.as_rule() == Rule::route_def {
            routes.push(parse_single_route(def)?);
        }
    }
    Ok(routes)
}

type DslRoutesPolicy = (
    Option<RouteAuthPolicy>,
    Option<RouteWafPolicy>,
    Option<RouteCorsPolicy>,
    Option<RouteLimiterPolicy>,
);

fn parse_single_route(pair: pest::iterators::Pair<Rule>) -> Result<RoutesConfig, Box<dyn std::error::Error>> {
    let mut inner = pair.into_inner();
    let path = extract_string(inner.next().unwrap());

    let mut backend: Option<BackendTarget> = None;
    let mut hosts: Vec<String> = Vec::new();
    let mut methods: HttpMethodSet = HttpMethodSet::new(HttpMethod::NONE);
    let mut rewrite: Option<RouteRewrites> = None;
    let mut auth_policy: Option<RouteAuthPolicy> = None;
    let mut waf_policy: Option<RouteWafPolicy> = None;
    let mut cors_policy: Option<RouteCorsPolicy> = None;
    let mut limiter_policy: Option<RouteLimiterPolicy> = None;
    let mut timeouts: Option<RouteTimeouts> = None;
    let mut streaming: Option<RouteStreaming> = None;

    for body in inner {
        match body.as_rule() {
            Rule::backend_assignment => {
                backend = Some(parse_backend(body)?);
            },
            Rule::route_policies_block => {
                let (a, w, c, l) = parse_route_policies(body)?;
                if a.is_some() {
                    auth_policy = a;
                }
                if w.is_some() {
                    waf_policy = w;
                }
                if c.is_some() {
                    cors_policy = c;
                }
                if l.is_some() {
                    limiter_policy = l;
                }
            },
            Rule::rewrite_block => {
                let mut rules = HashMap::new();
                for rule in body.into_inner() {
                    if rule.as_rule() == Rule::rewrite_rule {
                        let mut r = rule.into_inner();
                        let from = extract_string(r.next().unwrap());
                        let to = extract_string(r.next().unwrap());
                        rules.insert(from, to);
                    }
                }
                rewrite = Some(RouteRewrites {
                    rules: Some(rules),
                    append_headers: HashMap::new(),
                    prepend_headers: vec![],
                });
            },
            Rule::headers_block => {
                let mut add_headers = HashMap::new();
                let mut _remove_headers = Vec::new();
                for entry in body.into_inner() {
                    match entry.as_rule() {
                        Rule::headers_add | Rule::headers_set => {
                            let val = entry.into_inner().next().ok_or("headers: expected inline object")?;
                            if let Rule::inline_object = val.as_rule() {
                                for ikv in val.into_inner() {
                                    if ikv.as_rule() == Rule::inline_kv {
                                        let mut ikv_inner = ikv.into_inner();
                                        let hname = ikv_inner.next().ok_or("headers: expected name")?.as_str();
                                        let hval = ikv_inner
                                            .next()
                                            .ok_or("headers: expected value")?
                                            .into_inner()
                                            .next()
                                            .ok_or("headers: expected value inner")?;
                                        add_headers.insert(hname.to_string(), extract_string(hval));
                                    }
                                }
                            }
                        },
                        Rule::headers_remove => {
                            let val = entry.into_inner().next().ok_or("headers: expected array")?;
                            _remove_headers = extract_array(val);
                        },
                        _ => return Err("unexpected entry in headers block".into()),
                    }
                }
                let existing = rewrite.get_or_insert(RouteRewrites {
                    rules: None,
                    append_headers: HashMap::new(),
                    prepend_headers: vec![],
                });
                if !add_headers.is_empty() {
                    existing.append_headers = add_headers;
                }
            },
            Rule::timeouts_block => {
                timeouts = Some(parse_timeouts_block(body)?);
            },
            Rule::streaming_block => {
                streaming = Some(parse_streaming_block(body)?);
            },
            Rule::route_hosts => {
                let val = body.into_inner().next().ok_or("route: expected hosts value")?;
                hosts = extract_array(val);
            },
            Rule::route_methods => {
                let val = body.into_inner().next().ok_or("route: expected methods value")?;
                methods = extract_route_methods(val);
            },
            // _ => return Err(format!("unexpected entry in route").into()),
            _ => {},
        }
    }

    Ok(RoutesConfig {
        path,
        hosts,
        methods,
        backend: backend.unwrap_or(BackendTarget::Upstream("default".into())),
        auth_policy,
        waf_policy,
        cors_policy,
        limiter_policy,
        priority: 1,
        rewrite,
        timeouts,
        streaming,
    })
}

fn parse_route_policies(pair: pest::iterators::Pair<Rule>) -> Result<DslRoutesPolicy, Box<dyn std::error::Error>> {
    let mut auth: Option<RouteAuthPolicy> = None;
    let mut waf: Option<RouteWafPolicy> = None;
    let mut cors: Option<RouteCorsPolicy> = None;
    let mut limiter: Option<RouteLimiterPolicy> = None;

    for entry in pair.into_inner() {
        match entry.as_rule() {
            Rule::policy_direct => {
                let mut inner = entry.into_inner();
                let ptype = inner.next().ok_or("route policy direct: expected policy type")?.as_str().to_string();
                let pname = extract_string(inner.next().ok_or("route policy direct: expected policy name")?);
                match ptype.as_str() {
                    "auth" => auth = Some(RouteAuthPolicy::Reference(pname)),
                    "waf" => waf = Some(RouteWafPolicy::Reference(pname)),
                    "cors" => cors = Some(RouteCorsPolicy::Reference(pname)),
                    "limiter" => limiter = Some(RouteLimiterPolicy::Reference(pname)),
                    _ => {},
                }
            },
            Rule::policy_extends => {
                let mut inner = entry.into_inner();
                let ptype = inner.next().ok_or("route policy extends: expected policy type")?.as_str().to_string();
                let pname = extract_string(inner.next().ok_or("route policy extends: expected policy name")?);

                match ptype.as_str() {
                    "waf" => {
                        let mut enabled_explicitly_false = false;
                        let mut cfg = WafConfig::default();
                        for kv in inner {
                            if kv.as_rule() == Rule::key_value {
                                let mut kv_inner = kv.into_inner();
                                let key = kv_inner.next().ok_or("waf extends: expected key")?.as_str().to_string();
                                let val_inner = kv_inner.next().ok_or("waf extends: expected value")?;
                                let val = val_inner.into_inner().next().ok_or("waf extends: expected value inner")?;
                                match key.as_str() {
                                    "enabled" => {
                                        enabled_explicitly_false = !extract_bool(val);
                                    },
                                    "max_body_size" => cfg.max_body_size = parse_size_to_bytes(val),
                                    "anomaly_threshold" => cfg.anomaly_threshold = extract_number(val) as u32,
                                    "mode" => {
                                        cfg.mode = match extract_string(val).as_str() {
                                            "detection_only" => WafMode::DetectionOnly,
                                            _ => WafMode::Blocking,
                                        };
                                    },
                                    "excludes" => cfg.excludes = extract_array(val),
                                    _ => {},
                                }
                            }
                        }
                        if !enabled_explicitly_false {
                            waf = Some(RouteWafPolicy::Override { base: pname, config: cfg });
                        }
                    },
                    "auth" => {
                        let mut cfg = OAuthConfig {
                            issuer: String::new(),
                            client_id: String::new(),
                            client_secret: None,
                            scopes: Vec::new(),
                            sources: Vec::new(),
                            jwk_uri: String::new(),
                            refresh_token: None,
                            excludes: vec![],
                        };
                        for body in inner {
                            match body.as_rule() {
                                Rule::key_value => {
                                    let mut kv_inner = body.into_inner();
                                    let key = kv_inner.next().ok_or("auth extends: expected key")?.as_str().to_string();
                                    let val_inner = kv_inner.next().ok_or("auth extends: expected value")?;
                                    let val = val_inner.into_inner().next().ok_or("auth extends: expected value inner")?;
                                    match key.as_str() {
                                        "issuer" => cfg.issuer = extract_string(val),
                                        "client_id" => cfg.client_id = extract_string(val),
                                        "client_secret" => cfg.client_secret = Some(extract_string(val)),
                                        "jwks_uri" => cfg.jwk_uri = extract_string(val),
                                        "excludes" => cfg.excludes = extract_array(val),
                                        _ => {},
                                    }
                                },
                                Rule::sources_block => {
                                    cfg.sources = parse_sources_block(body);
                                },
                                Rule::refresh_block => {
                                    cfg.refresh_token = Some(parse_refresh_block(body));
                                },
                                _ => {},
                            }
                        }
                        auth = Some(RouteAuthPolicy::Override { base: pname, config: cfg });
                    },
                    "cors" => {
                        let mut cfg = CorsConfig::default();
                        for kv in inner {
                            if kv.as_rule() == Rule::key_value {
                                let mut kv_inner = kv.into_inner();
                                let key = kv_inner.next().ok_or("cors extends: expected key")?.as_str().to_string();
                                let val_inner = kv_inner.next().ok_or("cors extends: expected value")?;
                                let val = val_inner.into_inner().next().ok_or("cors extends: expected value inner")?;
                                match key.as_str() {
                                    "allow_origin" => cfg.allow_origins = extract_array(val),
                                    "allow_methods" => cfg.allow_methods = extract_array(val),
                                    "allow_headers" => cfg.allow_headers = extract_array(val),
                                    "allow_credentials" => cfg.allow_credentials = extract_bool(val),
                                    "max_age" => cfg.max_age = Some(parse_duration_to_secs(val)),
                                    "excludes" => cfg.excludes = extract_array(val),
                                    _ => {},
                                }
                            }
                        }
                        cors = Some(RouteCorsPolicy::Override { base: pname, config: cfg });
                    },
                    "limiter" => {
                        let mut cfg = LimiterConfig::default();
                        for kv in inner {
                            if kv.as_rule() == Rule::key_value {
                                let mut kv_inner = kv.into_inner();
                                let key = kv_inner.next().ok_or("limiter extends: expected key")?.as_str().to_string();
                                let val_inner = kv_inner.next().ok_or("limiter extends: expected value")?;
                                let val = val_inner.into_inner().next().ok_or("limiter extends: expected value inner")?;
                                match key.as_str() {
                                    "rate" => cfg.rate = parse_rate(val),
                                    "burst" => cfg.burst = extract_number(val),
                                    "algorithm" => {
                                        cfg.algorithm = match extract_string(val).as_str() {
                                            "token_bucket" => RateLimitAlgorithm::TokenBucket,
                                            _ => RateLimitAlgorithm::SlidingWindow,
                                        };
                                    },
                                    "identifier" => {
                                        cfg.identifier = match extract_string(val).as_str() {
                                            "ip" => LimiterIdentifier::Ip,
                                            other => LimiterIdentifier::Header(other.to_string()),
                                        };
                                    },
                                    "excludes" => cfg.excludes = extract_array(val),
                                    _ => {},
                                }
                            }
                        }
                        limiter = Some(RouteLimiterPolicy::Override { base: pname, config: cfg });
                    },
                    _ => {},
                }
            },
            Rule::policy_local_block => {
                let mut inner = entry.into_inner();
                let ptype = inner.next().ok_or("route policy local block: expected policy type")?.as_str().to_string();

                match ptype.as_str() {
                    "limiter" => {
                        let mut cfg = LimiterConfig::default();
                        for kv in inner {
                            if kv.as_rule() == Rule::key_value {
                                let mut kv_inner = kv.into_inner();
                                let key = kv_inner.next().ok_or("limiter local: expected key")?.as_str().to_string();
                                let val_inner = kv_inner.next().ok_or("limiter local: expected value")?;
                                let val = val_inner.into_inner().next().ok_or("limiter local: expected value inner")?;
                                match key.as_str() {
                                    "rate" => cfg.rate = parse_rate(val),
                                    "burst" => cfg.burst = extract_number(val),
                                    "algorithm" => {
                                        cfg.algorithm = match extract_string(val).as_str() {
                                            "token_bucket" => RateLimitAlgorithm::TokenBucket,
                                            _ => RateLimitAlgorithm::SlidingWindow,
                                        };
                                    },
                                    "identifier" => {
                                        cfg.identifier = match extract_string(val).as_str() {
                                            "ip" => LimiterIdentifier::Ip,
                                            other => LimiterIdentifier::Header(other.to_string()),
                                        };
                                    },
                                    "excludes" => cfg.excludes = extract_array(val),
                                    _ => {},
                                }
                            }
                        }
                        limiter = Some(RouteLimiterPolicy::Local(cfg));
                    },
                    "waf" => {
                        let mut enabled_explicitly_false = false;
                        let mut cfg = WafConfig::default();
                        for kv in inner {
                            if kv.as_rule() == Rule::key_value {
                                let mut kv_inner = kv.into_inner();
                                let key = kv_inner.next().ok_or("waf local: expected key")?.as_str().to_string();
                                let val_inner = kv_inner.next().ok_or("waf local: expected value")?;
                                let val = val_inner.into_inner().next().ok_or("waf local: expected value inner")?;
                                match key.as_str() {
                                    "enabled" => {
                                        enabled_explicitly_false = !extract_bool(val);
                                    },
                                    "max_body_size" => cfg.max_body_size = parse_size_to_bytes(val),
                                    "anomaly_threshold" => cfg.anomaly_threshold = extract_number(val) as u32,
                                    "mode" => {
                                        cfg.mode = match extract_string(val).as_str() {
                                            "detection_only" => WafMode::DetectionOnly,
                                            _ => WafMode::Blocking,
                                        };
                                    },
                                    "excludes" => cfg.excludes = extract_array(val),
                                    _ => {},
                                }
                            }
                        }
                        if !enabled_explicitly_false {
                            waf = Some(RouteWafPolicy::Local(cfg));
                        }
                    },
                    "cors" => {
                        let mut cfg = CorsConfig::default();
                        for kv in inner {
                            if kv.as_rule() == Rule::key_value {
                                let mut kv_inner = kv.into_inner();
                                let key = kv_inner.next().ok_or("cors local: expected key")?.as_str().to_string();
                                let val_inner = kv_inner.next().ok_or("cors local: expected value")?;
                                let val = val_inner.into_inner().next().ok_or("cors local: expected value inner")?;
                                match key.as_str() {
                                    "allow_origin" => cfg.allow_origins = extract_array(val),
                                    "allow_methods" => cfg.allow_methods = extract_array(val),
                                    "allow_headers" => cfg.allow_headers = extract_array(val),
                                    "allow_credentials" => cfg.allow_credentials = extract_bool(val),
                                    "max_age" => cfg.max_age = Some(parse_duration_to_secs(val)),
                                    "excludes" => cfg.excludes = extract_array(val),
                                    _ => {},
                                }
                            }
                        }
                        cors = Some(RouteCorsPolicy::Local(cfg));
                    },
                    "auth" => {
                        let mut cfg = OAuthConfig {
                            issuer: String::new(),
                            client_id: String::new(),
                            client_secret: None,
                            scopes: Vec::new(),
                            sources: Vec::new(),
                            jwk_uri: String::new(),
                            refresh_token: None,
                            excludes: vec![],
                        };
                        for kv in inner {
                            if kv.as_rule() == Rule::key_value {
                                let mut kv_inner = kv.into_inner();
                                let key = kv_inner.next().ok_or("auth local: expected key")?.as_str().to_string();
                                let val_inner = kv_inner.next().ok_or("auth local: expected value")?;
                                let val = val_inner.into_inner().next().ok_or("auth local: expected value inner")?;
                                match key.as_str() {
                                    "issuer" => cfg.issuer = extract_string(val),
                                    "client_id" => cfg.client_id = extract_string(val),
                                    "client_secret" => cfg.client_secret = Some(extract_string(val)),
                                    "jwks_uri" => cfg.jwk_uri = extract_string(val),
                                    "excludes" => cfg.excludes = extract_array(val),
                                    _ => {},
                                }
                            }
                        }
                        auth = Some(RouteAuthPolicy::Local(cfg));
                    },
                    _ => {},
                }
            },
            _ => {},
        }
    }

    Ok((auth, waf, cors, limiter))
}

fn parse_timeouts_block(pair: pest::iterators::Pair<Rule>) -> Result<RouteTimeouts, Box<dyn std::error::Error>> {
    let mut connect: Option<Duration> = None;
    let mut read: Option<Duration> = None;
    let mut send: Option<Duration> = None;

    for kv in pair.into_inner() {
        let rule = kv.as_rule();
        let val_inner = kv.into_inner().next().ok_or("timeouts: expected value")?;
        let raw = val_inner.into_inner().next().ok_or("timeouts: expected value inner")?;
        let unquoted = if raw.as_rule() == Rule::string {
            raw.into_inner().next().ok_or("timeouts: expected string content")?
        } else {
            raw
        };
        let secs = parse_duration_to_secs(unquoted);
        match rule {
            Rule::timeout_connect => connect = Some(Duration::from_secs(secs)),
            Rule::timeout_read => read = Some(Duration::from_secs(secs)),
            Rule::timeout_send => send = Some(Duration::from_secs(secs)),
            _ => return Err("unexpected key in timeouts block".into()),
        }
    }

    Ok(RouteTimeouts { connect, read, send })
}

fn parse_streaming_block(pair: pest::iterators::Pair<Rule>) -> Result<RouteStreaming, Box<dyn std::error::Error>> {
    let mut buffering = true;
    let mut chunked = true;

    for kv in pair.into_inner() {
        let rule = kv.as_rule();
        let val = kv.into_inner().next().ok_or("streaming: expected value")?;
        match rule {
            Rule::streaming_buffering => buffering = extract_bool(val),
            Rule::streaming_chunked => chunked = extract_bool(val),
            _ => return Err("unexpected key in streaming block".into()),
        }
    }

    Ok(RouteStreaming { buffering, chunked })
}

fn parse_backend(pair: pest::iterators::Pair<Rule>) -> Result<BackendTarget, Box<dyn std::error::Error>> {
    let target = pair.into_inner().next().unwrap();
    let inner = target.into_inner().next().unwrap();

    match inner.as_rule() {
        Rule::backend_static => {
            let mut root = String::new();
            let mut listing = false;
            let mut dotfiles = false;
            let mut permissions: Option<String> = None;
            let mut blacklist: Vec<String> = Vec::new();

            for kv in inner.into_inner() {
                match kv.as_rule() {
                    Rule::static_root => {
                        root = extract_string(kv.into_inner().next().ok_or("static: expected root value")?);
                    },
                    Rule::static_listing => {
                        listing = extract_bool(kv.into_inner().next().ok_or("static: expected listing value")?);
                    },
                    Rule::static_dotfiles => {
                        dotfiles = extract_bool(kv.into_inner().next().ok_or("static: expected dotfiles value")?);
                    },
                    Rule::static_permissions => {
                        permissions =
                            Some(kv.into_inner().next().ok_or("static: expected permissions value")?.as_str().to_string());
                    },
                    Rule::static_disallow => {
                        blacklist = extract_array(kv.into_inner().next().ok_or("static: expected disallow value")?);
                    },
                    _ => return Err("unexpected key in static backend".into()),
                }
            }

            Ok(BackendTarget::Static(Arc::new(StaticUpstream::Local {
                path: root,
                permissions,
                listing,
                dotfiles,
                blacklist,
            })))
        },
        Rule::backend_upstream => {
            let name_pair = inner.into_inner().next().unwrap();
            Ok(BackendTarget::Upstream(extract_string(name_pair)))
        },
        _ => Err("Unknown backend type".into()),
    }
}

fn parse_policy_block(pair: pest::iterators::Pair<Rule>) -> Result<(String, String, PolicyConfig), Box<dyn std::error::Error>> {
    let mut inner = pair.into_inner();
    let ptype = inner.next().unwrap().as_str().to_string();
    let pname = extract_string(inner.next().unwrap());

    let mut policy = PolicyConfig::default();

    match ptype.as_str() {
        "auth" => {
            let mut oauth = OAuthConfig {
                issuer: String::new(),
                client_id: String::new(),
                client_secret: None,
                scopes: Vec::new(),
                sources: Vec::new(),
                jwk_uri: String::new(),
                refresh_token: None,
                excludes: vec![],
            };

            for body in inner {
                match body.as_rule() {
                    Rule::auth_issuer => {
                        oauth.issuer = extract_string(body.into_inner().next().ok_or("auth: expected issuer value")?);
                    },
                    Rule::auth_client_id => {
                        oauth.client_id = extract_string(body.into_inner().next().ok_or("auth: expected client_id value")?);
                    },
                    Rule::auth_client_secret => {
                        oauth.client_secret = Some(extract_string(
                            body.into_inner().next().ok_or("auth: expected client_secret value")?,
                        ));
                    },
                    Rule::auth_jwks_uri => {
                        oauth.jwk_uri = extract_string(body.into_inner().next().ok_or("auth: expected jwks_uri value")?);
                    },
                    Rule::auth_audience => {},
                    Rule::auth_excludes => {
                        oauth.excludes = extract_array(body.into_inner().next().ok_or("auth: expected excludes value")?);
                    },
                    Rule::sources_block => {
                        oauth.sources = parse_sources_block(body);
                    },
                    Rule::refresh_block => {
                        oauth.refresh_token = Some(parse_refresh_block(body));
                    },
                    _ => return Err(format!("unexpected entry in auth policy '{}'", pname).into()),
                }
            }

            let mut auth_map = HashMap::new();
            auth_map.insert(pname.clone(), oauth);
            policy.auth = Some(auth_map);
        },
        "waf" => {
            let mut waf = WafConfig::default();
            let mut rules = Vec::new();

            for body in inner {
                match body.as_rule() {
                    Rule::waf_enabled => {
                        waf.enabled = extract_bool(body.into_inner().next().ok_or("waf: expected enabled value")?);
                    },
                    Rule::waf_mode => {
                        let mode_str = extract_string(body.into_inner().next().ok_or("waf: expected mode value")?);
                        waf.mode = match mode_str.as_str() {
                            "detection_only" => WafMode::DetectionOnly,
                            "blocking" => WafMode::Blocking,
                            _ => {
                                return Err(
                                    format!("invalid waf mode '{}': expected detection_only or blocking", mode_str).into(),
                                );
                            },
                        };
                    },
                    Rule::waf_max_body_size => {
                        waf.max_body_size =
                            parse_size_to_bytes(body.into_inner().next().ok_or("waf: expected max_body_size value")?);
                    },
                    Rule::waf_anomaly_threshold => {
                        waf.anomaly_threshold =
                            extract_number(body.into_inner().next().ok_or("waf: expected anomaly_threshold value")?) as u32;
                    },
                    Rule::waf_excludes => {
                        waf.excludes = extract_array(body.into_inner().next().ok_or("waf: expected excludes value")?);
                    },
                    Rule::rules_block => {
                        rules = parse_rules_block(body)?;
                    },
                    _ => return Err(format!("unexpected entry in waf policy '{}'", pname).into()),
                }
            }
            waf.rules = rules;
            let mut waf_map = HashMap::new();
            waf_map.insert(pname.clone(), waf);
            policy.waf = Some(waf_map);
        },
        "cors" => {
            let mut cors = CorsConfig::default();
            for body in inner {
                match body.as_rule() {
                    Rule::cors_allow_origin => {
                        cors.allow_origins = extract_array(body.into_inner().next().ok_or("cors: expected allow_origin value")?);
                    },
                    Rule::cors_allow_methods => {
                        cors.allow_methods = extract_array(body.into_inner().next().ok_or("cors: expected allow_methods value")?);
                    },
                    Rule::cors_allow_headers => {
                        cors.allow_headers = extract_array(body.into_inner().next().ok_or("cors: expected allow_headers value")?);
                    },
                    Rule::cors_allow_credentials => {
                        cors.allow_credentials =
                            extract_bool(body.into_inner().next().ok_or("cors: expected allow_credentials value")?);
                    },
                    Rule::cors_max_age => {
                        cors.max_age = Some(parse_duration_to_secs(
                            body.into_inner().next().ok_or("cors: expected max_age value")?,
                        ));
                    },
                    Rule::cors_excludes => {
                        cors.excludes = extract_array(body.into_inner().next().ok_or("cors: expected excludes value")?);
                    },
                    _ => return Err(format!("unexpected entry in cors policy '{}'", pname).into()),
                }
            }
            let mut cors_map = HashMap::new();
            cors_map.insert(pname.clone(), cors);
            policy.cors = Some(cors_map);
        },
        "limiter" => {
            let mut limiter = LimiterConfig::default();
            for body in inner {
                match body.as_rule() {
                    Rule::limiter_rate => {
                        let val = body.into_inner().next().ok_or("limiter: expected rate value")?;
                        let inner = val.into_inner().next().ok_or("limiter: expected rate literal")?;
                        limiter.rate = parse_rate(inner);
                    },
                    Rule::limiter_burst => {
                        limiter.burst = extract_number(body.into_inner().next().ok_or("limiter: expected burst value")?);
                    },
                    Rule::limiter_algorithm => {
                        let alg = extract_string(body.into_inner().next().ok_or("limiter: expected algorithm value")?);
                        limiter.algorithm = match alg.as_str() {
                            "token_bucket" => RateLimitAlgorithm::TokenBucket,
                            "sliding_window" => RateLimitAlgorithm::SlidingWindow,
                            _ => {
                                return Err(format!(
                                    "invalid limiter algorithm '{}': expected token_bucket or sliding_window",
                                    alg
                                )
                                .into());
                            },
                        };
                    },
                    Rule::limiter_identifier => {
                        let id = extract_string(body.into_inner().next().ok_or("limiter: expected identifier value")?);
                        limiter.identifier = match id.as_str() {
                            "ip" => LimiterIdentifier::Ip,
                            other => LimiterIdentifier::Header(other.to_string()),
                        };
                    },
                    Rule::limiter_excludes => {
                        limiter.excludes = extract_array(body.into_inner().next().ok_or("limiter: expected excludes value")?);
                    },
                    _ => return Err(format!("unexpected entry in limiter policy '{}'", pname).into()),
                }
            }
            let mut limiter_map = HashMap::new();
            limiter_map.insert(pname.clone(), limiter);
            policy.limiter = Some(limiter_map);
        },
        _ => return Err(format!("unknown policy type '{}'", ptype).into()),
    }

    Ok((ptype, pname, policy))
}

fn parse_sources_block(pair: pest::iterators::Pair<Rule>) -> Vec<TokenSource> {
    let mut sources = Vec::new();
    for item in pair.into_inner() {
        if item.as_rule() == Rule::source_item {
            let mut inner = item.into_inner();
            let src_type = inner.next().unwrap().as_str();
            let mut name = String::new();
            let mut prefix = None;

            for kv in inner {
                match kv.as_rule() {
                    Rule::source_name => {
                        if let Some(val) = kv.into_inner().next() {
                            name = extract_string(val);
                        }
                    },
                    Rule::source_prefix => {
                        if let Some(val) = kv.into_inner().next() {
                            prefix = Some(extract_string(val));
                        }
                    },
                    _ => {},
                }
            }

            match src_type {
                "header" => sources.push(TokenSource::Header { name, prefix }),
                "cookie" => sources.push(TokenSource::Cookie { name, prefix }),
                "query" => sources.push(TokenSource::QueryParam { name, prefix }),
                _ => {},
            }
        }
    }
    sources
}

fn parse_refresh_block(pair: pest::iterators::Pair<Rule>) -> RefreshTokenConfig {
    let mut enabled = false;
    let mut endpoint = String::new();
    let mut source = TokenSource::Cookie { name: "refresh_token".into(), prefix: None };

    for body in pair.into_inner() {
        match body.as_rule() {
            Rule::refresh_enabled => {
                if let Some(val) = body.into_inner().next() {
                    enabled = extract_bool(val);
                }
            },
            Rule::refresh_endpoint => {
                if let Some(val) = body.into_inner().next() {
                    endpoint = extract_string(val);
                }
            },
            Rule::sources_block => {
                let sources = parse_sources_block(body);
                if let Some(first) = sources.into_iter().next() {
                    source = first;
                }
            },
            _ => {},
        }
    }

    RefreshTokenConfig {
        enabled,
        source,
        token_endpoint: endpoint,
        auto_rotate_response: true,
    }
}

fn parse_rules_block(pair: pest::iterators::Pair<Rule>) -> Result<Vec<WafRule>, Box<dyn std::error::Error>> {
    let mut rules = Vec::new();
    for def in pair.into_inner() {
        if def.as_rule() == Rule::rule_def {
            let mut inner = def.into_inner();
            let id = extract_string(inner.next().ok_or("rule: expected id")?);

            let mut phase = WafPhase::RequestBody;
            let mut condition = WafCondition::SqlTokenMatch;
            let mut action = WafAction::Block;
            let mut score = 5u32;

            for kv in inner {
                match kv.as_rule() {
                    Rule::rule_phase => {
                        let p = extract_string(kv.into_inner().next().ok_or("rule: expected phase value")?);
                        phase = match p.as_str() {
                            "request_headers" => WafPhase::RequestHeaders,
                            "request_body" => WafPhase::RequestBody,
                            "response_headers" => WafPhase::ResponseHeaders,
                            "response_body" => WafPhase::ResponseBody,
                            _ => return Err(format!(
                                "invalid phase '{}': expected request_headers, request_body, response_headers, or response_body",
                                p
                            )
                            .into()),
                        };
                    },
                    Rule::rule_condition => {
                        let val = kv.into_inner().next().ok_or("rule: expected condition value")?;
                        let cond_str = val.as_str();
                        condition = match cond_str {
                            "sql_token_match" => WafCondition::SqlTokenMatch,
                            _ => return Err(format!("invalid condition '{}': expected sql_token_match", cond_str).into()),
                        };
                    },
                    Rule::rule_action => {
                        let a = extract_string(kv.into_inner().next().ok_or("rule: expected action value")?);
                        action = match a.as_str() {
                            "block" => WafAction::Block,
                            "log" => WafAction::Log,
                            "challenge" => WafAction::Challenge,
                            "allow" => WafAction::Allow,
                            _ => return Err(format!("invalid action '{}': expected block, log, challenge, or allow", a).into()),
                        };
                    },
                    Rule::rule_score => {
                        score = extract_number(kv.into_inner().next().ok_or("rule: expected score value")?) as u32;
                    },
                    _ => return Err(format!("unexpected entry in rule '{}'", id).into()),
                }
            }

            rules.push(WafRule { id, phase, condition, action, score });
        }
    }
    Ok(rules)
}
