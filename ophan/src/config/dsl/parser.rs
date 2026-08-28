use std::str::FromStr;
use std::time::Duration;

use pest::Parser;
use pest_derive::Parser;

use flatkit::sizes::ByteSize;

use super::blocks::*;
use super::errors::{ConfigError, PairErrExt};

#[derive(Parser)]
#[grammar = "../../ophan_grammar.pest"]
pub struct OphanConfigParser;

pub fn parse_raw_master<'a>(input: &'a str) -> Result<RawMaster<'a>, ConfigError> {
    let mut parsed = OphanConfigParser::parse(Rule::master_file, input)?;
    let root = parsed.next().unwrap();
    let master_block = root.into_inner().next().unwrap();
    let mut inner = master_block.into_inner();

    let name = extract_str(inner.next().unwrap());
    let mut user = "www-data";
    let mut workers = RawWorkers::Count(1);

    #[cfg(unix)]
    let mut pid = "/run/ophan.pid";
    #[cfg(not(unix))]
    let mut pid = "C:\\ophan-gateway\\ophan.pid";

    #[cfg(unix)]
    let mut error_log = "/var/log/ophan/error.log";
    #[cfg(not(unix))]
    let mut error_log = "C:\\ophan-gateway\\logs\\error.log";

    let mut includes = Vec::new();

    for entry in inner {
        match entry.as_rule() {
            Rule::master_user => {
                user = extract_str(entry.into_inner().next().unwrap());
            },
            Rule::master_workers => {
                let val = entry.into_inner().next().unwrap();
                let s = extract_str(val);
                workers = if s == "auto" {
                    RawWorkers::Auto
                } else {
                    let count: usize = s.parse().map_err(|_| {
                        ConfigError::parse(format!(
                            "workers: invalid value '{}', expected 'auto' or a positive integer",
                            s
                        ))
                    })?;
                    RawWorkers::Count(count)
                };
            },
            Rule::master_pid => {
                pid = extract_str(entry.into_inner().next().unwrap());
            },
            Rule::master_error_log => {
                error_log = extract_str(entry.into_inner().next().unwrap());
            },
            Rule::master_includes => {
                includes.push(extract_str(entry.into_inner().next().unwrap()));
            },
            Rule::EOI => {},
            _ => return Err(entry.error(format!("unexpected field '{}' in master block", entry.as_str()))),
        }
    }

    Ok(RawMaster { name, user, workers, pid, error_log, includes })
}

pub fn parse_raw_gateway<'a>(input: &'a str) -> Result<RawGateway<'a>, ConfigError> {
    let mut parsed = OphanConfigParser::parse(Rule::gateway_file, input)?;
    let root = parsed.next().unwrap();

    let mut name = "";
    let mut listeners = Vec::new();
    let mut upstreams = Vec::new();
    let mut routes = Vec::new();
    let mut policies = Vec::new();

    for pair in root.into_inner() {
        match pair.as_rule() {
            Rule::name_assignment => {
                name = extract_str(pair.into_inner().next().unwrap());
            },
            Rule::listeners_block => {
                listeners = parse_raw_listeners(pair)?;
            },
            Rule::upstreams_block => {
                upstreams = parse_raw_upstreams(pair)?;
            },
            Rule::routes_block => {
                routes = parse_raw_routes(pair)?;
            },
            Rule::policy_block => {
                policies.push(parse_raw_policy(pair)?);
            },
            Rule::EOI => {},
            _ => return Err(pair.error(format!("unexpected block '{}' in gateway", pair.as_str()))),
        }
    }

    Ok(RawGateway { name, listeners, upstreams, routes, policies })
}

// ============================================================================
// LISTENERS
// ============================================================================

fn parse_raw_listeners(pair: pest::iterators::Pair<Rule>) -> Result<Vec<RawListener>, ConfigError> {
    let mut listeners = Vec::new();
    for def in pair.into_inner() {
        if def.as_rule() == Rule::listener_def {
            let mut inner = def.into_inner();
            let name = extract_str(inner.next().unwrap());

            let mut address = "";
            let mut protocols = Vec::new();
            let mut ssl = None;
            let mut network_policy = None;
            let mut limits = None;
            let mut timeouts = None;

            for body in inner {
                match body.as_rule() {
                    Rule::listener_address => {
                        address = extract_str(body.into_inner().next().unwrap());
                    },
                    Rule::listener_protocols => {
                        let val = body.into_inner().next().unwrap();
                        protocols = extract_raw_array(val);
                    },
                    Rule::ssl_block => {
                        ssl = Some(parse_raw_ssl(body)?);
                    },
                    Rule::network_policy_block => {
                        network_policy = Some(parse_raw_net_policy(body)?);
                    },
                    Rule::limits_block => {
                        limits = Some(parse_raw_listener_limits(body));
                    },
                    Rule::listener_timeouts_block => {
                        timeouts = Some(parse_raw_listener_timeouts(body));
                    },
                    Rule::EOI => {},
                    _ => return Err(body.error(format!("unexpected field '{}' in listener '{}'", body.as_str(), name))),
                }
            }

            listeners.push(RawListener {
                name,
                address,
                protocols,
                tls: ssl,
                network_policy,
                limits,
                timeouts,
            });
        }
    }
    Ok(listeners)
}

fn parse_raw_ssl(pair: pest::iterators::Pair<Rule>) -> Result<RawTls, ConfigError> {
    let mut cert = "";
    let mut key = "";
    let mut client_ca = None;
    let mut versions = Vec::new();
    let mut client_auth = None;
    let mut ciphers = Vec::new();

    for kv in pair.into_inner() {
        match kv.as_rule() {
            Rule::ssl_cert => {
                cert = extract_str(kv.into_inner().next().unwrap());
            },
            Rule::ssl_key => {
                key = extract_str(kv.into_inner().next().unwrap());
            },
            Rule::ssl_client_ca => {
                client_ca = Some(extract_str(kv.into_inner().next().unwrap()));
            },
            Rule::ssl_versions => {
                let val = kv.into_inner().next().unwrap();
                versions = extract_raw_array(val);
            },
            Rule::ssl_client_auth => {
                client_auth = Some(extract_str(kv.into_inner().next().unwrap()));
            },
            Rule::ssl_ciphers => {
                let val = kv.into_inner().next().unwrap();
                ciphers = extract_raw_array(val);
            },
            Rule::EOI => {},
            _ => return Err(kv.error(format!("unexpected field '{}' in ssl block", kv.as_str()))),
        }
    }

    Ok(RawTls { cert, key, client_ca, versions, client_auth, ciphers })
}

fn parse_raw_listener_limits(pair: pest::iterators::Pair<Rule>) -> RawListenerLimits {
    let mut connections = None;
    let mut request_size = None;

    for entry in pair.into_inner() {
        match entry.as_rule() {
            Rule::limits_connections => {
                let val = entry.into_inner().next().unwrap();
                connections = val.as_str().parse().ok();
            },
            Rule::limits_request_size => {
                let val = entry.into_inner().next().unwrap();
                request_size = ByteSize::from_str(val.as_str()).ok();
            },
            _ => {},
        }
    }

    RawListenerLimits { connections, request_size }
}

fn parse_raw_listener_timeouts(pair: pest::iterators::Pair<Rule>) -> RawListenerTimeouts {
    let mut idle = None;
    let mut keepalive = None;

    for entry in pair.into_inner() {
        match entry.as_rule() {
            Rule::listener_timeout_idle => {
                let val = entry.into_inner().next().unwrap();
                let s = extract_value(val);
                idle = parse_duration_millis(s).ok().map(Duration::from_millis);
            },
            Rule::listener_timeout_keepalive => {
                let val = entry.into_inner().next().unwrap();
                let s = extract_value(val);
                keepalive = parse_duration_millis(s).ok().map(Duration::from_millis);
            },
            _ => {},
        }
    }

    RawListenerTimeouts { idle, keepalive }
}

fn parse_raw_net_policy(pair: pest::iterators::Pair<Rule>) -> Result<RawNetworkPolicy, ConfigError> {
    let mut allowed_ip_ranges = Vec::new();
    let mut blocked_ip_ranges = Vec::new();
    let mut real_ip_header = None;
    let mut proxy_allowed_ips = None;
    // let mut policy = None;

    for entry in pair.into_inner() {
        match entry.as_rule() {
            Rule::allowed_ip_ranges => {
                let val = entry.into_inner().next().unwrap();
                allowed_ip_ranges = extract_raw_array(val);
            },
            Rule::blocked_ip_ranges => {
                let val = entry.into_inner().next().unwrap();
                blocked_ip_ranges = extract_raw_array(val);
            },
            Rule::real_ip_header => {
                real_ip_header = Some(extract_str(entry.into_inner().next().unwrap()));
            },
            Rule::proxy_allowed_ips => {
                let val = entry.into_inner().next().unwrap();
                proxy_allowed_ips = Some(extract_raw_array(val));
            },
            Rule::tp_policy => {
                // policy = Some(extract_str(entry.into_inner().next().unwrap()));
            },
            Rule::EOI => {},
            _ => return Err(entry.error(format!("unexpected field '{}' in network_policy", entry.as_str()))),
        }
    }

    Ok(RawNetworkPolicy {
        allowed_ip_ranges,
        blocked_ip_ranges,
        real_ip_header,
        proxy_allowed_ips,
    })
}

// ============================================================================
// UPSTREAMS
// ============================================================================

fn parse_raw_upstreams(pair: pest::iterators::Pair<Rule>) -> Result<Vec<RawUpstream>, ConfigError> {
    let mut upstreams = Vec::new();
    for def in pair.into_inner() {
        if def.as_rule() == Rule::upstream_def {
            let mut inner = def.into_inner();
            let name = extract_str(inner.next().unwrap());

            let mut servers = vec![];
            let mut load_balance = None;
            let mut health_check = None;

            for body in inner {
                match body.as_rule() {
                    Rule::servers_assignment => {
                        let sv = body.into_inner().next().unwrap();
                        servers = parse_raw_servers_value(sv)?;
                    },
                    Rule::load_balance_assignment => {
                        load_balance = Some(extract_str(body.into_inner().next().unwrap()));
                    },
                    Rule::health_check_assignment => {
                        let obj = body.into_inner().next().unwrap();
                        health_check = Some(parse_raw_health_check(obj)?);
                    },
                    Rule::EOI => {},
                    _ => return Err(body.error(format!("unexpected field '{}' in upstream '{}'", body.as_str(), name))),
                }
            }

            upstreams.push(RawUpstream {
                name,
                static_servers: servers,
                balance_strategy: load_balance,
                health_check,
                security: None,
                circuit_breaker: None,
                discovery: None,
                registry: None,
            });
        }
    }
    Ok(upstreams)
}

fn parse_raw_servers_value(pair: pest::iterators::Pair<Rule>) -> Result<Vec<RawUpstreamServer>, ConfigError> {
    let err_pair = pair.clone();
    let inner = pair.into_inner().next().ok_or_else(|| err_pair.error("missing servers"))?;
    let mut servers = vec![];

    match inner.as_rule() {
        Rule::string => {
            servers.push(RawUpstreamServer { endpoint: extract_str(inner), weight: 1, protocol: None });
        },
        Rule::inline_object => servers.push(parse_raw_inline_server(inner)?),
        Rule::array => {
            for item in inner.into_inner() {
                let item_str = item.as_str().to_string();
                let inner_val = item
                    .into_inner()
                    .next()
                    .ok_or_else(|| ConfigError::parse(format!("expected server entry in array, got '{}'", item_str)))?;
                match inner_val.as_rule() {
                    Rule::string => {
                        servers.push(RawUpstreamServer { endpoint: extract_str(inner_val), weight: 1, protocol: None });
                    },
                    Rule::inline_object => {
                        servers.push(parse_raw_inline_server(inner_val)?);
                    },
                    _ => {
                        return Err(ConfigError::parse(format!(
                            "invalid server entry '{}', expected a string or object",
                            item_str
                        )));
                    },
                }
            }
        },
        Rule::EOI => {},
        _ => return Err(err_pair.error(format!("unexpected servers value `{}`", err_pair.as_str()))),
    }

    Ok(servers)
}

fn parse_raw_inline_server(pair: pest::iterators::Pair<Rule>) -> Result<RawUpstreamServer, ConfigError> {
    let mut endpoint = "";
    let mut weight = 1;
    let mut protocol = None;

    for kv in pair.into_inner() {
        if kv.as_rule() == Rule::inline_kv {
            // let key_str = kv.as_str();
            let mut kv_inner = kv.into_inner();
            let key = extract_str(kv_inner.next().unwrap());
            let val = kv_inner.next().unwrap();
            let value_str = extract_value(val);
            match key {
                "endpoint" | "address" => endpoint = value_str,
                "weight" => {
                    weight = value_str.parse().map_err(|_| {
                        ConfigError::parse(format!("invalid weight '{}' in server object, expected a number", value_str))
                    })?;
                },
                "protocol" => protocol = Some(value_str),
                _ => return Err(ConfigError::parse(format!("unknown key '{}' in server object", key))),
            }
        }
    }

    Ok(RawUpstreamServer { endpoint, weight, protocol })
}

fn parse_raw_health_check(pair: pest::iterators::Pair<Rule>) -> Result<RawHealthCheck, ConfigError> {
    let mut path = None;
    let mut interval = None;
    let mut timeout = None;
    let mut unhealthy_threshold = None;
    let mut healthy_threshold = None;

    for kv in pair.into_inner() {
        if kv.as_rule() == Rule::inline_kv {
            let mut kv_inner = kv.into_inner();
            let key = extract_str(kv_inner.next().unwrap());
            let val = kv_inner.next().unwrap();
            let value_str = extract_value(val);
            match key {
                "path" => path = Some(value_str),
                "interval" => {
                    let dur: u64 = parse_duration_millis(value_str)?;
                    interval = Some(Duration::from_millis(dur));
                },
                "timeout" => {
                    let dur: u64 = parse_duration_millis(value_str)?;
                    timeout = Some(Duration::from_millis(dur));
                },
                "unhealthy_threshold" => {
                    unhealthy_threshold = Some(value_str.parse().map_err(|_| {
                        ConfigError::parse(format!("invalid unhealthy_threshold '{}', expected a number", value_str))
                    })?);
                },
                "healthy_threshold" => {
                    healthy_threshold = Some(value_str.parse().map_err(|_| {
                        ConfigError::parse(format!("invalid healthy_threshold '{}', expected a number", value_str))
                    })?);
                },
                _ => return Err(ConfigError::parse(format!("unknown key '{}' in health_check", key))),
            }
        }
    }

    Ok(RawHealthCheck {
        path,
        interval,
        timeout,
        unhealthy_threshold,
        healthy_threshold,
    })
}

// ============================================================================
// ROUTES
// ============================================================================

fn parse_raw_routes(pair: pest::iterators::Pair<Rule>) -> Result<Vec<RawRoute>, ConfigError> {
    let mut routes = Vec::new();
    for def in pair.into_inner() {
        if def.as_rule() == Rule::route_def {
            routes.push(parse_raw_single_route(def)?);
        }
    }
    Ok(routes)
}

fn parse_raw_single_route(pair: pest::iterators::Pair<Rule>) -> Result<RawRoute, ConfigError> {
    let mut inner = pair.into_inner();
    let path = extract_str(inner.next().unwrap());

    let mut backend = RawBackend::Upstream("");
    let mut hosts = Vec::new();
    let mut methods = Vec::new();
    let mut protocols = Vec::new();
    let mut policies = None;
    let mut rewrite = None;
    let mut inbound_headers = None;
    let mut outbound_headers = None;
    let mut timeouts = None;
    let mut streaming = None;
    let mut route_static_config: Option<(RawStaticFlags, Vec<&str>)> = None;

    for body in inner {
        match body.as_rule() {
            Rule::backend_assignment => {
                backend = parse_raw_backend(body)?;
            },
            Rule::route_policies_block => {
                policies = Some(parse_raw_route_policies(body)?);
            },
            Rule::rewrite_block => {
                rewrite = Some(parse_raw_rewrite(body));
            },
            Rule::inbound_headers_block => {
                inbound_headers = Some(parse_raw_inbound_headers(body));
            },
            Rule::outbound_headers_block => {
                outbound_headers = Some(parse_raw_outbound_headers(body));
            },
            Rule::timeouts_block => {
                timeouts = Some(parse_raw_timeouts(body)?);
            },
            Rule::streaming_block => {
                streaming = Some(parse_raw_streaming(body));
            },
            Rule::route_hosts => {
                let val = body.into_inner().next().unwrap();
                hosts = extract_raw_array(val);
            },
            Rule::route_methods => {
                let val = body.into_inner().next().unwrap();
                methods = extract_raw_array(val);
            },
            Rule::route_protocols => {
                let val = body.into_inner().next().unwrap();
                protocols = extract_raw_array(val);
            },
            Rule::static_config_block => {
                route_static_config = Some(parse_raw_static_config(body));
            },
            Rule::EOI => {},
            _ => return Err(body.error(format!("unexpected field '{}' in route '{}'", body.as_str(), path))),
        }
    }

    if let Some((flags, exclude_paths)) = route_static_config {
        if let RawBackend::Static(ref mut sb) = backend {
            if flags.listing.is_some() {
                sb.flags.listing = flags.listing;
            }
            if flags.dotfiles.is_some() {
                sb.flags.dotfiles = flags.dotfiles;
            }
            if flags.index.is_some() {
                sb.flags.index = flags.index;
            }
            if flags.symlinks.is_some() {
                sb.flags.symlinks = flags.symlinks;
            }
            sb.exclude_paths.extend(exclude_paths);
        } else {
            return Err(ConfigError::parse(format!(
                "static_config requires a static backend in route '{}'",
                path
            )));
        }
    }

    Ok(RawRoute::Path(RawPathRoute {
        path,
        hosts,
        methods,
        protocols,
        backend,
        timeouts,
        streaming,
        policies,
        rewrite,
        inbound_headers,
        outbound_headers,
    }))
}

fn parse_raw_backend(pair: pest::iterators::Pair<Rule>) -> Result<RawBackend, ConfigError> {
    let target = pair
        .into_inner()
        .next()
        .ok_or_else(|| ConfigError::parse("backend: expected upstream or static target"))?;
    let inner = target
        .into_inner()
        .next()
        .ok_or_else(|| ConfigError::parse("backend: expected upstream(...) or static(...)"))?;

    match inner.as_rule() {
        Rule::backend_static => {
            let root = inner
                .into_inner()
                .next()
                .ok_or_else(|| ConfigError::parse("backend: static() requires a path argument"))?;
            Ok(RawBackend::Static(RawStaticBackend {
                root: extract_str(root),
                flags: RawStaticFlags { listing: None, dotfiles: None, index: None, symlinks: None },
                exclude_paths: Vec::new(),
            }))
        },
        Rule::backend_upstream => {
            let name_pair = inner.into_inner().next().ok_or_else(|| ConfigError::parse("backend: upstream requires a name"))?;
            Ok(RawBackend::Upstream(extract_str(name_pair)))
        },
        _ => Err(inner.error(format!("unexpected backend type '{}'", inner.as_str()))),
    }
}

fn parse_raw_static_config(pair: pest::iterators::Pair<'_, Rule>) -> (RawStaticFlags, Vec<&str>) {
    let mut listing = None;
    let mut dotfiles = None;
    let mut index = None;
    let mut symlinks = None;
    let mut exclude_paths = Vec::new();

    for entry in pair.into_inner() {
        match entry.as_rule() {
            Rule::static_config_listing => {
                let val = entry.into_inner().next().unwrap();
                listing = Some(extract_str(val) == "true");
            },
            Rule::static_config_dotfiles => {
                let val = entry.into_inner().next().unwrap();
                dotfiles = Some(extract_str(val) == "true");
            },
            Rule::static_config_index => {
                let val = entry.into_inner().next().unwrap();
                index = Some(extract_str(val) == "true");
            },
            Rule::static_config_symlinks => {
                let val = entry.into_inner().next().unwrap();
                symlinks = Some(extract_str(val) == "true");
            },
            Rule::static_config_exclude_paths => {
                let val = entry.into_inner().next().unwrap();
                exclude_paths = extract_raw_array(val);
            },
            _ => {},
        }
    }

    (RawStaticFlags { listing, dotfiles, index, symlinks }, exclude_paths)
}

// ============================================================================
// ROUTE POLICIES
// ============================================================================

fn parse_raw_route_policies(pair: pest::iterators::Pair<Rule>) -> Result<RawRoutePolicies, ConfigError> {
    let mut auth = None;
    let mut cors = None;
    let mut waf = None;
    let mut limiter = None;
    let mut helmet = None;

    for entry in pair.into_inner() {
        match entry.as_rule() {
            Rule::policy_direct => {
                let mut inner = entry.into_inner();
                let policy_type = inner.next().unwrap().as_str();
                let name = extract_str(inner.next().unwrap());
                let action = match policy_type {
                    "auth" => {
                        auth = Some(RawRouteAction::Ref(name));
                        Ok(())
                    },
                    "waf" => {
                        waf = Some(RawRouteAction::Ref(name));
                        Ok(())
                    },
                    "cors" => {
                        cors = Some(RawRouteAction::Ref(name));
                        Ok(())
                    },
                    "limiter" => {
                        limiter = Some(RawRouteAction::Ref(name));
                        Ok(())
                    },
                    "helmet" => {
                        helmet = Some(RawRouteAction::Ref(name));
                        Ok(())
                    },
                    _ => Err(ConfigError::parse(format!("unknown policy type '{}'", policy_type))),
                };
                action?;
            },
            Rule::policy_extends => {
                let mut inner = entry.into_inner();
                let policy_type = inner.next().unwrap().as_str();
                let base = extract_str(inner.next().unwrap());
                let action = match policy_type {
                    "auth" => {
                        auth = Some(RawRouteAction::Extends { base, overrides: parse_raw_auth_config(inner)? });
                        Ok(())
                    },
                    "waf" => {
                        waf = Some(RawRouteAction::Extends { base, overrides: parse_raw_waf_config(inner)? });
                        Ok(())
                    },
                    "cors" => {
                        cors = Some(RawRouteAction::Extends { base, overrides: parse_raw_cors_config(inner)? });
                        Ok(())
                    },
                    "limiter" => {
                        limiter = Some(RawRouteAction::Extends { base, overrides: parse_raw_limiter_config(inner)? });
                        Ok(())
                    },
                    "helmet" => {
                        helmet = Some(RawRouteAction::Extends { base, overrides: parse_raw_helmet_config(inner)? });
                        Ok(())
                    },
                    _ => Err(ConfigError::parse(format!("unknown policy type '{}'", policy_type))),
                };
                action?;
            },
            Rule::policy_local_block => {
                let mut inner = entry.into_inner();
                let policy_type = inner.next().unwrap().as_str();
                let action = match policy_type {
                    "auth" => {
                        auth = Some(RawRouteAction::Inline(parse_raw_auth_config(inner)?));
                        Ok(())
                    },
                    "waf" => {
                        waf = Some(RawRouteAction::Inline(parse_raw_waf_config(inner)?));
                        Ok(())
                    },
                    "cors" => {
                        cors = Some(RawRouteAction::Inline(parse_raw_cors_config(inner)?));
                        Ok(())
                    },
                    "limiter" => {
                        limiter = Some(RawRouteAction::Inline(parse_raw_limiter_config(inner)?));
                        Ok(())
                    },
                    "helmet" => {
                        helmet = Some(RawRouteAction::Inline(parse_raw_helmet_config(inner)?));
                        Ok(())
                    },
                    _ => Err(ConfigError::parse(format!("unknown policy type '{}'", policy_type))),
                };
                action?;
            },
            Rule::EOI => {},
            _ => {},
        }
    }
    Ok(RawRoutePolicies { auth, cors, waf, limiter, helmet })
}

// ============================================================================
// REWRITE / HEADERS / TIMEOUTS / STREAMING
// ============================================================================

fn parse_raw_rewrite(pair: pest::iterators::Pair<Rule>) -> RawUriRewrite {
    let mut strip_prefix = None;
    let mut strip_suffix = None;
    let mut replaces = Vec::new();
    let mut trailing_slash = None;

    for directive in pair.into_inner() {
        match directive.as_rule() {
            Rule::rewrite_strip_prefix => {
                strip_prefix = Some(extract_str(directive.into_inner().next().unwrap()));
            },
            Rule::rewrite_strip_suffix => {
                strip_suffix = Some(extract_str(directive.into_inner().next().unwrap()));
            },
            Rule::rewrite_replace => {
                let mut inner = directive.into_inner();
                let from = extract_str(inner.next().unwrap());
                let to = extract_str(inner.next().unwrap());
                replaces.push((from, to));
            },
            Rule::rewrite_trailing_slash => {
                trailing_slash = Some(extract_str(directive.into_inner().next().unwrap()));
            },
            Rule::EOI => {},
            _ => {},
        }
    }

    RawUriRewrite { strip_prefix, strip_suffix, replaces, trailing_slash }
}

fn parse_raw_inbound_headers(pair: pest::iterators::Pair<Rule>) -> RawRouteHeadersOpts<RawHeadersOps> {
    let mut set = Vec::new();
    let mut remove = Vec::new();
    let mut to_upstream = None;

    for entry in pair.into_inner() {
        match entry.as_rule() {
            Rule::headers_set => {
                let val = entry.into_inner().next().unwrap();
                if val.as_rule() == Rule::inline_object {
                    for ikv in val.into_inner() {
                        if ikv.as_rule() == Rule::inline_kv {
                            let mut ikv_inner = ikv.into_inner();
                            let hname = extract_str(ikv_inner.next().unwrap());
                            let hval = extract_value(ikv_inner.next().unwrap());
                            set.push((hname, hval));
                        }
                    }
                }
            },
            Rule::headers_remove => {
                let val = entry.into_inner().next().unwrap();
                remove = extract_raw_array(val);
            },
            Rule::headers_add => {
                let val = entry.into_inner().next().unwrap();
                if val.as_rule() == Rule::inline_object {
                    for ikv in val.into_inner() {
                        if ikv.as_rule() == Rule::inline_kv {
                            let mut ikv_inner = ikv.into_inner();
                            let hname = extract_str(ikv_inner.next().unwrap());
                            let hval = extract_value(ikv_inner.next().unwrap());
                            set.push((hname, hval));
                        }
                    }
                }
            },
            Rule::headers_to_upstream => {
                to_upstream = Some(Box::new(parse_raw_headers_direction(entry)));
            },
            Rule::EOI => {},
            _ => {},
        }
    }

    RawRouteHeadersOpts {
        opts: RawHeadersOps { set, remove },
        upstream: to_upstream
            .map(|d| RawHeadersOps { set: d.set, remove: d.remove })
            .unwrap_or(RawHeadersOps { set: Vec::new(), remove: Vec::new() }),
    }
}

fn parse_raw_outbound_headers(pair: pest::iterators::Pair<Rule>) -> RawRouteHeadersOpts<RawHeadersRemove> {
    let mut set = Vec::new();
    let mut remove = Vec::new();
    let mut from_upstream = None;

    for entry in pair.into_inner() {
        match entry.as_rule() {
            Rule::headers_set => {
                let val = entry.into_inner().next().unwrap();
                if val.as_rule() == Rule::inline_object {
                    for ikv in val.into_inner() {
                        if ikv.as_rule() == Rule::inline_kv {
                            let mut ikv_inner = ikv.into_inner();
                            let hname = extract_str(ikv_inner.next().unwrap());
                            let hval = extract_value(ikv_inner.next().unwrap());
                            set.push((hname, hval));
                        }
                    }
                }
            },
            Rule::headers_remove => {
                let val = entry.into_inner().next().unwrap();
                remove = extract_raw_array(val);
            },
            Rule::headers_add => {
                let val = entry.into_inner().next().unwrap();
                if val.as_rule() == Rule::inline_object {
                    for ikv in val.into_inner() {
                        if ikv.as_rule() == Rule::inline_kv {
                            let mut ikv_inner = ikv.into_inner();
                            let hname = extract_str(ikv_inner.next().unwrap());
                            let hval = extract_value(ikv_inner.next().unwrap());
                            set.push((hname, hval));
                        }
                    }
                }
            },
            Rule::headers_from_upstream => {
                from_upstream = Some(Box::new(parse_raw_headers_direction(entry)));
            },
            Rule::EOI => {},
            _ => {},
        }
    }

    let upstream_remove = from_upstream.map(|d| d.remove).unwrap_or_default();

    RawRouteHeadersOpts {
        opts: RawHeadersOps { set, remove },
        upstream: RawHeadersRemove { remove: upstream_remove },
    }
}

fn parse_raw_headers_direction(pair: pest::iterators::Pair<Rule>) -> RawHeadersOps {
    let mut set = Vec::new();
    let mut remove = Vec::new();

    for entry in pair.into_inner() {
        match entry.as_rule() {
            Rule::headers_direction_set => {
                let val = entry.into_inner().next().unwrap();
                if val.as_rule() == Rule::inline_object {
                    for ikv in val.into_inner() {
                        if ikv.as_rule() == Rule::inline_kv {
                            let mut ikv_inner = ikv.into_inner();
                            let hname = extract_str(ikv_inner.next().unwrap());
                            let hval = extract_value(ikv_inner.next().unwrap());
                            set.push((hname, hval));
                        }
                    }
                }
            },
            Rule::headers_direction_remove => {
                let val = entry.into_inner().next().unwrap();
                remove = extract_raw_array(val);
            },
            Rule::headers_to_upstream => {
                let nested = parse_raw_headers_direction(entry);
                set.extend(nested.set);
                remove.extend(nested.remove);
            },
            Rule::headers_from_upstream => {
                let nested = parse_raw_headers_direction(entry);
                set.extend(nested.set);
                remove.extend(nested.remove);
            },
            Rule::EOI => {},
            _ => {},
        }
    }

    RawHeadersOps { set, remove }
}

fn parse_raw_timeouts(pair: pest::iterators::Pair<Rule>) -> Result<RawRouteTimeouts, ConfigError> {
    let mut connect = None;
    let mut read = None;
    let mut send = None;

    for kv in pair.into_inner() {
        let rule = kv.as_rule();
        let val = kv.into_inner().next().unwrap();
        let value_str = extract_value(val);
        match rule {
            Rule::timeout_connect => {
                let value: u64 = parse_duration_millis(value_str)?;
                connect = Some(Duration::from_millis(value));
            },
            Rule::timeout_read => {
                let value: u64 = parse_duration_millis(value_str)?;
                read = Some(Duration::from_millis(value));
            },
            Rule::timeout_send => {
                let value: u64 = parse_duration_millis(value_str)?;
                send = Some(Duration::from_millis(value));
            },
            Rule::EOI => {},
            _ => {},
        }
    }

    Ok(RawRouteTimeouts { connect, read, send })
}

fn parse_raw_streaming(pair: pest::iterators::Pair<Rule>) -> RawStreaming {
    let mut buffering = None;
    let mut chunked = None;

    for kv in pair.into_inner() {
        let rule = kv.as_rule();
        let val = kv.into_inner().next().unwrap();
        match rule {
            Rule::streaming_buffering => buffering = Some(extract_str(val) == "true"),
            Rule::streaming_chunked => chunked = Some(extract_str(val) == "true"),
            Rule::EOI => {},
            _ => {},
        }
    }

    RawStreaming { buffering, chunked }
}

// ============================================================================
// GLOBAL POLICIES (auth, waf, cors, limiter, helmet)
// ============================================================================

fn parse_raw_policy(pair: pest::iterators::Pair<Rule>) -> Result<RawPolicy, ConfigError> {
    let mut inner = pair.into_inner();
    let policy_type = inner.next().unwrap().as_str();
    let name = extract_str(inner.next().unwrap());

    match policy_type {
        "cors" => Ok(RawPolicy::Cors { name, config: parse_raw_cors_config(inner)? }),
        "auth" => Ok(RawPolicy::Auth { name, config: parse_raw_auth_config(inner)? }),
        "waf" => Ok(RawPolicy::Waf { name, config: parse_raw_waf_config(inner)? }),
        "limiter" => Ok(RawPolicy::Limiter { name, config: parse_raw_limiter_config(inner)? }),
        "helmet" => Ok(RawPolicy::Helmet { name, config: parse_raw_helmet_config(inner)? }),
        _ => {
            let mut msg = String::new();
            for body in inner {
                if !msg.is_empty() {
                    msg.push_str(", ");
                }
                msg.push_str(body.as_str());
            }
            Err(ConfigError::parse(format!("unknown policy type '{}'", policy_type)))
        },
    }
}

fn parse_raw_cors_config(pairs: pest::iterators::Pairs<Rule>) -> Result<RawCorsConfig, ConfigError> {
    let mut config = RawCorsConfig {
        allow_origins: Vec::new(),
        allow_methods: Vec::new(),
        allow_headers: Vec::new(),
        expose_headers: Vec::new(),
        allow_credentials: None,
        max_age: None,
        exclude_paths: Vec::new(),
    };

    for body in pairs {
        if let Some((key, value)) = extract_key_value_from_pair(body) {
            match key {
                "allow_origins" => {
                    config.allow_origins = split_csv_values(value);
                },
                "allow_credentials" => {
                    config.allow_credentials = Some(value == "true");
                },
                "max_age" => {
                    let val = parse_duration_millis(value)?;
                    config.max_age = Some(Duration::from_millis(val));
                },
                "allow_methods" => {
                    config.allow_methods = split_csv_values(value);
                },
                "allow_headers" => {
                    config.allow_headers = split_csv_values(value);
                },
                "expose_headers" => {
                    config.expose_headers = split_csv_values(value);
                },
                "exclude_paths" => {
                    config.exclude_paths = split_csv_values(value);
                },
                _ => {},
            }
        }
    }

    Ok(config)
}

fn parse_raw_auth_config(pairs: pest::iterators::Pairs<Rule>) -> Result<RawAuthConfig, ConfigError> {
    let mut config = RawAuthConfig {
        issuer: None,
        audience: None,
        client_id: None,
        mode: None,
        dpop_proof: None,
        sources: None,
        refresh: None,
        exclude_paths: Vec::new(),
    };

    for body in pairs {
        match body.as_rule() {
            Rule::sources_block => {
                config.sources = Some(parse_raw_sources(body));
            },
            Rule::refresh_block => {
                config.refresh = Some(parse_raw_refresh(body));
            },
            Rule::auth_mode => {
                config.mode = Some(parse_raw_auth_mode(body));
            },
            _ => {
                if let Some((key, value)) = extract_key_value_from_pair(body) {
                    match key {
                        "issuer" => config.issuer = Some(value),
                        "audience" => config.audience = Some(value),
                        "client_id" => config.client_id = Some(value),
                        "dpop_proof" => config.dpop_proof = Some(value),
                        "exclude_paths" => config.exclude_paths = split_csv_values(value),
                        _ => {},
                    }
                }
            },
        }
    }

    Ok(config)
}

fn parse_raw_waf_config(pairs: pest::iterators::Pairs<Rule>) -> Result<RawWafConfig, ConfigError> {
    let mut config = RawWafConfig {
        mode: None,
        ruleset: None,
        max_body_size: None,
        anomaly_threshold: None,
        rules: Vec::new(),
        exclude_paths: Vec::new(),
    };

    for body in pairs {
        match body.as_rule() {
            Rule::rules_block => {
                config.rules = parse_raw_rules(body);
            },
            _ => {
                if let Some((key, value)) = extract_key_value_from_pair(body) {
                    match key {
                        "mode" => config.mode = Some(value),
                        "ruleset" => config.ruleset = Some(value),
                        "max_body_size" => config.max_body_size = Some(ByteSize::from_str(value)?),
                        "anomaly_threshold" => config.anomaly_threshold = value.parse().ok(),
                        "exclude_paths" => config.exclude_paths = split_csv_values(value),
                        _ => {},
                    }
                }
            },
        }
    }

    Ok(config)
}

fn parse_raw_limiter_config(pairs: pest::iterators::Pairs<Rule>) -> Result<RawLimiterConfig, ConfigError> {
    let mut config = RawLimiterConfig {
        rate: None,
        burst: None,
        strategy: None,
        identifier: None,
        exclude_paths: Vec::new(),
    };

    for body in pairs {
        if let Some((key, value)) = extract_key_value_from_pair(body) {
            match key {
                "rate" => config.rate = Some(parse_rate(value)?),
                "burst" => config.burst = value.parse().ok(),
                "strategy" => config.strategy = Some(value),
                "identifier" => config.identifier = Some(value),
                "exclude_paths" => config.exclude_paths = split_csv_values(value),
                _ => {},
            }
        }
    }

    Ok(config)
}

fn parse_raw_helmet_config(pairs: pest::iterators::Pairs<Rule>) -> Result<RawHelmetConfig, ConfigError> {
    let mut config = RawHelmetConfig { target: None, level: None };

    for body in pairs {
        if let Some((key, value)) = extract_key_value_from_pair(body) {
            match key {
                "target" => config.target = Some(value),
                "level" => config.level = Some(value),
                _ => {},
            }
        }
    }

    Ok(config)
}

// ============================================================================
// SOURCES / REFRESH / RULES
// ============================================================================

fn parse_raw_sources(pair: pest::iterators::Pair<Rule>) -> Vec<RawTokenSource> {
    pair.into_inner()
        .filter_map(|item| {
            if item.as_rule() != Rule::source_item {
                return None;
            }
            let mut inner = item.into_inner();
            let source_type = inner.next().unwrap().as_str();
            let mut name = None;
            let mut prefix = None;

            for field in inner {
                match field.as_rule() {
                    Rule::source_name => {
                        name = Some(extract_str(field.into_inner().next().unwrap()));
                    },
                    Rule::source_prefix => {
                        prefix = Some(extract_str(field.into_inner().next().unwrap()));
                    },
                    Rule::EOI => {},
                    _ => {},
                }
            }

            let source = match source_type {
                "header" => RawTokenSource::Header { name: name.unwrap_or(""), prefix },
                "cookie" => RawTokenSource::Cookie { name: name.unwrap_or(""), prefix },
                "query" => RawTokenSource::QueryParam { name: name.unwrap_or(""), prefix },
                _ => RawTokenSource::Header { name: name.unwrap_or(""), prefix },
            };
            Some(source)
        })
        .collect()
}

fn parse_raw_refresh(pair: pest::iterators::Pair<Rule>) -> RawRefreshConfig {
    let mut enabled = None;
    let mut endpoint = None;
    let mut sources = None;
    let mut inject = None;

    for body in pair.into_inner() {
        match body.as_rule() {
            Rule::refresh_enabled => {
                let val = body.into_inner().next().unwrap();
                enabled = Some(extract_str(val) == "true");
            },
            Rule::refresh_endpoint => {
                endpoint = Some(extract_str(body.into_inner().next().unwrap()));
            },
            Rule::sources_block => {
                let srcs = parse_raw_sources(body);
                sources = srcs.into_iter().next();
            },
            Rule::inject_block => {
                inject = Some(parse_raw_inject(body));
            },
            Rule::EOI => {},
            _ => {},
        }
    }

    RawRefreshConfig { enabled, endpoint, sources, inject }
}

fn parse_raw_auth_mode(pair: pest::iterators::Pair<Rule>) -> RawAuthMode {
    let mut inner = pair.into_inner();
    let mode_type = extract_str(inner.next().unwrap());

    let mut uri = None;
    let mut ttl = None;
    let mut algorithms = Vec::new();

    for entry in inner {
        match entry.as_rule() {
            Rule::auth_mode_uri => {
                uri = Some(extract_str(entry.into_inner().next().unwrap()));
            },
            Rule::auth_mode_ttl => {
                let val = extract_str(entry.into_inner().next().unwrap());
                ttl = parse_duration_millis(val).ok().map(Duration::from_millis);
            },
            Rule::auth_mode_algorithms => {
                let val = entry.into_inner().next().unwrap();
                algorithms = extract_raw_array(val);
            },
            Rule::EOI => {},
            _ => {},
        }
    }

    match mode_type {
        "jwks" => RawAuthMode::Jwks { uri, ttl, algorithms },
        "oidc" => RawAuthMode::Oidc { discovery_url: uri, ttl },
        _ => RawAuthMode::Jwks { uri, ttl, algorithms },
    }
}

fn parse_raw_inject(pair: pest::iterators::Pair<Rule>) -> RawInjectConfig {
    let mut access_token = Vec::new();
    let mut refresh_token = Vec::new();

    for target in pair.into_inner() {
        match target.as_rule() {
            Rule::inject_access_token => {
                access_token.extend(parse_raw_inject_targets(target));
            },
            Rule::inject_refresh_token => {
                refresh_token.extend(parse_raw_inject_targets(target));
            },
            Rule::EOI => {},
            _ => {},
        }
    }

    RawInjectConfig { access_token, refresh_token }
}

fn parse_raw_inject_targets(pair: pest::iterators::Pair<Rule>) -> Vec<RawInjectTarget> {
    let mut targets = Vec::new();
    for dest in pair.into_inner() {
        match dest.as_rule() {
            Rule::inject_header => {
                let name = extract_str(dest.into_inner().next().unwrap().into_inner().next().unwrap());
                targets.push(RawInjectTarget::Header { name });
            },
            Rule::inject_cookie => {
                targets.push(RawInjectTarget::Cookie(parse_raw_cookie_config(dest)));
            },
            Rule::EOI => {},
            _ => {},
        }
    }
    targets
}

fn parse_raw_cookie_config(pair: pest::iterators::Pair<Rule>) -> RawCookieConfig {
    let mut name = "";
    let mut path = None;
    let mut secure = None;
    let mut http_only = None;
    let mut same_site = None;

    for entry in pair.into_inner() {
        if entry.as_rule() == Rule::inject_cookie_entry {
            for field in entry.into_inner() {
                match field.as_rule() {
                    Rule::inject_cookie_name => {
                        name = extract_str(field.into_inner().next().unwrap());
                    },
                    Rule::inject_cookie_path => {
                        path = Some(extract_str(field.into_inner().next().unwrap()));
                    },
                    Rule::inject_cookie_secure => {
                        secure = Some(extract_str(field.into_inner().next().unwrap()) == "true");
                    },
                    Rule::inject_cookie_http_only => {
                        http_only = Some(extract_str(field.into_inner().next().unwrap()) == "true");
                    },
                    Rule::inject_cookie_same_site => {
                        same_site = Some(extract_str(field.into_inner().next().unwrap()));
                    },
                    Rule::EOI => {},
                    _ => {},
                }
            }
        }
    }

    RawCookieConfig { name, path, secure, http_only, same_site }
}

fn parse_raw_rules(pair: pest::iterators::Pair<Rule>) -> Vec<RawWafRule> {
    pair.into_inner()
        .filter_map(|def| {
            if def.as_rule() != Rule::rule_def {
                return None;
            }
            let mut inner = def.into_inner();
            let name = extract_str(inner.next().unwrap());
            let mut phase = "";
            let mut when = "";
            let mut action = "";
            let mut score = None;
            let mut message = None;

            for body in inner {
                match body.as_rule() {
                    Rule::rule_phase => {
                        phase = extract_str(body.into_inner().next().unwrap());
                    },
                    Rule::rule_when => {
                        when = extract_str(body.into_inner().next().unwrap());
                    },
                    Rule::rule_action => {
                        action = extract_str(body.into_inner().next().unwrap());
                    },
                    Rule::rule_score => {
                        let inner_pair = body.into_inner().next().unwrap();
                        score = inner_pair.as_str().parse().ok();
                    },
                    Rule::rule_message => {
                        message = Some(extract_str(body.into_inner().next().unwrap()));
                    },
                    Rule::EOI => {},
                    _ => {},
                }
            }

            Some(RawWafRule { name, phase, action, score, when, message })
        })
        .collect()
}

// ============================================================================
// HELPERS
// ============================================================================

fn extract_key_value_from_pair(body: pest::iterators::Pair<'_, Rule>) -> Option<(&str, &str)> {
    let full = body.as_str();
    let (key, _rest) = full.split_once('=')?;
    let key = key.trim();
    let val_pair = if body.as_rule() == Rule::key_value {
        body.into_inner().nth(1)
    } else {
        body.into_inner().next()
    };
    let value = extract_value(val_pair?);
    Some((key, value))
}

fn extract_str(pair: pest::iterators::Pair<'_, Rule>) -> &str {
    match pair.as_rule() {
        Rule::string => pair.into_inner().next().unwrap().as_str(),
        _ => pair.as_str(),
    }
}

fn extract_value(pair: pest::iterators::Pair<'_, Rule>) -> &str {
    match pair.as_rule() {
        Rule::value => {
            let inner = pair.into_inner().next().unwrap();
            extract_value(inner)
        },
        Rule::string => extract_str(pair),
        _ => pair.as_str(),
    }
}

fn extract_raw_array(pair: pest::iterators::Pair<'_, Rule>) -> Vec<&str> {
    pair.into_inner()
        .filter_map(|v| {
            let inner = v.into_inner().next()?;
            Some(extract_str(inner))
        })
        .collect()
}

fn split_csv_values(s: &str) -> Vec<&str> {
    let s = s.trim();
    if s.starts_with('[') && s.ends_with(']') {
        let inner = &s[1..s.len() - 1];
        inner
            .split(',')
            .map(|s| s.trim().trim_matches('"').trim_matches('\''))
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        s.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect()
    }
}

pub fn parse_duration_millis(s: &str) -> Result<u64, String> {
    let s = s.trim();

    // Handle milliseconds directly
    if let Some(val) = s.strip_suffix("ms") {
        let ms: u64 = val.parse().map_err(|_| format!("invalid duration '{}'", s))?;
        return Ok(ms);
    }

    // Handle seconds (1s = 1,000ms)
    if let Some(val) = s.strip_suffix('s') {
        let secs: u64 = val.parse().map_err(|_| format!("invalid duration '{}'", s))?;
        return secs.checked_mul(1_000).ok_or_else(|| format!("duration overflow in '{}'", s));
    }

    // Handle minutes (1m = 60,000ms)
    if let Some(val) = s.strip_suffix('m') {
        let mins: u64 = val.parse().map_err(|_| format!("invalid duration '{}'", s))?;
        return mins.checked_mul(60_000).ok_or_else(|| format!("duration overflow in '{}'", s));
    }

    // Handle hours (1h = 3,600,000ms)
    if let Some(val) = s.strip_suffix('h') {
        let hrs: u64 = val.parse().map_err(|_| format!("invalid duration '{}'", s))?;
        return hrs.checked_mul(3_600_000).ok_or_else(|| format!("duration overflow in '{}'", s));
    }

    // Default fallback (assume raw numbers are raw seconds)
    let secs: u64 = s.parse().map_err(|_| format!("invalid duration '{}'", s))?;
    secs.checked_mul(1_000).ok_or_else(|| format!("duration overflow in '{}'", s))
}

fn parse_rate(s: &str) -> Result<(u64, Duration), String> {
    let s = s.trim();

    if let Some((num, period)) = s.split_once('/') {
        // Exprimimos CPU: El error de parseo solo formatea el string SI falla
        let requests: u64 = num.parse().map_err(|_| format!("invalid rate number '{}' in '{}'", num, s))?;

        let per = match period.trim() {
            "s" => Duration::from_secs(1),
            "m" => Duration::from_secs(60),
            "h" => Duration::from_secs(3600),
            "d" => Duration::from_secs(86400),
            _ => return Err(format!("invalid rate period '{}' in '{}'", period, s)),
        };

        Ok((requests, per))
    } else {
        Err(format!("invalid rate format '{}': expected N/s, N/m, N/h, or N/d", s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_master() {
        let input = r#"
master "ophan-01" {
    user = "www-data"
    workers = "auto"
    pid = "/run/ophan.pid"
    error_log = "/var/log/ophan/error.log"
    includes = "/etc/ophan/gateways/*.conf"
}
"#;
        let m = parse_raw_master(input).unwrap();
        assert_eq!(m.name, "ophan-01");
        assert_eq!(m.user, "www-data");
        assert!(matches!(m.workers, RawWorkers::Auto));
        assert_eq!(m.pid, "/run/ophan.pid");
        assert_eq!(m.error_log, "/var/log/ophan/error.log");
        assert_eq!(m.includes.len(), 1);
        assert_eq!(m.includes[0], "/etc/ophan/gateways/*.conf");
    }

    #[test]
    fn test_parse_master_numeric_workers() {
        let input = r#"
master "test" {
    workers = 4
}
"#;
        let m = parse_raw_master(input).unwrap();
        assert!(matches!(m.workers, RawWorkers::Count(4)));
    }

    #[test]
    fn test_parse_minimal_gateway() {
        let input = r#"
name = "test-gw"
"#;
        let gw = parse_raw_gateway(input).unwrap();
        assert_eq!(gw.name, "test-gw");
        assert!(gw.listeners.is_empty());
        assert!(gw.upstreams.is_empty());
        assert!(gw.routes.is_empty());
        assert!(gw.policies.is_empty());
    }

    #[test]
    fn test_parse_listener_minimal() {
        let input = r#"
name = "test-gw"
listeners {
    listener "http" {
        address = ":8080"
    }
}
"#;
        let gw = parse_raw_gateway(input).unwrap();
        assert_eq!(gw.listeners.len(), 1);
        let l = &gw.listeners[0];
        assert_eq!(l.name, "http");
        assert_eq!(l.address, ":8080");
        assert!(l.protocols.is_empty());
        assert!(l.tls.is_none());
    }

    #[test]
    fn test_parse_listener_full() {
        let input = r#"
name = "test-gw"
listeners {
    listener "https" {
        address = "0.0.0.0:443"
        protocols = ["http1", "http2"]

        ssl {
            cert = "/etc/certs/public.pem"
            key = "/etc/certs/private.key"
            versions = ["TLS1.2", "TLS1.3"]
            client_auth = "optional"
            client_ca = "/etc/certs/ca.pem"
            ciphers = ["TLS_AES_256_GCM_SHA384"]
        }

        network_policy {
            allowed_ip_ranges = ["10.0.0.0/8"]
            blocked_ip_ranges = ["192.168.1.0/24"]
            real_ip_header = "X-Forwarded-For"
            proxy_allowed_ips = ["173.245.48.0/20"]
            policy = "degrade"
        }

        limits {
            connections = 100000
            request_size = 10mb
        }

        timeouts {
            idle = 60s
            keepalive = 30s
        }
    }
}
"#;
        let gw = parse_raw_gateway(input).unwrap();
        let l = &gw.listeners[0];
        assert_eq!(l.name, "https");
        assert_eq!(l.address, "0.0.0.0:443");
        assert_eq!(l.protocols, vec!["http1", "http2"]);

        let tls = l.tls.as_ref().unwrap();
        assert_eq!(tls.cert, "/etc/certs/public.pem");
        assert_eq!(tls.key, "/etc/certs/private.key");
        assert_eq!(tls.versions, vec!["TLS1.2", "TLS1.3"]);
        assert_eq!(tls.client_auth, Some("optional"));
        assert_eq!(tls.client_ca, Some("/etc/certs/ca.pem"));
        assert_eq!(tls.ciphers, vec!["TLS_AES_256_GCM_SHA384"]);

        let np = l.network_policy.as_ref().unwrap();
        assert_eq!(np.allowed_ip_ranges, vec!["10.0.0.0/8"]);
        assert_eq!(np.blocked_ip_ranges, vec!["192.168.1.0/24"]);
        assert_eq!(np.real_ip_header, Some("X-Forwarded-For"));
        assert_eq!(np.proxy_allowed_ips, Some(vec!["173.245.48.0/20"]));

        let limits = l.limits.as_ref().unwrap();
        assert_eq!(limits.connections, Some(100000));

        let timeouts = l.timeouts.as_ref().unwrap();
        assert!(timeouts.idle.is_some());
        assert!(timeouts.keepalive.is_some());
    }

    #[test]
    fn test_parse_upstream_minimal() {
        let input = r#"
name = "test-gw"
upstreams {
    upstream "api" {
        static_servers = ["127.0.0.1:8080"]
    }
}
"#;
        let gw = parse_raw_gateway(input).unwrap();
        assert_eq!(gw.upstreams.len(), 1);
        let u = &gw.upstreams[0];
        assert_eq!(u.name, "api");
        assert_eq!(u.static_servers.len(), 1);
        assert_eq!(u.static_servers[0].endpoint, "127.0.0.1:8080");
    }

    #[test]
    fn test_parse_upstream_with_objects() {
        let input = r#"
name = "test-gw"
upstreams {
    upstream "api" {
        balance_strategy = "round_robin"
        static_servers = [
            "api-1:8080",
            { endpoint = "api-2:8080", weight = 50 }
        ]
        health_check = {
            path = "/health",
            interval = "10s",
            timeout = "2s",
            healthy_threshold = 2,
            unhealthy_threshold = 3
        }
    }
}
"#;
        let gw = parse_raw_gateway(input).unwrap();
        let u = &gw.upstreams[0];
        assert_eq!(u.name, "api");
        assert_eq!(u.balance_strategy, Some("round_robin"));
        assert_eq!(u.static_servers.len(), 2);
        assert_eq!(u.static_servers[0].endpoint, "api-1:8080");
        assert_eq!(u.static_servers[1].endpoint, "api-2:8080");
        assert_eq!(u.static_servers[1].weight, 50);
        let hc = u.health_check.as_ref().unwrap();
        assert_eq!(hc.path, Some("/health"));
        assert!(hc.interval.is_some());
        assert!(hc.timeout.is_some());
    }

    #[test]
    fn test_parse_route_minimal() {
        let input = r#"
name = "test-gw"
routes {
    path "/api/*" {
        backend = upstream("api")
    }
}
"#;
        let gw = parse_raw_gateway(input).unwrap();
        assert_eq!(gw.routes.len(), 1);
        match &gw.routes[0] {
            RawRoute::Path(p) => {
                assert_eq!(p.path, "/api/*");
                assert!(matches!(p.backend, RawBackend::Upstream("api")));
            },
            _ => panic!("expected Path route"),
        }
    }

    #[test]
    fn test_parse_route_full() {
        let input = r#"
name = "test-gw"
upstreams {
    upstream "api" {
        static_servers = ["127.0.0.1:8080"]
    }
}
routes {
    path "/api/*" {
        hosts = ["api.example.me"]
        methods = ["GET", "POST"]

        backend = upstream("api")

        timeouts {
            connect = "5s"
            read = "30s"
            send = "30s"
        }

        streaming {
            buffering = false
            chunked = true
        }

        rewrite {
            strip_prefix = "/api"
            trailing_slash = "ensure"
        }

        inbound_headers {
            set = { "X-Client-Layer" = "edge" }
            remove = ["X-Bad-Header"]
        }

        outbound_headers {
            set = { "Cache-Control" = "no-store" }
            remove = ["Server", "X-Powered-By"]
        }
    }
}
"#;
        let gw = parse_raw_gateway(input).unwrap();
        match &gw.routes[0] {
            RawRoute::Path(p) => {
                assert_eq!(p.path, "/api/*");
                assert_eq!(p.hosts, vec!["api.example.me"]);
                assert_eq!(p.methods, vec!["GET", "POST"]);

                let to = p.timeouts.as_ref().unwrap();
                assert!(to.connect.is_some());
                assert!(to.read.is_some());
                assert!(to.send.is_some());

                let st = p.streaming.as_ref().unwrap();
                assert_eq!(st.buffering, Some(false));
                assert_eq!(st.chunked, Some(true));

                let rw = p.rewrite.as_ref().unwrap();
                assert_eq!(rw.strip_prefix, Some("/api"));
                assert_eq!(rw.trailing_slash, Some("ensure"));

                assert!(p.inbound_headers.is_some());
                assert!(p.outbound_headers.is_some());
            },
            _ => panic!("expected Path route"),
        }
    }

    #[test]
    fn test_parse_route_static_backend() {
        let input = r#"
name = "test-gw"
routes {
    path "/" {
        backend = static("/var/www/public")
        static_config {
            listing = false
            dotfiles = false
            index = true
            symlinks = false
            exclude_paths = [".git/*", ".env"]
        }
    }
}
"#;
        let gw = parse_raw_gateway(input).unwrap();
        match &gw.routes[0] {
            RawRoute::Path(p) => match &p.backend {
                RawBackend::Static(sb) => {
                    assert_eq!(sb.root, "/var/www/public");
                    assert_eq!(sb.flags.listing, Some(false));
                    assert_eq!(sb.flags.dotfiles, Some(false));
                    assert_eq!(sb.flags.index, Some(true));
                    assert_eq!(sb.flags.symlinks, Some(false));
                    assert_eq!(sb.exclude_paths, vec![".git/*", ".env"]);
                },
                _ => panic!("expected Static backend"),
            },
            _ => panic!("expected Path route"),
        }
    }

    #[test]
    fn test_parse_auth_policy_minimal() {
        let input = r#"
name = "test-gw"
policy auth "default" {
    issuer = "https://auth.example.com"
    audience = "api"
}
"#;
        let gw = parse_raw_gateway(input).unwrap();
        assert_eq!(gw.policies.len(), 1);
        match &gw.policies[0] {
            RawPolicy::Auth { name, config } => {
                assert_eq!(*name, "default");
                assert_eq!(config.issuer, Some("https://auth.example.com"));
                assert_eq!(config.audience, Some("api"));
            },
            _ => panic!("expected Auth policy"),
        }
    }

    #[test]
    fn test_parse_auth_policy_full() {
        let input = r#"
name = "test-gw"
policy auth "default" {
    issuer = "https://auth.example.com"
    audience = "api"
    client_id = "edge"
    dpop_proof = "required"
    exclude_paths = ["src/*"]

    mode "jwks" {
        uri = "http://localhost:4040/v1/oauth/.well-known/jwks.json"
        ttl = 1h
        algorithms = ["RS256", "ES256"]
    }

    sources {
        header {
            name = "Authorization"
            prefix = "Bearer "
        }
        cookie {
            name = "access_token"
        }
    }
}
"#;
        let gw = parse_raw_gateway(input).unwrap();
        match &gw.policies[0] {
            RawPolicy::Auth { name, config } => {
                assert_eq!(*name, "default");
                assert_eq!(config.issuer, Some("https://auth.example.com"));
                assert_eq!(config.audience, Some("api"));
                assert_eq!(config.client_id, Some("edge"));
                assert_eq!(config.dpop_proof, Some("required"));
                assert_eq!(config.exclude_paths, vec!["src/*"]);

                let mode = config.mode.as_ref().unwrap();
                match mode {
                    RawAuthMode::Jwks { uri, ttl, algorithms } => {
                        assert_eq!(*uri, Some("http://localhost:4040/v1/oauth/.well-known/jwks.json"));
                        assert!(ttl.is_some());
                        assert_eq!(*algorithms, vec!["RS256", "ES256"]);
                    },
                    _ => panic!("expected JWKS mode"),
                }

                let sources = config.sources.as_ref().unwrap();
                assert_eq!(sources.len(), 2);
            },
            _ => panic!("expected Auth policy"),
        }
    }

    #[test]
    fn test_parse_waf_policy() {
        let input = r#"
name = "test-gw"
policy waf "default" {
    mode = "block"
    ruleset = "owasp"
    max_body_size = 10mb
    anomaly_threshold = 5
    exclude_paths = ["/health", "/metrics"]

    rules {
        rule "block_sqli" {
            phase = "request_headers"
            when = "request.method IN (GET, POST)"
            action = "block"
            score = 5
            message = "Possible SQL injection"
        }
    }
}
"#;
        let gw = parse_raw_gateway(input).unwrap();
        match &gw.policies[0] {
            RawPolicy::Waf { name, config } => {
                assert_eq!(*name, "default");
                assert_eq!(config.mode, Some("block"));
                assert_eq!(config.ruleset, Some("owasp"));
                assert!(config.max_body_size.is_some());
                assert_eq!(config.anomaly_threshold, Some(5));
                assert_eq!(config.exclude_paths, vec!["/health", "/metrics"]);
                assert_eq!(config.rules.len(), 1);
                assert_eq!(config.rules[0].name, "block_sqli");
                assert_eq!(config.rules[0].phase, "request_headers");
                assert_eq!(config.rules[0].when, "request.method IN (GET, POST)");
                assert_eq!(config.rules[0].action, "block");
                assert_eq!(config.rules[0].score, Some(5));
                assert_eq!(config.rules[0].message, Some("Possible SQL injection"));
            },
            _ => panic!("expected Waf policy"),
        }
    }

    #[test]
    fn test_parse_cors_policy() {
        let input = r#"
name = "test-gw"
policy cors "default" {
    allow_origins = ["https://example.com", "https://app.example.com"]
    allow_methods = ["GET", "POST", "OPTIONS"]
    allow_headers = ["Authorization", "X-Request-Id"]
    expose_headers = ["X-Request-Id"]
    allow_credentials = true
    max_age = "2h"
    exclude_paths = ["/health"]
}
"#;
        let gw = parse_raw_gateway(input).unwrap();
        match &gw.policies[0] {
            RawPolicy::Cors { name, config } => {
                assert_eq!(*name, "default");
                assert_eq!(config.allow_origins, vec!["https://example.com", "https://app.example.com"]);
                assert_eq!(config.allow_methods, vec!["GET", "POST", "OPTIONS"]);
                assert_eq!(config.allow_headers, vec!["Authorization", "X-Request-Id"]);
                assert_eq!(config.expose_headers, vec!["X-Request-Id"]);
                assert_eq!(config.allow_credentials, Some(true));
                assert!(config.max_age.is_some());
                assert_eq!(config.exclude_paths, vec!["/health"]);
            },
            _ => panic!("expected Cors policy"),
        }
    }

    #[test]
    fn test_parse_limiter_policy() {
        let input = r#"
name = "test-gw"
policy limiter "default" {
    rate = "100/s"
    burst = 50
    strategy = "sliding_window"
    identifier = "ip"
    exclude_paths = ["/health"]
}
"#;
        let gw = parse_raw_gateway(input).unwrap();
        match &gw.policies[0] {
            RawPolicy::Limiter { name, config } => {
                assert_eq!(*name, "default");
                assert_eq!(config.rate, Some((100, Duration::from_secs(1))));
                assert_eq!(config.burst, Some(50));
                assert_eq!(config.strategy, Some("sliding_window"));
                assert_eq!(config.identifier, Some("ip"));
                assert_eq!(config.exclude_paths, vec!["/health"]);
            },
            _ => panic!("expected Limiter policy"),
        }
    }

    #[test]
    fn test_parse_helmet_policy() {
        let input = r#"
name = "test-gw"
policy helmet "web-strict" {
    target = "web"
    level = "strict"
}
"#;
        let gw = parse_raw_gateway(input).unwrap();
        match &gw.policies[0] {
            RawPolicy::Helmet { name, config } => {
                assert_eq!(*name, "web-strict");
                assert_eq!(config.target, Some("web"));
                assert_eq!(config.level, Some("strict"));
            },
            _ => panic!("expected Helmet policy"),
        }
    }

    #[test]
    fn test_parse_route_policy_direct() {
        let input = r#"
name = "test-gw"
policy auth "oauth" {
    issuer = "https://auth.example.com"
}
routes {
    path "/api/*" {
        backend = upstream("api")
        policies {
            auth = "oauth"
        }
    }
}
"#;
        let gw = parse_raw_gateway(input).unwrap();
        match &gw.routes[0] {
            RawRoute::Path(p) => {
                let policies = p.policies.as_ref().unwrap();
                assert!(policies.auth.is_some());
                assert!(policies.waf.is_none());
                assert!(policies.cors.is_none());
                assert!(policies.limiter.is_none());
                assert!(policies.helmet.is_none());
                match policies.auth.as_ref().unwrap() {
                    RawRouteAction::Ref(name) => assert_eq!(*name, "oauth"),
                    _ => panic!("expected Ref"),
                }
            },
            _ => panic!("expected Path route"),
        }
    }

    #[test]
    fn test_parse_route_policy_extends() {
        let input = r#"
name = "test-gw"
policy cors "base-cors" {
    allow_origins = ["https://example.com"]
}
routes {
    path "/api/*" {
        backend = upstream("api")
        policies {
            cors extends "base-cors" {
                max_age = "4h"
            }
        }
    }
}
"#;
        let gw = parse_raw_gateway(input).unwrap();
        match &gw.routes[0] {
            RawRoute::Path(p) => {
                let policies = p.policies.as_ref().unwrap();
                match policies.cors.as_ref().unwrap() {
                    RawRouteAction::Extends { base, overrides } => {
                        assert_eq!(*base, "base-cors");
                        assert_eq!(overrides.max_age, Some(Duration::from_secs(14400)));
                    },
                    _ => panic!("expected Extends"),
                }
            },
            _ => panic!("expected Path route"),
        }
    }

    #[test]
    fn test_parse_route_policy_local_block() {
        let input = r#"
name = "test-gw"
routes {
    path "/api/*" {
        backend = upstream("api")
        policies {
            limiter {
                rate = "50/s"
                burst = 25
            }
        }
    }
}
"#;
        let gw = parse_raw_gateway(input).unwrap();
        match &gw.routes[0] {
            RawRoute::Path(p) => {
                let policies = p.policies.as_ref().unwrap();
                match policies.limiter.as_ref().unwrap() {
                    RawRouteAction::Inline(config) => {
                        assert_eq!(config.rate, Some((50, Duration::from_secs(1))));
                        assert_eq!(config.burst, Some(25));
                    },
                    _ => panic!("expected Inline"),
                }
            },
            _ => panic!("expected Path route"),
        }
    }

    #[test]
    fn test_parse_auth_with_refresh_inject() {
        let input = r#"
name = "test-gw"
policy auth "default" {
    issuer = "https://auth.example.com"

    refresh {
        enabled = true
        endpoint = "http://localhost:4040/v1/oauth/token"

        sources {
            cookie {
                name = "refresh_token"
            }
        }
        inject {
            access_token {
                header {
                    name = "X-Access-Token"
                }
                cookie {
                    name = "op_token"
                    path = "/"
                    http_only = true
                    secure = true
                    same_site = "Lax"
                }
            }
            refresh_token {
                cookie {
                    name = "op_refresh"
                    path = "/"
                    http_only = true
                    secure = true
                }
            }
        }
    }
}
"#;
        let gw = parse_raw_gateway(input).unwrap();
        match &gw.policies[0] {
            RawPolicy::Auth { config, .. } => {
                let refresh = config.refresh.as_ref().unwrap();
                assert_eq!(refresh.enabled, Some(true));
                assert_eq!(refresh.endpoint, Some("http://localhost:4040/v1/oauth/token"));
                assert!(refresh.sources.is_some());
                let inject = refresh.inject.as_ref().unwrap();
                assert_eq!(inject.access_token.len(), 2);
                assert_eq!(inject.refresh_token.len(), 1);
            },
            _ => panic!("expected Auth policy"),
        }
    }

    #[test]
    fn test_parse_duration_millis() {
        assert_eq!(parse_duration_millis("100ms").unwrap(), 100);
        assert_eq!(parse_duration_millis("5s").unwrap(), 5000);
        assert_eq!(parse_duration_millis("2m").unwrap(), 120000);
        assert_eq!(parse_duration_millis("1h").unwrap(), 3600000);
        assert_eq!(parse_duration_millis("30").unwrap(), 30000);
    }

    #[test]
    fn test_parse_rate() {
        assert_eq!(parse_rate("100/s").unwrap(), (100, Duration::from_secs(1)));
        assert_eq!(parse_rate("500/m").unwrap(), (500, Duration::from_mins(1)));
        assert_eq!(parse_rate("10000/h").unwrap(), (10000, Duration::from_hours(1)));
        assert_eq!(parse_rate("100/d").unwrap(), (100, Duration::from_hours(24)));
    }

    #[test]
    fn test_parse_full_gateway() {
        let input = r#"
name = "full-gateway"

listeners {
    listener "https" {
        address = "0.0.0.0:443"
        protocols = ["http1", "http2"]
        ssl {
            cert = "/etc/certs/public.pem"
            key = "/etc/certs/private.key"
        }
    }
}

upstreams {
    upstream "api" {
        balance_strategy = "round_robin"
        static_servers = ["api-1:8080", "api-2:8080"]
    }
}

policy auth "oauth-default" {
    issuer = "https://auth.example.com"
    audience = "api"
}

policy cors "cors-default" {
    allow_origins = ["https://example.com"]
}

policy limiter "limiter-default" {
    rate = "100/s"
}

routes {
    path "/api/*" {
        hosts = ["api.example.me"]
        methods = ["GET", "POST"]
        backend = upstream("api")

        policies {
            auth = "oauth-default"
            cors extends "cors-default" {
                max_age = "4h"
            }
            limiter = "limiter-default"
        }

        timeouts {
            connect = "5s"
            read = "30s"
        }

        rewrite {
            strip_prefix = "/api"
        }
    }
}
"#;
        let gw = parse_raw_gateway(input).unwrap();
        assert_eq!(gw.name, "full-gateway");
        assert_eq!(gw.listeners.len(), 1);
        assert_eq!(gw.upstreams.len(), 1);
        assert_eq!(gw.policies.len(), 3);
        assert_eq!(gw.routes.len(), 1);

        match &gw.routes[0] {
            RawRoute::Path(p) => {
                assert_eq!(p.path, "/api/*");
                assert_eq!(p.hosts, vec!["api.example.me"]);
                assert_eq!(p.methods, vec!["GET", "POST"]);
                let policies = p.policies.as_ref().unwrap();
                assert!(policies.auth.is_some());
                assert!(policies.cors.is_some());
                assert!(policies.limiter.is_some());
                assert!(policies.waf.is_none());
                assert!(policies.helmet.is_none());
            },
            _ => panic!("expected Path route"),
        }
    }

    #[test]
    fn test_parse_invalid_field_errors() {
        let input = r#"
name = "test"
listeners {
    listener "http" {
        address = ":8080"
        invalid_field = "bad"
    }
}
"#;
        let result = parse_raw_gateway(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_network_policy_in_listener() {
        let input = r#"
name = "test-gw"
listeners {
    listener "https" {
        address = "0.0.0.0:443"
        network_policy {
            allowed_ip_ranges = ["10.0.0.0/8", "172.16.0.0/12"]
            blocked_ip_ranges = ["192.168.1.0/24"]
            real_ip_header = "X-Real-IP"
            proxy_allowed_ips = ["173.245.48.0/20"]
            policy = "degrade"
        }
    }
}
"#;
        let gw = parse_raw_gateway(input).unwrap();
        let l = &gw.listeners[0];
        let np = l.network_policy.as_ref().unwrap();
        assert_eq!(np.allowed_ip_ranges, vec!["10.0.0.0/8", "172.16.0.0/12"]);
        assert_eq!(np.blocked_ip_ranges, vec!["192.168.1.0/24"]);
        assert_eq!(np.real_ip_header, Some("X-Real-IP"));
        assert_eq!(np.proxy_allowed_ips, Some(vec!["173.245.48.0/20"]));
    }

    #[test]
    fn test_parse_multiple_routes() {
        let input = r#"
name = "test-gw"
upstreams {
    upstream "api" { static_servers = ["127.0.0.1:8080"] }
    upstream "web" { static_servers = ["127.0.0.1:3000"] }
}
routes {
    path "/api/*" { backend = upstream("api") }
    path "/web/*" { backend = upstream("web") }
    path "/static/*" { backend = static("/var/www") }
}
"#;
        let gw = parse_raw_gateway(input).unwrap();
        assert_eq!(gw.routes.len(), 3);
    }

    // =====================================================================
    // Docs-aligned: valid syntax per config_blocks/ docs
    // =====================================================================

    #[test]
    fn test_docs_listener_tls_keyword() {
        let input = r#"
name = "test-gw"
listeners {
    listener "ingress-https" {
        address = ":443"
        protocols = ["https"]
        tls {
            cert = "/etc/certs/public.pem"
            key = "/etc/certs/private.key"
            versions = ["TLS1.2", "TLS1.3"]
            client_auth = "optional"
            client_ca = "/etc/certs/ca.pem"
        }
    }
}
"#;
        let gw = parse_raw_gateway(input).unwrap();
        let l = &gw.listeners[0];
        assert_eq!(l.name, "ingress-https");
        assert_eq!(l.address, ":443");
        let tls = l.tls.as_ref().unwrap();
        assert_eq!(tls.cert, "/etc/certs/public.pem");
        assert_eq!(tls.key, "/etc/certs/private.key");
        assert_eq!(tls.versions, vec!["TLS1.2", "TLS1.3"]);
        assert_eq!(tls.client_auth, Some("optional"));
        assert_eq!(tls.client_ca, Some("/etc/certs/ca.pem"));
    }

    #[test]
    fn test_docs_static_backend_minimal() {
        let input = r#"
name = "test-gw"
routes {
    path "/static/*" {
        hosts = ["storage.domain.com"]
        backend = static("/var/www/public")
    }
}
"#;
        let gw = parse_raw_gateway(input).unwrap();
        match &gw.routes[0] {
            RawRoute::Path(p) => {
                assert_eq!(p.path, "/static/*");
                assert_eq!(p.hosts, vec!["storage.domain.com"]);
                match &p.backend {
                    RawBackend::Static(sb) => {
                        assert_eq!(sb.root, "/var/www/public");
                    },
                    _ => panic!("expected Static backend"),
                }
            },
            _ => panic!("expected Path route"),
        }
    }

    #[test]
    fn test_docs_static_config_at_route_level() {
        let input = r#"
name = "test-gw"
routes {
    path "/" {
        hosts = ["blob.domain.com"]
        backend = static("/var/www/public")
        static_config {
            listing = false
            dotfiles = false
            index = true
            symlinks = false
            exclude_paths = [".git/*", ".env"]
        }
    }
}
"#;
        let gw = parse_raw_gateway(input).unwrap();
        match &gw.routes[0] {
            RawRoute::Path(p) => match &p.backend {
                RawBackend::Static(sb) => {
                    assert_eq!(sb.root, "/var/www/public");
                    assert_eq!(sb.flags.listing, Some(false));
                    assert_eq!(sb.flags.dotfiles, Some(false));
                    assert_eq!(sb.flags.index, Some(true));
                    assert_eq!(sb.flags.symlinks, Some(false));
                    assert!(sb.exclude_paths.contains(&".git/*"));
                    assert!(sb.exclude_paths.contains(&".env"));
                },
                _ => panic!("expected Static backend"),
            },
            _ => panic!("expected Path route"),
        }
    }

    #[test]
    fn test_docs_rewrite_without_equals() {
        let input = r#"
name = "test-gw"
routes {
    path "/api/*" {
        backend = upstream("api")
        rewrite {
            strip_prefix "/api"
            strip_suffix ".json"
            trailing_slash "ensure"
        }
    }
}
upstreams {
    upstream "api" { static_servers = ["127.0.0.1:8080"] }
}
"#;
        let gw = parse_raw_gateway(input).unwrap();
        match &gw.routes[0] {
            RawRoute::Path(p) => {
                let rw = p.rewrite.as_ref().unwrap();
                assert_eq!(rw.strip_prefix, Some("/api"));
                assert_eq!(rw.strip_suffix, Some(".json"));
                assert_eq!(rw.trailing_slash, Some("ensure"));
            },
            _ => panic!("expected Path route"),
        }
    }

    #[test]
    fn test_docs_rewrite_with_equals_still_works() {
        let input = r#"
name = "test-gw"
routes {
    path "/api/*" {
        backend = upstream("api")
        rewrite {
            strip_prefix = "/api"
            trailing_slash = "ensure"
        }
    }
}
upstreams {
    upstream "api" { static_servers = ["127.0.0.1:8080"] }
}
"#;
        let gw = parse_raw_gateway(input).unwrap();
        match &gw.routes[0] {
            RawRoute::Path(p) => {
                let rw = p.rewrite.as_ref().unwrap();
                assert_eq!(rw.strip_prefix, Some("/api"));
                assert_eq!(rw.trailing_slash, Some("ensure"));
            },
            _ => panic!("expected Path route"),
        }
    }

    #[test]
    fn test_docs_upstream_server_address_key() {
        let input = r#"
name = "test-gw"
upstreams {
    upstream "api" {
        balance_strategy = "round_robin"
        static_servers = [
            "api-1:8080",
            { address = "api-2:8080", weight = 50 }
        ]
    }
}
"#;
        let gw = parse_raw_gateway(input).unwrap();
        let u = &gw.upstreams[0];
        assert_eq!(u.static_servers.len(), 2);
        assert_eq!(u.static_servers[0].endpoint, "api-1:8080");
        assert_eq!(u.static_servers[1].endpoint, "api-2:8080");
        assert_eq!(u.static_servers[1].weight, 50);
    }

    #[test]
    fn test_docs_auth_full_with_refresh_inject() {
        let input = r#"
name = "test-gw"
policy auth "default" {
    issuer = "https://auth.example.com"
    audience = "api"
    client_id = "edge"
    dpop_proof = "required"

    mode "jwks" {
        uri = "http://localhost:4040/v1/oauth/.well-known/jwks.json"
        ttl = 1h
        algorithms = ["RS256", "ES256"]
    }

    sources {
        header {
            name = "Authorization"
            prefix = "Bearer "
        }
        cookie {
            name = "access_token"
        }
        query {
            name = "access_token"
        }
    }

    refresh {
        enabled = true
        endpoint = "http://localhost:4040/v1/oauth/token"
        sources {
            cookie { name = "refresh_token" }
        }
        inject {
            access_token {
                header { name = "X-Access-Token" }
                cookie {
                    name = "op_token"
                    path = "/"
                    http_only = true
                    secure = true
                    same_site = "Lax"
                }
            }
            refresh_token {
                cookie {
                    name = "op_refresh"
                    path = "/"
                    http_only = true
                    secure = true
                }
            }
        }
    }

    exclude_paths = ["src/*"]
}
"#;
        let gw = parse_raw_gateway(input).unwrap();
        match &gw.policies[0] {
            RawPolicy::Auth { name, config } => {
                assert_eq!(*name, "default");
                assert_eq!(config.issuer, Some("https://auth.example.com"));
                assert_eq!(config.audience, Some("api"));
                assert_eq!(config.client_id, Some("edge"));
                assert_eq!(config.dpop_proof, Some("required"));
                assert_eq!(config.exclude_paths, vec!["src/*"]);

                let mode = config.mode.as_ref().unwrap();
                match mode {
                    RawAuthMode::Jwks { uri, ttl, algorithms } => {
                        assert_eq!(*uri, Some("http://localhost:4040/v1/oauth/.well-known/jwks.json"));
                        assert!(ttl.is_some());
                        assert_eq!(*algorithms, vec!["RS256", "ES256"]);
                    },
                    _ => panic!("expected JWKS mode"),
                }

                let sources = config.sources.as_ref().unwrap();
                assert_eq!(sources.len(), 3);
                match &sources[0] {
                    RawTokenSource::Header { name, prefix } => {
                        assert_eq!(*name, "Authorization");
                        assert_eq!(*prefix, Some("Bearer "));
                    },
                    _ => panic!("expected Header source"),
                }
                match &sources[1] {
                    RawTokenSource::Cookie { name, .. } => assert_eq!(*name, "access_token"),
                    _ => panic!("expected Cookie source"),
                }
                match &sources[2] {
                    RawTokenSource::QueryParam { name, .. } => assert_eq!(*name, "access_token"),
                    _ => panic!("expected QueryParam source"),
                }

                let refresh = config.refresh.as_ref().unwrap();
                assert_eq!(refresh.enabled, Some(true));
                assert_eq!(refresh.endpoint, Some("http://localhost:4040/v1/oauth/token"));
                assert!(refresh.sources.is_some());
                let inject = refresh.inject.as_ref().unwrap();
                assert_eq!(inject.access_token.len(), 2);
                assert_eq!(inject.refresh_token.len(), 1);
            },
            _ => panic!("expected Auth policy"),
        }
    }

    #[test]
    fn test_docs_waf_full_with_rules() {
        let input = r#"
name = "test-gw"
policy waf "default" {
    mode = "block"
    ruleset = "owasp"
    max_body_size = 10mb
    anomaly_threshold = 5
    exclude_paths = ["/health", "/metrics"]

    rules {
        rule "block_sqli" {
            phase = "request_headers"
            when = "request.method IN (GET, POST)"
            action = "block"
            score = 5
            message = "Possible SQL injection"
        }
    }
}
"#;
        let gw = parse_raw_gateway(input).unwrap();
        match &gw.policies[0] {
            RawPolicy::Waf { name, config } => {
                assert_eq!(*name, "default");
                assert_eq!(config.mode, Some("block"));
                assert_eq!(config.ruleset, Some("owasp"));
                assert!(config.max_body_size.is_some());
                assert_eq!(config.anomaly_threshold, Some(5));
                assert_eq!(config.exclude_paths, vec!["/health", "/metrics"]);
                assert_eq!(config.rules.len(), 1);
                assert_eq!(config.rules[0].name, "block_sqli");
                assert_eq!(config.rules[0].phase, "request_headers");
                assert_eq!(config.rules[0].action, "block");
                assert_eq!(config.rules[0].score, Some(5));
                assert_eq!(config.rules[0].message, Some("Possible SQL injection"));
            },
            _ => panic!("expected Waf policy"),
        }
    }

    #[test]
    fn test_docs_listener_with_network_policy_full() {
        let input = r#"
name = "test-gw"
listeners {
    listener "public-https" {
        address = "0.0.0.0:443"
        protocols = ["http1", "http2", "grpc", "websocket"]
        tls {
            cert = "/etc/certs/public.pem"
            key = "/etc/certs/private.key"
            versions = ["TLS1.2", "TLS1.3"]
            ciphers = ["TLS_AES_256_GCM_SHA384"]
        }
        network_policy {
            allowed_ip_ranges = ["10.0.0.0/8"]
            blocked_ip_ranges = ["192.168.1.0/24"]
            real_ip_header = "X-Forwarded-For"
            proxy_allowed_ips = ["173.245.48.0/20"]
        }
        limits {
            connections = 100000
            request_size = 10mb
        }
        timeouts {
            idle = 60s
            keepalive = 30s
        }
    }
}
"#;
        let gw = parse_raw_gateway(input).unwrap();
        let l = &gw.listeners[0];
        assert_eq!(l.name, "public-https");
        assert_eq!(l.address, "0.0.0.0:443");
        assert_eq!(l.protocols, vec!["http1", "http2", "grpc", "websocket"]);
        let tls = l.tls.as_ref().unwrap();
        assert_eq!(tls.cert, "/etc/certs/public.pem");
        assert_eq!(tls.key, "/etc/certs/private.key");
        assert_eq!(tls.versions, vec!["TLS1.2", "TLS1.3"]);
        assert_eq!(tls.ciphers, vec!["TLS_AES_256_GCM_SHA384"]);
        let np = l.network_policy.as_ref().unwrap();
        assert_eq!(np.allowed_ip_ranges, vec!["10.0.0.0/8"]);
        assert_eq!(np.real_ip_header, Some("X-Forwarded-For"));
        let limits = l.limits.as_ref().unwrap();
        assert_eq!(limits.connections, Some(100000));
        let timeouts = l.timeouts.as_ref().unwrap();
        assert!(timeouts.idle.is_some());
        assert!(timeouts.keepalive.is_some());
    }

    #[test]
    fn test_docs_route_full_with_all_blocks() {
        let input = r#"
name = "test-gw"
upstreams {
    upstream "api" { static_servers = ["127.0.0.1:8080"] }
}
routes {
    path "/api/*" {
        hosts = ["api.example.me", "payments.domain.com"]
        methods = ["GET", "POST", "PUT", "PATCH", "DELETE"]
        backend = upstream("api")
        timeouts {
            connect = "600s"
            read = "3600s"
            send = "3600s"
        }
        streaming {
            buffering = false
            chunked = false
        }
        rewrite {
            strip_prefix "/api"
            replace "/v1/*" -> "/v2/$1"
            trailing_slash "ensure"
        }
        inbound_headers {
            set = { "X-Client-Layer" = "edge" }
            remove = ["X-Bad-Header"]
            to_upstream {
                set = { "X-Forwarded-By" = "Ophan-Edge" }
                remove = ["Authorization"]
            }
        }
        outbound_headers {
            from_upstream {
                remove = ["X-Internal-Cluster-ID"]
            }
            set = { "Cache-Control" = "no-store" }
            remove = ["Server", "X-Powered-By"]
        }
        policies {
            auth extends "oauth-default" {
                sources {
                    cookie { name = "access_token" }
                }
            }
            cors extends "cors-default" {
                max_age = "4h"
            }
            limiter = "limiter-default"
        }
    }
}
policy auth "oauth-default" {
    issuer = "https://auth.example.com"
    audience = "api"
}
policy cors "cors-default" {
    allow_origins = ["https://example.com"]
}
policy limiter "limiter-default" {
    rate = "100/s"
}
"#;
        let gw = parse_raw_gateway(input).unwrap();
        assert_eq!(gw.listeners.len(), 0);
        assert_eq!(gw.upstreams.len(), 1);
        assert_eq!(gw.policies.len(), 3);
        assert_eq!(gw.routes.len(), 1);

        match &gw.routes[0] {
            RawRoute::Path(p) => {
                assert_eq!(p.path, "/api/*");
                assert_eq!(p.hosts, vec!["api.example.me", "payments.domain.com"]);
                assert_eq!(p.methods, vec!["GET", "POST", "PUT", "PATCH", "DELETE"]);

                let to = p.timeouts.as_ref().unwrap();
                assert!(to.connect.is_some());
                assert!(to.read.is_some());
                assert!(to.send.is_some());

                let st = p.streaming.as_ref().unwrap();
                assert_eq!(st.buffering, Some(false));
                assert_eq!(st.chunked, Some(false));

                let rw = p.rewrite.as_ref().unwrap();
                assert_eq!(rw.strip_prefix, Some("/api"));
                assert_eq!(rw.replaces, vec![("/v1/*", "/v2/$1")]);
                assert_eq!(rw.trailing_slash, Some("ensure"));

                assert!(p.inbound_headers.is_some());
                assert!(p.outbound_headers.is_some());

                let pol = p.policies.as_ref().unwrap();
                assert!(pol.auth.is_some());
                assert!(pol.cors.is_some());
                assert!(pol.limiter.is_some());
            },
            _ => panic!("expected Path route"),
        }
    }

    // =====================================================================
    // Error tests: invalid syntax / wrong data
    // =====================================================================

    #[test]
    fn test_error_invalid_workers_value() {
        let input = r#"
master "test" {
    workers = "foo"
}
"#;
        let result = parse_raw_master(input);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("workers"), "error should mention workers: {}", msg);
        assert!(msg.contains("foo"), "error should mention bad value: {}", msg);
    }

    #[test]
    fn test_error_server_unknown_key() {
        let input = r#"
name = "test-gw"
upstreams {
    upstream "api" {
        static_servers = [{ endpoint = "127.0.0.1:8080", typo_field = "bad" }]
    }
}
"#;
        let result = parse_raw_gateway(input);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("typo_field"), "error should mention unknown key: {}", msg);
    }

    #[test]
    fn test_error_server_invalid_weight() {
        let input = r#"
name = "test-gw"
upstreams {
    upstream "api" {
        static_servers = [{ endpoint = "127.0.0.1:8080", weight = "not_a_number" }]
    }
}
"#;
        let result = parse_raw_gateway(input);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("weight"), "error should mention weight: {}", msg);
    }

    #[test]
    fn test_error_static_config_on_upstream_backend() {
        let input = r#"
name = "test-gw"
routes {
    path "/api/*" {
        backend = upstream("api")
        static_config { listing = true }
    }
}
upstreams {
    upstream "api" { static_servers = ["127.0.0.1:8080"] }
}
"#;
        let result = parse_raw_gateway(input);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("static_config"), "error should mention static_config: {}", msg);
        assert!(msg.contains("static"), "error should mention static backend: {}", msg);
    }

    #[test]
    fn test_error_health_check_unknown_key() {
        let input = r#"
name = "test-gw"
upstreams {
    upstream "api" {
        static_servers = ["127.0.0.1:8080"]
        health_check = { path = "/health", typo_key = "bad" }
    }
}
"#;
        let result = parse_raw_gateway(input);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("typo_key"), "error should mention unknown key: {}", msg);
    }

    #[test]
    fn test_error_health_check_bad_threshold() {
        let input = r#"
name = "test-gw"
upstreams {
    upstream "api" {
        static_servers = ["127.0.0.1:8080"]
        health_check = { path = "/health", healthy_threshold = "not_a_number" }
    }
}
"#;
        let result = parse_raw_gateway(input);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("healthy_threshold"),
            "error should mention healthy_threshold: {}",
            msg
        );
    }

    #[test]
    fn test_error_invalid_array_server_entry() {
        let input = r#"
name = "test-gw"
upstreams {
    upstream "api" {
        static_servers = [12345]
    }
}
"#;
        let result = parse_raw_gateway(input);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("invalid server entry"),
            "error should mention invalid entry: {}",
            msg
        );
    }

    #[test]
    fn test_error_missing_route_backend() {
        let input = r#"
name = "test-gw"
routes {
    path "/api/*" {
        hosts = ["api.example.me"]
    }
}
"#;
        let result = parse_raw_gateway(input);
        assert!(result.is_ok());
        match &parse_raw_gateway(input).unwrap().routes[0] {
            RawRoute::Path(p) => {
                assert!(matches!(p.backend, RawBackend::Upstream("")));
            },
            _ => panic!("expected Path route"),
        }
    }

    // =====================================================================
    // Deep structure tests: verify exact values, not just is_some()
    // =====================================================================

    #[test]
    fn test_listener_ssl_all_fields() {
        let input = r#"
name = "test-gw"
listeners {
    listener "tls-listener" {
        address = "0.0.0.0:8443"
        protocols = ["http2", "grpc"]
        tls {
            cert = "/certs/server.pem"
            key = "/certs/server.key"
            client_ca = "/certs/ca.pem"
            client_auth = "require"
            versions = ["TLS1.3"]
            ciphers = ["TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"]
        }
    }
}
"#;
        let gw = parse_raw_gateway(input).unwrap();
        let l = &gw.listeners[0];
        assert_eq!(l.name, "tls-listener");
        assert_eq!(l.address, "0.0.0.0:8443");
        assert_eq!(l.protocols, vec!["http2", "grpc"]);
        let tls = l.tls.as_ref().unwrap();
        assert_eq!(tls.cert, "/certs/server.pem");
        assert_eq!(tls.key, "/certs/server.key");
        assert_eq!(tls.client_ca, Some("/certs/ca.pem"));
        assert_eq!(tls.client_auth, Some("require"));
        assert_eq!(tls.versions, vec!["TLS1.3"]);
        assert_eq!(tls.ciphers, vec!["TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"]);
    }

    #[test]
    fn test_upstream_inline_server_all_fields() {
        let input = r#"
name = "test-gw"
upstreams {
    upstream "mixed" {
        static_servers = [
            "simple:8080",
            { address = "weighted:9090", weight = 100, protocol = "http2" }
        ]
    }
}
"#;
        let gw = parse_raw_gateway(input).unwrap();
        let u = &gw.upstreams[0];
        assert_eq!(u.static_servers.len(), 2);
        assert_eq!(u.static_servers[0].endpoint, "simple:8080");
        assert_eq!(u.static_servers[0].weight, 1);
        assert!(u.static_servers[0].protocol.is_none());
        assert_eq!(u.static_servers[1].endpoint, "weighted:9090");
        assert_eq!(u.static_servers[1].weight, 100);
        assert_eq!(u.static_servers[1].protocol, Some("http2"));
    }

    #[test]
    fn test_static_config_partial_flags() {
        let input = r#"
name = "test-gw"
routes {
    path "/" {
        backend = static("/app")
        static_config {
            index = true
            exclude_paths = ["node_modules", ".cache"]
        }
    }
}
"#;
        let gw = parse_raw_gateway(input).unwrap();
        match &gw.routes[0] {
            RawRoute::Path(p) => match &p.backend {
                RawBackend::Static(sb) => {
                    assert_eq!(sb.root, "/app");
                    assert!(sb.flags.listing.is_none());
                    assert!(sb.flags.dotfiles.is_none());
                    assert_eq!(sb.flags.index, Some(true));
                    assert!(sb.flags.symlinks.is_none());
                    assert_eq!(sb.exclude_paths, vec!["node_modules", ".cache"]);
                },
                _ => panic!("expected Static"),
            },
            _ => panic!("expected Path route"),
        }
    }

    #[test]
    fn test_rewrite_preserves_values_with_and_without_equals() {
        let with_eq = r#"
name = "gw"
routes {
    path "/api/*" {
        backend = upstream("api")
        rewrite {
            strip_prefix = "/api"
            strip_suffix = ".json"
            replace = "/v1/*" -> "/v2/$1"
            trailing_slash = "ensure"
        }
    }
}
upstreams { upstream "api" { static_servers = ["127.0.0.1:80"] } }
"#;
        let without_eq = r#"
name = "gw"
routes {
    path "/api/*" {
        backend = upstream("api")
        rewrite {
            strip_prefix "/api"
            strip_suffix ".json"
            replace "/v1/*" -> "/v2/$1"
            trailing_slash "ensure"
        }
    }
}
upstreams { upstream "api" { static_servers = ["127.0.0.1:80"] } }
"#;
        let gw1 = parse_raw_gateway(with_eq).unwrap();
        let gw2 = parse_raw_gateway(without_eq).unwrap();
        let rw1 = match &gw1.routes[0] {
            RawRoute::Path(p) => p.rewrite.as_ref().unwrap(),
            _ => panic!(),
        };
        let rw2 = match &gw2.routes[0] {
            RawRoute::Path(p) => p.rewrite.as_ref().unwrap(),
            _ => panic!(),
        };
        assert_eq!(rw1.strip_prefix, rw2.strip_prefix);
        assert_eq!(rw1.strip_suffix, rw2.strip_suffix);
        assert_eq!(rw1.replaces, rw2.replaces);
        assert_eq!(rw1.trailing_slash, rw2.trailing_slash);
    }

    #[test]
    fn test_auth_sources_all_types() {
        let input = r#"
name = "test-gw"
policy auth "multi-source" {
    issuer = "https://auth.example.com"
    sources {
        header { name = "Authorization", prefix = "Bearer " }
        cookie { name = "session_token" }
        query { name = "token" }
    }
}
"#;
        let gw = parse_raw_gateway(input).unwrap();
        match &gw.policies[0] {
            RawPolicy::Auth { config, .. } => {
                let sources = config.sources.as_ref().unwrap();
                assert_eq!(sources.len(), 3);
                match &sources[0] {
                    RawTokenSource::Header { name, prefix } => {
                        assert_eq!(*name, "Authorization");
                        assert_eq!(*prefix, Some("Bearer "));
                    },
                    _ => panic!("expected Header"),
                }
                match &sources[1] {
                    RawTokenSource::Cookie { name, prefix } => {
                        assert_eq!(*name, "session_token");
                        assert!(prefix.is_none());
                    },
                    _ => panic!("expected Cookie"),
                }
                match &sources[2] {
                    RawTokenSource::QueryParam { name, prefix } => {
                        assert_eq!(*name, "token");
                        assert!(prefix.is_none());
                    },
                    _ => panic!("expected QueryParam"),
                }
            },
            _ => panic!("expected Auth"),
        }
    }

    #[test]
    fn test_inbound_outbound_headers_nested() {
        let input = r#"
name = "test-gw"
routes {
    path "/api/*" {
        backend = upstream("api")
        inbound_headers {
            set = { "X-Request-Id" = "generated-id" }
            remove = ["X-Internal"]
            to_upstream {
                set = { "X-Forwarded-By" = "edge" }
                remove = ["Cookie"]
            }
        }
        outbound_headers {
            set = { "X-Powered-By" = "none" }
            remove = ["Server", "X-Runtime"]
            from_upstream {
                remove = ["X-Debug"]
            }
        }
    }
}
upstreams { upstream "api" { static_servers = ["127.0.0.1:80"] } }
"#;
        let gw = parse_raw_gateway(input).unwrap();
        match &gw.routes[0] {
            RawRoute::Path(p) => {
                let ih = p.inbound_headers.as_ref().unwrap();
                assert_eq!(ih.opts.set.len(), 1);
                assert_eq!(ih.opts.set[0], ("X-Request-Id", "generated-id"));
                assert_eq!(ih.opts.remove, vec!["X-Internal"]);
                assert_eq!(ih.upstream.set.len(), 1);
                assert_eq!(ih.upstream.set[0], ("X-Forwarded-By", "edge"));
                assert_eq!(ih.upstream.remove, vec!["Cookie"]);

                let oh = p.outbound_headers.as_ref().unwrap();
                assert_eq!(oh.opts.set.len(), 1);
                assert_eq!(oh.opts.set[0], ("X-Powered-By", "none"));
                assert_eq!(oh.opts.remove, vec!["Server", "X-Runtime"]);
                assert_eq!(oh.upstream.remove, vec!["X-Debug"]);
            },
            _ => panic!("expected Path"),
        }
    }

    #[test]
    fn test_health_check_all_fields() {
        let input = r#"
name = "test-gw"
upstreams {
    upstream "svc" {
        static_servers = ["10.0.0.1:8080"]
        health_check = {
            path = "/ready",
            interval = "15s",
            timeout = "3s",
            healthy_threshold = 3,
            unhealthy_threshold = 5
        }
    }
}
"#;
        let gw = parse_raw_gateway(input).unwrap();
        let hc = gw.upstreams[0].health_check.as_ref().unwrap();
        assert_eq!(hc.path, Some("/ready"));
        assert_eq!(hc.interval, Some(Duration::from_millis(15000)));
        assert_eq!(hc.timeout, Some(Duration::from_millis(3000)));
        assert_eq!(hc.healthy_threshold, Some(3));
        assert_eq!(hc.unhealthy_threshold, Some(5));
    }

    #[test]
    fn test_cors_full_explicit_values() {
        let input = r#"
name = "test-gw"
policy cors "strict" {
    allow_origins = ["https://app.example.com", "https://admin.example.com"]
    allow_methods = ["GET", "POST", "OPTIONS"]
    allow_headers = ["Authorization", "Content-Type"]
    expose_headers = ["X-Request-Id"]
    allow_credentials = true
    max_age = "2h"
    exclude_paths = ["/health", "/metrics"]
}
"#;
        let gw = parse_raw_gateway(input).unwrap();
        match &gw.policies[0] {
            RawPolicy::Cors { config, .. } => {
                assert_eq!(
                    config.allow_origins,
                    vec!["https://app.example.com", "https://admin.example.com"]
                );
                assert_eq!(config.allow_methods, vec!["GET", "POST", "OPTIONS"]);
                assert_eq!(config.allow_headers, vec!["Authorization", "Content-Type"]);
                assert_eq!(config.expose_headers, vec!["X-Request-Id"]);
                assert_eq!(config.allow_credentials, Some(true));
                assert_eq!(config.max_age, Some(Duration::from_secs(7200)));
                assert_eq!(config.exclude_paths, vec!["/health", "/metrics"]);
            },
            _ => panic!("expected Cors"),
        }
    }

    // =====================================================================
    // Error tests: verify specific error messages
    // =====================================================================

    #[test]
    fn test_error_invalid_workers_message_contains_value() {
        let input = r#"
master "test" {
    workers = "not_a_number_or_auto"
}
"#;
        let err = parse_raw_master(input).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not_a_number_or_auto"), "should contain bad value: {}", msg);
        assert!(msg.contains("workers"), "should mention workers: {}", msg);
    }

    #[test]
    fn test_error_server_unknown_key_message() {
        let input = r#"
name = "test-gw"
upstreams {
    upstream "api" {
        static_servers = [{ endpoint = "1.2.3.4:80", bad_key = "value" }]
    }
}
"#;
        let err = parse_raw_gateway(input).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("bad_key"), "should mention unknown key: {}", msg);
        assert!(msg.contains("server"), "should mention context: {}", msg);
    }

    #[test]
    fn test_error_static_config_on_upstream_message() {
        let input = r#"
name = "test-gw"
routes {
    path "/api/*" {
        backend = upstream("api")
        static_config { listing = true }
    }
}
upstreams { upstream "api" { static_servers = ["127.0.0.1:80"] } }
"#;
        let err = parse_raw_gateway(input).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("static_config"), "should mention static_config: {}", msg);
        assert!(msg.contains("static backend"), "should mention static backend: {}", msg);
        assert!(msg.contains("/api/*"), "should mention route path: {}", msg);
    }

    #[test]
    fn test_error_invalid_duration_message() {
        let input = r#"
name = "test-gw"
routes {
    path "/api/*" {
        backend = upstream("api")
        timeouts { connect = "bad_duration" }
    }
}
upstreams { upstream "api" { static_servers = ["127.0.0.1:80"] } }
"#;
        let err = parse_raw_gateway(input).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("bad_duration"), "should mention bad value: {}", msg);
    }

    #[test]
    fn test_error_health_check_bad_threshold_message() {
        let input = r#"
name = "test-gw"
upstreams {
    upstream "api" {
        static_servers = ["127.0.0.1:80"]
        health_check = { path = "/health", healthy_threshold = "abc" }
    }
}
"#;
        let err = parse_raw_gateway(input).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("healthy_threshold"), "should mention field: {}", msg);
        assert!(msg.contains("abc"), "should mention bad value: {}", msg);
    }

    #[test]
    fn test_error_invalid_weight_message() {
        let input = r#"
name = "test-gw"
upstreams {
    upstream "api" {
        static_servers = [{ endpoint = "1.2.3.4:80", weight = "xyz" }]
    }
}
"#;
        let err = parse_raw_gateway(input).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("weight"), "should mention weight: {}", msg);
        assert!(msg.contains("xyz"), "should mention bad value: {}", msg);
    }

    #[test]
    fn test_error_invalid_array_entry_message() {
        let input = r#"
name = "test-gw"
upstreams {
    upstream "api" {
        static_servers = [true]
    }
}
"#;
        let err = parse_raw_gateway(input).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("invalid server entry"), "should mention invalid entry: {}", msg);
    }
}
