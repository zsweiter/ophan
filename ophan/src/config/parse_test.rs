use crate::config::dsl_parser::{parse_gateway_config, parse_master_config};
use crate::config::parts::{
    BackendTarget, BalanceStrategy, Http2Mode, LimiterIdentifier, NetworkProtocol, NetworkTransport, SecurityConfig, TokenSource,
};
use crate::config::utils;
use ophan_net::http::HttpMethod;

use ophan_waf::config::WafMode;

#[test]
fn test_parse_master_config() {
    let master_conf = r#"
master "ophan-01" {
    user = "www-data"
    workers = "auto"
    pid = "/run/ophan.pid"
    error_log = "/var/log/ophan/error.log"
    includes = "/etc/ophan/gateways/*.conf"
}
"#;

    let master = parse_master_config(master_conf).expect("Failed to parse master config");

    assert_eq!(master.name, "ophan-01");
    assert_eq!(master.user, "www-data");
    assert_eq!(master.workers, utils::get_parallel_size());
    assert_eq!(master.pid, "/run/ophan.pid");
    assert_eq!(master.error_log, "/var/log/ophan/error.log");
    assert_eq!(master.includes.len(), 1);
    assert_eq!(master.includes[0], "/etc/ophan/gateways/*.conf");
}

#[test]
fn test_parse_gateway_name() {
    let gateway_conf = r#"
name = "edge-gateway-prod"
"#;

    let config = parse_gateway_config(gateway_conf).expect("Failed to parse gateway config");
    assert_eq!(config.name, "edge-gateway-prod");
}

#[test]
fn test_parse_listeners_tcp() {
    let gateway_conf = r#"
listeners {
    listener "ingress-secure" {
        address = "0.0.0.0:443"
        protocols = ["http1", "http2"]
    }
}
"#;

    let config = parse_gateway_config(gateway_conf).expect("Failed to parse gateway config");
    assert_eq!(config.listeners.len(), 1);

    let listener = &config.listeners[0];
    assert_eq!(listener.name, "ingress-secure");
    assert_eq!(listener.listen, vec!["0.0.0.0:443"]);
    assert!(matches!(listener.transport, NetworkTransport::Tcp(_)));
    assert!(matches!(listener.security, SecurityConfig::Plaintext));
    assert_eq!(listener.protocols.len(), 2);
}

#[test]
fn test_parse_listeners_with_ssl() {
    let gateway_conf = r#"
listeners {
    listener "ingress-secure" {
        address = "0.0.0.0:443"
        protocols = ["http1", "http2"]

        ssl {
            cert = "/home/alex/.certs/cert.pem"
            key = "/home/alex/.certs/key.pem"
        }
    }
}
"#;

    let config = parse_gateway_config(gateway_conf).expect("Failed to parse gateway config");
    let listener = &config.listeners[0];

    match &listener.security {
        SecurityConfig::Tls { certs, .. } => {
            assert_eq!(certs.cert, "/home/alex/.certs/cert.pem");
            assert_eq!(certs.key, "/home/alex/.certs/key.pem");
            assert!(certs.client_ca.is_none());
        },
        _ => panic!("Expected TLS security"),
    }
}

#[test]
fn test_parse_listeners_unix_socket() {
    let gateway_conf = r#"
listeners {
    listener "ingress-internal" {
        address = "unix:/var/run/ophan-internal.sock"
        protocols = ["grpc"]
    }
}
"#;

    let config = parse_gateway_config(gateway_conf).expect("Failed to parse gateway config");
    let listener = &config.listeners[0];

    assert!(matches!(listener.transport, NetworkTransport::Uds(_)));
    if let NetworkTransport::Uds(path) = &listener.transport {
        assert_eq!(path, "/var/run/ophan-internal.sock");
    }

    assert_eq!(listener.protocols.len(), 1);
    assert!(matches!(
        listener.protocols[0],
        NetworkProtocol::Http2 { mode: Http2Mode::Grpc }
    ));
}

#[test]
fn test_parse_upstream_simple_string() {
    let gateway_conf = r#"
upstreams {
    upstream "billing-srv" {
        servers = "10.0.2.50:3000"
    }
}
"#;

    let config = parse_gateway_config(gateway_conf).expect("Failed to parse gateway config");
    assert_eq!(config.upstreams.len(), 1);

    let upstream = &config.upstreams[0];
    assert_eq!(upstream.name, "billing-srv");
    assert_eq!(upstream.servers.len(), 1);
    assert_eq!(upstream.servers[0].address, "10.0.2.50:3000");
    assert_eq!(upstream.servers[0].weight, 1);
}

#[test]
fn test_parse_upstream_inline_object() {
    let gateway_conf = r#"
upstreams {
    upstream "auth-srv" {
        servers = { endpoint = "auth-internal.lan:9000", weight = 100, protocol = "http2" }
    }
}
"#;

    let config = parse_gateway_config(gateway_conf).expect("Failed to parse gateway config");
    let upstream = &config.upstreams[0];

    assert_eq!(upstream.name, "auth-srv");
    assert_eq!(upstream.servers.len(), 1);
    assert_eq!(upstream.servers[0].address, "auth-internal.lan:9000");
    assert_eq!(upstream.servers[0].weight, 100);
    assert!(matches!(
        upstream.servers[0].protocol,
        NetworkProtocol::Http2 { mode: Http2Mode::Standard }
    ));
}

#[test]
fn test_parse_upstream_array() {
    let gateway_conf = r#"
upstreams {
    upstream "api-main-cluster" {
        load_balance = "least_connections"

        servers = [
            { endpoint = "10.0.1.10:4040", weight = 100 },
            { endpoint = "10.0.1.11:8080", weight = 50, protocol = "http2" },
            { endpoint = "10.0.1.12:9000", protocol = "http1" }
        ]
    }
}
"#;

    let config = parse_gateway_config(gateway_conf).expect("Failed to parse gateway config");
    let upstream = &config.upstreams[0];

    assert_eq!(upstream.name, "api-main-cluster");
    assert!(matches!(upstream.balance_strategy, BalanceStrategy::LeastConnections));
    assert_eq!(upstream.servers.len(), 3);

    assert_eq!(upstream.servers[0].address, "10.0.1.10:4040");
    assert_eq!(upstream.servers[0].weight, 100);

    assert_eq!(upstream.servers[1].address, "10.0.1.11:8080");
    assert_eq!(upstream.servers[1].weight, 50);
    assert!(matches!(
        upstream.servers[1].protocol,
        NetworkProtocol::Http2 { mode: Http2Mode::Standard }
    ));

    assert_eq!(upstream.servers[2].address, "10.0.1.12:9000");
    assert!(matches!(upstream.servers[2].protocol, NetworkProtocol::Http1 { .. }));
}

#[test]
fn test_parse_upstream_with_health_check() {
    let gateway_conf = r#"
upstreams {
    upstream "api-main-cluster" {
        servers = "10.0.1.10:4040"
        health_check = { path = "/healthz", interval = 10s, timeout = 250ms, unhealthy_threshold = 3, healthy_threshold = 2 }
    }
}
"#;

    let config = parse_gateway_config(gateway_conf).expect("Failed to parse gateway config");
    let upstream = &config.upstreams[0];

    assert!(upstream.health_check.is_some());
    let hc = upstream.health_check.as_ref().unwrap();
    assert_eq!(hc.path, "/healthz");
    assert_eq!(hc.interval, 10);
    assert_eq!(hc.timeout, 0);
    assert_eq!(hc.unhealthy_threshold, 3);
    assert_eq!(hc.healthy_threshold, 2);
}

#[test]
fn test_parse_route_backend_upstream() {
    let gateway_conf = r#"
routes {
    route "/api/v1/*" {
        hosts = ["api.example.me"]
        methods = ["GET", "POST", "PUT", "DELETE"]
        backend = upstream("api-main-cluster")
    }
}
"#;

    let config = parse_gateway_config(gateway_conf).expect("Failed to parse gateway config");
    assert_eq!(config.routes.len(), 1);

    let route = &config.routes[0];
    assert_eq!(route.path, "/api/v1/*");
    assert_eq!(route.hosts, vec!["api.example.me"]);
    assert!(
        route
            .methods
            .contains_http(HttpMethod::GET | HttpMethod::POST | HttpMethod::PUT | HttpMethod::DELETE)
    );

    match &route.backend {
        BackendTarget::Upstream(name) => assert_eq!(name, "api-main-cluster"),
        _ => panic!("Expected Upstream backend"),
    }
}

#[test]
fn test_parse_route_with_rewrite() {
    let gateway_conf = r#"
routes {
    route "/api/v1/*" {
        backend = upstream("api-main-cluster")

        rewrite {
            "/api/*" -> "/$1"
        }
    }
}
"#;

    let config = parse_gateway_config(gateway_conf).expect("Failed to parse gateway config");
    let route = &config.routes[0];

    assert!(route.rewrite.is_some());
    let rewrite = route.rewrite.as_ref().unwrap();
    assert!(rewrite.rules.is_some());
    let rules = rewrite.rules.as_ref().unwrap();
    assert_eq!(rules.get("/api/*"), Some(&"/$1".to_string()));
}

#[test]
fn test_parse_route_with_policies_direct() {
    let gateway_conf = r#"
policy auth "oauth-core" {
    issuer = "https://auth.example.me"
    client_id = "ophan-gateway"
    jwks_uri = "https://auth.example.me/.well-known/jwks.json"
}

routes {
    route "/api/v1/*" {
        backend = upstream("api-main-cluster")

        policies {
            auth = "oauth-core"
        }
    }
}
"#;

    let config = parse_gateway_config(gateway_conf).expect("Failed to parse gateway config");
    let route = &config.routes[0];

    assert!(route.auth_policy.is_some());
    match route.auth_policy.as_ref().unwrap() {
        crate::config::parts::RouteAuthPolicy::Reference(name) => assert_eq!(name, "oauth-core"),
        _ => panic!("Expected Reference auth policy"),
    }
}

#[test]
fn test_parse_route_with_policies_extends() {
    let gateway_conf = r#"
policy waf "waf-hardened" {
    enabled = true
    mode = "blocking"
    max_body_size = 4mb
    anomaly_threshold = 5
}

routes {
    route "/api/v1/media/upload" {
        backend = upstream("media-srv")

        policies {
            waf extends "waf-hardened" {
                max_body_size = 100mb
                anomaly_threshold = 15
            }
        }
    }
}
"#;

    let config = parse_gateway_config(gateway_conf).expect("Failed to parse gateway config");
    let route = &config.routes[0];

    assert!(route.waf_policy.is_some());
    match route.waf_policy.as_ref().unwrap() {
        crate::config::parts::RouteWafPolicy::Override { base, config } => {
            assert_eq!(base, "waf-hardened");
            assert_eq!(config.max_body_size, 100 * 1024 * 1024);
            assert_eq!(config.anomaly_threshold, 15);
        },
        _ => panic!("Expected Override waf policy"),
    }
}

#[test]
fn test_parse_route_with_policies_local_limiter() {
    let gateway_conf = r#"
routes {
    route "/api/v1/checkout/*" {
        backend = upstream("billing-srv")

        policies {
            limiter {
                rate = "10/m"
                burst = 2
                algorithm = "token_bucket"
                identifier = "ip"
            }
        }
    }
}
"#;

    let config = parse_gateway_config(gateway_conf).expect("Failed to parse gateway config");
    let route = &config.routes[0];

    assert!(route.limiter_policy.is_some());
    match route.limiter_policy.as_ref().unwrap() {
        crate::config::parts::RouteLimiterPolicy::Local(cfg) => {
            assert_eq!(cfg.rate.requests, 10);
            assert_eq!(cfg.rate.per_seconds, 60);
            assert_eq!(cfg.burst, 2);
            assert!(matches!(cfg.identifier, LimiterIdentifier::Ip));
        },
        _ => panic!("Expected Local limiter policy"),
    }
}

#[test]
fn test_parse_global_policy_auth() {
    let gateway_conf = r#"
policy auth "oauth-default" {
    issuer = "https://auth.example.me"
    client_id = "ophan-gateway-edge"
    client_secret = "env:AUTH_CLIENT_SECRET"
    jwks_uri = "https://auth.example.me/.well-known/jwks.json"

    sources {
        header { name = "Authorization", prefix = "Bearer " }
        cookie { name = "access_token" }
    }
}
"#;

    let config = parse_gateway_config(gateway_conf).expect("Failed to parse gateway config");
    assert!(config.policies.auth.is_some());

    let auth_map = config.policies.auth.as_ref().unwrap();
    assert!(auth_map.contains_key("oauth-default"));

    let oauth = auth_map.get("oauth-default").unwrap();
    assert_eq!(oauth.issuer, "https://auth.example.me");
    assert_eq!(oauth.client_id, "ophan-gateway-edge");
    assert_eq!(oauth.client_secret, Some("env:AUTH_CLIENT_SECRET".to_string()));
    assert_eq!(oauth.jwk_uri, "https://auth.example.me/.well-known/jwks.json");
    assert_eq!(oauth.sources.len(), 2);
}

#[test]
fn test_parse_global_policy_waf() {
    let gateway_conf = r#"
policy waf "waf-hardened" {
    enabled = true
    mode = "blocking"
    max_body_size = 4mb
    anomaly_threshold = 5

    rules {
        rule "block_sql_injection" {
            phase = "request_body"
            condition = sql_token_match
            action = "block"
            score = 5
        }
    }
}
"#;

    let config = parse_gateway_config(gateway_conf).expect("Failed to parse gateway config");
    let waf = config.policies.waf.as_ref().unwrap().get("waf-hardened").unwrap();
    assert!(waf.enabled);
    assert!(matches!(waf.mode, WafMode::Blocking));
    assert_eq!(waf.max_body_size, 4 * 1024 * 1024);
    assert_eq!(waf.anomaly_threshold, 5);
    assert_eq!(waf.rules.len(), 1);
    assert_eq!(waf.rules[0].id, "block_sql_injection");
    assert_eq!(waf.rules[0].score, 5);
}

#[test]
fn test_parse_global_policy_cors() {
    let gateway_conf = r#"
policy cors "cors-default" {
    allow_origin = ["https://example.me"]
    allow_methods = ["GET", "POST"]
    allow_headers = ["Content-Type", "Authorization"]
    allow_credentials = true
    max_age = 1h
}
"#;

    let config = parse_gateway_config(gateway_conf).expect("Failed to parse gateway config");
    let cors = config.policies.cors.as_ref().unwrap().get("cors-default").unwrap();
    assert_eq!(cors.allow_origins, vec!["https://example.me"]);
    assert_eq!(cors.allow_methods, vec!["GET", "POST"]);
    assert_eq!(cors.allow_headers, vec!["Content-Type", "Authorization"]);
    assert!(cors.allow_credentials);
    assert_eq!(cors.max_age, Some(3600));
}

#[test]
fn test_parse_global_policy_limiter() {
    let gateway_conf = r#"
policy limiter "rate-limit" {
    rate = "100/m"
    burst = 20
    algorithm = "sliding_window"
    identifier = "ip"
}
"#;

    let config = parse_gateway_config(gateway_conf).expect("Failed to parse gateway config");
    let limiter = config.policies.limiter.as_ref().unwrap().get("rate-limit").unwrap();
    assert_eq!(limiter.rate.requests, 100);
    assert_eq!(limiter.rate.per_seconds, 60);
    assert_eq!(limiter.burst, 20);
    assert!(matches!(limiter.identifier, LimiterIdentifier::Ip));
}

#[test]
fn test_parse_full_gateway_config() {
    let gateway_conf = r#"
name = "edge-gateway-prod"

listeners {
    listener "ingress-secure" {
        address = "0.0.0.0:443"
        protocols = ["http1", "http2"]

        ssl {
            cert = "/home/alex/.certs/cert.pem"
            key = "/home/alex/.certs/key.pem"
        }
    }

    listener "ingress-internal" {
        address = "unix:/var/run/ophan-internal.sock"
        protocols = ["grpc"]
    }
}

upstreams {
    upstream "api-main-cluster" {
        load_balance = "least_connections"

        servers = [
            { endpoint = "10.0.1.10:4040", weight = 100 },
            { endpoint = "10.0.1.11:8080", weight = 50, protocol = "http2" }
        ]

        health_check = { path = "/healthz", interval = 10s, timeout = 250ms }
    }

    upstream "billing-srv" {
        servers = "10.0.2.50:3000"
    }
}

routes {
    route "/" {
        hosts = ["example.me"]
        backend = static {
            root = "/var/www/public"
            listing = false
            dotfiles = false
        }
    }

    route "/api/v1/*" {
        hosts = ["api.example.me"]
        methods = ["GET", "POST"]
        backend = upstream("api-main-cluster")
    }

    route "/api/stream/*" {
        backend = upstream("api-main-cluster")

        timeouts {
            connect = "30s"
            read    = "300s"
            send    = "300s"
        }

        streaming {
            buffering = false
            chunked   = false
        }
    }
}

policy auth "oauth-core" {
    issuer = "https://auth.example.me"
    client_id = "ophan-gateway"
    jwks_uri = "https://auth.example.me/.well-known/jwks.json"
}

policy waf "waf-hardened" {
    enabled = true
    mode = "blocking"
    max_body_size = 4mb
    anomaly_threshold = 5
}
"#;

    let config = parse_gateway_config(gateway_conf).expect("Failed to parse gateway config");

    assert_eq!(config.name, "edge-gateway-prod");
    assert_eq!(config.listeners.len(), 2);
    assert_eq!(config.upstreams.len(), 2);
    assert_eq!(config.routes.len(), 3);
    assert!(config.policies.auth.is_some());
    let waf = config.policies.waf.as_ref().unwrap().get("waf-hardened").unwrap();
    assert!(waf.enabled);

    let stream_route = &config.routes[2];
    assert_eq!(stream_route.path, "/api/stream/*");
    assert!(stream_route.timeouts.is_some());
    let t = stream_route.timeouts.as_ref().unwrap();
    assert_eq!(t.connect, Some(std::time::Duration::from_secs(30)));
    assert_eq!(t.read, Some(std::time::Duration::from_secs(300)));
    assert_eq!(t.send, Some(std::time::Duration::from_secs(300)));
    assert!(stream_route.streaming.is_some());
    let s = stream_route.streaming.as_ref().unwrap();
    assert!(!s.buffering);
    assert!(!s.chunked);
}

#[test]
fn test_parse_comments_ignored() {
    let gateway_conf = r#"
# This is a comment
name = "test-gateway"
# Another comment
listeners {
    # Comment inside block
    listener "test" {
        address = "0.0.0.0:8080"
        protocols = ["http1"]
    }
}
"#;

    let config = parse_gateway_config(gateway_conf).expect("Failed to parse gateway config");
    assert_eq!(config.name, "test-gateway");
    assert_eq!(config.listeners.len(), 1);
}

#[test]
fn test_parse_multiple_routes() {
    let gateway_conf = r#"
routes {
    route "/" {
        backend = static {
            root = "/var/www"
            listing = false
            dotfiles = false
        }
    }

    route "/api/v1/*" {
        backend = upstream("api-cluster")
    }

    route "/api/v2/*" {
        backend = upstream("api-cluster-v2")
    }
}
"#;

    let config = parse_gateway_config(gateway_conf).expect("Failed to parse gateway config");
    assert_eq!(config.routes.len(), 3);
    assert_eq!(config.routes[0].path, "/");
    assert_eq!(config.routes[1].path, "/api/v1/*");
    assert_eq!(config.routes[2].path, "/api/v2/*");
}

#[test]
fn test_parse_upstream_load_balance_strategies() {
    let gateway_conf = r#"
upstreams {
    upstream "round-robin" {
        load_balance = "round_robin"
        servers = "localhost:8080"
    }

    upstream "least-conn" {
        load_balance = "least_connections"
        servers = "localhost:8081"
    }

    upstream "ip-hash" {
        load_balance = "ip_hash"
        servers = "localhost:8082"
    }

    upstream "random" {
        load_balance = "random"
        servers = "localhost:8083"
    }
}
"#;

    let config = parse_gateway_config(gateway_conf).expect("Failed to parse gateway config");
    assert_eq!(config.upstreams.len(), 4);

    assert!(matches!(config.upstreams[0].balance_strategy, BalanceStrategy::RoundRobin));
    assert!(matches!(
        config.upstreams[1].balance_strategy,
        BalanceStrategy::LeastConnections
    ));
    assert!(matches!(config.upstreams[2].balance_strategy, BalanceStrategy::IpHash));
    assert!(matches!(config.upstreams[3].balance_strategy, BalanceStrategy::Random));
}

#[test]
fn test_parse_route_with_policies_extends_auth() {
    let gateway_conf = r#"
policy auth "oauth-default" {
    issuer = "https://auth.example.com"
    client_id = "test-client"
    jwks_uri = "https://auth.example.com/.well-known/jwks.json"

    sources {
        header { name = "Authorization", prefix = "Bearer " }
    }
}

routes {
    route "/api/*" {
        backend = upstream("api")

        policies {
            auth extends "oauth-default" {
                sources {
                    cookie { name = "access_token" }
                }
            }
        }
    }
}
"#;

    let config = parse_gateway_config(gateway_conf).expect("Failed to parse gateway config");
    let route = &config.routes[0];

    assert!(route.auth_policy.is_some());
    match route.auth_policy.as_ref().unwrap() {
        crate::config::parts::RouteAuthPolicy::Override { base, config } => {
            assert_eq!(base, "oauth-default");
            assert_eq!(config.sources.len(), 1);
            match &config.sources[0] {
                TokenSource::Cookie { name, prefix } => {
                    assert_eq!(name, "access_token");
                    assert!(prefix.is_none());
                },
                _ => panic!("Expected Cookie source"),
            }
            assert!(config.issuer.is_empty());
            assert!(config.client_id.is_empty());
        },
        _ => panic!("Expected Override auth policy"),
    }
}

#[test]
fn test_parse_route_with_policies_extends_cors() {
    let gateway_conf = r#"
policy cors "cors-default" {
    allow_origin = ["https://example.com"]
    allow_methods = ["GET", "POST"]
}

routes {
    route "/api/*" {
        backend = upstream("api")

        policies {
            cors extends "cors-default" {
                allow_origin = ["https://app.example.com"]
                allow_credentials = true
            }
        }
    }
}
"#;

    let config = parse_gateway_config(gateway_conf).expect("Failed to parse gateway config");
    let route = &config.routes[0];

    assert!(route.cors_policy.is_some());
    match route.cors_policy.as_ref().unwrap() {
        crate::config::parts::RouteCorsPolicy::Override { base, config } => {
            assert_eq!(base, "cors-default");
            assert_eq!(config.allow_origins, vec!["https://app.example.com"]);
            assert!(config.allow_credentials);
        },
        _ => panic!("Expected Override cors policy"),
    }
}

#[test]
fn test_parse_route_with_policies_extends_limiter() {
    let gateway_conf = r#"
policy limiter "limiter-default" {
    rate = 100/m
    identifier = "ip"
}

routes {
    route "/api/*" {
        backend = upstream("api")

        policies {
            limiter extends "limiter-default" {
                rate = 50/m
                burst = 10
            }
        }
    }
}
"#;

    let config = parse_gateway_config(gateway_conf).expect("Failed to parse gateway config");
    let route = &config.routes[0];

    assert!(route.limiter_policy.is_some());
    match route.limiter_policy.as_ref().unwrap() {
        crate::config::parts::RouteLimiterPolicy::Override { base, config } => {
            assert_eq!(base, "limiter-default");
            assert_eq!(config.rate.requests, 50);
            assert_eq!(config.rate.per_seconds, 60);
            assert_eq!(config.burst, 10);
        },
        _ => panic!("Expected Override limiter policy"),
    }
}

#[test]
fn test_parse_route_timeouts() {
    let gateway_conf = r#"
routes {
    route "/api/stream/*" {
        backend = upstream("api")

        timeouts {
            connect = "600s"
            read    = "3600s"
            send    = "3600s"
        }
    }
}
"#;

    let config = parse_gateway_config(gateway_conf).expect("Failed to parse gateway config");
    let route = &config.routes[0];

    assert!(route.timeouts.is_some());
    let timeouts = route.timeouts.as_ref().unwrap();
    assert_eq!(timeouts.connect, Some(std::time::Duration::from_secs(600)));
    assert_eq!(timeouts.read, Some(std::time::Duration::from_secs(3600)));
    assert_eq!(timeouts.send, Some(std::time::Duration::from_secs(3600)));
}

#[test]
fn test_parse_route_streaming() {
    let gateway_conf = r#"
routes {
    route "/api/ws/*" {
        backend = upstream("api")

        streaming {
            buffering = false
            chunked   = false
        }
    }
}
"#;

    let config = parse_gateway_config(gateway_conf).expect("Failed to parse gateway config");
    let route = &config.routes[0];

    assert!(route.streaming.is_some());
    let streaming = route.streaming.as_ref().unwrap();
    assert!(!streaming.buffering);
    assert!(!streaming.chunked);
}

#[test]
fn test_parse_route_timeouts_and_streaming() {
    let gateway_conf = r#"
routes {
    route "/api/live/*" {
        backend = upstream("live")

        timeouts {
            connect = "30s"
            read    = "300s"
            send    = "300s"
        }

        streaming {
            buffering = false
            chunked   = true
        }
    }
}
"#;

    let config = parse_gateway_config(gateway_conf).expect("Failed to parse gateway config");
    let route = &config.routes[0];

    assert!(route.timeouts.is_some());
    let timeouts = route.timeouts.as_ref().unwrap();
    assert_eq!(timeouts.connect, Some(std::time::Duration::from_secs(30)));
    assert_eq!(timeouts.read, Some(std::time::Duration::from_secs(300)));
    assert_eq!(timeouts.send, Some(std::time::Duration::from_secs(300)));

    assert!(route.streaming.is_some());
    let streaming = route.streaming.as_ref().unwrap();
    assert!(!streaming.buffering);
    assert!(streaming.chunked);
}

#[test]
fn test_parse_route_timeouts_partial() {
    let gateway_conf = r#"
routes {
    route "/api/connect-only/*" {
        backend = upstream("api")

        timeouts {
            connect = "5s"
        }
    }
}
"#;

    let config = parse_gateway_config(gateway_conf).expect("Failed to parse gateway config");
    let route = &config.routes[0];

    assert!(route.timeouts.is_some());
    let timeouts = route.timeouts.as_ref().unwrap();
    assert_eq!(timeouts.connect, Some(std::time::Duration::from_secs(5)));
    assert!(timeouts.read.is_none());
    assert!(timeouts.send.is_none());
}

#[test]
fn test_parse_upstream_server_protocol_websocket() {
    let gateway_conf = r#"
upstreams {
    upstream "ws-cluster" {
        servers = [
            { endpoint = "10.0.1.10:8080", protocol = "websocket" },
            { endpoint = "10.0.1.11:8081", protocol = "http1" },
        ]
        load_balance = "round_robin"
    }
}
"#;

    let config = parse_gateway_config(gateway_conf).expect("Failed to parse gateway config");
    let upstream = &config.upstreams[0];

    assert_eq!(upstream.servers.len(), 2);

    // First server: websocket protocol
    match &upstream.servers[0].protocol {
        NetworkProtocol::Http1 { allow_websocket_upgrade } => {
            assert!(
                *allow_websocket_upgrade,
                "websocket server should have allow_websocket_upgrade=true"
            );
        },
        other => panic!("Expected Http1 with websocket, got {:?}", other),
    }

    // Second server: plain http1
    match &upstream.servers[1].protocol {
        NetworkProtocol::Http1 { allow_websocket_upgrade } => {
            assert!(
                !allow_websocket_upgrade,
                "http1 server should have allow_websocket_upgrade=false"
            );
        },
        other => panic!("Expected Http1 without websocket, got {:?}", other),
    }
}

#[test]
fn test_parse_upstream_server_protocol_grpc() {
    let gateway_conf = r#"
upstreams {
    upstream "grpc-cluster" {
        servers = [
            { endpoint = "10.0.2.10:50051", protocol = "grpc" },
            { endpoint = "10.0.2.11:50052", protocol = "http2" },
        ]
    }
}
"#;

    let config = parse_gateway_config(gateway_conf).expect("Failed to parse gateway config");
    let upstream = &config.upstreams[0];

    assert_eq!(upstream.servers.len(), 2);

    // First server: gRPC protocol
    match &upstream.servers[0].protocol {
        NetworkProtocol::Http2 { mode } => {
            assert!(matches!(mode, Http2Mode::Grpc), "Expected gRPC mode, got {:?}", mode);
        },
        other => panic!("Expected Http2 with Grpc mode, got {:?}", other),
    }

    // Second server: standard http2
    match &upstream.servers[1].protocol {
        NetworkProtocol::Http2 { mode } => {
            assert!(matches!(mode, Http2Mode::Standard), "Expected Standard mode, got {:?}", mode);
        },
        other => panic!("Expected Http2 with Standard mode, got {:?}", other),
    }
}

#[test]
fn test_parse_full_route_all_features() {
    let gateway_conf = r#"
upstreams {
    upstream "api" {
        servers = "localhost:8080"
    }
}

routes {
    route "/api/v2/*" {
        hosts   = ["api.example.me"]
        methods = ["GET", "POST", "PUT", "DELETE"]

        backend = upstream("api")

        policies {
            auth = "oauth-core"

            cors {
                allow_origin = ["*"]
                allow_methods = ["GET", "POST"]
            }
        }

        rewrite {
            "/api/*" -> "/$1"
        }

        headers {
            add = { X-Custom = "test" }
        }

        timeouts {
            connect = "10s"
            read    = "60s"
            send    = "30s"
        }

        streaming {
            buffering = false
            chunked   = true
        }
    }
}

policy auth "oauth-core" {
    issuer = "https://auth.example.me"
    client_id = "test"
    jwks_uri = "https://auth.example.me/.well-known/jwks.json"
}
"#;

    let config = parse_gateway_config(gateway_conf).expect("Failed to parse gateway config");

    assert_eq!(config.upstreams.len(), 1);
    assert_eq!(config.routes.len(), 1);

    let route = &config.routes[0];
    assert_eq!(route.path, "/api/v2/*");
    assert_eq!(route.hosts, vec!["api.example.me"]);
    assert!(
        route
            .methods
            .contains_http(HttpMethod::GET | HttpMethod::POST | HttpMethod::PUT | HttpMethod::DELETE)
    );

    // Policies
    assert!(route.auth_policy.is_some());
    match route.auth_policy.as_ref().unwrap() {
        crate::config::parts::RouteAuthPolicy::Reference(name) => assert_eq!(name, "oauth-core"),
        _ => panic!("Expected Reference auth policy"),
    }
    assert!(route.cors_policy.is_some());
    match route.cors_policy.as_ref().unwrap() {
        crate::config::parts::RouteCorsPolicy::Local(cfg) => {
            assert_eq!(cfg.allow_origins, vec!["*"]);
        },
        _ => panic!("Expected Local cors policy"),
    }

    // Rewrite
    assert!(route.rewrite.is_some());
    let rewrite = route.rewrite.as_ref().unwrap();
    assert!(rewrite.rules.is_some());
    assert_eq!(rewrite.rules.as_ref().unwrap().get("/api/*"), Some(&"/$1".to_string()));

    // Timeouts
    assert!(route.timeouts.is_some());
    let timeouts = route.timeouts.as_ref().unwrap();
    assert_eq!(timeouts.connect, Some(std::time::Duration::from_secs(10)));
    assert_eq!(timeouts.read, Some(std::time::Duration::from_secs(60)));
    assert_eq!(timeouts.send, Some(std::time::Duration::from_secs(30)));

    // Streaming
    assert!(route.streaming.is_some());
    let streaming = route.streaming.as_ref().unwrap();
    assert!(!streaming.buffering);
    assert!(streaming.chunked);
}
