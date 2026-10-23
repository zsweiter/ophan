//! Prometheus metrics.
//!
//! Every metric is registered in the default registry and exposed through the
//! endpoint configured by the `master { metrics { ... } }` block. Hot-path handles
//! (per route and per backend) are resolved once when the configuration is built,
//! so recording a sample is a plain atomic operation.

use std::sync::{LazyLock, OnceLock};
use std::time::Duration;

use crate::config::{ListenerAddress, MetricsConfig};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use http::{Method, Response, StatusCode, header};
use pingora::apps::http_app::ServeHttp;
use pingora::protocols::http::ServerSession;
use pingora::services::listening::Service;
use prometheus::core::{Collector, Desc};
use prometheus::proto::{Counter, Gauge, LabelPair, Metric, MetricFamily, MetricType};
use std::sync::Arc;

use crate::state::AppContext;
use prometheus::{
    Encoder, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGaugeVec, Opts, TextEncoder,
    register_histogram_vec, register_int_counter_vec, register_int_gauge_vec,
};

const LATENCY_BUCKETS: &[f64] = &[0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0];

pub static REQUESTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        Opts::new("ophan_requests_total", "Requests handled by the gateway"),
        &["gateway", "route", "method", "status"]
    )
    .expect("register ophan_requests_total")
});

pub static REQUEST_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        HistogramOpts::new(
            "ophan_request_duration_seconds",
            "Time from request start until the response is finished"
        )
        .buckets(LATENCY_BUCKETS.to_vec()),
        &["gateway", "route"]
    )
    .expect("register ophan_request_duration_seconds")
});

pub static POLICY_REJECTIONS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        Opts::new("ophan_policy_rejections_total", "Requests rejected by a route policy"),
        &["gateway", "policy"]
    )
    .expect("register ophan_policy_rejections_total")
});

pub static CONFIG_RELOADS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        Opts::new("ophan_config_reloads_total", "Configuration reload attempts by outcome"),
        &["outcome"]
    )
    .expect("register ophan_config_reloads_total")
});

pub static RATE_LIMIT_ENTRIES: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        Opts::new(
            "ophan_rate_limit_tracked_clients",
            "Clients currently tracked by the in-memory rate limiter"
        ),
        &["gateway"]
    )
    .expect("register ophan_rate_limit_tracked_clients")
});

const METHODS: [&str; 10] = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE", "OTHER"];

/// Status codes with a cached counter; any other code goes through the label lookup.
///
/// Keep both arrays and the arms of [`status_index`] in the same order: the match
/// arms return the position of the status in these arrays.
const CACHED_STATUSES: [u16; 32] = [
    0, 100, 101, 200, 201, 202, 204, 206, 226, 301, 302, 304, 307, 308, 400, 401, 403, 404, 405, 409, 410, 412, 413, 416, 418,
    421, 422, 429, 500, 502, 503, 504,
];
const CACHED_STATUS_LABELS: [&str; 32] = [
    "0", "100", "101", "200", "201", "202", "204", "206", "226", "301", "302", "304", "307", "308", "400", "401", "403", "404",
    "405", "409", "410", "412", "413", "416", "418", "421", "422", "429", "500", "502", "503", "504",
];

/// O(1) index of `status` within [`CACHED_STATUSES`], `None` for uncached codes.
#[inline]
fn status_index(status: u16) -> Option<usize> {
    Some(match status {
        0 => 0,
        100 => 1,
        101 => 2,
        200 => 3,
        201 => 4,
        202 => 5,
        204 => 6,
        206 => 7,
        226 => 8,
        301 => 9,
        302 => 10,
        304 => 11,
        307 => 12,
        308 => 13,
        400 => 14,
        401 => 15,
        403 => 16,
        404 => 17,
        405 => 18,
        409 => 19,
        410 => 20,
        412 => 21,
        413 => 22,
        416 => 23,
        418 => 24,
        421 => 25,
        422 => 26,
        429 => 27,
        500 => 28,
        502 => 29,
        503 => 30,
        504 => 31,
        _ => return None,
    })
}

#[inline]
fn method_index(method: &Method) -> usize {
    match *method {
        Method::GET => 0,
        Method::POST => 1,
        Method::PUT => 2,
        Method::DELETE => 3,
        Method::PATCH => 4,
        Method::HEAD => 5,
        Method::OPTIONS => 6,
        Method::CONNECT => 7,
        Method::TRACE => 8,
        _ => 9,
    }
}

/// Bounded label value for the request method.
#[inline]
pub fn method_label(method: &Method) -> &'static str {
    METHODS[method_index(method)]
}

/// Lazily resolved `ophan_requests_total` children for one (gateway, route) pair.
#[derive(Debug)]
struct RequestCounters {
    gateway: Box<str>,
    route: Box<str>,
    cells: Box<[OnceLock<IntCounter>]>,
}

impl RequestCounters {
    fn new(gateway: &str, route: &str) -> Self {
        Self {
            gateway: gateway.into(),
            route: route.into(),
            cells: (0..METHODS.len() * CACHED_STATUSES.len()).map(|_| OnceLock::new()).collect(),
        }
    }

    #[inline]
    fn inc(&self, method: &Method, status: u16) {
        let method_idx = method_index(method);

        let Some(status_idx) = status_index(status) else {
            let status = status.to_string();
            REQUESTS_TOTAL
                .with_label_values(&[&*self.gateway, &*self.route, METHODS[method_idx], &status])
                .inc();
            return;
        };

        self.cells[method_idx * CACHED_STATUSES.len() + status_idx]
            .get_or_init(|| {
                REQUESTS_TOTAL.with_label_values(&[
                    &*self.gateway,
                    &*self.route,
                    METHODS[method_idx],
                    CACHED_STATUS_LABELS[status_idx],
                ])
            })
            .inc();
    }
}

/// Per-route handles, resolved when the route is compiled.
#[derive(Debug)]
pub struct RouteMetrics {
    pub duration: Histogram,
    requests: RequestCounters,
}

impl RouteMetrics {
    pub fn new(gateway: &str, route: &str) -> Self {
        Self {
            duration: REQUEST_DURATION.with_label_values(&[gateway, route]),
            requests: RequestCounters::new(gateway, route),
        }
    }
}

/// Per-gateway handles for samples that are not tied to a route.
pub struct GatewayMetrics {
    unmatched: RouteMetrics,
    pub rejected_rate_limit: IntCounter,
    pub rejected_auth: IntCounter,
    pub rejected_other: IntCounter,
}

impl GatewayMetrics {
    pub fn new(gateway: &str) -> Self {
        Self {
            unmatched: RouteMetrics::new(gateway, ""),
            rejected_rate_limit: POLICY_REJECTIONS.with_label_values(&[gateway, "rate_limit"]),
            rejected_auth: POLICY_REJECTIONS.with_label_values(&[gateway, "auth"]),
            rejected_other: POLICY_REJECTIONS.with_label_values(&[gateway, "other"]),
        }
    }

    #[inline]
    pub fn observe(&self, route: Option<&RouteMetrics>, method: &Method, status: Option<StatusCode>, elapsed: Duration) {
        let route = route.unwrap_or(&self.unmatched);

        route.requests.inc(method, status.map_or(0, |s| s.as_u16()));
        route.duration.observe(elapsed.as_secs_f64());
    }
}

/// Upstream backend metrics, read from the live load balancers when Prometheus scrapes.
///
/// Backends keep their own counters; reading them on demand avoids a second set of counters
/// on the request path, and backends removed by a reload simply stop being reported.
pub struct UpstreamCollector {
    gateways: Vec<(Box<str>, Arc<ArcSwap<AppContext>>)>,
    descs: Vec<Desc>,
}

impl UpstreamCollector {
    const LABELS: [&str; 3] = ["gateway", "upstream", "backend"];

    const FAMILIES: [(&str, &str, MetricType); 4] = [
        (
            "ophan_upstream_requests_total",
            "Requests sent to an upstream backend",
            MetricType::COUNTER,
        ),
        (
            "ophan_upstream_failures_total",
            "Requests to an upstream backend that ended with an upstream error",
            MetricType::COUNTER,
        ),
        (
            "ophan_upstream_active_requests",
            "In-flight requests per upstream backend",
            MetricType::GAUGE,
        ),
        (
            "ophan_upstream_healthy",
            "1 when the backend is considered healthy, 0 otherwise",
            MetricType::GAUGE,
        ),
    ];

    pub fn new(gateways: Vec<(Box<str>, Arc<ArcSwap<AppContext>>)>) -> prometheus::Result<Self> {
        let descs = Self::FAMILIES
            .iter()
            .map(|(name, help, _)| {
                Desc::new(
                    name.to_string(),
                    help.to_string(),
                    Self::LABELS.iter().map(|l| l.to_string()).collect(),
                    Default::default(),
                )
            })
            .collect::<prometheus::Result<Vec<_>>>()?;

        Ok(Self { gateways, descs })
    }

    fn sample(labels: &[&str; 3], value: f64, kind: MetricType) -> Metric {
        let mut metric = Metric::default();
        metric.set_label(
            Self::LABELS
                .iter()
                .zip(labels)
                .map(|(name, value)| {
                    let mut pair = LabelPair::default();
                    pair.set_name(name.to_string());
                    pair.set_value(value.to_string());
                    pair
                })
                .collect(),
        );

        if kind == MetricType::COUNTER {
            let mut counter = Counter::default();
            counter.set_value(value);
            metric.set_counter(counter);
        } else {
            let mut gauge = Gauge::default();
            gauge.set_value(value);
            metric.set_gauge(gauge);
        }

        metric
    }
}

impl Collector for UpstreamCollector {
    fn desc(&self) -> Vec<&Desc> {
        self.descs.iter().collect()
    }

    fn collect(&self) -> Vec<MetricFamily> {
        let mut samples: [Vec<Metric>; 4] = Default::default();

        for (gateway, context) in &self.gateways {
            let context = context.load();

            for upstream in context.load_balancer.upstreams().iter() {
                for backend in upstream.servers.load().iter() {
                    let addr = backend.addr.to_string();
                    let labels = [&**gateway, &*upstream.name, addr.as_str()];
                    let values = [
                        backend.total_requests() as f64,
                        backend.failed_requests() as f64,
                        backend.active_conns() as f64,
                        if backend.is_healthy() { 1.0 } else { 0.0 },
                    ];

                    for (i, (_, _, kind)) in Self::FAMILIES.iter().enumerate() {
                        samples[i].push(Self::sample(&labels, values[i], *kind));
                    }
                }
            }
        }

        Self::FAMILIES
            .iter()
            .zip(samples)
            .map(|((name, help, kind), metrics)| {
                let mut family = MetricFamily::default();
                family.set_name(name.to_string());
                family.set_help(help.to_string());
                family.set_field_type(*kind);
                family.set_metric(metrics);
                family
            })
            .collect()
    }
}

/// HTTP app that serves the default registry in the Prometheus text format.
pub struct MetricsApp {
    path: String,
}

impl MetricsApp {
    pub fn new(path: String) -> Self {
        Self { path }
    }

    /// Listening service for the `master { metrics { ... } }` block.
    pub fn service(config: &MetricsConfig) -> Service<Self> {
        let mut service = Service::new("metrics".to_string(), Self::new(config.path.clone()));
        service.threads = Some(1);

        match &config.listen {
            ListenerAddress::Tcp(addr) => service.add_tcp(&addr.to_string()),
            #[cfg(unix)]
            ListenerAddress::Uds(path) => service.add_uds(path, None),
        }

        service
    }
}

#[async_trait]
impl ServeHttp for MetricsApp {
    async fn response(&self, session: &mut ServerSession) -> Response<Vec<u8>> {
        let req = session.req_header();

        if req.uri.path() != self.path {
            return plain_response(StatusCode::NOT_FOUND, b"not found\n".to_vec());
        }

        if req.method != Method::GET && req.method != Method::HEAD {
            return plain_response(StatusCode::METHOD_NOT_ALLOWED, b"method not allowed\n".to_vec());
        }

        let encoder = TextEncoder::new();
        let mut body = Vec::with_capacity(16 * 1024);

        if let Err(e) = encoder.encode(&prometheus::gather(), &mut body) {
            tracing::error!("failed to encode metrics: {e}");
            return plain_response(StatusCode::INTERNAL_SERVER_ERROR, b"failed to encode metrics\n".to_vec());
        }

        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, encoder.format_type())
            .header(header::CONTENT_LENGTH, body.len())
            .body(body)
            .expect("valid metrics response")
    }
}

fn plain_response(status: StatusCode, body: Vec<u8>) -> Response<Vec<u8>> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CONTENT_LENGTH, body.len())
        .body(body)
        .expect("valid metrics response")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_label_is_bounded() {
        assert_eq!(method_label(&Method::GET), "GET");
        assert_eq!(method_label(&Method::from_bytes(b"PURGE").unwrap()), "OTHER");
    }

    #[test]
    fn cached_status_tables_match_the_index() {
        for (i, status) in CACHED_STATUSES.iter().enumerate() {
            assert_eq!(status_index(*status), Some(i), "status {status}");
            assert_eq!(CACHED_STATUS_LABELS[i], status.to_string(), "status {status}");
        }
    }

    #[test]
    fn observe_records_request_and_latency() {
        let gw = GatewayMetrics::new("test_observe");
        let route = RouteMetrics::new("test_observe", "/api/*");

        gw.observe(Some(&route), &Method::GET, Some(StatusCode::OK), Duration::from_millis(3));
        gw.observe(None, &Method::POST, None, Duration::from_millis(1));

        gw.observe(
            Some(&route),
            &Method::GET,
            Some(StatusCode::IM_A_TEAPOT),
            Duration::from_millis(1),
        );
        gw.observe(Some(&route), &Method::GET, Some(StatusCode::OK), Duration::from_millis(1));

        let ok = REQUESTS_TOTAL.with_label_values(&["test_observe", "/api/*", "GET", "200"]).get();
        let teapot = REQUESTS_TOTAL.with_label_values(&["test_observe", "/api/*", "GET", "418"]).get();
        let aborted = REQUESTS_TOTAL.with_label_values(&["test_observe", "", "POST", "0"]).get();

        assert_eq!(ok, 2);
        assert_eq!(teapot, 1);
        assert_eq!(aborted, 1);
        assert_eq!(route.duration.get_sample_count(), 3);
    }
}
