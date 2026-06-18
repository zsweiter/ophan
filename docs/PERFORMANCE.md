# Ophan Gateway — Performance Analysis

**Date:** June 2026
**Tool:** `wrk -t5 -c500 -d10s`

## Baseline — Direct Upstream

```
http://localhost:4040/v1/health
   Latency:      9.80ms  avg
   Requests:   514k in 10s
   Throughput:  51,122 req/s
```

## Throughput via Gateway

| Protocol | Throughput | vs Direct | Penalty |
|---|---|---|---|
| **HTTP** | 836 req/s | 51,122 req/s | **61× slower** |
| **HTTPS** | 612 req/s | 51,122 req/s | **83× slower** |

---

## Bottleneck Analysis

### 1. 🔴 TLS Handshake (HTTPS: −27%)

```
HTTPS:  612 req/s
HTTP:   836 req/s
Diff:    224 req/s (27% slower with TLS)
```

`s2n-tls` per-connection handshake adds latency. With 500 concurrent connections and
keep-alive, each new connection pays a full TLS 1.3 round-trip. Pingora's default
connection pool + keep-alive mitigates this, but 500 concurrent clients will
constantly open new connections.

**Fix:** Increase `upstream_keepalive_pool_size` and tune `max_h2_streams`.

---

### 2. 🔴 Every Request Runs ALL Middlewares

The `Pipeline` unconditionally runs all 4 middlewares on every request:

```
cors → waf → rate_limit → auth
```

Each middleware does two things per request:
1. **Shared:** Access `ctx.matched_route` → deref `Arc<CompiledRoute>` → check if policy is `Some`
2. **Conditional:** If policy is `Some`, run the middleware logic

For a route like `/*` (catch-all for `api.example.me`), the auth policy IS set
(extends `oauth-default`). So every request pays the cost of:

- Parsing headers (Authorization, Cookie, Origin)
- Calling `to_str()` (UTF-8 validation) on headers
- String allocations for token extraction
- `make_auth_config()` clones (5+ string clones per request)

Even requests that fail auth (no token) still do this work before returning 401.

**Fix:** Short-circuit routes with no policies at the router level, or batch the
`matched_route` access once and pass it to middleware as a pre-resolved struct.

---

### 3. 🟠 ArcSwap Contention

```rust
let state = self.app_state.load();  // Guard<AppContext>
// ... find_route, backend selection ...
drop(state);  // release Guard
```

`ArcSwap::load()` acquires an atomic read on every request. With 500 concurrent
workers, the atomic operations cause cache-line bouncing across cores. The
`Guard` keeps a reference-counted `Arc` alive, adding refcount traffic.

**Fix:** Batch request handling in shared-nothing workers (one ArcSwap per thread),
or use `ArcSwap::load_full()` + `clone()` once per batch.

---

### 4. 🟠 High Connection Count Exposes Single-Thread Bottleneck

Pingora's proxy lifecycle hooks (`request_filter`, `upstream_peer`, etc.) are
async functions multiplexed by tokio. With 500 concurrent connections, all
lifecycle stages compete for the same thread pool. Any synchronous operation
(longer than expected) stalls other connections.

Key synchronous stalls:
- `resolve_vhost()`: HashMap lookup in `SniTableRouter` (fast)
- `router.find_route()`: radix tree walk (fast)
- `matched.methods.contains_str()`: bitmask check (fast)
- `upstreams.get(name)`: HashMap lookup (fast)
- `load_balancer.select_server()`: load balancer selection — **this may block**

The load balancer uses `DashMap` with `parking_lot` locks. Under 500 concurrent
requests, the load balancer's state (`DashMap<_, Vec<Arc<Backend>>>`) experiences
lock contention.

**Fix:** Profile `select_server()` under load. Consider read-optimised load
balancer (lock-free or EBR-based).

---

### 5. 🟡 Tracing Subscriber Overhead

```rust
let subscriber = FmtSubscriber::builder()
    .with_max_level(Level::INFO)
    .with_thread_ids(true)      // formats thread ID on every logged line
    .with_thread_names(true)     // formats thread name on every logged line
    .with_target(false)
    .finish();
```

Even at INFO level, every `tracing::info!()` and `tracing::warn!()` call formats
fields (thread ID, thread name). In a hot request loop, this shows up in profiles.

**Fix:** Remove `with_thread_ids` and `with_thread_names` in release/production.
Or switch to a minimal subscriber in release builds.

---

### 6. 🟡 Heap Allocations per Request

Every request allocates:
- `Box<pingora::Error>` on error paths
- `String` for error messages (`.into()`)
- `Arc<CompiledRoute>` refcount increment
- `HashMap` entry in load balancer (key lookup)
- Various `Vec` and `String` in middleware token extraction
- `http::Uri` parse in `upstream_request_filter`

Most are small, but with 500 concurrent connections the allocator becomes contended.

**Fix:** Pre-allocate reusable buffers. Use bump allocator (`snmalloc`/`mimalloc`).
Audit hot path for hidden allocations (`grep 'to_string\|\.into()\|format!\|String::new'`.

---

## Recommended Quick Wins

| Priority | Change | Estimated Gain |
|----------|--------|---------------|
| 🔴 | Fix `make_auth_config` clones (pre-compute in `build_app_context`) | 15-20% |
| 🔴 | Remove `with_thread_ids` / `with_thread_names` from subscriber | 10-15% |
| 🟠 | Profile `load_balancer.select_server()` under contention | 10-30% |
| 🟠 | Switch to `mimalloc` or `snmalloc` | 5-15% |
| 🟡 | Remove `CorsMiddleware` from default pipeline (register only when CORS policy exists) | 2-5% |
| 🟡 | Batch `ArcSwap` loads — use one snapshot for a batch of requests | 5-10% |

## Target

With all fixes applied, we should see:

```
HTTP:  5,000 - 15,000 req/s  (vs 836 today)
HTTPS: 3,500 - 10,000 req/s  (vs 612 today)
```

The `/*` route with `auth extends "oauth-default"` is the worst case.
Routes without any policies should be significantly faster after fixes 1, 2, 5.
