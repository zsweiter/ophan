---
title: Request Lifecycle
description: The middleware pipeline and hook model behind every request
tags: ["architecture"]
order: 101
---

Every request in Ophan flows through a composable pipeline. Middlewares observe the request, enrich a shared `Context`, and express decisions — but they **never** write HTTP responses or touch the socket. The gateway is the only component that builds responses and coordinates the connection lifecycle.

> **⚠️ In development** — The middleware API is actively evolving. Signatures may change as the codebase matures.

---

## Pipeline Overview

```text
Incoming Request
        │
        ▼
   on_request()
        │
        ├──────────────┐
        │              │
        ▼              ▼
 Continue         Respond/Reject
        │              │
        │              ▼
        │        handle_error()
        │              │
        │              ▼
        │     prepare_response()
        │              │
        │              ▼
        │      write_response()
        │              │
        │              ▼
        │        on_finish()
        │
        ▼
 ┌──────────────┐
 │              │
 ▼              ▼
Static      Upstream
 │              │
 │              ▼
 │    on_upstream_request()
 │              │
 │              ▼
 │      connect/send
 │              │
 │              ▼
 │   on_upstream_response()
 │              │
 └───────┬──────┘
         │
         ▼
 prepare_response()
         │
         ▼
 write_response()
         │
         ▼
   on_finish()
```

---

## Hooks

### on_request

First phase for every incoming request. This is the **only** phase where a middleware can stop the flow before a response exists.

- Validates authentication
- Runs the rate limiter
- Runs the WAF over headers and URI
- Processes CORS preflight
- Initializes shared context

```rust
ctx.auth = Some(AuthContext { claims, user });
ctx.rate_limit.remaining = remaining;
ctx.waf.score = score;
ctx.cors.preflight = true;
```

### on_upstream_request

Runs immediately before the request is sent to the backend (upstream branch only).

- Modifies upstream headers
- Rewrites the URI
- Injects authenticated information

```rust
request.insert_header("x-user-claims", claims.encode())?;
```

### on_upstream_response

Runs when the backend responded successfully.

- Inspects the response
- Registers timing info
- Modifies upstream headers

```rust
ctx.backend.elapsed = elapsed;
```

### handle_error

Converts any internal error into a consistent HTTP response. Invoked from:

- A `Reject` produced by `on_request()`
- FileServer errors
- Upstream errors
- Pingora `fail_to_proxy()`

```text
GatewayError → Response
```

### prepare_response

Last chance to modify a response before it is sent — regardless of origin (upstream, static, error, redirect, or preflight).

- Adds CORS headers
- Adds rate limit headers
- Adds security headers (helmet)
- Adds WAF headers

```rust
response.insert_header("x-ratelimit-remaining", ctx.rate_limit.remaining)?;
```

### write_response

The only point where the gateway writes to the socket.

### on_finish

Always executes, even on error.

- Frees resources
- Records metrics
- Updates health checks
- Logging and audit

---

## Decision Model

After each middleware, the pipeline inspects the context:

```text
Continue → next middleware
Respond  → build response
Reject   → handle_error()
```

## Responsibilities Summary

| Hook                 | Can end flow | Modifies Context | Modifies Request | Modifies Response |
| -------------------- | ------------ | ---------------- | ---------------- | ----------------- |
| `on_request`         | Yes          | Yes              | Yes (where applicable) | No            |
| `on_upstream_request`  | No        | Yes              | Yes              | No                |
| `on_upstream_response` | No        | Yes              | No               | Upstream headers  |
| `handle_error`       | No           | No               | No               | Builds error response |
| `prepare_response`   | No           | Reads context    | No               | Yes               |
| `on_finish`          | No           | Optional         | No               | No                |

Middlewares describe facts and enrich the context. The gateway interprets those facts, builds HTTP responses, writes them to the client, and coordinates the full connection lifecycle.

## Next Steps

- [Core Model](/core-model)
- [Configuration Reference](/configuration)