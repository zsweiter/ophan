# Static Content Delivery

Ophan should support serving static content from both local storage and external CDN providers.

This enables the gateway to function not only as an API edge layer, but also as a high-performance static asset server.

---

## Static Content Sources

### Local Filesystem

Serve files directly from local directories.

Example use cases:

- Frontend SPA hosting
- Documentation sites
- Images and media
- Downloadable assets
- Static dashboards

Example:

```txt
/var/www/public
/static/*
/assets/*
```

Features:

- Directory mounting (planned)
- Index files
- Auto compression
- Cache headers
- ETag support
- Range requests
- MIME type detection

---

### CDN Integration (planed)

Ophan should support external CDN-backed asset delivery.

Examples:

- Cloudflare R2
- Amazon S3 + CloudFront
- Google Cloud Storage
- Azure Blob Storage
- BunnyCDN
- Fastly

Supported capabilities:

- Origin proxying
- CDN caching
- Signed URLs
- Cache invalidation
- Edge cache control
- Multi-region asset delivery

---

# Static Asset Features

## Performance

- Zero-copy file serving (sendfile)
- Streaming
- Sendfile optimization
- Brotli compression
- Gzip compression
- Cache preloading
- HTTP caching
- Conditional requests

---

## Caching

Supported cache controls:

- Cache-Control
- ETag
- Last-Modified
- Immutable assets
- Stale-while-revalidate
- Stale-if-error

Example:

```http
Cache-Control: public, max-age=31536000, immutable
```

---

## Security

- Path traversal protection
- Hidden file protection
- Extension filtering
- Signed asset URLs
- Tokenized downloads
- Hotlink protection

---

# Edge Caching (planed)

Ophan should support built-in edge caching capabilities.

Example flow:

```txt
client
   ↓
edge cache
   ↓
static storage / CDN
```

Benefits:

- Reduced latency
- Reduced backend traffic
- Improved scalability
- Faster global delivery

---

# Architecture Overview

```txt
Edge Gateway / API Gateway
    ├── Reverse Proxy
    ├── Load Balancer
    ├── Authentication Gateway
    ├── Rate Limiter
    ├── TLS Terminator
    ├── Router
    ├── Rewrite Engine
    ├── Static File Server
    ├── CDN Edge Cache
    └── Service Mesh Edge
```

---

# Supported Features Planned

## Static Content Delivery

- Local filesystem serving
- CDN integration
- Edge caching
- Brotli/Gzip compression
- ETag support
- Range requests
- Immutable asset caching
- Streaming downloads
- Signed URLs
- Hotlink protection
- Cache invalidation
- Multi-origin asset routing

---

# Design Philosophy

Static asset delivery should be treated as a first-class capability of the edge layer.

The gateway should be capable of serving:

- APIs
- Web applications
- Static assets
- Media content
- Streaming resources

through a unified routing and policy system.
