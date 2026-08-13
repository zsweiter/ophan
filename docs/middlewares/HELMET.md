# Helmet Security Policies Configuration Reference

This document details the HTTP security headers strategy using the `helmet` policy block. Security levels can be fine-tuned based on target execution contexts (APIs or Web applications) within the gateway server configuration.

---

## Configuration Block: `gateway.conf`

The Helmet configuration is defined within the `policies` block of the gateway settings. To manage security hardening globally or per route, configure the variables as shown below:

```bash
policies {
    helmet {
        # Defines the strictness level of the security headers.
        # Options: "disabled", "standard", "strict"
        level = "standard"

        # Specifies the architecture context.
        # Options: "api", "web"
        target = "api"
    }
}
```

---

## Helmet Profiles Matrix

The matrix below highlights which security controls are systematically enforced depending on your configured **Target** and **Level**:

| Target  | Disabled                       | Standard                                                                                                                                                                                                                                         | Strict                                                                                                                                                                                                                  |
| :------ | :----------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **API** | No security headers are added. | Security headers tailored for JSON/REST APIs. Excludes browser-specific vectors like CSP, `X-Frame-Options`, and `Permissions-Policy`. Enforces isolation (`nosniff`, `COOP`, `CORP`, `Origin-Agent-Cluster`).                                   | Adds stronger runtime isolation layers (e.g., `COEP: require-corp`), a strict `Referrer-Policy`, and other hardening rules optimized for secure API endpoints.                                                          |
| **Web** | No security headers are added. | Recommended defaults for HTML browser-facing applications. Includes clickjacking and referrer protections (`X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: strict-origin-when-cross-origin`). CSP is expected to be managed by the application. | Maximum browser-level hardening. Employs rigid frame sandboxing (`X-Frame-Options: DENY`), strict `COEP`, restrictive `Permissions-Policy`, `no-referrer`, etc. CSP should be explicitly configured by the application. |

---

## Target Details & Headers Payload

### 1. API Standard

Optimized for REST/JSON API payloads where responses do not execute or render HTML components.

```http
X-Content-Type-Options: nosniff
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Origin-Agent-Cluster: ?1
X-DNS-Prefetch-Control: off
X-Permitted-Cross-Domain-Policies: none
X-Download-Options: noopen
X-XSS-Protection: 0
```

**Exclusions:**

- `Content-Security-Policy` (CSP)
- `X-Frame-Options`
- `Permissions-Policy`
- `Cross-Origin-Embedder-Policy` (COEP)

---

### 2. API Strict

Contains all configurations specified under **API Standard** plus the following runtime isolation headers:

```http
Cross-Origin-Embedder-Policy: require-corp
Referrer-Policy: no-referrer
```

---

### 3. Web Standard

The baseline secure header stack recommended for HTML client applications rendered in browsers.

```http
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Referrer-Policy: strict-origin-when-cross-origin
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Origin-Agent-Cluster: ?1
X-DNS-Prefetch-Control: off
X-Permitted-Cross-Domain-Policies: none
X-Download-Options: noopen
X-XSS-Protection: 0
```

**Exclusions:**

- `COEP`
- `CSP`
- `Permissions-Policy` (Are excluded by default to avoid breaking cross-origin browser resources unless manually designated)

---

### 4. Web Strict

Maximum browser hardening stack. Incorporates everything in **Web Standard** plus:

```http
X-Frame-Options: DENY
Cross-Origin-Embedder-Policy: require-corp
Referrer-Policy: no-referrer
Permissions-Policy: ...
```

> 💡 **Development Recommendation:** It is highly recommended to explicitly define and inject a tailored **Content-Security-Policy (CSP)** at the application level alongside the Strict profile.

---

## API Engine Proposal (Rust Implementation)

The configuration correlates cleanly with the gateway engine parser. Below is the proposed representation inside the Rust-based proxy handler:

```rust
pub enum HelmetTarget {
    Api,
    Web,
}

pub enum HelmetLevel {
    Disabled,
    Standard,
    Strict,
}

pub struct HelmetConfig {
    pub target: HelmetTarget,
    pub level: HelmetLevel,
}
```
