# L7 WAF Field × Matcher Rules

This document defines which matchers are valid for each field and phase in the L7 WAF compiler.

## Phase Mapping

| Phase           | Fields                                                                               |
| --------------- | ------------------------------------------------------------------------------------ |
| Inbound Header  | `Ip`, `Method`, `Host`, `Path`, `Query`, `UserAgent`, `Header(name)`, `Cookie(name)` |
| Inbound Body    | `Body`                                                                               |
| Outbound Header | `StatusCode`, `Header(name)`                                                         |
| Outbound Body   | `Body`                                                                               |


## Field × Matcher Matrix

| Field          | Eq  | Ne  | Lt/Gt/Le/Ge | Contains | StartsWith | EndsWith | Regex | Glob | In  |
| -------------- | :-: | :-: | :---------: | :------: | :--------: | :------: | :---: | :--: | :-: |
| `Method`       | ✅  | ❌  |     ❌      |    ❌    |     ❌     |    ❌    |  ❌   |  ❌  | ✅  |
| `Ip`           | ✅  | ❌  |     ❌      |    ❌    |     ❌     |    ❌    |  ❌   |  ❌  | ✅  |
| `Host`         | ✅  | ❌  |     ❌      |    ✅    |     ✅     |    ✅    |  ❌   |  ❌  | ❌  |
| `Path`         | ✅  | ❌  |     ❌      |    ✅    |     ✅     |    ✅    |  ✅   |  ✅  | ❌  |
| `Query`        | ✅  | ❌  |     ❌      |    ✅    |     ✅     |    ✅    |  ✅   |  ❌  | ❌  |
| `Header(name)` | ✅  | ❌  |     ❌      |    ✅    |     ✅     |    ✅    |  ✅   |  ❌  | ❌  |
| `Cookie(name)` | ✅  | ❌  |     ❌      |    ✅    |     ✅     |    ✅    |  ✅   |  ❌  | ❌  |
| `UserAgent`    | ✅  | ❌  |     ❌      |    ✅    |     ✅     |    ❌    |  ✅   |  ❌  | ❌  |
| `Body`         | ❌  | ❌  |     ❌      |    ✅    |     ❌     |    ❌    |  ✅   |  ❌  | ❌  |
| `StatusCode`   | ✅  | ❌  |     ❌      |    ✅    |     ❌     |    ❌    |  ✅   |  ❌  | ✅  |

**Legend:** ✅ Recommended | ❌ Not valid

---

## Per-Field Justification

### `Method`

| Matcher | Valid | Justification                                 |
| ------- | :---: | --------------------------------------------- |
| `Eq`    |  ✅   | `Method == "POST"` — exact HTTP method check  |
| `In`    |  ✅   | `Method IN ["GET","HEAD"]` — method whitelist |

**Compilation:** `HttpMethodSet` (bitset, O(1) lookup)

---

### `Ip`

| Matcher | Valid | Justification                                       |
| ------- | :---: | --------------------------------------------------- |
| `Eq/In` |  ✅   | `Ip IN_CIDR [10.0.0.0/8]` — CIDR blocking, IP whitelisting |

**Compilation:** `IpSet` (flatkit) — `allow_list` + `deny_list`

---

### `Host`

| Matcher      | Valid | Justification                                               |
| ------------ | :---: | ----------------------------------------------------------- |
| `Eq`         |  ✅   | `Host == "api.example.com"` — virtual hosting exacto        |
| `Contains`   |  ✅   | `Host Contains ".evil.com"` — malicious subdomain detection |
| `StartsWith` |  ✅   | `Host StartsWith "internal."` — internal service prefix     |
| `EndsWith`   |  ✅   | `Host EndsWith ".co.uk"` — TLD matching                     |

**Compilation:** `TextMatchers` (AhoCorasick + prefix/suffix + optional RegexSet/GlobSet)

---

### `Path`

| Matcher      | Valid | Justification                                            |
| ------------ | :---: | -------------------------------------------------------- |
| `Eq`         |  ✅   | `Path == "/admin"` — exact route                         |
| `Contains`   |  ✅   | `Path Contains "../"` — path traversal, injection        |
| `StartsWith` |  ✅   | `Path StartsWith "/api/v1/"` — API versioning            |
| `EndsWith`   |  ✅   | `Path EndsWith ".env"` — sensitive files                 |
| `Regex`      |  ✅   | `Path Regex "^/users/\d+/admin$"` — parameterized routes |
| `Glob`       |  ✅   | `Path Glob "/api/v*/*"` — flexible versioning            |

**Compilation:** `TextMatchers` (AhoCorasick + prefix/suffix + RegexSet/GlobSet)

---

### `Query`

| Matcher      | Valid | Justification                                                   |
| ------------ | :---: | --------------------------------------------------------------- |
| `Eq`         |  ✅   | `Query == "debug=true"` — exact parameter                       |
| `Contains`   |  ✅   | `Query Contains "union select"` — SQL injection in query string |
| `StartsWith` |  ✅   | `Query StartsWith "redirect="` — open redirect                  |
| `EndsWith`   |  ✅   | `Query EndsWith ".html"` — file extension injection             |
| `Regex`      |  ✅   | `Query Regex "id=\d+.*union"` — injection patterns              |

**Compilation:** `TextMatchers` (AhoCorasick + prefix/suffix + RegexSet)

---

### `Header(HeaderName)`

| Matcher      | Valid | Justification                                                                |
| ------------ | :---: | ---------------------------------------------------------------------------- |
| `Eq`         |  ✅   | `Header("Authorization") == "Bearer null"` — empty/invalid token             |
| `Contains`   |  ✅   | `Header("User-Agent") Contains "sqlmap"` — scanner detection                 |
| `StartsWith` |  ✅   | `Header("Authorization") StartsWith "Basic "` — auth type detection          |
| `EndsWith`   |  ✅   | `Header("Cookie") EndsWith "=; Path=/"` — cookie injection                   |
| `Regex`      |  ✅   | `Header("X-Forwarded-For") Regex "^\d+\.\d+\.\d+\.\d+$"` — format validation |

**Compilation:** `AHashMap<HeaderName, TextMatchers>`

---

### `Cookie(ImmerStr)`

| Matcher      | Valid | Justification                                                     |
| ------------ | :---: | ----------------------------------------------------------------- |
| `Eq`         |  ✅   | `Cookie("session") == ""` — empty session                         |
| `Contains`   |  ✅   | `Cookie("token") Contains "<script"` — XSS in cookie              |
| `StartsWith` |  ✅   | `Cookie("jwt") StartsWith "eyJ"` — JWT header detection           |
| `EndsWith`   |  ✅   | `Cookie("lang") EndsWith "-admin"` — cookie manipulation          |
| `Regex`      |  ✅   | `Cookie("jwt") Regex "eyJ.*\.eyJ.*\."` — JWT structure validation |

**Compilation:** `AHashMap<ImmerStr, TextMatchers>`

---

### `UserAgent`

| Matcher      | Valid | Justification                                                      |
| ------------ | :---: | ------------------------------------------------------------------ |
| `Eq`         |  ✅   | `UserAgent == "curl/7.68.0"` — exact UA                            |
| `Contains`   |  ✅   | `UserAgent Contains "sqlmap"` — scanner/bot detection              |
| `StartsWith` |  ✅   | `UserAgent StartsWith "Googlebot"` — bot detection                 |
| `Regex`      |  ✅   | `UserAgent Regex "Mozilla/5\.0.*Windows"` — browser fingerprinting |

**Compilation:** `TextMatchers` (AhoCorasick + prefix + RegexSet)

---

### `Body`

| Matcher    | Valid | Justification                                                      |
| ---------- | :---: | ------------------------------------------------------------------ |
| `Contains` |  ✅   | `Body Contains "union select"` — SQL injection, XSS payloads       |
| `Regex`    |  ✅   | `Body Regex "(?i)select\s+.*\s+from"` — complex injection patterns |

**Compilation:** `StreamingBodyMatcher` with HybridDFA (no full-body buffering, ~100-400KB constant memory)

---

### `StatusCode`

| Matcher    | Valid | Justification                                         |
| ---------- | :---: | ----------------------------------------------------- |
| `Eq`       |  ✅   | `Status == 500` — detect internal errors              |
| `In`       |  ✅   | `Status In [401,403,500,502,503]` — group of statuses |
| `Contains` |  ✅   | `Status Contains "5xx"` — detect all 5xx              |

**Compilation:** `StatusCodeSet` (bitset from `ophan-net`, O(1) lookup, 512 bits = 64 bytes)

```rust
// StatusCodeSet supports:
set.insert(StatusCode::OK);              // exact code
set.insert(StatusPattern::ServerError);  // all 5xx
set.contains(status)                     // O(1) check
```

---

## Compilation Summary

| Field        | Compilation Type                     | Memory                 |
| ------------ | ------------------------------------ | ---------------------- |
| `Method`     | `HttpMethodSet` (bitset)             | 8 bytes                |
| `Ip`         | `IpSet` (flatkit radix tree)         | ~KB (depends on CIDRs) |
| `Host`       | `TextMatchers`                       | ~KB                    |
| `Path`       | `TextMatchers`                       | ~KB                    |
| `Query`      | `TextMatchers`                       | ~KB                    |
| `Header(*)`  | `AHashMap<HeaderName, TextMatchers>` | ~KB per header         |
| `Cookie(*)`  | `AHashMap<ImmerStr, TextMatchers>`   | ~KB per cookie         |
| `UserAgent`  | `TextMatchers`                       | ~KB                    |
| `Body`       | `StreamingBodyMatcher` (HybridDFA)   | ~100-400KB constant    |
| `StatusCode` | `StatusCodeSet` (bitset)             | 64 bytes               |

## Operators Eliminated per Field

| Operator              | Eliminated From                                     |
| --------------------- | --------------------------------------------------- |
| `Lt/Le/Gt/Ge`         | Method, Host, Path, Header, Cookie, UserAgent, Body |
| `Ne`                  | All (rarely useful, expressible as `NOT(Eq)`)       |
| `Glob`                | Ip, Body, Header                                    |
| `StartsWith/EndsWith` | Ip, Method, StatusCode                              |
