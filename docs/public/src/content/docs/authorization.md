---
title: Authorization Roadmap (RBAC & ABAC)
description: Planned fine-grained authorization model for Ophan
tags: ["project"]
order: 900
---

Ophan currently handles **authentication** (who you are) at the edge. A **fine-grained authorization** layer (what you may do) is on the roadmap.

> **⚠️ Planned** — Authorization is specified on the roadmap but not yet implemented.

---

## Current State

| Layer      | Status                                          |
| ---------- | ----------------------------------------------- |
| Authentication (JWT, OAuth2, HMAC) | <span class="status-badge badge-dev">In development</span> |
| Edge token validation + claim propagation | <span class="status-badge badge-dev">In development</span> |
| Authorization (RBAC / ABAC) | <span class="status-badge badge-planned">Planned</span> |

Authentication produces a set of verified claims (`sub`, `scope`, custom `extra_data`) that are propagated upstream. Authorization will use those same claims — plus request context — to decide whether a caller may perform an action.

---

## Planned Authorization Model

### RBAC — Role-Based Access Control

Access is granted through roles assigned to the caller:

```text
subject (claims)
   → roles        (e.g. "admin", "billing:read")
   → permissions  (e.g. "payments.write")
   → route / method
```

### ABAC — Attribute-Based Access Control

Access is decided by evaluating attributes of the subject, resource, action, and environment:

```text
subject.role = "operator"
AND resource.path = "/admin/*"
AND environment.ip in allowed_ranges
```

### Integration with Policies

Authorization will be exposed as a policy that composes with the existing pipeline (`auth`, `waf`, `limiter`, `cors`, `helmet`), evaluated after authentication during `on_request`.

---

## Proposed Configuration Shape

> Indicative only — subject to change during design.

```hcl
policy rbac "internal-api" {
    role "admin" {
        allow = ["payments.write", "users.delete"]
    }
    role "readonly" {
        allow = ["payments.read"]
    }

    default = "deny"
}

policy abac "pci" {
    rule "allow_card_data" {
        when = (
            subject.role == "card_ops"
            AND resource.path STARTS_WITH "/cards/"
            AND environment.ip IN trusted_ips
        )
    }
}
```

---

## Roadmap

1. Authorization decision engine integrated with the request lifecycle
2. RBAC policy with roles and permission sets
3. ABAC rules with claim/resource/environment attributes
4. Reuse of `exclude_paths` semantics for admin endpoints
5. Admin API for managing roles and permissions at runtime (planned)

## Next Steps

- [Authentication](/authentication) — the identity layer this builds on
- [Contributing](/contributing) — help shape the design