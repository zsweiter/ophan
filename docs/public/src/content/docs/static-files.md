---
title: Static File Serving
description: Serve static files directly from the filesystem
tags: ["delivery"]
order: 600
---

Ophan can serve static files directly from the local filesystem, eliminating the need for a separate web server.

> **⚠️ In development** — Static serving is being implemented.

---

## Configuration

Use the `static` backend type within a route:

```hcl
routes {
    path "/static/*" {
        hosts = ["storage.domain.com"]
        backend = static("/var/www/public")
    }
}
```

The `static` backend takes a single filesystem path as its root.

## Static Configuration

Additional options can be provided with a `static_config` block:

```hcl
path "/" {
    hosts = ["blob.domain.com", "storage.domain.com"]
    backend = static("/var/www/public")

    static_config {
        listing       = false
        dotfiles      = false
        index         = true
        symlinks      = false
        exclude_paths = [".git/*", ".env"]
    }
}
```

| Property         | Type      | Description                                        |
| ---------------- | --------- | -------------------------------------------------- |
| `listing`        | `Boolean` | Enable directory listing when no index exists      |
| `dotfiles`       | `Boolean` | Allow serving hidden files (starting with `.`)     |
| `index`          | `Boolean` | Serve index files for directories                  |
| `symlinks`       | `Boolean` | Follow symbolic links                              |
| `exclude_paths`  | `Array`   | Glob paths that must never be served               |

## Security

By default, directory listing and dotfile access are disabled. Enable them only when explicitly needed:

```hcl
static_config {
    listing  = true    # Enable directory listing
    dotfiles = false   # Keep hidden files inaccessible
    symlinks = false   # Prevent traversal via symlinks
}
```

Additional protections planned: path traversal protection, extension filtering, and signed asset URLs.

## Use Cases

- Single-page application hosting
- Static asset delivery (CSS, JS, images)
- Documentation sites
- Maintenance pages during deployments

## Next Steps

- [Path & Header Matching](/routing)
- [URL & Header Rewriting](/rewriting)
- [Configuration Reference](/configuration)