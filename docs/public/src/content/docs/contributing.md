---
title: Contributing
description: How to contribute to Ophan
tags: ["project"]
order: 901
---

## Feedback

Found a bug? Have a suggestion? Reach out:

📧 **zsweiter@gmail.com**

Ophan is early-stage and every piece of feedback helps shape the roadmap.

## Development

```bash
make fmt
make lint
make test
make run
```

## CI Pipeline

```bash
make ci              # fmt → lint → test → package (auto-detect OS)
make package-all     # Build + package for Linux, macOS, Windows
make package-docker  # Build Docker image (musl)
make checksum        # Generate SHA256 checksums
```

## Building from Source

Clone the repository and use the Makefile targets above to build, test, and package the gateway.

## Contributing Guidelines

- Follow the code style of the project
- Write tests for new features
- Update documentation for configuration changes
- Use the identifier naming conventions (lowercase, kebab-case, snake_case)

## Documentation

The documentation site lives in `docs/public/` (Astro). Content source files live in `docs/`. When configuration changes, update the affected pages under:

- [Configuration Reference](/configuration)
- [Authentication](/authentication)
- [WAF](/waf)
- [Rate Limiting](/rate-limiting)