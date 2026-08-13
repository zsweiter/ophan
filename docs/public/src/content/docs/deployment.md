---
title: Deployment & Hot Reload
description: Deploy with Docker or system services, and reload config atomically
tags: ["operations"]
order: 701
---

## Docker

```bash
docker run -p 8080:8080 \
  -v /path/to/config:/etc/ophan \
  ghcr.io/zsweiter/ophan:latest
```

## Linux Service (systemd)

```bash
sudo cp ophan-*/stubs/ophan.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ophan
```

## macOS Service (LaunchDaemon)

```bash
sudo cp ophan-*/stubs/io.ophan.ophan.plist /Library/LaunchDaemons/
sudo launchctl load /Library/LaunchDaemons/io.ophan.ophan.plist
```

## Configuration Layout

```
/etc/ophan/
├── ophan.conf          # Main configuration
├── certs/
│   ├── cert.pem
│   └── key.pem
└── gateways/
    └── *.conf          # Included configurations
```

The main `master` block supports `includes` for splitting configuration into multiple files:

```text
master "ophan-01" {
    user      = "www-data"
    workers   = "auto"
    pid       = "/run/ophan.pid"
    error_log = "/var/log/ophan/error.log"
    includes  = "/etc/ophan/gateways/*.conf"
}
```

## Hot Reload

Ophan supports atomic configuration reload without dropping connections. Send a SIGHUP signal to trigger a reload:

```bash
kill -HUP $(cat /run/ophan.pid)
```

> **⚠️ In development** — Hot reload behavior is being implemented and may change.

## Directory Layout

```
/var/log/ophan/        # Error logs
/var/www/public/       # Static file root
/run/ophan.pid         # PID file
```

## Next Steps

- [Observability](/observability)
- [Configuration Reference](/configuration)