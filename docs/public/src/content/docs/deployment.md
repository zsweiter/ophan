---
title: Deployment & Hot Reload
description: Deploy with Docker or system services, and reload config atomically
tags: ["operations"]
order: 701
---

## Docker

```bash
# Maps host port 8080 to the gateway's HTTP listener (port 80)
docker run -p 8080:80 \
  -v /path/to/config:/etc/ophan \
  ghcr.io/zsweiter/ophan:latest
```

## Linux Service (systemd)

```bash
# The stub contains @SBINDIR@/@CONFIGDIR@ placeholders — substitute them first
sudo sed -e 's|@SBINDIR@|/usr/local/bin|g' -e 's|@CONFIGDIR@|/etc/ophan|g' \
    ophan-*/stubs/systemd.service | \
    sudo tee /etc/systemd/system/ophan.service > /dev/null
sudo systemctl daemon-reload
sudo systemctl enable --now ophan
```

## macOS Service (LaunchDaemon)

```bash
sudo sed -e 's|@SBINDIR@|/usr/local/bin|g' -e 's|@CONFIGDIR@|/etc/ophan|g' \
    ophan-*/stubs/io.ophan.ophan.plist | \
    sudo tee /Library/LaunchDaemons/io.ophan.ophan.plist > /dev/null
sudo launchctl bootstrap system /Library/LaunchDaemons/io.ophan.ophan.plist
```

## Configuration Layout

```
/etc/ophan/
├── master.conf            # Main configuration
├── certs/
│   ├── cert.pem
│   └── key.pem
└── gateways/
    └── *.conf             # Included configurations
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
/var/www/html/         # Static file root (index.html + favicon.svg)
/run/ophan.pid         # PID file
```

## Next Steps

- [Observability](/observability)
- [Configuration Reference](/configuration)