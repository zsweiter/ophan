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

Routes, upstreams and policies are swapped in place; in-flight requests finish on the old
configuration. Backends that did not change keep their health state and rate-limit counters
of unchanged policies are kept.

When listeners, gateways or the `metrics` block change, the process starts a new copy of
itself, hands it the listening sockets and drains. If the new process cannot start, the
current one keeps serving.

## Binary Upgrade

Install the new binary over the old one and run:

```bash
ophan --upgrade -c /etc/ophan/master.conf
```

The new binary starts in upgrade mode, receives the listening sockets from the running
process and takes over; the old process stops accepting and drains in-flight requests.

## Shutdown

`SIGTERM` and `SIGINT` stop accepting connections, wait 3 seconds and then give in-flight
requests up to 5 more seconds, which fits the default 10 second stop timeout of Docker.

## Directory Layout

```
/var/log/ophan/        # Error logs
/var/www/html/         # Static file root (index.html + favicon.svg)
/run/ophan.pid         # PID file
```

## Next Steps

- [Observability](/observability)
- [Configuration Reference](/configuration)