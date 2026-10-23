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
  -v ophan-config:/etc/ophan \
  -v ophan-www:/var/www \
  -v ophan-logs:/var/log/ophan \
  -v ophan-run:/run/ophan \
  ghcr.io/zsweiter/ophan:latest
```

The image is distroless: the static binary, CA certificates and the default configuration,
running as uid `65532`. Like nginx, it exposes only port 80. The default gateway serves
`/var/www` on port 80 and on the unix socket `/run/ophan/ophan_gateway.sock`, for a proxy in
front such as cloudflared, which must send the client address in `X-Forwarded-For`.

| Volume           | Content                                                  |
| ---------------- | -------------------------------------------------------- |
| `/etc/ophan`     | Configuration; filled with the defaults when empty       |
| `/var/www`       | Static content                                           |
| `/var/log/ophan` | Logs                                                     |
| `/run/ophan`     | Unix sockets shared with other containers or the host    |

The PID file and the upgrade socket live in `/tmp/ophan`, inside the container.

## Debian / Ubuntu (.deb)

```bash
VERSION=0.1.32
ARCH=$(dpkg --print-architecture)      # amd64 or arm64
curl -fLO "https://github.com/zsweiter/ophan/releases/download/v${VERSION}/ophan_${VERSION}_${ARCH}.deb"
sudo apt install "./ophan_${VERSION}_${ARCH}.deb"
sudo systemctl start ophan
```

The package installs a static binary in `/usr/bin`, the configuration in `/etc/ophan` (kept on
upgrades) and an enabled `ophan` systemd unit. Installing a newer package reloads the service,
which hands its listeners over to the new binary without downtime.

## Linux Service (systemd)

```bash
# The stub contains @SBINDIR@/@CONFIGDIR@ placeholders — substitute them first
sudo sed -e 's|@SBINDIR@|/usr/local/bin|g' -e 's|@CONFIGDIR@|/etc/ophan|g' \
    ophan-*/stubs/systemd.service | \
    sudo tee /etc/systemd/system/ophan.service > /dev/null
sudo systemctl daemon-reload
sudo systemctl enable --now ophan
```

### Service user

The systemd unit runs the gateway as the system user `ophan`, created by the package and by
the install script, with `CAP_NET_BIND_SERVICE` as its only privilege (ports 80/443) and
`NoNewPrivileges`. systemd creates `/run/ophan` and `/var/log/ophan` for it, and `/etc/ophan`
is readable by the `ophan` group. Files the gateway must read, such as TLS keys, need that
group too:

```bash
sudo chown root:ophan /etc/ophan/certs/key.pem
sudo chmod 640 /etc/ophan/certs/key.pem
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
    user      = "ophan"
    workers   = "auto"
    pid       = "/var/run/ophan/ophan.pid"
    error_log = "/var/log/ophan/error.log"
    includes  = "/etc/ophan/gateways/*.conf"
}
```

## Hot Reload

Ophan supports atomic configuration reload without dropping connections. Send a SIGHUP signal to trigger a reload:

```bash
sudo systemctl reload ophan      # or: kill -HUP $(cat /var/run/ophan/ophan.pid)
```

Routes, upstreams and policies are swapped in place; in-flight requests finish on the old
configuration. Backends that did not change keep their health state and rate-limit counters
of unchanged policies are kept.

When listeners, gateways or the `metrics` block change, or the binary was replaced, the reload
hands over to a new process instead (see below).

## Upgrade

```bash
sudo ophan --upgrade             # latest release
sudo ophan --upgrade 0.1.32      # a given version
```

Downloads the release for this platform, verifies its SHA-256, checks that the new binary
accepts the current configuration and replaces the binary atomically, keeping the previous
one as `ophan.old`. Then it reloads the running instance (`SIGHUP`). `latest` never installs
an older version. Installations managed by dpkg, Homebrew or a container are left to those
tools.

## Zero-downtime Upgrade

A reload (`SIGHUP`, `systemctl reload ophan` or `ophan -s reload`) hands the listeners over
to a new process when the binary on disk was replaced (by `ophan --upgrade`, a package or a
copy) or when listeners, gateways or the `metrics` block changed. The new binary first has to
accept the current configuration; if it does not, the running process keeps serving and logs
the reason. The new process receives the listening sockets, and the old one stops accepting
and drains its in-flight requests.

Under systemd the unit runs with `Type=notify`: the new process reports itself as the main
process, so systemd follows the upgrade instead of restarting the service.

## Shutdown

`SIGTERM` and `SIGINT` stop accepting connections, wait 3 seconds and then give in-flight
requests up to 5 more seconds, which fits the default 10 second stop timeout of Docker.

## Directory Layout

```
/var/log/ophan/        # Error logs (owned by ophan)
/var/www/html/         # Static file root (index.html + favicon.svg)
/run/ophan/            # PID file and upgrade socket (created by systemd for ophan)
```

## Next Steps

- [Observability](/observability)
- [Configuration Reference](/configuration)