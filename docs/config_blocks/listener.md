## Minimal config

```hcl
# minimal config
listeners  {
    # Minimal https listener
    listener "ingress-https" {
        address = ":443" # valid values like tcp://127.0.1.0:80, or only ip:port or :port, or unix path
        protocols = ["https"] # support http2, grpc (planed), ws, wss

        # Required when protocol is https, wss
        tls {
            cert = "/etc/certs/public.pem"
            key = "/etc/certs/private.key"
        }
    }

    # Minimal http listener
    listener "ingress-http" {
        address = ":443"
    }

    # Minimal http listener via unix (not support tls)
    listener "ingress-http" {
        address = "unix://run/process.sock"
    }
}
```

```hcl
# full config
listeners {
    listener "public-https" {
        address = "0.0.0.0:443"
        protocols = ["http1", "http2", "grpc", "websocket"]

        # Optional, if port is 443 made required
        tls {
            cert = "/etc/certs/public.pem"
            key = "/etc/certs/private.key"

            # Optional
            versions = ["TLS1.2","TLS1.3"]

            # Optional
            client_auth = "optional"
            client_ca = "/etc/certs/ca.pem"

            # Optional (planed)
            ciphers = [
                "TLS_AES_256_GCM_SHA384"
            ]
        }

        # Optional
        network_policy {
            # ACL
            allowed_ip_ranges = ["10.0.0.0/8"]
            blocked_ip_ranges = ["10.0.0.0/8"]

            # When your server is behind of proxy like fastly, cloudflare
            # Both rules is required
            real_ip_header = "X-Forwarded-For"
            proxy_allowed_ips = [
                "173.245.48.0/20",
                "103.21.244.0/22",
                "103.22.200.0/22",
                "103.31.4.0/22",
                "141.101.64.0/18",
                "108.162.192.0/18",
                "190.93.240.0/20",
                "188.114.96.0/20",
                "197.234.240.0/22",
                "198.41.128.0/17",
                "162.158.0.0/15",
                "104.16.0.0/13",
                "104.24.0.0/14",
                "172.64.0.0/13",
                "131.0.72.0/22"
            ]
        }

        # Optional (planed)
        limits {
            connections = 100000
            request_size = "10mb"
        }

        # Optional (planed)
        timeouts {
            idle = "60s"
            keepalive = "30s"
        }
    }
}
```
