```hcl
# minimal config
upstreams {
    upstream "api" {
        static_servers = ["127.1.0.2:8080"]
    }
}
```

```hcl
# full config
upstreams {
    upstream "api" {
        balance_strategy = "round_robin"
        static_servers = [
            "api-1:8080",
            {
                address = "api-2:8080"
                weight = 50
            }
        ]

        # Planed
        security {
            cert = "/etc/certs/public.pem"
            key = "/etc/certs/private.key"
            client_ca = "/etc/certs/ca.pem"
            # Optional
            client_auth = "optional"
            # Optional
            versions = ["TLS1.2","TLS1.3"]
        }

        # Planned
        health_check {
            path = "/health" # or none for only tcp check
            interval = "10s"
            timeout = "2s"
            healthy_threshold = 2
            unhealthy_threshold = 3
        }

        # Planned
        circuit_breaker {
            consecutive_failures = 5
            ejection_time = "30s"
            max_ejection_percent = 50
        }

        # Planned (for active discovery)
        discovery {
            driver = "kubernetes"
            dns = "api.internal.company.com"
            refresh_interval = "15m"
        }

        # Planned (for pasive discovery)
        registry {
            driver = "..."
            security "mtls" {
                cert = "/etc/certs/upstream/public.pem"
                key = "/etc/certs/upstream/private.key"
                client_ca = "/etc/certs/upstream/ca.pem"
            }

            # security "api-key" {
            #    key = "base64_secret_key"
            #    algo = "HMAC" # RSA, Ed2559
            # }
        }
    }
}
```

enums:
balance_strategy:

- round_robin (default)
- ip_hash
- least_connections

static_servers:

- type List<String | Object{endpoint: String, weight: number}>
