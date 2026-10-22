```hcl
master "ophan-01"  {
    user = "www-data"
    workers = "auto" # or size
    pid = "/run/ophan.pid"

    error_log = "/var/log/ophan/error.log"

    # include all gateways
    includes = "/etc/ophan/gateways/*.conf"

    # prometheus endpoint (optional)
    metrics {
        listen = "127.0.0.1:9100" # or "unix:/run/ophan/metrics.sock"
        path = "/metrics"
    }
}
```
