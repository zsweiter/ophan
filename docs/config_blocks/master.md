```hcl
master "ophan-01"  {
    user = "www-data"
    workers = "auto" # or size
    pid = "/run/ophan.pid"

    error_log = "/var/log/ophan/error.log"

    # include all gateways
    includes = "/etc/ophan/gateways/*.conf"
}
```