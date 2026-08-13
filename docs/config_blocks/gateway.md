```hcl
name = "ophan-test-gateway" # required name

listeners {
    # listener block
}

upstreams {
    # upstreams block
}

routes {
    # routes block
}

# POLICY DEFINITIONS 
# policy <type> "<name>"
# types: auth, cors, helmet, limiter, waf
policy auth "default" {
    # policy rules
}
```