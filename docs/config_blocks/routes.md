```hcl
# Mininal routes config
routes {
    # to backend api
    path "/api/*" {
        hosts   = ["api.example.me"] 
        backend = upstream("api")
    }

    # to backend static
    path "/static/*" {
        hosts = ["storage.domain.com"]
        backend = static("/var/www/public")
    }
}
```

```hcl
routes {
    # Static backend (files)
    path "/" {
        hosts = ["blob.domain.com", "storage.domain.com"]

        backend = static("/var/www/public") 

        static_config {
            listing  = false
            dotfiles = false
            index    = true
            symlinks = false
            exclude_paths = [".git/*", ".env"]
        }
    }

    ## Full configuration with upstream backend
    path "/api/*" {
        hosts   = ["api.example.me", "payments.domain.com"] # Match against Host header
        methods = ["GET", "POST", "PUT", "PATCH", "DELETE"]

        backend = upstream("api")

        timeouts {
            connect = "600s"
            read    = "3600s"
            send    = "3600s"
        }

        streaming {
            buffering = false
            chunked   = false
        }

        policies {
            # Allows overriding global configuration
            auth extends "oauth-default" {
                sources {
                    cookie { name = "access_token" }
                }
            }

            cors extends "cors-default" {
                max_age = 7200
            }

            limiter = "limiter-default"
        }

        rewrite {
            strip_prefix "/api"
            strip_suffix ".json"
            
            replace "/v1/*" -> "/v2/$1"
            replace "/users/(.*)/posts" -> "/posts?user=$1"
            
            trailing_slash "ensure" # o "strip", "keep"
        }

        inbound_headers {
            set = { "X-Client-Layer" = "edge" }
            remove = ["X-Bad-Header"]

            to_upstream {
                set = { "X-Forwarded-By" = "Ophan-Edge" }
                remove = ["Authorization"] # p.ej. si el edge ya validó el token
            }
        }

        outbound_headers {
            from_upstream {
                remove = ["X-Internal-Cluster-ID"]
            }

            set = { 
                "Cache-Control" = "no-store",
                "Cache-Control" = "no-store"
            }
            remove = ["Server", "X-Powered-By"]
        }
    }

    # Planed
    group "public-api" {
        hosts   = ["api.example.me", "payments.domain.com"] # Match against Host header
        methods = ["GET", "POST", "PUT", "PATCH", "DELETE"]

        backend = upstream("api")

        policies {
            # Allows overriding global configuration
            auth extends "oauth-default" {
                sources {
                    cookie { name = "access_token" }
                }
            }

            cors extends "cors-default" {
                allow_origin      = ["https://app.example.com"]
                allow_methods     = ["GET", "POST", "OPTIONS"]
                allow_headers     = ["*"]
                allow_credentials = true
                max_age = 7200
            }

            limiter = "limiter-default"
        }

        outbound_headers {
            from_upstream {
                remove = ["X-Internal-Cluster-ID"]
            }

            set = { 
                "Cache-Control" = "no-store",
                "Cache-Control" = "no-store"
            }
            remove = ["Server", "X-Powered-By"]
        }

        match "GET /*" {
            backend = upstream("api")
        }
    }
}
```
