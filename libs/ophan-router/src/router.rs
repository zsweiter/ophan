use ophan_net::http::{HttpMethod, HttpMethodSet};

use super::{
    error::{InsertError, MatchError},
    params::Params,
    pattern::normalize_pattern,
    sni::SniTableRouter,
    vhost::VirtualHost,
};

/// Multi-stage API Gateway Router path matching.
///
/// Resolution flow:
///
/// 1. **SNI / Host matching**
///    - Matches the incoming host name via `SniTableRouter`.
///    - Supports exact (`api.domain.com`) and wildcard (`*.domain.com`) hosts.
///    - Falls through to the default vhost if no match.
///
/// 2. **HTTP method filtering**
///    - Per-vhost bitmask check with bitwise OR merging on duplicate hosts.
///
/// 3. **Path routing**
///    - Radix tree lookup (static → param → wildcard → catch-all).
pub struct Router<T> {
    hosts_table: SniTableRouter,
    routes_bucket: Vec<VirtualHost<T>>,
    default_id: u32,
}

impl<T> Default for Router<T> {
    fn default() -> Self {
        Self {
            hosts_table: SniTableRouter::new(),
            routes_bucket: vec![VirtualHost::new("__default__", HttpMethodSet::all())],
            default_id: 0,
        }
    }
}

impl<T> Router<T> {
    /// Construct a new router with a default vhost (methods = ALL).
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct router with routes capacity
    ///
    ///  This capacity only applied to routes
    pub fn with_capacity(capacity: usize) -> Self {
        let mut routes = Vec::with_capacity(capacity + 1);
        routes.push(VirtualHost::new("__default__", HttpMethodSet::all()));

        Self {
            hosts_table: SniTableRouter::new(),
            routes_bucket: routes,
            default_id: 0,
        }
    }

    /// Add a route.
    ///
    /// - `host`: if `Some`, routes to the matching vhost (creates it if needed);
    ///   if `None`, uses the default vhost.
    /// - `path`: Ophan path syntax (`/users/:id`, `/api/files/*`, etc.)
    /// - `methods`: HTTP methods allowed for this route (merged via OR with existing).
    /// - `value`: stored value returned on match.
    pub fn add_route(&mut self, path: &str, methods: HttpMethodSet, hosts: Vec<&str>, value: T) -> Result<(), InsertError>
    where
        T: Clone,
    {
        let vhost_id = if hosts.is_empty() {
            Self::merge_methods(&mut self.routes_bucket[self.default_id as usize].methods, &methods);
            self.default_id
        } else {
            let mut vhost_id = self.default_id;
            for host in hosts {
                if let Some(id) = self.hosts_table.route(host) {
                    Self::merge_methods(&mut self.routes_bucket[id as usize].methods, &methods);
                    vhost_id = id;
                } else {
                    vhost_id = self.add_vhost_inner(host, methods.clone());
                }
            }
            vhost_id
        };

        let vhost = &mut self.routes_bucket[vhost_id as usize];

        let normalized = normalize_pattern(path);

        // catch-all `/*` is a special case: we insert it into the tree as `/{*_}` but also insert `/` to match the root path.
        if path == "/*" {
            vhost.tree.insert(normalized, value.clone())?;
            let _ = vhost.tree.insert("/".to_string(), value);
            return Ok(());
        }

        vhost.tree.insert(normalized, value)
    }

    /// Resolve a request through multi-stage routing:
    ///
    /// Returns the matched value and extracted path parameters,
    /// or a `MatchError` describing the failure.
    #[inline]
    pub fn match_route<'p>(
        &self,
        host: Option<&str>,
        method: &'p http::Method,
        path: &'p str,
    ) -> Result<Match<'_, 'p, &T>, MatchError> {
        let vhost_id = self.resolve_vhost(host);
        let bucket = &self.routes_bucket[vhost_id as usize];

        if !bucket.methods.contains_method(method) {
            return Err(MatchError::MethodNotAllowed);
        }

        let normalized_path = normalize_trailing_slash(path);

        match bucket.tree.at(normalized_path.as_bytes()) {
            Ok((value, params)) => Ok(Match { value: unsafe { &*value.get() }, params }),
            Err(e) => Err(e),
        }
    }

    /// Mutable variant of `find_route`.
    #[inline]
    pub fn find_route_mut<'path>(
        &mut self,
        host: Option<&str>,
        method: &'path http::Method,
        path: &'path str,
    ) -> Result<Match<'_, 'path, &mut T>, MatchError> {
        let vhost_id = self.resolve_vhost(host);
        let bucket = &self.routes_bucket[vhost_id as usize];

        if !bucket.methods.contains_method(method) {
            return Err(MatchError::MethodNotAllowed);
        }

        let normalized_path = normalize_trailing_slash(path);

        match self.routes_bucket[vhost_id as usize].tree.at(normalized_path.as_bytes()) {
            Ok((value, params)) => Ok(Match { value: unsafe { &mut *value.get() }, params }),
            Err(e) => Err(e),
        }
    }

    /// Remove a route from the default virtual host's tree.
    pub fn remove(&mut self, path: impl Into<String>) -> Option<T> {
        let normalized = normalize_pattern(&path.into());
        self.routes_bucket[self.default_id as usize].tree.remove(normalized)
    }

    /// Remove a route from a specific virtual host's tree.
    pub fn remove_from_vhost(&mut self, vhost_id: u32, path: impl Into<String>) -> Option<T> {
        let normalized = normalize_pattern(&path.into());
        self.routes_bucket[vhost_id as usize].tree.remove(normalized)
    }

    fn add_vhost_inner(&mut self, host: &str, methods: HttpMethodSet) -> u32 {
        // If no methods were specified, default to ALL to avoid MethodNotAllowed
        // for every request on a route that didn't set explicit methods.
        let bits = methods.standard().bits();
        let methods = if bits == 0 { HttpMethodSet::all() } else { methods };
        let id = self.routes_bucket.len() as u32;
        self.routes_bucket.push(VirtualHost::new(host, methods));
        self.hosts_table.add_route(host, id);
        id
    }

    fn resolve_vhost(&self, host: Option<&str>) -> u32 {
        match host {
            Some(h) => {
                let clean = h.split(':').next().unwrap_or(h);
                self.hosts_table.route(clean).unwrap_or(self.default_id)
            },
            None => self.default_id,
        }
    }

    fn merge_methods(existing: &mut HttpMethodSet, new: &HttpMethodSet) {
        let merged = HttpMethod::from_bits(existing.standard().bits() | new.standard().bits());
        let mut result = HttpMethodSet::new(merged);
        for m in existing.custom() {
            result.add_custom(m);
        }
        for m in new.custom() {
            result.add_custom(m);
        }
        *existing = result;
    }
}

fn normalize_trailing_slash(path: &str) -> &str {
    if path == "/" { path } else { path.trim_end_matches('/') }
}

/// A successful match consisting of the registered value
/// and URL parameters, returned by [`Router::find_route`].
#[derive(Debug)]
pub struct Match<'k, 'v, V> {
    pub value: V,
    pub params: Params<'k, 'v>,
}
