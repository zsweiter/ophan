use ophan_net::http::HttpMethodSet;

use super::{
    error::{InsertError, MatchError},
    params::Params,
    pattern::normalize_pattern,
    sni::SniTableRouter,
    tree::Node,
    vhost::{RouteEntry, RouteSlot, VirtualHost},
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
/// 2. **Path routing**
///    - Radix tree lookup (static → param → wildcard → catch-all).
///
/// 3. **HTTP method filtering**
///    - Each route keeps its own method set; a path match with another method is `MethodNotAllowed`.
pub struct Router<T> {
    hosts_table: SniTableRouter,
    routes_bucket: Vec<VirtualHost<T>>,
    default_id: u32,
}

impl<T> Default for Router<T> {
    fn default() -> Self {
        Self {
            hosts_table: SniTableRouter::new(),
            routes_bucket: vec![VirtualHost::new("__default__")],
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
        routes.push(VirtualHost::new("__default__"));

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
    /// - `methods`: HTTP methods allowed for this route; empty means every method.
    /// - `value`: stored value returned on match.
    pub fn add_route(&mut self, path: &str, methods: HttpMethodSet, hosts: Vec<&str>, value: T) -> Result<(), InsertError>
    where
        T: Clone,
    {
        // A route without explicit methods accepts every method.
        let methods = if methods.is_empty() { HttpMethodSet::all() } else { methods };

        let mut vhost_ids = Vec::with_capacity(hosts.len().max(1));
        if hosts.is_empty() {
            vhost_ids.push(self.default_id);
        }

        for host in hosts {
            let id = match self.hosts_table.route(host) {
                Some(id) if self.routes_bucket[id as usize].name.eq_ignore_ascii_case(host) => id,
                _ => self.add_vhost_inner(host),
            };

            if !vhost_ids.contains(&id) {
                vhost_ids.push(id);
            }
        }

        let entry = RouteEntry { methods, value, implicit: false };
        for id in vhost_ids {
            self.insert_into(id, path, entry.clone())?;
        }

        Ok(())
    }

    fn insert_into(&mut self, vhost_id: u32, path: &str, entry: RouteEntry<T>) -> Result<(), InsertError>
    where
        T: Clone,
    {
        let vhost = &mut self.routes_bucket[vhost_id as usize];

        // Requests are matched without a trailing slash, so patterns are stored the same way.
        let path = if path.len() > 1 && !path.ends_with("/*") {
            path.trim_end_matches('/')
        } else {
            path
        };
        let path = if path.is_empty() { "/" } else { path };
        let normalized = normalize_pattern(path);

        // `/x/*` also answers `/x` (and `/x/`, which is matched as `/x`) for the methods `/x`
        // does not route itself.
        if let Some(base) = path.strip_suffix("/*") {
            Self::insert_entry(&mut vhost.tree, normalized, entry.clone(), path)?;

            let base = normalize_pattern(if base.is_empty() { "/" } else { base });
            let implicit = RouteEntry { implicit: true, ..entry };
            return Self::insert_entry(&mut vhost.tree, base, implicit, path).or(Ok(()));
        }

        Self::insert_entry(&mut vhost.tree, normalized, entry, path)
    }

    /// Adds `entry` to the slot of `pattern`, creating it when the pattern is new. Routes
    /// of the same pattern must not share a method.
    fn insert_entry(tree: &mut Node<RouteSlot<T>>, pattern: String, entry: RouteEntry<T>, path: &str) -> Result<(), InsertError> {
        let Some(mut slot) = tree.remove(pattern.clone()) else {
            return tree.insert(pattern, RouteSlot::new(entry));
        };

        let pushed = slot.push(entry).map_err(|_| InsertError::MethodConflict { path: path.to_string() });
        tree.insert(pattern, slot)?;
        pushed
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

        let normalized_path = normalize_trailing_slash(path);
        let (slot, params) = bucket.tree.at(normalized_path.as_bytes())?;
        let slot = unsafe { &*slot.get() };

        let Some(entry) = slot.find(method) else {
            return Err(MatchError::MethodNotAllowed);
        };

        Ok(Match { value: &entry.value, params })
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

        let normalized_path = normalize_trailing_slash(path);
        let (slot, params) = bucket.tree.at(normalized_path.as_bytes())?;
        let slot = unsafe { &mut *slot.get() };

        let Some(entry) = slot.find_mut(method) else {
            return Err(MatchError::MethodNotAllowed);
        };

        Ok(Match { value: &mut entry.value, params })
    }

    /// Remove a route from the default virtual host's tree.
    pub fn remove(&mut self, path: impl Into<String>) -> Option<T> {
        let normalized = normalize_pattern(&path.into());
        self.routes_bucket[self.default_id as usize].tree.remove(normalized).map(RouteSlot::into_first)
    }

    /// Remove a route from a specific virtual host's tree.
    pub fn remove_from_vhost(&mut self, vhost_id: u32, path: impl Into<String>) -> Option<T> {
        let normalized = normalize_pattern(&path.into());
        self.routes_bucket[vhost_id as usize].tree.remove(normalized).map(RouteSlot::into_first)
    }

    fn add_vhost_inner(&mut self, host: &str) -> u32 {
        let id = self.routes_bucket.len() as u32;
        self.routes_bucket.push(VirtualHost::new(host));
        self.hosts_table.add_route(host, id);
        id
    }

    fn resolve_vhost(&self, host: Option<&str>) -> u32 {
        match host {
            Some(h) => self.hosts_table.route(ophan_net::http::utils::strip_port(h)).unwrap_or(self.default_id),
            None => self.default_id,
        }
    }
}

fn normalize_trailing_slash(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() { "/" } else { trimmed }
}

/// A successful match consisting of the registered value
/// and URL parameters, returned by [`Router::find_route`].
#[derive(Debug)]
pub struct Match<'k, 'v, V> {
    pub value: V,
    pub params: Params<'k, 'v>,
}
