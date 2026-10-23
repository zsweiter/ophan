use ophan_net::http::HttpMethodSet;

use super::tree::Node;

/// A routed value together with the HTTP methods its route accepts.
#[derive(Clone, Debug)]
pub struct RouteEntry<T> {
    pub methods: HttpMethodSet,
    pub value: T,
    /// Registered on behalf of a `/x/*` route at `/x`; a route of `/x` itself replaces it.
    pub implicit: bool,
}

impl<T> RouteEntry<T> {
    #[inline]
    pub fn allows(&self, method: &http::Method) -> bool {
        self.methods.is_any() || self.methods.contains_method(method)
    }
}

/// The routes registered for one path pattern, each with its own methods.
///
/// The method sets never overlap, so at most one entry serves a request. The first
/// entry is stored inline: most paths have a single route.
#[derive(Clone, Debug)]
pub struct RouteSlot<T> {
    first: RouteEntry<T>,
    rest: Vec<RouteEntry<T>>,
}

impl<T> RouteSlot<T> {
    pub fn new(entry: RouteEntry<T>) -> Self {
        Self { first: entry, rest: Vec::new() }
    }

    #[inline]
    pub fn find(&self, method: &http::Method) -> Option<&RouteEntry<T>> {
        if self.first.allows(method) {
            return Some(&self.first);
        }
        self.rest.iter().find(|entry| entry.allows(method))
    }

    #[inline]
    pub fn find_mut(&mut self, method: &http::Method) -> Option<&mut RouteEntry<T>> {
        if self.first.allows(method) {
            return Some(&mut self.first);
        }
        self.rest.iter_mut().find(|entry| entry.allows(method))
    }

    /// Adds `entry` to the routes of this pattern.
    ///
    /// An explicit entry takes its methods away from the implicit entries, and fails,
    /// giving the entry back, when it shares a method with an explicit entry. An implicit
    /// entry only keeps the methods nothing here routes yet.
    pub fn push(&mut self, mut entry: RouteEntry<T>) -> Result<(), RouteEntry<T>> {
        if entry.implicit {
            for existing in self.entries() {
                entry.methods = entry.methods.without(&existing.methods);
            }
            if !entry.methods.is_empty() {
                self.rest.push(entry);
            }
            return Ok(());
        }

        if self.entries().any(|existing| !existing.implicit && existing.methods.intersects(&entry.methods)) {
            return Err(entry);
        }

        for existing in std::iter::once(&mut self.first).chain(self.rest.iter_mut()) {
            if existing.implicit {
                existing.methods = existing.methods.without(&entry.methods);
            }
        }
        self.rest.retain(|existing| !existing.methods.is_empty());

        if self.first.methods.is_empty() {
            self.first = entry;
        } else {
            self.rest.push(entry);
        }
        Ok(())
    }

    fn entries(&self) -> impl Iterator<Item = &RouteEntry<T>> {
        std::iter::once(&self.first).chain(&self.rest)
    }

    pub fn into_first(self) -> T {
        self.first.value
    }
}

#[derive(Clone, Debug)]
pub struct VirtualHost<T> {
    pub name: String,
    pub tree: Node<RouteSlot<T>>,
}

impl<T> VirtualHost<T> {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), tree: Node::default() }
    }
}
