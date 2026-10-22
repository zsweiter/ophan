use ophan_net::http::HttpMethodSet;

use super::tree::Node;

/// A routed value together with the HTTP methods its route accepts.
#[derive(Clone, Debug)]
pub struct RouteEntry<T> {
    pub methods: HttpMethodSet,
    pub value: T,
}

impl<T> RouteEntry<T> {
    #[inline]
    pub fn allows(&self, method: &http::Method) -> bool {
        self.methods.is_any() || self.methods.contains_method(method)
    }
}

#[derive(Clone, Debug)]
pub struct VirtualHost<T> {
    pub name: String,
    pub tree: Node<RouteEntry<T>>,
    /// Patterns inserted on behalf of a `/x/*` route; an explicit route may replace them.
    pub implicit: Vec<String>,
}

impl<T> VirtualHost<T> {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            tree: Node::default(),
            implicit: Vec::new(),
        }
    }
}
