use ophan_net::http::HttpMethodSet;
use regex::Regex;

use super::tree::Node;

/// A virtual host with its own radix tree, HTTP method filter, and regex fallback routes.
///
/// Each `VirtualHost` holds:
/// - A radix tree (`Node<T>`) for zero-copy path matching
/// - A method bitmask for host-level HTTP method filtering
/// - A list of raw regex routes (fallback when tree returns NotFound)
#[derive(Clone, Debug)]
pub struct VirtualHost<T> {
    pub name: String,
    pub tree: Node<T>,
    pub methods: HttpMethodSet,
    pub regex_routes: Vec<(Regex, T)>,
}

impl<T> VirtualHost<T> {
    pub fn new(name: impl Into<String>, methods: HttpMethodSet) -> Self {
        Self {
            name: name.into(),
            tree: Node::default(),
            methods,
            regex_routes: Vec::new(),
        }
    }
}
