use ophan_net::http::HttpMethodSet;

use super::tree::Node;

#[derive(Clone, Debug)]
pub struct VirtualHost<T> {
    pub name: String,
    pub tree: Node<T>,
    pub methods: HttpMethodSet,
}

impl<T> VirtualHost<T> {
    pub fn new(name: impl Into<String>, methods: HttpMethodSet) -> Self {
        Self { name: name.into(), tree: Node::default(), methods }
    }
}
