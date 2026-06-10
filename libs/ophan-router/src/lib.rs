pub mod error;

mod escape;
mod params;
mod pattern;
mod router;
mod sni;
mod tree;
mod vhost;

pub use params::{Params, ParamsIter};
pub use pattern::normalize_pattern;
pub use router::{Match, Router};
pub use vhost::VirtualHost;

#[cfg(test)]
mod tests;
