use core::future::Future;
use core::pin::Pin;

pub use pingora::proxy::Session;

use crate::http::client::response::Response;
use crate::http::ingress::request::IncomingRequest;

pub type Result<T> = crate::http::client::error::Result<T>;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait HttpProxy: Send + Sync {
    /// New connection accepted.
    fn on_connect<'a>(&'a self, _session: &'a mut Session) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Ok(()) })
    }

    /// Request headers/body fully parsed.
    fn on_request<'a>(&'a self, _req: &'a IncomingRequest<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Ok(()) })
    }

    /// Main request processing.
    ///
    /// This is where routing, auth, WAF, load balancing,
    /// caching, etc. may happen.
    fn handle_request<'a>(&'a self, req: &'a IncomingRequest<'a>) -> BoxFuture<'a, Result<Response>>;

    /// Response received from upstream.
    fn on_response<'a>(&'a self, _req: &'a IncomingRequest<'a>, resp: Response) -> BoxFuture<'a, Result<Response>> {
        Box::pin(async move { Ok(resp) })
    }

    /// Right before writing the response to the client.
    fn before_send<'a>(&'a self, _req: &'a IncomingRequest<'a>, resp: Response) -> BoxFuture<'a, Result<Response>> {
        Box::pin(async move { Ok(resp) })
    }

    /// Request lifecycle finished.
    fn on_complete<'a>(&'a self, _req: &'a IncomingRequest<'a>) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }

    /// Error hook.
    fn on_error<'a>(
        &'a self,
        _req: Option<&'a IncomingRequest<'a>>,
        _error: &'a crate::http::client::error::Error,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }

    /// Connection closed.
    fn on_disconnect<'a>(&'a self, _session: &'a Session) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }
}
