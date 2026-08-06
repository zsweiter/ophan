mod response;
mod session;

pub use response::{HttpBody, HttpResponse};
pub use session::{Session, SessionExt};

pub type RequestParts = pingora::http::RequestHeader;
pub type ResponseParts = pingora::http::ResponseHeader;
