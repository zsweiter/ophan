pub type Session = pingora::proxy::Session;

pub trait HttpProxyGateway: pingora::proxy::ProxyHttp {
    type CTX;
}
