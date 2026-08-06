use tokio::net::TcpStream;

use crate::transport::error::{Error, ErrorKind};

pub async fn connect_tcp(host: &str, port: u16) -> Result<TcpStream, Error> {
    if host.is_empty() {
        return Err(Error::new(ErrorKind::DnsFailed("host is empty".into())));
    }
    if port == 0 {
        return Err(Error::new(ErrorKind::DnsFailed("port is zero".into())));
    }

    let stream = TcpStream::connect((host, port)).await?;
    stream.set_nodelay(true)?;
    Ok(stream)
}
