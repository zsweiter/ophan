use tokio::net::TcpStream;

use crate::transport::Transport;

pub async fn connect_tcp(host: &str, port: u16) -> Result<Transport, crate::transport::Error> {
    let stream = TcpStream::connect((host, port)).await?;
    stream.set_nodelay(true)?;
    Ok(Transport::Tcp(stream))
}
