use std::path::Path;

use tokio::net::UnixStream;

use crate::transport::Transport;

pub async fn connect_unix(path: &Path) -> Result<Transport, crate::transport::Error> {
    let stream = UnixStream::connect(path).await?;
    Ok(Transport::Unix(stream))
}
