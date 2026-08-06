use std::path::Path;

use tokio::net::UnixStream;

use crate::transport::RawStream;

pub async fn connect_unix(path: &Path) -> Result<RawStream, crate::transport::Error> {
    let stream = UnixStream::connect(path).await?;
    Ok(RawStream::Unix(stream))
}
