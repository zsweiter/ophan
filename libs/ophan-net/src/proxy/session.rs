use crate::proxy::{HttpBody, HttpResponse, ResponseParts};

pub type Session = pingora::proxy::Session;

#[async_trait::async_trait]
pub trait SessionExt {
    fn request_parts(&self) -> &pingora::http::RequestHeader;

    async fn send_response(&mut self, response: HttpResponse) -> pingora::Result<()>;

    async fn write_response(&mut self, headers: ResponseParts, body: Option<HttpBody>) -> pingora::Result<()>;
}

#[async_trait::async_trait]
impl SessionExt for Session {
    fn request_parts(&self) -> &pingora::http::RequestHeader {
        self.as_downstream().req_header()
    }

    async fn send_response(&mut self, response: HttpResponse) -> pingora::Result<()> {
        let (headers, body) = response.into_parts();

        self.write_response(headers, body).await
    }

    async fn write_response(&mut self, header: ResponseParts, body: Option<HttpBody>) -> pingora::Result<()> {
        self.write_response_header(Box::new(header), body.is_none()).await?;

        let Some(body) = body else {
            return Ok(());
        };

        match body {
            HttpBody::Bytes(bytes) => {
                self.write_response_body(Some(bytes), true).await?;
            },
            HttpBody::Stream(mut stream) => {
                use futures::StreamExt;

                while let Some(chunk_res) = stream.next().await {
                    match chunk_res {
                        Ok(data) => {
                            self.write_response_body(Some(data), false).await?;
                        },
                        Err(io_err) => {
                            return Err(pingora::Error::because(
                                pingora::ErrorType::ReadError,
                                "Failed reading chunk from source stream",
                                io_err,
                            ));
                        },
                    }
                }

                self.write_response_body(None, true).await?;
            },
        }

        return Ok(());
    }
}
