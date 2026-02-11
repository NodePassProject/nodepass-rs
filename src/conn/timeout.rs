use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, ReadBuf};

/// A reader wrapper that enforces a read deadline/timeout
pub struct TimeoutReader<T> {
    inner: T,
    timeout: Duration,
}

impl<T> TimeoutReader<T> {
    pub fn new(inner: T, timeout: Duration) -> Self {
        Self { inner, timeout }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for TimeoutReader<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncRead + Unpin> TimeoutReader<T> {
    /// Read with timeout - returns error on timeout
    pub async fn read_with_timeout(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use tokio::io::AsyncReadExt;
        if self.timeout.is_zero() {
            return self.inner.read(buf).await;
        }
        match tokio::time::timeout(self.timeout, self.inner.read(buf)).await {
            Ok(result) => result,
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "read timeout",
            )),
        }
    }
}
