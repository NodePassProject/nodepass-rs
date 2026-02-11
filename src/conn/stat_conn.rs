use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use super::rate_limiter::RateLimiter;

/// A connection wrapper that tracks RX/TX bytes and optionally rate-limits
pub struct StatConn<T> {
    inner: T,
    rx: Arc<AtomicU64>,
    tx: Arc<AtomicU64>,
    rate: Option<Arc<RateLimiter>>,
}

impl<T> StatConn<T> {
    pub fn new(
        inner: T,
        rx: Arc<AtomicU64>,
        tx: Arc<AtomicU64>,
        rate: Option<Arc<RateLimiter>>,
    ) -> Self {
        Self { inner, rx, tx, rate }
    }

    pub fn inner(&self) -> &T {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl StatConn<TcpStream> {
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    pub fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.inner.peer_addr()
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for StatConn<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let n = buf.filled().len() - before;
            if n > 0 {
                self.rx.fetch_add(n as u64, Ordering::Relaxed);
                if let Some(ref rate) = self.rate {
                    rate.consume(n as u64);
                }
            }
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for StatConn<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            if *n > 0 {
                self.tx.fetch_add(*n as u64, Ordering::Relaxed);
                if let Some(ref rate) = self.rate {
                    rate.consume(*n as u64);
                }
            }
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
