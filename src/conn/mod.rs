pub mod stat_conn;
pub mod rate_limiter;
pub mod timeout;
pub mod exchange;

pub use rate_limiter::RateLimiter;

use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite};

/// Type alias for pool connections - any async read/write stream
pub type PoolConn = Pin<Box<dyn AsyncReadWrite + Send>>;

/// Combined trait for async read + write
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}
