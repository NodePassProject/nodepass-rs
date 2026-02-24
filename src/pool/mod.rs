pub mod tcp;
pub mod quic;
pub mod websocket;
pub mod http2;

use std::time::Duration;
use crate::conn::PoolConn;

/// Transport pool trait - matches Go's TransportPool interface
#[async_trait::async_trait]
pub trait TransportPool: Send + Sync {
    /// Get an incoming connection with the given timeout.
    /// Returns (connection_id, connection)
    async fn incoming_get(&self, timeout: Duration) -> anyhow::Result<(String, PoolConn)>;

    /// Get an outgoing connection by ID with the given timeout.
    async fn outgoing_get(&self, id: &str, timeout: Duration) -> anyhow::Result<PoolConn>;

    /// Flush all connections in the pool
    async fn flush(&self);

    /// Close the pool
    async fn close(&self);

    /// Whether the pool is ready
    fn ready(&self) -> bool;

    /// Number of active connections
    fn active(&self) -> usize;

    /// Pool capacity
    fn capacity(&self) -> usize;

    /// Current pool fill interval
    fn interval(&self) -> Duration;

    /// Add an error count
    fn add_error(&self);

    /// Get error count
    fn error_count(&self) -> usize;

    /// Reset error count
    fn reset_error(&self);

    /// Get the TLS peer certificate fingerprint for a connection by ID.
    /// Only meaningful for client pools where peer certs are captured during TLS handshake.
    fn fingerprint_for(&self, _id: &str) -> Option<String> {
        None
    }
}
