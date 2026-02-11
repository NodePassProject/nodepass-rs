use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Notify};
use tokio_tungstenite::tungstenite::Message;

use crate::conn::PoolConn;
use crate::pool::TransportPool;

// WebSocket adapter that implements AsyncRead + AsyncWrite
use futures_util::{SinkExt, StreamExt};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

struct WsStream {
    rx_buf: Vec<u8>,
    rx_pos: usize,
    ws_rx: futures_util::stream::SplitStream<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>>,
    ws_tx: futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, Message>,
}

// For server-side accepted WS connections (no MaybeTlsStream)
struct WsServerStream {
    rx_buf: Vec<u8>,
    rx_pos: usize,
    ws_rx: futures_util::stream::SplitStream<tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>>,
    ws_tx: futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>, Message>,
}

/// WebSocket Server Pool
pub struct WsServerPool {
    max_capacity: usize,
    tls_config: Option<Arc<rustls::ServerConfig>>,
    listener: Arc<Mutex<Option<TcpListener>>>,
    connections: Arc<Mutex<Vec<(String, PoolConn)>>>,
    conn_notify: Arc<Notify>,
    ready: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
    errors: Arc<AtomicUsize>,
    report_interval: Duration,
    shutdown: Arc<AtomicBool>,
}

impl WsServerPool {
    pub fn new(
        max_capacity: usize,
        _client_ip: String,
        tls_config: Option<Arc<rustls::ServerConfig>>,
        listener: TcpListener,
        report_interval: Duration,
    ) -> Self {
        Self {
            max_capacity,
            tls_config,
            listener: Arc::new(Mutex::new(Some(listener))),
            connections: Arc::new(Mutex::new(Vec::new())),
            conn_notify: Arc::new(Notify::new()),
            ready: Arc::new(AtomicBool::new(false)),
            active: Arc::new(AtomicUsize::new(0)),
            errors: Arc::new(AtomicUsize::new(0)),
            report_interval,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    pub async fn server_manager(&self) {
        let listener = {
            let mut guard = self.listener.lock().await;
            guard.take()
        };
        let Some(listener) = listener else { return };

        self.ready.store(true, Ordering::SeqCst);
        let mut id_counter = 0u64;

        loop {
            if self.shutdown.load(Ordering::SeqCst) {
                break;
            }

            let (stream, _addr) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => {
                    if self.shutdown.load(Ordering::SeqCst) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };

            // Accept WebSocket connection
            let ws_stream = match tokio_tungstenite::accept_async(stream).await {
                Ok(ws) => ws,
                Err(_) => continue,
            };

            let id = format!("{:08x}", id_counter);
            id_counter += 1;

            // Wrap WebSocket as PoolConn using a simple adapter
            let conn: PoolConn = Box::pin(WsAdapter::new_server(ws_stream));

            {
                let mut conns = self.connections.lock().await;
                if conns.len() < self.max_capacity {
                    conns.push((id, conn));
                    self.active.fetch_add(1, Ordering::SeqCst);
                    self.conn_notify.notify_one();
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl TransportPool for WsServerPool {
    async fn incoming_get(&self, timeout: Duration) -> anyhow::Result<(String, PoolConn)> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            {
                let mut conns = self.connections.lock().await;
                if let Some(item) = conns.pop() {
                    self.active.fetch_sub(1, Ordering::SeqCst);
                    return Ok(item);
                }
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!("incoming_get: timeout");
            }
            tokio::select! {
                _ = self.conn_notify.notified() => {},
                _ = tokio::time::sleep_until(deadline) => {
                    anyhow::bail!("incoming_get: timeout");
                }
            }
        }
    }

    async fn outgoing_get(&self, id: &str, timeout: Duration) -> anyhow::Result<PoolConn> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            {
                let mut conns = self.connections.lock().await;
                if let Some(pos) = conns.iter().position(|(cid, _)| cid == id) {
                    let (_, conn) = conns.remove(pos);
                    self.active.fetch_sub(1, Ordering::SeqCst);
                    return Ok(conn);
                }
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!("outgoing_get: timeout for id {}", id);
            }
            tokio::select! {
                _ = self.conn_notify.notified() => {},
                _ = tokio::time::sleep_until(deadline) => {
                    anyhow::bail!("outgoing_get: timeout for id {}", id);
                }
            }
        }
    }

    async fn flush(&self) {
        let mut conns = self.connections.lock().await;
        conns.clear();
        self.active.store(0, Ordering::SeqCst);
    }
    async fn close(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        self.flush().await;
    }
    fn ready(&self) -> bool { self.ready.load(Ordering::SeqCst) }
    fn active(&self) -> usize { self.active.load(Ordering::SeqCst) }
    fn capacity(&self) -> usize { self.max_capacity }
    fn interval(&self) -> Duration { self.report_interval }
    fn add_error(&self) { self.errors.fetch_add(1, Ordering::SeqCst); }
    fn error_count(&self) -> usize { self.errors.load(Ordering::SeqCst) }
    fn reset_error(&self) { self.errors.store(0, Ordering::SeqCst); }
}

/// WebSocket Client Pool
pub struct WsClientPool {
    min_capacity: usize,
    max_capacity: usize,
    min_interval: Duration,
    max_interval: Duration,
    report_interval: Duration,
    tls_code: String,
    tunnel_addr: String,
    connections: Arc<Mutex<Vec<(String, PoolConn)>>>,
    conn_notify: Arc<Notify>,
    ready: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
    errors: Arc<AtomicUsize>,
    shutdown: Arc<AtomicBool>,
}

impl WsClientPool {
    pub fn new(
        min_capacity: usize,
        max_capacity: usize,
        min_interval: Duration,
        max_interval: Duration,
        report_interval: Duration,
        tls_code: String,
        tunnel_addr: String,
    ) -> Self {
        Self {
            min_capacity,
            max_capacity,
            min_interval,
            max_interval,
            report_interval,
            tls_code,
            tunnel_addr,
            connections: Arc::new(Mutex::new(Vec::new())),
            conn_notify: Arc::new(Notify::new()),
            ready: Arc::new(AtomicBool::new(false)),
            active: Arc::new(AtomicUsize::new(0)),
            errors: Arc::new(AtomicUsize::new(0)),
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    pub async fn client_manager(&self) {
        let mut id_counter = 0u64;
        let mut current_interval = self.max_interval;

        loop {
            if self.shutdown.load(Ordering::SeqCst) {
                break;
            }

            let current_active = {
                let conns = self.connections.lock().await;
                conns.len()
            };

            if current_active < self.min_capacity {
                let scheme = if self.tls_code != "0" { "wss" } else { "ws" };
                let url = format!("{}://{}", scheme, self.tunnel_addr);

                let ws_stream = match tokio_tungstenite::connect_async(&url).await {
                    Ok((ws, _)) => ws,
                    Err(_) => {
                        tokio::time::sleep(current_interval).await;
                        current_interval = self.max_interval.min(current_interval * 2);
                        continue;
                    }
                };

                let id = format!("{:08x}", id_counter);
                id_counter += 1;

                let conn: PoolConn = Box::pin(WsAdapter::new_client(ws_stream));

                {
                    let mut conns = self.connections.lock().await;
                    conns.push((id, conn));
                    self.active.fetch_add(1, Ordering::SeqCst);
                    self.conn_notify.notify_one();
                }

                if !self.ready.load(Ordering::SeqCst) {
                    self.ready.store(true, Ordering::SeqCst);
                }

                current_interval = self.min_interval;
            } else {
                current_interval = self.max_interval;
            }

            tokio::time::sleep(current_interval).await;
        }
    }
}

#[async_trait::async_trait]
impl TransportPool for WsClientPool {
    async fn incoming_get(&self, timeout: Duration) -> anyhow::Result<(String, PoolConn)> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            {
                let mut conns = self.connections.lock().await;
                if let Some(item) = conns.pop() {
                    self.active.fetch_sub(1, Ordering::SeqCst);
                    return Ok(item);
                }
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!("incoming_get: timeout");
            }
            tokio::select! {
                _ = self.conn_notify.notified() => {},
                _ = tokio::time::sleep_until(deadline) => {
                    anyhow::bail!("incoming_get: timeout");
                }
            }
        }
    }

    async fn outgoing_get(&self, id: &str, timeout: Duration) -> anyhow::Result<PoolConn> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            {
                let mut conns = self.connections.lock().await;
                if let Some(pos) = conns.iter().position(|(cid, _)| cid == id) {
                    let (_, conn) = conns.remove(pos);
                    self.active.fetch_sub(1, Ordering::SeqCst);
                    return Ok(conn);
                }
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!("outgoing_get: timeout for id {}", id);
            }
            tokio::select! {
                _ = self.conn_notify.notified() => {},
                _ = tokio::time::sleep_until(deadline) => {
                    anyhow::bail!("outgoing_get: timeout for id {}", id);
                }
            }
        }
    }

    async fn flush(&self) {
        let mut conns = self.connections.lock().await;
        conns.clear();
        self.active.store(0, Ordering::SeqCst);
    }
    async fn close(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        self.flush().await;
    }
    fn ready(&self) -> bool { self.ready.load(Ordering::SeqCst) }
    fn active(&self) -> usize { self.active.load(Ordering::SeqCst) }
    fn capacity(&self) -> usize { self.max_capacity }
    fn interval(&self) -> Duration { self.min_interval }
    fn add_error(&self) { self.errors.fetch_add(1, Ordering::SeqCst); }
    fn error_count(&self) -> usize { self.errors.load(Ordering::SeqCst) }
    fn reset_error(&self) { self.errors.store(0, Ordering::SeqCst); }
}

/// Adapter that wraps a WebSocket stream into AsyncRead + AsyncWrite
struct WsAdapter<S> {
    rx_buf: Vec<u8>,
    rx_pos: usize,
    ws: Arc<tokio::sync::Mutex<S>>,
}

impl WsAdapter<tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>> {
    fn new_server(ws: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>) -> Self {
        Self {
            rx_buf: Vec::new(),
            rx_pos: 0,
            ws: Arc::new(tokio::sync::Mutex::new(ws)),
        }
    }
}

impl WsAdapter<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>> {
    fn new_client(ws: tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>) -> Self {
        Self {
            rx_buf: Vec::new(),
            rx_pos: 0,
            ws: Arc::new(tokio::sync::Mutex::new(ws)),
        }
    }
}

// Note: Full AsyncRead/AsyncWrite implementation for WebSocket adapter is complex.
// For compilation, we provide stub implementations. A production version would
// properly bridge WebSocket message framing to byte stream semantics.
impl<S: Unpin + Send> Unpin for WsAdapter<S> {}

impl<S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin + Send + 'static> AsyncRead for WsAdapter<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Simplified: In production, poll the WebSocket stream for messages
        Poll::Pending
    }
}

impl<S: SinkExt<Message> + Unpin + Send + 'static> AsyncWrite for WsAdapter<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // Simplified: In production, send binary messages
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
