use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Notify};
use tokio_tungstenite::tungstenite::Message;

use crate::conn::PoolConn;
use crate::pool::TransportPool;
use crate::tls;

use futures_util::{SinkExt, StreamExt};

/// Spawn background tasks to bridge a WebSocket stream to a duplex byte stream.
/// Returns one end of the duplex as a PoolConn-compatible stream.
fn spawn_ws_bridge<S>(ws: tokio_tungstenite::WebSocketStream<S>) -> tokio::io::DuplexStream
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (app_side, bridge_side) = tokio::io::duplex(65536);
    let (bridge_read, bridge_write) = tokio::io::split(bridge_side);
    let (mut ws_tx, mut ws_rx) = ws.split();

    // WS recv -> bridge write (data from remote appears on app_side's read)
    tokio::spawn(async move {
        let mut bridge_write = bridge_write;
        while let Some(msg) = ws_rx.next().await {
            match msg {
                Ok(Message::Binary(data)) => {
                    if bridge_write.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Ok(Message::Close(_)) | Err(_) => break,
                _ => {} // ignore text, ping, pong
            }
        }
    });

    // Bridge read -> WS send (data written to app_side becomes WS Binary messages)
    tokio::spawn(async move {
        let mut bridge_read = bridge_read;
        let mut buf = vec![0u8; 65536];
        loop {
            match bridge_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if ws_tx
                        .send(Message::Binary(buf[..n].to_vec()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });

    app_side
}

/// WebSocket Server Pool
pub struct WsServerPool {
    max_capacity: usize,
    client_ip: String,
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
        client_ip: String,
        tls_config: Option<Arc<rustls::ServerConfig>>,
        listener: TcpListener,
        report_interval: Duration,
    ) -> Self {
        Self {
            max_capacity,
            client_ip,
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

            let (stream, addr) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => {
                    if self.shutdown.load(Ordering::SeqCst) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };

            // Filter by client IP if specified
            if !self.client_ip.is_empty() {
                let peer_ip = addr.ip().to_string();
                if peer_ip != self.client_ip {
                    continue;
                }
            }

            // Apply TLS if configured, then accept WebSocket
            let conn: PoolConn = if let Some(ref tls_config) = self.tls_config {
                let acceptor = tokio_rustls::TlsAcceptor::from(tls_config.clone());
                let tls_stream = match acceptor.accept(stream).await {
                    Ok(tls) => tls,
                    Err(_) => continue,
                };
                let ws_stream = match tokio_tungstenite::accept_async(tls_stream).await {
                    Ok(ws) => ws,
                    Err(_) => continue,
                };
                Box::pin(spawn_ws_bridge(ws_stream))
            } else {
                let ws_stream = match tokio_tungstenite::accept_async(stream).await {
                    Ok(ws) => ws,
                    Err(_) => continue,
                };
                Box::pin(spawn_ws_bridge(ws_stream))
            };

            let id = format!("{:08x}", id_counter);
            id_counter += 1;

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
    fingerprints: Arc<Mutex<HashMap<String, String>>>,
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
            fingerprints: Arc::new(Mutex::new(HashMap::new())),
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

                // Use custom TLS connector for insecure verification (self-signed certs)
                let connector = if self.tls_code != "0" {
                    Some(tokio_tungstenite::Connector::Rustls(
                        tls::insecure_client_config(),
                    ))
                } else {
                    None
                };

                let ws_stream = match tokio_tungstenite::connect_async_tls_with_config(
                    &url, None, false, connector,
                )
                .await
                {
                    Ok((ws, _)) => ws,
                    Err(_) => {
                        tokio::time::sleep(current_interval).await;
                        current_interval = self.max_interval.min(current_interval * 2);
                        continue;
                    }
                };

                // Extract peer certificate fingerprint before bridging
                let peer_fp = if self.tls_code != "0" {
                    match ws_stream.get_ref() {
                        tokio_tungstenite::MaybeTlsStream::Rustls(tls_stream) => {
                            let (_, session) = tls_stream.get_ref();
                            session
                                .peer_certificates()
                                .and_then(|certs| certs.first())
                                .map(|cert| tls::format_cert_fingerprint(cert.as_ref()))
                        }
                        _ => None,
                    }
                } else {
                    None
                };

                let id = format!("{:08x}", id_counter);
                id_counter += 1;

                let conn: PoolConn = Box::pin(spawn_ws_bridge(ws_stream));

                {
                    let mut conns = self.connections.lock().await;
                    conns.push((id.clone(), conn));
                    self.active.fetch_add(1, Ordering::SeqCst);
                    self.conn_notify.notify_one();
                }

                // Store fingerprint if available
                if let Some(fp) = peer_fp {
                    let mut fps = self.fingerprints.lock().await;
                    fps.insert(id, fp);
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
        let mut fps = self.fingerprints.lock().await;
        conns.clear();
        fps.clear();
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

    fn fingerprint_for(&self, id: &str) -> Option<String> {
        self.fingerprints.try_lock().ok()?.get(id).cloned()
    }
}
