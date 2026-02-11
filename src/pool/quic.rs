use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Mutex, Notify};

use crate::conn::PoolConn;
use crate::pool::TransportPool;

/// Wrapper combining QUIC SendStream + RecvStream into a single AsyncRead + AsyncWrite
struct QuicBiStream {
    recv: quinn::RecvStream,
    send: quinn::SendStream,
}

impl AsyncRead for QuicBiStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for QuicBiStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

impl Unpin for QuicBiStream {}

/// QUIC Server Pool
pub struct QuicServerPool {
    max_capacity: usize,
    client_ip: String,
    tls_config: Arc<rustls::ServerConfig>,
    bind_addr: String,
    connections: Arc<Mutex<Vec<(String, PoolConn)>>>,
    conn_notify: Arc<Notify>,
    ready: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
    errors: Arc<AtomicUsize>,
    report_interval: Duration,
    shutdown: Arc<AtomicBool>,
}

impl QuicServerPool {
    pub fn new(
        max_capacity: usize,
        client_ip: String,
        tls_config: Arc<rustls::ServerConfig>,
        bind_addr: String,
        report_interval: Duration,
    ) -> Self {
        Self {
            max_capacity,
            client_ip,
            tls_config,
            bind_addr,
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
        let quinn_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(self.tls_config.clone())
                .expect("valid QUIC server config"),
        ));

        let addr: SocketAddr = self.bind_addr.parse().expect("valid bind address");
        let endpoint = match quinn::Endpoint::server(quinn_config, addr) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("QUIC server bind failed: {}", e);
                return;
            }
        };

        self.ready.store(true, Ordering::SeqCst);
        let mut id_counter = 0u64;

        while let Some(incoming) = endpoint.accept().await {
            if self.shutdown.load(Ordering::SeqCst) {
                break;
            }

            let conn = match incoming.await {
                Ok(c) => c,
                Err(_) => continue,
            };

            // Filter by client IP
            if !self.client_ip.is_empty() {
                let peer_ip = conn.remote_address().ip().to_string();
                if peer_ip != self.client_ip {
                    continue;
                }
            }

            // Accept a bidirectional stream
            let (send, recv) = match conn.accept_bi().await {
                Ok(sr) => sr,
                Err(_) => continue,
            };

            let id = format!("{:08x}", id_counter);
            id_counter += 1;

            let conn: PoolConn = Box::pin(QuicBiStream { recv, send });

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
impl TransportPool for QuicServerPool {
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

    fn ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }

    fn active(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }

    fn capacity(&self) -> usize {
        self.max_capacity
    }

    fn interval(&self) -> Duration {
        self.report_interval
    }

    fn add_error(&self) {
        self.errors.fetch_add(1, Ordering::SeqCst);
    }

    fn error_count(&self) -> usize {
        self.errors.load(Ordering::SeqCst)
    }

    fn reset_error(&self) {
        self.errors.store(0, Ordering::SeqCst);
    }
}

/// QUIC Client Pool
pub struct QuicClientPool {
    min_capacity: usize,
    max_capacity: usize,
    min_interval: Duration,
    max_interval: Duration,
    report_interval: Duration,
    tls_code: String,
    server_name: String,
    addr_fn: Arc<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<String>> + Send>> + Send + Sync>,
    connections: Arc<Mutex<Vec<(String, PoolConn)>>>,
    conn_notify: Arc<Notify>,
    ready: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
    errors: Arc<AtomicUsize>,
    shutdown: Arc<AtomicBool>,
}

impl QuicClientPool {
    pub fn new<F, Fut>(
        min_capacity: usize,
        max_capacity: usize,
        min_interval: Duration,
        max_interval: Duration,
        report_interval: Duration,
        tls_code: String,
        server_name: String,
        addr_fn: F,
    ) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = anyhow::Result<String>> + Send + 'static,
    {
        let addr_fn: Arc<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<String>> + Send>> + Send + Sync> = Arc::new(move || {
            Box::pin(addr_fn())
        });
        Self {
            min_capacity,
            max_capacity,
            min_interval,
            max_interval,
            report_interval,
            tls_code,
            server_name,
            addr_fn,
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

        // Create QUIC client config
        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(crate::tls::NoVerifier))
            .with_no_client_auth();

        let client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .expect("valid QUIC client config"),
        ));

        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
            .expect("bind QUIC client");
        endpoint.set_default_client_config(client_config);

        loop {
            if self.shutdown.load(Ordering::SeqCst) {
                break;
            }

            let current_active = {
                let conns = self.connections.lock().await;
                conns.len()
            };

            if current_active < self.min_capacity {
                let addr_str = match (self.addr_fn)().await {
                    Ok(a) => a,
                    Err(_) => {
                        tokio::time::sleep(current_interval).await;
                        continue;
                    }
                };

                let addr: SocketAddr = match addr_str.parse() {
                    Ok(a) => a,
                    Err(_) => {
                        tokio::time::sleep(current_interval).await;
                        continue;
                    }
                };

                let sni = self.server_name.clone();
                let conn = match endpoint.connect(addr, &sni) {
                    Ok(connecting) => match connecting.await {
                        Ok(c) => c,
                        Err(_) => {
                            tokio::time::sleep(current_interval).await;
                            current_interval = self.max_interval.min(current_interval * 2);
                            continue;
                        }
                    },
                    Err(_) => {
                        tokio::time::sleep(current_interval).await;
                        continue;
                    }
                };

                let (send, recv) = match conn.open_bi().await {
                    Ok(sr) => sr,
                    Err(_) => {
                        tokio::time::sleep(current_interval).await;
                        continue;
                    }
                };

                let id = format!("{:08x}", id_counter);
                id_counter += 1;

                let pool_conn: PoolConn = Box::pin(QuicBiStream { recv, send });

                {
                    let mut conns = self.connections.lock().await;
                    conns.push((id, pool_conn));
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
impl TransportPool for QuicClientPool {
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

    fn ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }

    fn active(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }

    fn capacity(&self) -> usize {
        self.max_capacity
    }

    fn interval(&self) -> Duration {
        self.min_interval
    }

    fn add_error(&self) {
        self.errors.fetch_add(1, Ordering::SeqCst);
    }

    fn error_count(&self) -> usize {
        self.errors.load(Ordering::SeqCst)
    }

    fn reset_error(&self) {
        self.errors.store(0, Ordering::SeqCst);
    }
}
