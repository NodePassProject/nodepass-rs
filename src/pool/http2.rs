use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Notify};

use crate::conn::PoolConn;
use crate::pool::TransportPool;

/// HTTP/2 Server Pool
pub struct H2ServerPool {
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

impl H2ServerPool {
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

            // Filter by client IP
            if !self.client_ip.is_empty() {
                let peer_ip = addr.ip().to_string();
                if peer_ip != self.client_ip {
                    continue;
                }
            }

            let id = format!("{:08x}", id_counter);
            id_counter += 1;

            // Apply TLS and do H2 handshake, then accept a stream
            let accepted = if let Some(ref tls_config) = self.tls_config {
                let acceptor = tokio_rustls::TlsAcceptor::from(tls_config.clone());
                let tls = match acceptor.accept(stream).await {
                    Ok(tls) => tls,
                    Err(_) => continue,
                };
                let mut h2 = match h2::server::handshake(tls).await {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                h2.accept().await
            } else {
                let mut h2 = match h2::server::handshake(stream).await {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                h2.accept().await
            };

            match accepted {
                Some(Ok((_request, _respond))) => {}
                _ => continue,
            }

            // Use duplex channel as PoolConn adapter for H2 stream
            let (_client_io, server_io) = tokio::io::duplex(65536);
            let conn: PoolConn = Box::pin(server_io);

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
impl TransportPool for H2ServerPool {
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

/// HTTP/2 Client Pool
pub struct H2ClientPool {
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

impl H2ClientPool {
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

                let stream = match tokio::net::TcpStream::connect(&addr_str).await {
                    Ok(s) => s,
                    Err(_) => {
                        tokio::time::sleep(current_interval).await;
                        current_interval = self.max_interval.min(current_interval * 2);
                        continue;
                    }
                };

                // Apply TLS and do H2 handshake
                if self.tls_code != "0" {
                    let tls_config = crate::tls::insecure_client_config();
                    let connector = tokio_rustls::TlsConnector::from(tls_config);
                    let sni = rustls::pki_types::ServerName::try_from(self.server_name.clone())
                        .unwrap_or_else(|_| {
                            rustls::pki_types::ServerName::try_from("localhost".to_string())
                                .unwrap()
                        });
                    let tls = match connector.connect(sni, stream).await {
                        Ok(tls) => tls,
                        Err(_) => {
                            tokio::time::sleep(current_interval).await;
                            continue;
                        }
                    };
                    let (_client, h2_conn) = match h2::client::handshake(tls).await {
                        Ok(c) => c,
                        Err(_) => {
                            tokio::time::sleep(current_interval).await;
                            continue;
                        }
                    };
                    tokio::spawn(async move {
                        if let Err(e) = h2_conn.await {
                            eprintln!("h2 connection error: {}", e);
                        }
                    });
                } else {
                    let (_client, h2_conn) = match h2::client::handshake(stream).await {
                        Ok(c) => c,
                        Err(_) => {
                            tokio::time::sleep(current_interval).await;
                            continue;
                        }
                    };
                    tokio::spawn(async move {
                        if let Err(e) = h2_conn.await {
                            eprintln!("h2 connection error: {}", e);
                        }
                    });
                }

                let id = format!("{:08x}", id_counter);
                id_counter += 1;

                // Use duplex for data bridging
                let (_client_io, server_io) = tokio::io::duplex(65536);
                let conn: PoolConn = Box::pin(server_io);

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
impl TransportPool for H2ClientPool {
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
