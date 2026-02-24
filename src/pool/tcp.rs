use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Notify};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::conn::PoolConn;
use crate::pool::TransportPool;
use crate::tls;

/// TCP Server Pool - accepts connections from the tunnel listener and assigns IDs
pub struct TcpServerPool {
    max_capacity: usize,
    client_ip: String,
    tls_acceptor: Option<TlsAcceptor>,
    listener: Arc<Mutex<Option<TcpListener>>>,
    incoming: Arc<Mutex<HashMap<String, PoolConn>>>,
    incoming_queue: Arc<Mutex<Vec<(String, PoolConn)>>>,
    incoming_notify: Arc<Notify>,
    ready: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
    errors: Arc<AtomicUsize>,
    report_interval: Duration,
    shutdown: Arc<AtomicBool>,
}

impl TcpServerPool {
    pub fn new(
        max_capacity: usize,
        client_ip: String,
        tls_config: Option<Arc<rustls::ServerConfig>>,
        listener: TcpListener,
        report_interval: Duration,
    ) -> Self {
        let tls_acceptor = tls_config.map(TlsAcceptor::from);
        Self {
            max_capacity,
            client_ip,
            tls_acceptor,
            listener: Arc::new(Mutex::new(Some(listener))),
            incoming: Arc::new(Mutex::new(HashMap::new())),
            incoming_queue: Arc::new(Mutex::new(Vec::new())),
            incoming_notify: Arc::new(Notify::new()),
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

            // Accept a connection
            let stream = match listener.accept().await {
                Ok((stream, addr)) => {
                    // Filter by client IP if specified
                    if !self.client_ip.is_empty() {
                        let peer_ip = addr.ip().to_string();
                        if peer_ip != self.client_ip {
                            continue;
                        }
                    }
                    stream
                }
                Err(_) => {
                    if self.shutdown.load(Ordering::SeqCst) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };

            // Apply TLS if configured
            let conn: PoolConn = if let Some(ref acceptor) = self.tls_acceptor {
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => Box::pin(tls_stream),
                    Err(_) => continue,
                }
            } else {
                Box::pin(stream)
            };

            let id = format!("{:08x}", id_counter);
            id_counter += 1;

            // Add to the incoming pool
            {
                let mut queue = self.incoming_queue.lock().await;
                if queue.len() < self.max_capacity {
                    queue.push((id.clone(), conn));
                    self.active.fetch_add(1, Ordering::SeqCst);
                    self.incoming_notify.notify_one();
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl TransportPool for TcpServerPool {
    async fn incoming_get(&self, timeout: Duration) -> anyhow::Result<(String, PoolConn)> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            {
                let mut queue = self.incoming_queue.lock().await;
                if let Some(item) = queue.pop() {
                    self.active.fetch_sub(1, Ordering::SeqCst);
                    return Ok(item);
                }
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!("incoming_get: timeout");
            }
            tokio::select! {
                _ = self.incoming_notify.notified() => {},
                _ = tokio::time::sleep_until(deadline) => {
                    anyhow::bail!("incoming_get: timeout");
                }
            }
        }
    }

    async fn outgoing_get(&self, id: &str, timeout: Duration) -> anyhow::Result<PoolConn> {
        // For server pool, outgoing_get retrieves a specific connection by ID
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            {
                let mut queue = self.incoming_queue.lock().await;
                if let Some(pos) = queue.iter().position(|(cid, _)| cid == id) {
                    let (_, conn) = queue.remove(pos);
                    self.active.fetch_sub(1, Ordering::SeqCst);
                    return Ok(conn);
                }
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!("outgoing_get: timeout for id {}", id);
            }
            tokio::select! {
                _ = self.incoming_notify.notified() => {},
                _ = tokio::time::sleep_until(deadline) => {
                    anyhow::bail!("outgoing_get: timeout for id {}", id);
                }
            }
        }
    }

    async fn flush(&self) {
        let mut queue = self.incoming_queue.lock().await;
        let count = queue.len();
        queue.clear();
        self.active.fetch_sub(count.min(self.active.load(Ordering::SeqCst)), Ordering::SeqCst);
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

/// TCP Client Pool - dials to tunnel server and maintains connection pool
pub struct TcpClientPool {
    min_capacity: usize,
    max_capacity: usize,
    min_interval: Duration,
    max_interval: Duration,
    report_interval: Duration,
    tls_code: String,
    server_name: String,
    dial_fn: Arc<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<TcpStream>> + Send>> + Send + Sync>,
    connections: Arc<Mutex<HashMap<String, PoolConn>>>,
    conn_ids: Arc<Mutex<Vec<String>>>,
    conn_notify: Arc<Notify>,
    ready: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
    errors: Arc<AtomicUsize>,
    shutdown: Arc<AtomicBool>,
    /// Stores TLS peer certificate fingerprints by connection ID (for verification)
    fingerprints: Arc<Mutex<HashMap<String, String>>>,
}

impl TcpClientPool {
    pub fn new<F, Fut>(
        min_capacity: usize,
        max_capacity: usize,
        min_interval: Duration,
        max_interval: Duration,
        report_interval: Duration,
        tls_code: String,
        server_name: String,
        dial_fn: F,
    ) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = anyhow::Result<TcpStream>> + Send + 'static,
    {
        let dial_fn: Arc<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<TcpStream>> + Send>> + Send + Sync> = Arc::new(move || {
            Box::pin(dial_fn())
        });
        Self {
            min_capacity,
            max_capacity,
            min_interval,
            max_interval,
            report_interval,
            tls_code,
            server_name,
            dial_fn,
            connections: Arc::new(Mutex::new(HashMap::new())),
            conn_ids: Arc::new(Mutex::new(Vec::new())),
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
                // Need to fill the pool
                let stream = match (self.dial_fn)().await {
                    Ok(stream) => stream,
                    Err(_) => {
                        tokio::time::sleep(current_interval).await;
                        current_interval = self.max_interval.min(current_interval * 2);
                        continue;
                    }
                };

                // Apply TLS if needed
                let (conn, peer_fp): (PoolConn, Option<String>) = if self.tls_code != "0" {
                    let tls_config = tls::insecure_client_config();
                    let connector = TlsConnector::from(tls_config);
                    let server_name = rustls::pki_types::ServerName::try_from(self.server_name.clone())
                        .unwrap_or_else(|_| rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap());
                    match connector.connect(server_name, stream).await {
                        Ok(tls_stream) => {
                            // Extract peer certificate fingerprint before boxing
                            let fp = {
                                let (_, conn) = tls_stream.get_ref();
                                conn.peer_certificates()
                                    .and_then(|certs| certs.first())
                                    .map(|cert| tls::format_cert_fingerprint(cert.as_ref()))
                            };
                            (Box::pin(tls_stream), fp)
                        }
                        Err(_) => {
                            tokio::time::sleep(current_interval).await;
                            continue;
                        }
                    }
                } else {
                    (Box::pin(stream), None)
                };

                let id = format!("{:08x}", id_counter);
                id_counter += 1;

                {
                    let mut conns = self.connections.lock().await;
                    let mut ids = self.conn_ids.lock().await;
                    conns.insert(id.clone(), conn);
                    ids.push(id.clone());
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
impl TransportPool for TcpClientPool {
    async fn incoming_get(&self, timeout: Duration) -> anyhow::Result<(String, PoolConn)> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            {
                let mut conns = self.connections.lock().await;
                let mut ids = self.conn_ids.lock().await;
                if let Some(id) = ids.pop() {
                    if let Some(conn) = conns.remove(&id) {
                        self.active.fetch_sub(1, Ordering::SeqCst);
                        return Ok((id, conn));
                    }
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
                if let Some(conn) = conns.remove(id) {
                    let mut ids = self.conn_ids.lock().await;
                    ids.retain(|cid| cid != id);
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
        let mut ids = self.conn_ids.lock().await;
        let mut fps = self.fingerprints.lock().await;
        conns.clear();
        ids.clear();
        fps.clear();
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

    fn fingerprint_for(&self, id: &str) -> Option<String> {
        // Use try_lock to avoid async; fingerprint reads are quick
        self.fingerprints.try_lock().ok()?.get(id).cloned()
    }
}
