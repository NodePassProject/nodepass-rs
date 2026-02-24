use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Notify};

use crate::conn::PoolConn;
use crate::pool::TransportPool;
use crate::tls;

/// Bridge h2 RecvStream to a duplex write half.
/// Data received from the h2 stream is written to the duplex, making it readable from app_side.
async fn bridge_h2_recv_to_writer(
    mut recv: h2::RecvStream,
    mut writer: tokio::io::WriteHalf<tokio::io::DuplexStream>,
) {
    while let Some(chunk) = recv.data().await {
        match chunk {
            Ok(data) => {
                let len = data.len();
                let _ = recv.flow_control().release_capacity(len);
                if writer.write_all(&data).await.is_err() {
                    return;
                }
            }
            Err(_) => return,
        }
    }
}

/// Bridge a duplex read half to h2 SendStream.
/// Data written to app_side is read from the duplex and sent over h2.
async fn bridge_reader_to_h2_send(
    mut reader: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    mut send: h2::SendStream<bytes::Bytes>,
) {
    let mut buf = vec![0u8; 16384];
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) | Err(_) => {
                let _ = send.send_data(bytes::Bytes::new(), true);
                return;
            }
            Ok(n) => n,
        };
        let mut offset = 0;
        while offset < n {
            let remaining = n - offset;
            send.reserve_capacity(remaining);
            let cap = match futures_util::future::poll_fn(|cx| send.poll_capacity(cx)).await {
                Some(Ok(cap)) => cap,
                _ => return,
            };
            let chunk_len = cap.min(remaining);
            let chunk = bytes::Bytes::copy_from_slice(&buf[offset..offset + chunk_len]);
            if send.send_data(chunk, false).is_err() {
                return;
            }
            offset += chunk_len;
        }
    }
}

/// Create a duplex bridge for h2 RecvStream + SendStream, returning one end as PoolConn.
fn spawn_h2_bridge(
    recv: h2::RecvStream,
    send: h2::SendStream<bytes::Bytes>,
) -> tokio::io::DuplexStream {
    let (app_side, bridge_side) = tokio::io::duplex(65536);
    let (bridge_read, bridge_write) = tokio::io::split(bridge_side);

    tokio::spawn(bridge_h2_recv_to_writer(recv, bridge_write));
    tokio::spawn(bridge_reader_to_h2_send(bridge_read, send));

    app_side
}

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

            // Apply TLS and do H2 handshake, accept stream, bridge, and produce PoolConn.
            // Each branch handles its own Connection type to avoid type mismatch.
            let conn: PoolConn = if let Some(ref tls_config) = self.tls_config {
                let acceptor = tokio_rustls::TlsAcceptor::from(tls_config.clone());
                let tls = match acceptor.accept(stream).await {
                    Ok(tls) => tls,
                    Err(_) => continue,
                };
                let mut h2 = match h2::server::handshake(tls).await {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                let (request, mut respond) = match h2.accept().await {
                    Some(Ok(pair)) => pair,
                    _ => continue,
                };
                // Keep driving the h2 connection in the background
                tokio::spawn(async move {
                    while let Some(_) = h2.accept().await {}
                });
                let response = http::Response::builder().status(200).body(()).unwrap();
                let send_stream = match respond.send_response(response, false) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let recv_stream = request.into_body();
                Box::pin(spawn_h2_bridge(recv_stream, send_stream))
            } else {
                let mut h2 = match h2::server::handshake(stream).await {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                let (request, mut respond) = match h2.accept().await {
                    Some(Ok(pair)) => pair,
                    _ => continue,
                };
                // Keep driving the h2 connection in the background
                tokio::spawn(async move {
                    while let Some(_) = h2.accept().await {}
                });
                let response = http::Response::builder().status(200).body(()).unwrap();
                let send_stream = match respond.send_response(response, false) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let recv_stream = request.into_body();
                Box::pin(spawn_h2_bridge(recv_stream, send_stream))
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
    fingerprints: Arc<Mutex<HashMap<String, String>>>,
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

                // Apply TLS, do H2 handshake, send request, and bridge streams
                let (conn, peer_fp): (PoolConn, Option<String>) = if self.tls_code != "0" {
                    let tls_config = tls::insecure_client_config();
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

                    // Extract peer certificate fingerprint before h2 handshake
                    let fp = {
                        let (_, session) = tls.get_ref();
                        session
                            .peer_certificates()
                            .and_then(|certs| certs.first())
                            .map(|cert| tls::format_cert_fingerprint(cert.as_ref()))
                    };

                    let (send_request, h2_conn) = match h2::client::handshake(tls).await {
                        Ok(c) => c,
                        Err(_) => {
                            tokio::time::sleep(current_interval).await;
                            continue;
                        }
                    };

                    // Drive h2 connection in background
                    tokio::spawn(async move {
                        if let Err(e) = h2_conn.await {
                            eprintln!("h2 connection error: {}", e);
                        }
                    });

                    // Wait for send readiness, then send HTTP request
                    let mut ready_request = match send_request.ready().await {
                        Ok(r) => r,
                        Err(_) => {
                            tokio::time::sleep(current_interval).await;
                            continue;
                        }
                    };
                    let request = http::Request::builder()
                        .method("POST")
                        .uri("http://localhost/")
                        .body(())
                        .unwrap();
                    let (response_future, send_stream) =
                        match ready_request.send_request(request, false) {
                            Ok(pair) => pair,
                            Err(_) => {
                                tokio::time::sleep(current_interval).await;
                                continue;
                            }
                        };

                    // Get response and extract recv stream
                    let response = match response_future.await {
                        Ok(r) => r,
                        Err(_) => {
                            tokio::time::sleep(current_interval).await;
                            continue;
                        }
                    };
                    let recv_stream = response.into_body();

                    // Bridge h2 streams through duplex
                    (Box::pin(spawn_h2_bridge(recv_stream, send_stream)) as PoolConn, fp)
                } else {
                    let (send_request, h2_conn) = match h2::client::handshake(stream).await {
                        Ok(c) => c,
                        Err(_) => {
                            tokio::time::sleep(current_interval).await;
                            continue;
                        }
                    };

                    // Drive h2 connection in background
                    tokio::spawn(async move {
                        if let Err(e) = h2_conn.await {
                            eprintln!("h2 connection error: {}", e);
                        }
                    });

                    // Wait for send readiness, then send HTTP request
                    let mut ready_request = match send_request.ready().await {
                        Ok(r) => r,
                        Err(_) => {
                            tokio::time::sleep(current_interval).await;
                            continue;
                        }
                    };
                    let request = http::Request::builder()
                        .method("POST")
                        .uri("http://localhost/")
                        .body(())
                        .unwrap();
                    let (response_future, send_stream) =
                        match ready_request.send_request(request, false) {
                            Ok(pair) => pair,
                            Err(_) => {
                                tokio::time::sleep(current_interval).await;
                                continue;
                            }
                        };

                    // Get response and extract recv stream
                    let response = match response_future.await {
                        Ok(r) => r,
                        Err(_) => {
                            tokio::time::sleep(current_interval).await;
                            continue;
                        }
                    };
                    let recv_stream = response.into_body();

                    // Bridge h2 streams through duplex
                    (Box::pin(spawn_h2_bridge(recv_stream, send_stream)) as PoolConn, None)
                };

                let id = format!("{:08x}", id_counter);
                id_counter += 1;

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
