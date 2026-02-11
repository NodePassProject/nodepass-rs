use std::net::SocketAddr;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use dashmap::DashMap;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::config::*;
use crate::conn::{PoolConn, RateLimiter};
use crate::dns_cache::DnsCache;
use crate::logger::Logger;
use crate::pool::tcp::TcpServerPool;
use crate::pool::TransportPool;
use crate::signal_protocol::{self, Signal};
use crate::tls;
use crate::{log_debug, log_error, log_event, log_info};

/// Immutable server configuration shared across all client sessions via Arc.
pub struct ServerConfig {
    pub logger: Logger,
    pub dns_cache: DnsCache,
    pub tls_code: String,
    pub tls_config: Arc<RwLock<Option<Arc<rustls::ServerConfig>>>>,
    pub run_mode: String,
    pub pool_type: String,
    pub data_flow: String,
    pub tunnel_key: String,
    pub tunnel_tcp_addr: Option<SocketAddr>,
    pub target_tcp_addrs: Vec<SocketAddr>,
    pub target_udp_addrs: Vec<SocketAddr>,
    pub lb_strategy: String,
    pub max_pool_capacity: usize,
    pub proxy_protocol: String,
    pub block_protocol: String,
    pub disable_tcp: String,
    pub disable_udp: String,
    pub rate_limiter: Option<Arc<RateLimiter>>,
    pub read_timeout: Duration,
    pub slot_limit: i32,
    pub dialer_ip: String,
    pub server_name: String,
    pub rate_limit: usize,
}

impl ServerConfig {
    pub fn encode(&self, data: &[u8]) -> Vec<u8> {
        signal_protocol::encode_signal(data, self.tunnel_key.as_bytes())
    }
}

/// Handle for a running client session, stored in the sessions map.
pub struct SessionHandle {
    pub cancel: CancellationToken,
    pub pool_conn_tx: mpsc::Sender<PoolConn>,
    pub client_ip: String,
}

/// Per-client session state, spawned as an independent task.
struct ClientSession {
    config: Arc<ServerConfig>,
    client_ip: String,
    cancel: CancellationToken,
    signal_tx: mpsc::Sender<Signal>,
    signal_rx: Option<mpsc::Receiver<Signal>>,
    write_tx: mpsc::Sender<Vec<u8>>,
    write_rx: Option<mpsc::Receiver<Vec<u8>>>,
    tunnel_pool: Arc<dyn TransportPool>,
    tcp_rx: Arc<AtomicU64>,
    tcp_tx: Arc<AtomicU64>,
    udp_rx: Arc<AtomicU64>,
    udp_tx: Arc<AtomicU64>,
    tcp_slot: AtomicI32,
    udp_slot: AtomicI32,
    check_point: Instant,
    handshake_start: Instant,
}

impl ClientSession {
    fn new(
        config: Arc<ServerConfig>,
        client_ip: String,
        pool: Arc<dyn TransportPool>,
        handshake_start: Instant,
    ) -> Self {
        let (signal_tx, signal_rx) = mpsc::channel(SEMAPHORE_LIMIT());
        let (write_tx, write_rx) = mpsc::channel(SEMAPHORE_LIMIT());

        Self {
            config,
            client_ip,
            cancel: CancellationToken::new(),
            signal_tx,
            signal_rx: Some(signal_rx),
            write_tx,
            write_rx: Some(write_rx),
            tunnel_pool: pool,
            tcp_rx: Arc::new(AtomicU64::new(0)),
            tcp_tx: Arc::new(AtomicU64::new(0)),
            udp_rx: Arc::new(AtomicU64::new(0)),
            udp_tx: Arc::new(AtomicU64::new(0)),
            tcp_slot: AtomicI32::new(0),
            udp_slot: AtomicI32::new(0),
            check_point: Instant::now(),
            handshake_start,
        }
    }

    async fn run(&mut self) -> anyhow::Result<()> {
        self.set_control_conn().await?;
        self.common_control().await
    }

    async fn set_control_conn(&mut self) -> anyhow::Result<()> {
        let pool = &self.tunnel_pool;

        let start = Instant::now();
        loop {
            if self.cancel.is_cancelled() {
                anyhow::bail!("setControlConn: context error");
            }
            if pool.ready() && pool.active() > 0 {
                break;
            }
            if start.elapsed() > HANDSHAKE_TIMEOUT() {
                anyhow::bail!("setControlConn: handshake timeout");
            }
            tokio::time::sleep(CONTEXT_CHECK_INTERVAL).await;
        }

        // Get control connection (ID "00000000")
        let control_conn = pool.outgoing_get("00000000", POOL_GET_TIMEOUT()).await?;

        log_info!(
            self.config.logger,
            "[{}] Marking tunnel handshake as complete in {}ms",
            self.client_ip,
            self.handshake_start.elapsed().as_millis()
        );

        // Start writer task
        let mut write_rx = self.write_rx.take()
            .ok_or_else(|| anyhow::anyhow!("setControlConn: write_rx already taken"))?;
        let cancel = self.cancel.clone();

        let (reader, writer) = tokio::io::split(control_conn);
        let writer = Arc::new(tokio::sync::Mutex::new(writer));
        let writer_clone = writer.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    data = write_rx.recv() => {
                        match data {
                            Some(data) => {
                                let mut w = writer_clone.lock().await;
                                if let Err(e) = w.write_all(&data).await {
                                    eprintln!("startWriter: write failed: {}", e);
                                    return;
                                }
                            }
                            None => return,
                        }
                    }
                }
            }
        });

        // Start reader task - reads signals from control connection
        let signal_tx = self.signal_tx.clone();
        let tunnel_key = self.config.tunnel_key.clone();
        let logger = self.config.logger.clone();
        let cancel = self.cancel.clone();

        tokio::spawn(async move {
            let mut buf_reader = BufReader::new(reader);
            loop {
                let mut line = Vec::new();
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    result = buf_reader.read_until(b'\n', &mut line) => {
                        match result {
                            Ok(0) | Err(_) => return,
                            Ok(_) => {
                                match signal_protocol::decode_signal(&line, tunnel_key.as_bytes()) {
                                    Ok(data) => {
                                        match serde_json::from_slice::<Signal>(&data) {
                                            Ok(signal) => {
                                                let _ = signal_tx.send(signal).await;
                                            }
                                            Err(e) => {
                                                log_error!(logger, "commonQueue: unmarshal signal failed: {}", e);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        log_error!(logger, "commonQueue: decode signal failed: {}", e);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        if self.config.tls_code == "1" {
            log_info!(self.config.logger, "[{}] TLS code-1: RAM cert fingerprint verifying...", self.client_ip);
        }

        Ok(())
    }

    async fn common_control(&mut self) -> anyhow::Result<()> {
        let mut signal_rx = self.signal_rx.take()
            .ok_or_else(|| anyhow::anyhow!("commonControl: signal_rx already taken"))?;

        let cancel = self.cancel.clone();
        let logger = self.config.logger.clone();
        let pool = self.tunnel_pool.clone();
        let write_tx = self.write_tx.clone();
        let tunnel_key = self.config.tunnel_key.clone();

        // Health check task
        let health_cancel = cancel.clone();
        let health_pool = pool.clone();
        let health_write_tx = write_tx.clone();
        let health_key = tunnel_key.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(REPORT_INTERVAL());
            loop {
                tokio::select! {
                    _ = health_cancel.cancelled() => return,
                    _ = interval.tick() => {
                        if health_pool.error_count() > health_pool.active() / 2 {
                            let signal = Signal::new("flush");
                            if let Ok(data) = serde_json::to_vec(&signal) {
                                let encoded = signal_protocol::encode_signal(&data, health_key.as_bytes());
                                let _ = health_write_tx.send(encoded).await;
                            }
                            health_pool.flush().await;
                            health_pool.reset_error();
                        }

                        let signal = Signal::new("ping");
                        if let Ok(data) = serde_json::to_vec(&signal) {
                            let encoded = signal_protocol::encode_signal(&data, health_key.as_bytes());
                            let _ = health_write_tx.send(encoded).await;
                        }
                    }
                }
            }
        });

        // Signal dispatch loop
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    anyhow::bail!("commonControl: context error");
                }
                signal = signal_rx.recv() => {
                    let signal = signal.ok_or_else(|| anyhow::anyhow!("commonControl: signal channel closed"))?;
                    match signal.action.as_str() {
                        "tcp" => {
                            if self.config.disable_tcp != "1" {
                                let pool = pool.clone();
                                let logger = logger.clone();
                                let target_addrs = self.config.target_tcp_addrs.clone();
                                let tcp_rx = self.tcp_rx.clone();
                                let tcp_tx = self.tcp_tx.clone();
                                let rate_limiter = self.config.rate_limiter.clone();
                                let read_timeout = self.config.read_timeout;
                                let proxy_protocol = self.config.proxy_protocol.clone();

                                tokio::spawn(async move {
                                    if let Err(_e) = handle_tcp_once(
                                        signal, pool, logger, target_addrs, tcp_rx, tcp_tx,
                                        rate_limiter, read_timeout, proxy_protocol,
                                    ).await {
                                        // Error already logged inside
                                    }
                                });
                            }
                        }
                        "udp" => {
                            if self.config.disable_udp != "1" {
                                // Handle UDP signal
                            }
                        }
                        "flush" => {
                            let pool = pool.clone();
                            tokio::spawn(async move {
                                pool.flush().await;
                                pool.reset_error();
                            });
                        }
                        "ping" => {
                            let signal = Signal::new("pong");
                            if let Ok(data) = serde_json::to_vec(&signal) {
                                let encoded = self.config.encode(&data);
                                let _ = write_tx.send(encoded).await;
                            }
                        }
                        "pong" => {
                            let pool_active = pool.active();
                            log_event!(
                                self.config.logger,
                                "[{}] CHECK_POINT|MODE={}|PING={}ms|POOL={}|TCPS={}|UDPS={}|TCPRX={}|TCPTX={}|UDPRX={}|UDPTX={}",
                                self.client_ip,
                                self.config.run_mode,
                                self.check_point.elapsed().as_millis(),
                                pool_active,
                                self.tcp_slot.load(Ordering::SeqCst),
                                self.udp_slot.load(Ordering::SeqCst),
                                self.tcp_rx.load(Ordering::SeqCst),
                                self.tcp_tx.load(Ordering::SeqCst),
                                self.udp_rx.load(Ordering::SeqCst),
                                self.udp_tx.load(Ordering::SeqCst),
                            );
                            self.check_point = Instant::now();
                        }
                        "verify" => {
                            // TLS verification handling
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

pub struct Server {
    pub config: Arc<ServerConfig>,
    pub sessions: Arc<DashMap<String, SessionHandle>>,
}

impl Server {
    pub fn new(
        parsed_url: url::Url,
        tls_code: String,
        tls_config: Option<Arc<rustls::ServerConfig>>,
        logger: Logger,
    ) -> anyhow::Result<Self> {
        // Build ServerConfig by reusing Common's init_config logic
        use crate::common::Common;
        let mut common = Common::new(parsed_url, logger.clone());
        common.tls_code = tls_code.clone();
        common.tls_config = tls_config.clone();
        common.init_config()?;
        common.init_rate_limiter();

        // Determine data_flow based on run_mode
        let (run_mode, data_flow) = match common.run_mode.as_str() {
            "1" => (common.run_mode.clone(), "-".to_string()),
            "2" => (common.run_mode.clone(), "+".to_string()),
            _ => {
                // Auto-detect will be done later, default to mode "0" / empty for now
                (common.run_mode.clone(), String::new())
            }
        };

        let config = Arc::new(ServerConfig {
            logger: common.logger.clone(),
            dns_cache: common.dns_cache,
            tls_code: common.tls_code.clone(),
            tls_config: Arc::new(RwLock::new(tls_config)),
            run_mode,
            pool_type: common.pool_type.clone(),
            data_flow,
            tunnel_key: common.tunnel_key.clone(),
            tunnel_tcp_addr: common.tunnel_tcp_addr,
            target_tcp_addrs: common.target_tcp_addrs.clone(),
            target_udp_addrs: common.target_udp_addrs.clone(),
            lb_strategy: common.lb_strategy.clone(),
            max_pool_capacity: common.max_pool_capacity,
            proxy_protocol: common.proxy_protocol.clone(),
            block_protocol: common.block_protocol.clone(),
            disable_tcp: common.disable_tcp.clone(),
            disable_udp: common.disable_udp.clone(),
            rate_limiter: common.rate_limiter.clone(),
            read_timeout: common.read_timeout,
            slot_limit: common.slot_limit,
            dialer_ip: common.dialer_ip.clone(),
            server_name: common.server_name.clone(),
            rate_limit: common.rate_limit,
        });

        Ok(Self {
            config,
            sessions: Arc::new(DashMap::new()),
        })
    }

    pub async fn run(&self) {
        let config = &self.config;

        let target_addrs_str = config.target_tcp_addrs
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(",");

        let log_info_str = format!(
            "server://{}@{}/{}?dns={:?}&lbs={}&max={}&mode={}&type={}&dial={}&read={:?}&rate={}&slot={}&proxy={}&block={}&notcp={}&noudp={}",
            config.tunnel_key,
            config.tunnel_tcp_addr.map(|a| a.to_string()).unwrap_or_default(),
            target_addrs_str,
            config.dns_cache.ttl_display(),
            config.lb_strategy,
            config.max_pool_capacity,
            config.run_mode,
            config.pool_type,
            config.dialer_ip,
            config.read_timeout,
            config.rate_limit / 125000,
            config.slot_limit,
            config.proxy_protocol,
            config.block_protocol,
            config.disable_tcp,
            config.disable_udp,
        );
        log_info!(config.logger, "Server started: {}", log_info_str);

        let server_cancel = CancellationToken::new();
        let cancel_clone = server_cancel.clone();

        // Signal handling
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.ok();
            cancel_clone.cancel();
        });

        #[cfg(unix)]
        {
            let cancel_term = server_cancel.clone();
            tokio::spawn(async move {
                let mut sig = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
                sig.recv().await;
                cancel_term.cancel();
            });
        }

        // Bind the persistent listener
        let tunnel_addr = match config.tunnel_tcp_addr {
            Some(addr) => addr,
            None => {
                log_error!(config.logger, "Server error: nil tunnel address");
                return;
            }
        };

        let listener = match TcpListener::bind(tunnel_addr).await {
            Ok(l) => l,
            Err(e) => {
                log_error!(config.logger, "Server error: bind failed: {}", e);
                return;
            }
        };

        log_info!(config.logger, "Listening for tunnel connections on {}", tunnel_addr);

        // Resolve TLS config for the accept loop
        let tls_config_guard = config.tls_config.read().await;
        let initial_tls_config = tls_config_guard.clone()
            .or_else(|| tls::new_tls_config().ok());
        drop(tls_config_guard);

        let tls_acceptor = initial_tls_config.map(TlsAcceptor::from);

        // Session cleanup task
        let cleanup_sessions = self.sessions.clone();
        let cleanup_cancel = server_cancel.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(REPORT_INTERVAL());
            loop {
                tokio::select! {
                    _ = cleanup_cancel.cancelled() => return,
                    _ = interval.tick() => {
                        let mut to_remove = Vec::new();
                        for entry in cleanup_sessions.iter() {
                            if entry.value().cancel.is_cancelled() {
                                to_remove.push(entry.key().clone());
                            }
                        }
                        for key in to_remove {
                            cleanup_sessions.remove(&key);
                        }
                    }
                }
            }
        });

        // Central accept loop
        loop {
            tokio::select! {
                _ = server_cancel.cancelled() => break,
                result = listener.accept() => {
                    let (stream, addr) = match result {
                        Ok(v) => v,
                        Err(e) => {
                            log_error!(config.logger, "Accept error: {}", e);
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            continue;
                        }
                    };

                    let config = self.config.clone();
                    let sessions = self.sessions.clone();
                    let tls_acceptor = tls_acceptor.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_incoming(config, sessions, tls_acceptor, stream, addr).await {
                            // Connection-level error, not fatal
                            let _ = e;
                        }
                    });
                }
            }
        }

        // Shutdown: cancel all sessions
        for entry in self.sessions.iter() {
            entry.value().cancel.cancel();
        }
        self.sessions.clear();
        log_info!(config.logger, "Server shutdown complete");
    }
}

/// Handle a single incoming TCP connection: TLS accept, classify, route.
async fn handle_incoming(
    config: Arc<ServerConfig>,
    sessions: Arc<DashMap<String, SessionHandle>>,
    tls_acceptor: Option<TlsAcceptor>,
    stream: TcpStream,
    addr: SocketAddr,
) -> anyhow::Result<()> {
    // If TLS is configured, do TLS accept
    if let Some(acceptor) = tls_acceptor {
        let tls_stream = acceptor.accept(stream).await
            .map_err(|e| anyhow::anyhow!("TLS accept failed: {}", e))?;

        // Peek first bytes to classify: handshake (GET) vs pool connection
        let mut buf_reader = BufReader::new(tls_stream);
        let buf = buf_reader.fill_buf().await
            .map_err(|e| anyhow::anyhow!("peek failed: {}", e))?;

        if buf.len() >= 4 && &buf[..4] == b"GET " {
            // This is a handshake request
            handle_handshake(config, sessions, buf_reader, addr).await?;
        } else {
            // This is a pool connection - route to existing session
            let conn: PoolConn = Box::pin(buf_reader.into_inner());
            route_pool_connection(sessions, conn, addr).await;
        }
    } else {
        // No TLS - same classification logic on raw stream
        let mut buf_reader = BufReader::new(stream);
        let buf = buf_reader.fill_buf().await
            .map_err(|e| anyhow::anyhow!("peek failed: {}", e))?;

        if buf.len() >= 4 && &buf[..4] == b"GET " {
            handle_handshake(config, sessions, buf_reader, addr).await?;
        } else {
            let conn: PoolConn = Box::pin(buf_reader.into_inner());
            route_pool_connection(sessions, conn, addr).await;
        }
    }

    Ok(())
}

/// Handle a handshake request: validate auth, send config, create session.
async fn handle_handshake<R: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>(
    config: Arc<ServerConfig>,
    sessions: Arc<DashMap<String, SessionHandle>>,
    mut buf_reader: BufReader<R>,
    addr: SocketAddr,
) -> anyhow::Result<()> {
    let handshake_start = Instant::now();

    // Read request line (already peeked "GET ")
    let mut request_line = String::new();
    buf_reader.read_line(&mut request_line).await?;

    // Read headers
    let mut auth_header = String::new();
    loop {
        let mut line = String::new();
        buf_reader.read_line(&mut line).await?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if line.to_lowercase().starts_with("authorization:") {
            auth_header = line.trim().to_string();
        }
    }

    // Validate method and path
    if !request_line.starts_with("GET / ") {
        let response = "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n";
        buf_reader.get_mut().write_all(response.as_bytes()).await.ok();
        anyhow::bail!("handshake: invalid request path");
    }

    // Validate auth
    let token = auth_header
        .strip_prefix("Authorization: Bearer ")
        .or_else(|| auth_header.strip_prefix("authorization: Bearer "))
        .unwrap_or("");

    if !crate::auth::verify_auth_token(token, &config.tunnel_key) {
        let response = "HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n";
        buf_reader.get_mut().write_all(response.as_bytes()).await.ok();
        anyhow::bail!("handshake: unauthorized");
    }

    let client_ip = addr.ip().to_string();

    // Determine data_flow for this session
    let data_flow = if !config.data_flow.is_empty() {
        config.data_flow.clone()
    } else {
        // Auto-detect: try to bind target, if success = mode 1 (-)
        let target_addr = config.target_tcp_addrs.first().copied();
        if let Some(addr) = target_addr {
            if TcpListener::bind(addr).await.is_ok() {
                "-".to_string()
            } else {
                "+".to_string()
            }
        } else {
            "+".to_string()
        }
    };

    // Send config response
    let body = serde_json::json!({
        "flow": data_flow,
        "max": config.max_pool_capacity,
        "tls": config.tls_code,
        "type": config.pool_type,
    });
    let body_str = serde_json::to_string(&body)?;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
        body_str.len(),
        body_str
    );
    buf_reader.get_mut().write_all(response.as_bytes()).await.ok();

    log_info!(
        config.logger,
        "[{}] Sending tunnel config: FLOW={}|MAX={}|TLS={}|TYPE={}",
        client_ip, data_flow, config.max_pool_capacity, config.tls_code, config.pool_type
    );

    // Regenerate TLS cert for tls_code 1
    if config.tls_code == "1" {
        if let Ok(new_config) = tls::new_tls_config() {
            let mut tls_guard = config.tls_config.write().await;
            *tls_guard = Some(new_config);
            log_info!(config.logger, "[{}] TLS code-1: RAM cert regenerated with TLS 1.3", client_ip);
        }
    }

    // Remove any existing session for this client IP (client reconnected)
    if let Some((_, old_handle)) = sessions.remove(&client_ip) {
        old_handle.cancel.cancel();
        log_info!(config.logger, "[{}] Previous session replaced", client_ip);
    }

    // Create channel-fed pool for this session
    let (pool_conn_tx, pool_conn_rx) = mpsc::channel::<PoolConn>(config.max_pool_capacity);
    let pool = Arc::new(TcpServerPool::new_channel_fed(
        config.max_pool_capacity,
        pool_conn_rx,
        REPORT_INTERVAL(),
    ));
    let pool_clone = pool.clone();
    tokio::spawn(async move {
        pool_clone.channel_fed_manager().await;
    });

    // Create session
    let mut session = ClientSession::new(
        config.clone(),
        client_ip.clone(),
        pool,
        handshake_start,
    );

    // Register session handle
    let session_cancel = session.cancel.clone();
    sessions.insert(client_ip.clone(), SessionHandle {
        cancel: session_cancel.clone(),
        pool_conn_tx,
        client_ip: client_ip.clone(),
    });

    // Spawn session task
    let sessions_cleanup = sessions.clone();
    let logger = config.logger.clone();
    let ip = client_ip.clone();
    tokio::spawn(async move {
        log_info!(logger, "[{}] Session started", ip);
        match session.run().await {
            Ok(()) => {}
            Err(e) => {
                log_error!(logger, "[{}] Session error: {}", ip, e);
            }
        }
        session.cancel.cancel();
        // Close the pool
        session.tunnel_pool.close().await;
        sessions_cleanup.remove(&ip);
        log_info!(logger, "[{}] Session ended", ip);
    });

    Ok(())
}

/// Route a pool connection to the matching client session by IP.
async fn route_pool_connection(
    sessions: Arc<DashMap<String, SessionHandle>>,
    conn: PoolConn,
    addr: SocketAddr,
) {
    let peer_ip = addr.ip().to_string();

    if let Some(entry) = sessions.get(&peer_ip) {
        let _ = entry.value().pool_conn_tx.send(conn).await;
    }
    // No matching session → connection is dropped
}

pub async fn handle_tcp_once(
    signal: Signal,
    pool: Arc<dyn TransportPool>,
    logger: Logger,
    target_addrs: Vec<SocketAddr>,
    _tcp_rx: Arc<AtomicU64>,
    _tcp_tx: Arc<AtomicU64>,
    _rate_limiter: Option<Arc<RateLimiter>>,
    read_timeout: Duration,
    proxy_protocol: String,
) -> anyhow::Result<()> {
    use crate::conn::exchange::data_exchange;

    let id = signal.id.clone();
    log_debug!(logger, "TCP launch signal: cid {} <- control", id);

    let remote_conn = match pool.outgoing_get(&id, POOL_GET_TIMEOUT()).await {
        Ok(conn) => conn,
        Err(e) => {
            log_error!(logger, "commonTCPOnce: request timeout: {}", e);
            pool.add_error();
            return Ok(());
        }
    };

    log_debug!(logger, "Tunnel connection: get {} <- pool active {}", id, pool.active());

    // Dial target
    let target_addr = target_addrs.first()
        .ok_or_else(|| anyhow::anyhow!("no target addresses"))?;

    let target_conn = match tokio::time::timeout(
        TCP_DIAL_TIMEOUT(),
        TcpStream::connect(target_addr),
    ).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            log_error!(logger, "commonTCPOnce: dialWithRotation failed: {}", e);
            return Ok(());
        }
        Err(_) => {
            log_error!(logger, "commonTCPOnce: dial timeout");
            return Ok(());
        }
    };

    // Send PROXY v1 header if needed
    if proxy_protocol == "1" && !signal.remote.is_empty() {
        if let Ok(_remote_addr) = target_conn.peer_addr() {
            let _target_writer = &target_conn;
            // proxy::send_proxy_v1_header would go here
        }
    }

    // Data exchange
    let buf_size = TCP_DATA_BUF_SIZE();
    let mut buf1 = vec![0u8; buf_size];
    let mut buf2 = vec![0u8; buf_size];

    log_info!(logger, "Starting exchange: tunnel <-> target");
    let result = data_exchange(remote_conn, target_conn, read_timeout, &mut buf1, &mut buf2).await;
    log_info!(logger, "Exchange complete: {}", result);

    Ok(())
}
