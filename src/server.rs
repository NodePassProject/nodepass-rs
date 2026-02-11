use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use crate::common::Common;
use crate::config::*;
use crate::logger::Logger;
use crate::pool::tcp::TcpServerPool;
use crate::pool::TransportPool;
use crate::signal_protocol::Signal;
use crate::tls;
use crate::{log_debug, log_error, log_event, log_info};

pub struct Server {
    pub common: Common,
}

impl Server {
    pub fn new(
        parsed_url: url::Url,
        tls_code: String,
        tls_config: Option<Arc<rustls::ServerConfig>>,
        logger: Logger,
    ) -> anyhow::Result<Self> {
        let mut common = Common::new(parsed_url, logger);
        common.tls_code = tls_code;
        common.tls_config = tls_config;
        common.init_config()?;
        common.init_rate_limiter();
        Ok(Self { common })
    }

    pub async fn run(&mut self) {
        let log_info_str = format!(
            "server://{}@{}/{}?dns={:?}&lbs={}&max={}&mode={}&type={}&dial={}&read={:?}&rate={}&slot={}&proxy={}&block={}&notcp={}&noudp={}",
            self.common.tunnel_key,
            self.common.tunnel_tcp_addr.map(|a| a.to_string()).unwrap_or_default(),
            self.common.get_target_addrs_string(),
            self.common.dns_cache.ttl_display(),
            self.common.lb_strategy,
            self.common.max_pool_capacity,
            self.common.run_mode,
            self.common.pool_type,
            self.common.dialer_ip,
            self.common.read_timeout,
            self.common.rate_limit / 125000,
            self.common.slot_limit,
            self.common.proxy_protocol,
            self.common.block_protocol,
            self.common.disable_tcp,
            self.common.disable_udp,
        );
        log_info!(self.common.logger, "Server started: {}", log_info_str);

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        // Signal handling
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.ok();
            cancel_clone.cancel();
        });

        #[cfg(unix)]
        {
            let cancel_term = cancel.clone();
            tokio::spawn(async move {
                let mut sig = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
                sig.recv().await;
                cancel_term.cancel();
            });
        }

        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                result = self.start() => {
                    match result {
                        Ok(()) => {},
                        Err(e) => {
                            log_error!(self.common.logger, "Server error: {}", e);
                            self.common.stop();
                            tokio::select! {
                                _ = cancel.cancelled() => break,
                                _ = tokio::time::sleep(SERVICE_COOLDOWN()) => {},
                            }
                            log_info!(self.common.logger, "Server restart: {}", log_info_str);
                        }
                    }
                }
            }
        }

        self.common.stop();
        log_info!(self.common.logger, "Server shutdown complete");
    }

    async fn start(&mut self) -> anyhow::Result<()> {
        self.common.init_cancel();
        let _cancel = self.common.cancel.clone();

        // Init tunnel listener
        let tunnel_addr = self.common.tunnel_tcp_addr
            .ok_or_else(|| anyhow::anyhow!("start: nil tunnel address"))?;
        let tunnel_listener = TcpListener::bind(tunnel_addr).await
            .map_err(|e| anyhow::anyhow!("start: initTunnelListener failed: {}", e))?;

        // Determine run mode
        match self.common.run_mode.as_str() {
            "1" => {
                self.common.data_flow = "-".to_string();
            }
            "2" => {
                self.common.data_flow = "+".to_string();
            }
            _ => {
                // Auto-detect: try to bind target, if success = mode 1
                let target_addr = self.common.target_tcp_addrs.first().copied();
                if let Some(addr) = target_addr {
                    if TcpListener::bind(addr).await.is_ok() {
                        self.common.run_mode = "1".to_string();
                        self.common.data_flow = "-".to_string();
                    } else {
                        self.common.run_mode = "2".to_string();
                        self.common.data_flow = "+".to_string();
                    }
                } else {
                    self.common.run_mode = "2".to_string();
                    self.common.data_flow = "+".to_string();
                }
            }
        }

        log_info!(self.common.logger, "Pending tunnel handshake...");
        self.common.handshake_start = Instant::now();

        // Tunnel handshake - serve temp HTTPS to exchange config
        self.tunnel_handshake(tunnel_listener).await?;

        // Rebind tunnel listener after handshake
        let tunnel_listener = TcpListener::bind(tunnel_addr).await
            .map_err(|e| anyhow::anyhow!("start: rebind tunnel listener failed: {}", e))?;

        // Init tunnel pool
        self.init_tunnel_pool(tunnel_listener).await?;

        log_info!(self.common.logger, "Getting tunnel pool ready...");

        // Wait for pool to be ready and set control connection
        self.set_control_conn().await?;

        // Start data forwarding loops
        if self.common.data_flow == "-" {
            let _common_ref = &self.common;
            // commonLoop would start TCP/UDP accept loops on target
        }

        // Run common control loop (health check + signal dispatch)
        self.common_control().await
    }

    async fn tunnel_handshake(&mut self, listener: TcpListener) -> anyhow::Result<()> {
        let tls_config = self.common.tls_config.clone()
            .or_else(|| tls::new_tls_config().ok());
        let tls_config = tls_config.ok_or_else(|| anyhow::anyhow!("tunnelHandshake: no TLS config"))?;

        let data_flow = self.common.data_flow.clone();
        let max_pool = self.common.max_pool_capacity;
        let tls_code = self.common.tls_code.clone();
        let pool_type = self.common.pool_type.clone();
        let tunnel_key = self.common.tunnel_key.clone();
        let logger = self.common.logger.clone();
        let cancel = self.common.cancel.clone();

        let (_client_ip_tx, _client_ip_rx) = tokio::sync::oneshot::channel::<String>();
        let _sent = false;

        let acceptor = tokio_rustls::TlsAcceptor::from(tls_config.clone());

        // Accept one handshake connection
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    anyhow::bail!("tunnelHandshake: context canceled");
                }
                result = listener.accept() => {
                    let (stream, addr) = result?;

                    // TLS accept
                    let tls_stream = match acceptor.accept(stream).await {
                        Ok(s) => s,
                        Err(_) => continue,
                    };

                    // Simple HTTP/1.1 handling
                    let mut buf_reader = BufReader::new(tls_stream);
                    let mut request_line = String::new();
                    buf_reader.read_line(&mut request_line).await?;

                    // Read headers
                    let mut auth_header = String::new();
                    let mut headers = String::new();
                    loop {
                        let mut line = String::new();
                        buf_reader.read_line(&mut line).await?;
                        if line == "\r\n" || line.is_empty() {
                            break;
                        }
                        if line.to_lowercase().starts_with("authorization:") {
                            auth_header = line.trim().to_string();
                        }
                        headers.push_str(&line);
                    }

                    // Validate method and path
                    if !request_line.starts_with("GET / ") {
                        let response = "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n";
                        buf_reader.get_mut().write_all(response.as_bytes()).await.ok();
                        continue;
                    }

                    // Validate auth
                    let token = auth_header
                        .strip_prefix("Authorization: Bearer ")
                        .or_else(|| auth_header.strip_prefix("authorization: Bearer "))
                        .unwrap_or("");

                    if !crate::auth::verify_auth_token(token, &tunnel_key) {
                        let response = "HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n";
                        buf_reader.get_mut().write_all(response.as_bytes()).await.ok();
                        continue;
                    }

                    // Send config response
                    let body = serde_json::json!({
                        "flow": data_flow,
                        "max": max_pool,
                        "tls": tls_code,
                        "type": pool_type,
                    });
                    let body_str = serde_json::to_string(&body)?;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                        body_str.len(),
                        body_str
                    );
                    buf_reader.get_mut().write_all(response.as_bytes()).await.ok();

                    let client_ip = addr.ip().to_string();
                    log_info!(logger, "Sending tunnel config: FLOW={}|MAX={}|TLS={}|TYPE={}", data_flow, max_pool, tls_code, pool_type);

                    self.common.client_ip = client_ip;

                    // Regenerate TLS cert for tls_code 1
                    if self.common.tls_code == "1" {
                        if let Ok(new_config) = tls::new_tls_config() {
                            self.common.tls_config = Some(new_config);
                            log_info!(self.common.logger, "TLS code-1: RAM cert regenerated with TLS 1.3");
                        }
                    }

                    return Ok(());
                }
            }
        }
    }

    async fn init_tunnel_pool(&mut self, listener: TcpListener) -> anyhow::Result<()> {
        match self.common.pool_type.as_str() {
            "0" => {
                let pool = Arc::new(TcpServerPool::new(
                    self.common.max_pool_capacity,
                    self.common.client_ip.clone(),
                    self.common.tls_config.clone(),
                    listener,
                    REPORT_INTERVAL(),
                ));
                let pool_clone = pool.clone();
                tokio::spawn(async move {
                    pool_clone.server_manager().await;
                });
                self.common.tunnel_pool = Some(pool);
            }
            // Pool types 1, 2, 3 would use QUIC, WS, H2 respectively
            _ => {
                // Default to TCP pool
                let pool = Arc::new(TcpServerPool::new(
                    self.common.max_pool_capacity,
                    self.common.client_ip.clone(),
                    self.common.tls_config.clone(),
                    listener,
                    REPORT_INTERVAL(),
                ));
                let pool_clone = pool.clone();
                tokio::spawn(async move {
                    pool_clone.server_manager().await;
                });
                self.common.tunnel_pool = Some(pool);
            }
        }
        Ok(())
    }

    async fn set_control_conn(&mut self) -> anyhow::Result<()> {
        let pool = self.common.tunnel_pool.as_ref()
            .ok_or_else(|| anyhow::anyhow!("setControlConn: no pool"))?;

        let start = Instant::now();
        loop {
            if self.common.cancel.is_cancelled() {
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
            self.common.logger,
            "Marking tunnel handshake as complete in {}ms",
            self.common.handshake_start.elapsed().as_millis()
        );

        // Start writer task
        let mut write_rx = self.common.write_rx.take()
            .ok_or_else(|| anyhow::anyhow!("setControlConn: write_rx already taken"))?;
        let cancel = self.common.cancel.clone();

        // We need to split the control conn for reading and writing
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
        let signal_tx = self.common.signal_tx.clone();
        let tunnel_key = self.common.tunnel_key.clone();
        let logger = self.common.logger.clone();
        let cancel = self.common.cancel.clone();

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
                                match crate::signal_protocol::decode_signal(&line, tunnel_key.as_bytes()) {
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

        if self.common.tls_code == "1" {
            log_info!(self.common.logger, "TLS code-1: RAM cert fingerprint verifying...");
        }

        Ok(())
    }

    async fn common_control(&mut self) -> anyhow::Result<()> {
        let mut signal_rx = self.common.signal_rx.take()
            .ok_or_else(|| anyhow::anyhow!("commonControl: signal_rx already taken"))?;

        let cancel = self.common.cancel.clone();
        let logger = self.common.logger.clone();
        let pool = self.common.tunnel_pool.clone()
            .ok_or_else(|| anyhow::anyhow!("commonControl: no pool"))?;
        let write_tx = self.common.write_tx.clone();
        let tunnel_key = self.common.tunnel_key.clone();

        // Health check task
        let health_cancel = cancel.clone();
        let health_pool = pool.clone();
        let health_write_tx = write_tx.clone();
        let health_key = tunnel_key.clone();
        let _health_logger = logger.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(REPORT_INTERVAL());
            loop {
                tokio::select! {
                    _ = health_cancel.cancelled() => return,
                    _ = interval.tick() => {
                        // Check pool health
                        if health_pool.error_count() > health_pool.active() / 2 {
                            let signal = Signal::new("flush");
                            if let Ok(data) = serde_json::to_vec(&signal) {
                                let encoded = crate::signal_protocol::encode_signal(&data, health_key.as_bytes());
                                let _ = health_write_tx.send(encoded).await;
                            }
                            health_pool.flush().await;
                            health_pool.reset_error();
                        }

                        // Send ping
                        let signal = Signal::new("ping");
                        if let Ok(data) = serde_json::to_vec(&signal) {
                            let encoded = crate::signal_protocol::encode_signal(&data, health_key.as_bytes());
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
                            if self.common.disable_tcp != "1" {
                                let pool = pool.clone();
                                let _common_cancel = cancel.clone();
                                let logger = logger.clone();
                                let target_addrs = self.common.target_tcp_addrs.clone();
                                let tcp_rx = self.common.tcp_rx.clone();
                                let tcp_tx = self.common.tcp_tx.clone();
                                let rate_limiter = self.common.rate_limiter.clone();
                                let read_timeout = self.common.read_timeout;
                                let proxy_protocol = self.common.proxy_protocol.clone();
                                let _lb_strategy = self.common.lb_strategy.clone();
                                let _target_idx = self.common.target_idx.load(Ordering::SeqCst);
                                let _slot_limit = self.common.slot_limit;

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
                            if self.common.disable_udp != "1" {
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
                                let encoded = self.common.encode(&data);
                                let _ = write_tx.send(encoded).await;
                            }
                        }
                        "pong" => {
                            let pool_active = pool.active();
                            log_event!(
                                self.common.logger,
                                "CHECK_POINT|MODE={}|PING={}ms|POOL={}|TCPS={}|UDPS={}|TCPRX={}|TCPTX={}|UDPRX={}|UDPTX={}",
                                self.common.run_mode,
                                self.common.check_point.elapsed().as_millis(),
                                pool_active,
                                self.common.tcp_slot.load(Ordering::SeqCst),
                                self.common.udp_slot.load(Ordering::SeqCst),
                                self.common.tcp_rx.load(Ordering::SeqCst),
                                self.common.tcp_tx.load(Ordering::SeqCst),
                                self.common.udp_rx.load(Ordering::SeqCst),
                                self.common.udp_tx.load(Ordering::SeqCst),
                            );
                            self.common.check_point = Instant::now();
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

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::net::TcpStream;

pub async fn handle_tcp_once(
    signal: Signal,
    pool: Arc<dyn TransportPool>,
    logger: Logger,
    target_addrs: Vec<SocketAddr>,
    _tcp_rx: Arc<AtomicU64>,
    _tcp_tx: Arc<AtomicU64>,
    _rate_limiter: Option<Arc<crate::conn::RateLimiter>>,
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
