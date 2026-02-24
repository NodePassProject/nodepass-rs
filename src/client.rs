use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use crate::common::Common;
use crate::config::*;
use crate::conn::exchange::data_exchange;
use crate::logger::Logger;
use crate::pool::tcp::TcpClientPool;
use crate::pool::quic::QuicClientPool;
use crate::pool::websocket::WsClientPool;
use crate::pool::http2::H2ClientPool;
use crate::signal_protocol::Signal;
use crate::{log_debug, log_error, log_event, log_info, log_warn};

pub struct Client {
    pub common: Common,
}

impl Client {
    pub fn new(parsed_url: url::Url, logger: Logger) -> anyhow::Result<Self> {
        let mut common = Common::new(parsed_url, logger);
        common.init_config()?;
        common.init_rate_limiter();
        Ok(Self { common })
    }

    pub async fn run(&mut self) {
        let log_info_str = format!(
            "client://{}@{}/{}?dns={:?}&sni={}&lbs={}&min={}&mode={}&dial={}&read={:?}&rate={}&slot={}&proxy={}&block={}&notcp={}&noudp={}",
            self.common.tunnel_key,
            self.common.tunnel_tcp_addr.map(|a| a.to_string()).unwrap_or_default(),
            self.common.get_target_addrs_string(),
            self.common.dns_cache.ttl_display(),
            self.common.server_name,
            self.common.lb_strategy,
            self.common.min_pool_capacity,
            self.common.run_mode,
            self.common.dialer_ip,
            self.common.read_timeout,
            self.common.rate_limit / 125000,
            self.common.slot_limit,
            self.common.proxy_protocol,
            self.common.block_protocol,
            self.common.disable_tcp,
            self.common.disable_udp,
        );
        log_info!(self.common.logger, "Client started: {}", log_info_str);

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

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
                            log_error!(self.common.logger, "Client error: {}", e);
                            self.common.stop();
                            tokio::select! {
                                _ = cancel.cancelled() => break,
                                _ = tokio::time::sleep(SERVICE_COOLDOWN()) => {},
                            }
                            log_info!(self.common.logger, "Client restart: {}", log_info_str);
                        }
                    }
                }
            }
        }

        self.common.stop();
        log_info!(self.common.logger, "Client shutdown complete");
    }

    async fn start(&mut self) -> anyhow::Result<()> {
        self.common.init_cancel();

        match self.common.run_mode.as_str() {
            "1" => {
                // Single mode - direct TCP/UDP forwarding without tunnel pool
                self.single_start().await
            }
            "2" => {
                // Common mode - use tunnel pool
                self.common_start().await
            }
            _ => {
                // Auto-detect
                let tunnel_addr = self.common.tunnel_tcp_addr
                    .ok_or_else(|| anyhow::anyhow!("start: nil tunnel address"))?;
                if TcpListener::bind(tunnel_addr).await.is_ok() {
                    self.common.run_mode = "1".to_string();
                    self.single_start().await
                } else {
                    self.common.run_mode = "2".to_string();
                    self.common_start().await
                }
            }
        }
    }

    async fn single_start(&mut self) -> anyhow::Result<()> {
        // Single mode: listen on tunnel address, forward directly to targets
        let tunnel_addr = self.common.tunnel_tcp_addr
            .ok_or_else(|| anyhow::anyhow!("singleStart: nil tunnel address"))?;

        let listener = TcpListener::bind(tunnel_addr).await
            .map_err(|e| anyhow::anyhow!("singleStart: bind failed: {}", e))?;

        let cancel = self.common.cancel.clone();
        let logger = self.common.logger.clone();
        let target_addrs = self.common.target_tcp_addrs.clone();
        let tcp_rx = self.common.tcp_rx.clone();
        let tcp_tx = self.common.tcp_tx.clone();
        let rate_limiter = self.common.rate_limiter.clone();
        let read_timeout = self.common.read_timeout;
        let run_mode = self.common.run_mode.clone();

        // Event loop for checkpoint reporting
        let event_cancel = cancel.clone();
        let event_logger = logger.clone();
        let _event_target_addrs = target_addrs.clone();
        let tcp_rx_clone = tcp_rx.clone();
        let tcp_tx_clone = tcp_tx.clone();
        let udp_rx = self.common.udp_rx.clone();
        let udp_tx = self.common.udp_tx.clone();
        let _tcp_slot = &self.common.tcp_slot;
        let _udp_slot = &self.common.udp_slot;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(REPORT_INTERVAL());
            loop {
                tokio::select! {
                    _ = event_cancel.cancelled() => return,
                    _ = interval.tick() => {
                        // Probe best target
                        log_event!(event_logger,
                            "CHECK_POINT|MODE={}|PING=0ms|POOL=0|TCPS=0|UDPS=0|TCPRX={}|TCPTX={}|UDPRX={}|UDPTX={}",
                            run_mode,
                            tcp_rx_clone.load(Ordering::SeqCst),
                            tcp_tx_clone.load(Ordering::SeqCst),
                            udp_rx.load(Ordering::SeqCst),
                            udp_tx.load(Ordering::SeqCst),
                        );
                    }
                }
            }
        });

        // TCP accept loop
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    anyhow::bail!("singleTCPLoop: context error");
                }
                result = listener.accept() => {
                    let (tunnel_conn, addr) = result
                        .map_err(|e| anyhow::anyhow!("singleTCPLoop: accept failed: {}", e))?;

                    log_debug!(logger, "Tunnel connection: local <-> {}", addr);

                    let logger = logger.clone();
                    let target_addrs = target_addrs.clone();
                    let _tcp_rx = tcp_rx.clone();
                    let _tcp_tx = tcp_tx.clone();
                    let _rate_limiter = rate_limiter.clone();
                    let read_timeout = read_timeout;

                    let dialer_ip = self.common.dialer_ip.clone();
                    let dialer_fallback = self.common.dialer_fallback.clone();
                    let proxy_protocol = self.common.proxy_protocol.clone();
                    let block_socks = self.common.block_socks;
                    let block_http = self.common.block_http;
                    let block_tls = self.common.block_tls;

                    tokio::spawn(async move {
                        // Protocol blocking check
                        if block_socks || block_http || block_tls {
                            let mut peek_buf = [0u8; 8];
                            match tunnel_conn.peek(&mut peek_buf).await {
                                Ok(n) if n > 0 => {
                                    if let Some(protocol) = crate::block::detect_block_protocol(
                                        &peek_buf[..n], block_socks, block_http, block_tls,
                                    ) {
                                        log_warn!(logger, "singleTCPLoop: blocked {} protocol from {}", protocol, addr);
                                        return;
                                    }
                                }
                                _ => {}
                            }
                        }

                        // Dial target
                        let target_addr = match target_addrs.first() {
                            Some(a) => *a,
                            None => return,
                        };

                        let mut target_conn = match tokio::time::timeout(
                            TCP_DIAL_TIMEOUT(),
                            crate::common::connect_tcp_bound(target_addr, &dialer_ip, &dialer_fallback, &logger),
                        ).await {
                            Ok(Ok(s)) => s,
                            Ok(Err(e)) => {
                                log_error!(logger, "singleTCPLoop: dial failed: {}", e);
                                return;
                            }
                            Err(_) => {
                                log_error!(logger, "singleTCPLoop: dial timeout");
                                return;
                            }
                        };

                        // Send PROXY v1 header if needed
                        if proxy_protocol == "1" {
                            if let Ok(remote_addr) = target_conn.peer_addr() {
                                if let Err(e) = crate::proxy::send_proxy_v1_header(
                                    &addr.to_string(),
                                    remote_addr,
                                    &mut target_conn,
                                ).await {
                                    log_error!(logger, "singleTCPLoop: sendProxyV1Header failed: {}", e);
                                    return;
                                }
                            }
                        }

                        let buf_size = TCP_DATA_BUF_SIZE();
                        let mut buf1 = vec![0u8; buf_size];
                        let mut buf2 = vec![0u8; buf_size];

                        log_info!(logger, "Starting exchange: {} <-> {}", addr, target_addr);
                        let result = data_exchange(tunnel_conn, target_conn, read_timeout, &mut buf1, &mut buf2).await;
                        log_info!(logger, "Exchange complete: {}", result);
                    });
                }
            }
        }
    }

    async fn common_start(&mut self) -> anyhow::Result<()> {
        log_info!(self.common.logger, "Pending tunnel handshake...");
        self.common.handshake_start = Instant::now();
        self.tunnel_handshake().await?;

        self.init_tunnel_pool().await?;

        log_info!(self.common.logger, "Getting tunnel pool ready...");
        self.set_control_conn().await?;

        // If data flow is "+", client accepts connections and forwards through tunnel
        if self.common.data_flow == "+" {
            // Start target listener and forward loop
        }

        self.common_control().await
    }

    async fn tunnel_handshake(&mut self) -> anyhow::Result<()> {
        let url = format!("https://{}/", self.common.tunnel_addr);
        let token = self.common.generate_auth_token();

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()?;

        let resp = client
            .get(&url)
            .header("Host", &self.common.server_name)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("tunnelHandshake: {}", e))?;

        if resp.status() != reqwest::StatusCode::OK {
            anyhow::bail!("tunnelHandshake: status {}", resp.status());
        }

        #[derive(serde::Deserialize)]
        struct TunnelConfig {
            flow: String,
            max: usize,
            tls: String,
            #[serde(rename = "type")]
            pool_type: String,
        }

        let config: TunnelConfig = resp.json().await
            .map_err(|e| anyhow::anyhow!("tunnelHandshake: {}", e))?;

        self.common.data_flow = config.flow;
        self.common.max_pool_capacity = config.max;
        self.common.tls_code = config.tls;
        self.common.pool_type = config.pool_type;

        log_info!(
            self.common.logger,
            "Loading tunnel config: FLOW={}|MAX={}|TLS={}|TYPE={}",
            self.common.data_flow,
            self.common.max_pool_capacity,
            self.common.tls_code,
            self.common.pool_type,
        );

        Ok(())
    }

    async fn init_tunnel_pool(&mut self) -> anyhow::Result<()> {
        let tunnel_addr = self.common.tunnel_addr.clone();
        let tls_code = self.common.tls_code.clone();
        let server_name = self.common.server_name.clone();

        match self.common.pool_type.as_str() {
            "1" => {
                // QUIC
                let tunnel_addr_clone = tunnel_addr.clone();
                let pool = Arc::new(QuicClientPool::new(
                    self.common.min_pool_capacity,
                    self.common.max_pool_capacity,
                    MIN_POOL_INTERVAL(),
                    MAX_POOL_INTERVAL(),
                    REPORT_INTERVAL(),
                    tls_code,
                    server_name,
                    move || {
                        let addr = tunnel_addr_clone.clone();
                        async move { Ok(addr) }
                    },
                ));
                let pool_clone = pool.clone();
                tokio::spawn(async move {
                    pool_clone.client_manager().await;
                });
                self.common.tunnel_pool = Some(pool);
            }
            "2" => {
                // WebSocket
                let pool = Arc::new(WsClientPool::new(
                    self.common.min_pool_capacity,
                    self.common.max_pool_capacity,
                    MIN_POOL_INTERVAL(),
                    MAX_POOL_INTERVAL(),
                    REPORT_INTERVAL(),
                    tls_code,
                    tunnel_addr,
                ));
                let pool_clone = pool.clone();
                tokio::spawn(async move {
                    pool_clone.client_manager().await;
                });
                self.common.tunnel_pool = Some(pool);
            }
            "3" => {
                // HTTP/2
                let tunnel_addr_clone = tunnel_addr.clone();
                let pool = Arc::new(H2ClientPool::new(
                    self.common.min_pool_capacity,
                    self.common.max_pool_capacity,
                    MIN_POOL_INTERVAL(),
                    MAX_POOL_INTERVAL(),
                    REPORT_INTERVAL(),
                    tls_code,
                    server_name,
                    move || {
                        let addr = tunnel_addr_clone.clone();
                        async move { Ok(addr) }
                    },
                ));
                let pool_clone = pool.clone();
                tokio::spawn(async move {
                    pool_clone.client_manager().await;
                });
                self.common.tunnel_pool = Some(pool);
            }
            _ => {
                // Default: TCP
                let pool = Arc::new(TcpClientPool::new(
                    self.common.min_pool_capacity,
                    self.common.max_pool_capacity,
                    MIN_POOL_INTERVAL(),
                    MAX_POOL_INTERVAL(),
                    REPORT_INTERVAL(),
                    tls_code,
                    server_name,
                    move || {
                        let addr = tunnel_addr.clone();
                        async move {
                            TcpStream::connect(&addr).await
                                .map_err(|e| anyhow::anyhow!("{}", e))
                        }
                    },
                ));
                let pool_clone = pool.clone();
                tokio::spawn(async move {
                    pool_clone.client_manager().await;
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

        let control_conn = pool.outgoing_get("00000000", POOL_GET_TIMEOUT()).await?;

        log_info!(
            self.common.logger,
            "Marking tunnel handshake as complete in {}ms",
            self.common.handshake_start.elapsed().as_millis()
        );

        let (reader, writer) = tokio::io::split(control_conn);
        let writer = Arc::new(tokio::sync::Mutex::new(writer));

        // Writer task
        let mut write_rx = self.common.write_rx.take()
            .ok_or_else(|| anyhow::anyhow!("setControlConn: write_rx already taken"))?;
        let cancel = self.common.cancel.clone();
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

        // Reader task
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

        // Incoming verify task - client sends peer cert fingerprint to server
        if self.common.tls_code == "1" {
            let verify_cancel = cancel.clone();
            let verify_pool = pool.clone();
            let verify_write_tx = write_tx.clone();
            let verify_key = self.common.tunnel_key.clone();
            let verify_logger = logger.clone();

            tokio::spawn(async move {
                // Wait one report interval before verifying (matches Go behavior)
                tokio::select! {
                    _ = verify_cancel.cancelled() => return,
                    _ = tokio::time::sleep(REPORT_INTERVAL()) => {},
                }

                // Wait for pool to be ready with connections
                loop {
                    if verify_cancel.is_cancelled() { return; }
                    if verify_pool.ready() && verify_pool.active() > 0 { break; }
                    tokio::time::sleep(CONTEXT_CHECK_INTERVAL).await;
                }

                // Get a test connection from the pool
                let (id, test_conn) = match verify_pool.incoming_get(POOL_GET_TIMEOUT()).await {
                    Ok(v) => v,
                    Err(e) => {
                        log_error!(verify_logger, "incomingVerify: incomingGet failed: {}", e);
                        verify_cancel.cancel();
                        return;
                    }
                };

                // Get peer cert fingerprint from pool (stored during TLS handshake)
                let fingerprint = verify_pool.fingerprint_for(&id).unwrap_or_default();

                drop(test_conn); // Close the test connection

                // Send verify signal to server
                let signal = Signal::verify(&id, &fingerprint);
                if let Ok(data) = serde_json::to_vec(&signal) {
                    let encoded = crate::signal_protocol::encode_signal(&data, verify_key.as_bytes());
                    let _ = verify_write_tx.send(encoded).await;
                }

                log_debug!(verify_logger, "TLS code-1: verify signal: cid {} -> control", id);
            });
        }

        // Health check
        let health_cancel = cancel.clone();
        let health_pool = pool.clone();
        let health_write_tx = write_tx.clone();
        let health_key = self.common.tunnel_key.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(REPORT_INTERVAL());
            loop {
                tokio::select! {
                    _ = health_cancel.cancelled() => return,
                    _ = interval.tick() => {
                        if health_pool.error_count() > health_pool.active() / 2 {
                            let signal = Signal::new("flush");
                            if let Ok(data) = serde_json::to_vec(&signal) {
                                let encoded = crate::signal_protocol::encode_signal(&data, health_key.as_bytes());
                                let _ = health_write_tx.send(encoded).await;
                            }
                            health_pool.flush().await;
                            health_pool.reset_error();
                        }

                        let signal = Signal::new("ping");
                        if let Ok(data) = serde_json::to_vec(&signal) {
                            let encoded = crate::signal_protocol::encode_signal(&data, health_key.as_bytes());
                            let _ = health_write_tx.send(encoded).await;
                        }
                    }
                }
            }
        });

        // Wait for TLS verification before starting data loops (if tls_code == "1")
        if self.common.tls_code == "1" {
            let mut verify_rx = self.common.verify_rx.take();
            if let Some(ref mut rx) = verify_rx {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        anyhow::bail!("commonControl: context error during verify wait");
                    }
                    _ = rx.recv() => {
                        // Verification complete
                    }
                }
            }
        }

        // Signal dispatch
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
                                let logger = logger.clone();
                                let target_addrs = self.common.target_tcp_addrs.clone();
                                let tcp_rx = self.common.tcp_rx.clone();
                                let tcp_tx = self.common.tcp_tx.clone();
                                let rate_limiter = self.common.rate_limiter.clone();
                                let read_timeout = self.common.read_timeout;
                                let proxy_protocol = self.common.proxy_protocol.clone();
                                let dialer_ip = self.common.dialer_ip.clone();
                                let dialer_fallback = self.common.dialer_fallback.clone();
                                let block_socks = self.common.block_socks;
                                let block_http = self.common.block_http;
                                let block_tls = self.common.block_tls;

                                tokio::spawn(async move {
                                    crate::server::handle_tcp_once(
                                        signal, pool, logger, target_addrs, tcp_rx, tcp_tx,
                                        rate_limiter, read_timeout, proxy_protocol,
                                        dialer_ip, dialer_fallback,
                                        block_socks, block_http, block_tls,
                                    ).await.ok();
                                });
                            }
                        }
                        "udp" => {
                            // Handle UDP
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
                            log_event!(
                                self.common.logger,
                                "CHECK_POINT|MODE={}|PING={}ms|POOL={}|TCPS={}|UDPS={}|TCPRX={}|TCPTX={}|UDPRX={}|UDPTX={}",
                                self.common.run_mode,
                                self.common.check_point.elapsed().as_millis(),
                                pool.active(),
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
                            if self.common.tls_code == "1" {
                                let pool = pool.clone();
                                let logger = logger.clone();
                                let cancel = cancel.clone();
                                let verify_tx = self.common.verify_tx.clone();

                                tokio::spawn(async move {
                                    // Wait for pool ready
                                    loop {
                                        if cancel.is_cancelled() { return; }
                                        if pool.ready() { break; }
                                        tokio::time::sleep(CONTEXT_CHECK_INTERVAL).await;
                                    }

                                    let server_fingerprint = signal.fp.clone();
                                    if server_fingerprint.is_empty() {
                                        log_error!(logger, "outgoingVerify: no fingerprint in signal");
                                        cancel.cancel();
                                        return;
                                    }

                                    let id = signal.id.clone();
                                    log_debug!(logger, "TLS verify signal: cid {} <- control", id);

                                    // Get the peer cert fingerprint stored during TLS handshake
                                    let client_fingerprint = pool.fingerprint_for(&id).unwrap_or_default();

                                    // Get the test connection (consume it)
                                    let test_conn = match pool.outgoing_get(&id, POOL_GET_TIMEOUT()).await {
                                        Ok(conn) => conn,
                                        Err(e) => {
                                            log_error!(logger, "outgoingVerify: request timeout: {}", e);
                                            cancel.cancel();
                                            return;
                                        }
                                    };
                                    drop(test_conn);

                                    if client_fingerprint.is_empty() {
                                        log_error!(logger, "outgoingVerify: no peer certificates found");
                                        cancel.cancel();
                                        return;
                                    }

                                    if server_fingerprint != client_fingerprint {
                                        log_error!(logger, "outgoingVerify: certificate fingerprint mismatch: server: {} - client: {}", server_fingerprint, client_fingerprint);
                                        cancel.cancel();
                                        return;
                                    }

                                    log_info!(logger, "TLS code-1: RAM cert fingerprint verified: {}", server_fingerprint);
                                    let _ = verify_tx.send(()).await;
                                });
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}
