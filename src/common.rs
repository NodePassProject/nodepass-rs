use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use dashmap::DashMap;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::auth;
use crate::config::*;
use crate::conn::RateLimiter;
use crate::dns_cache::DnsCache;
use crate::logger::Logger;
use crate::pool::TransportPool;
use crate::signal_protocol::{self, Signal};
use crate::log_error;

pub struct Common {
    pub parsed_url: url::Url,
    pub logger: Logger,
    pub dns_cache: DnsCache,
    pub tls_code: String,
    pub tls_config: Option<Arc<rustls::ServerConfig>>,
    pub core_type: String,
    pub run_mode: String,
    pub pool_type: String,
    pub data_flow: String,
    pub server_name: String,
    pub server_port: String,
    pub client_ip: String,
    pub dialer_ip: String,
    pub dialer_fallback: AtomicU32,
    pub tunnel_key: String,
    pub tunnel_addr: String,
    pub tunnel_tcp_addr: Option<SocketAddr>,
    pub tunnel_udp_addr: Option<SocketAddr>,
    pub target_addrs: Vec<String>,
    pub target_tcp_addrs: Vec<SocketAddr>,
    pub target_udp_addrs: Vec<SocketAddr>,
    pub target_idx: AtomicU64,
    pub last_fallback: AtomicU64,
    pub best_latency: AtomicI32,
    pub lb_strategy: String,
    pub min_pool_capacity: usize,
    pub max_pool_capacity: usize,
    pub proxy_protocol: String,
    pub block_protocol: String,
    pub block_socks: bool,
    pub block_http: bool,
    pub block_tls: bool,
    pub disable_tcp: String,
    pub disable_udp: String,
    pub rate_limit: usize,
    pub rate_limiter: Option<Arc<RateLimiter>>,
    pub read_timeout: Duration,
    pub slot_limit: i32,
    pub tcp_slot: AtomicI32,
    pub udp_slot: AtomicI32,
    pub tcp_rx: Arc<AtomicU64>,
    pub tcp_tx: Arc<AtomicU64>,
    pub udp_rx: Arc<AtomicU64>,
    pub udp_tx: Arc<AtomicU64>,
    pub tunnel_pool: Option<Arc<dyn TransportPool>>,
    pub signal_tx: mpsc::Sender<Signal>,
    pub signal_rx: Option<mpsc::Receiver<Signal>>,
    pub write_tx: mpsc::Sender<Vec<u8>>,
    pub write_rx: Option<mpsc::Receiver<Vec<u8>>>,
    pub verify_tx: mpsc::Sender<()>,
    pub verify_rx: Option<mpsc::Receiver<()>>,
    pub handshake_start: Instant,
    pub check_point: Instant,
    pub cancel: CancellationToken,
    pub target_udp_sessions: Arc<DashMap<String, Arc<tokio::sync::Mutex<UdpSocket>>>>,
}

impl Common {
    pub fn new(parsed_url: url::Url, logger: Logger) -> Self {
        let (signal_tx, signal_rx) = mpsc::channel(SEMAPHORE_LIMIT());
        let (write_tx, write_rx) = mpsc::channel(SEMAPHORE_LIMIT());
        let (verify_tx, verify_rx) = mpsc::channel(1);

        Self {
            parsed_url,
            logger,
            dns_cache: DnsCache::new(DEFAULT_DNS_TTL),
            tls_code: "0".to_string(),
            tls_config: None,
            core_type: String::new(),
            run_mode: String::new(),
            pool_type: String::new(),
            data_flow: String::new(),
            server_name: String::new(),
            server_port: String::new(),
            client_ip: String::new(),
            dialer_ip: DEFAULT_DIALER_IP.to_string(),
            dialer_fallback: AtomicU32::new(0),
            tunnel_key: String::new(),
            tunnel_addr: String::new(),
            tunnel_tcp_addr: None,
            tunnel_udp_addr: None,
            target_addrs: Vec::new(),
            target_tcp_addrs: Vec::new(),
            target_udp_addrs: Vec::new(),
            target_idx: AtomicU64::new(0),
            last_fallback: AtomicU64::new(0),
            best_latency: AtomicI32::new(0),
            lb_strategy: DEFAULT_LB_STRATEGY.to_string(),
            min_pool_capacity: DEFAULT_MIN_POOL,
            max_pool_capacity: DEFAULT_MAX_POOL,
            proxy_protocol: DEFAULT_PROXY_PROTOCOL.to_string(),
            block_protocol: DEFAULT_BLOCK_PROTOCOL.to_string(),
            block_socks: false,
            block_http: false,
            block_tls: false,
            disable_tcp: DEFAULT_TCP_STRATEGY.to_string(),
            disable_udp: DEFAULT_UDP_STRATEGY.to_string(),
            rate_limit: DEFAULT_RATE_LIMIT,
            rate_limiter: None,
            read_timeout: DEFAULT_READ_TIMEOUT,
            slot_limit: DEFAULT_SLOT_LIMIT,
            tcp_slot: AtomicI32::new(0),
            udp_slot: AtomicI32::new(0),
            tcp_rx: Arc::new(AtomicU64::new(0)),
            tcp_tx: Arc::new(AtomicU64::new(0)),
            udp_rx: Arc::new(AtomicU64::new(0)),
            udp_tx: Arc::new(AtomicU64::new(0)),
            tunnel_pool: None,
            signal_tx,
            signal_rx: Some(signal_rx),
            write_tx,
            write_rx: Some(write_rx),
            verify_tx,
            verify_rx: Some(verify_rx),
            handshake_start: Instant::now(),
            check_point: Instant::now(),
            cancel: CancellationToken::new(),
            target_udp_sessions: Arc::new(DashMap::new()),
        }
    }

    pub fn init_config(&mut self) -> anyhow::Result<()> {
        self.get_address()?;
        self.core_type = self.parsed_url.scheme().to_string();
        self.get_dns_ttl();
        self.get_tunnel_key();
        self.get_pool_capacity();
        self.get_server_name();
        self.get_lb_strategy();
        self.get_run_mode();
        self.get_pool_type();
        self.get_dialer_ip();
        self.get_read_timeout();
        self.get_rate_limit();
        self.get_slot_limit();
        self.get_proxy_protocol();
        self.get_block_protocol();
        self.get_tcp_strategy();
        self.get_udp_strategy();
        Ok(())
    }

    fn get_address(&mut self) -> anyhow::Result<()> {
        let tunnel_addr = self.parsed_url.host_str()
            .ok_or_else(|| anyhow::anyhow!("getAddress: no valid tunnel address found"))?;
        let port = self.parsed_url.port()
            .ok_or_else(|| anyhow::anyhow!("getAddress: no valid port found"))?;

        self.tunnel_addr = format!("{}:{}", tunnel_addr, port);
        self.server_name = tunnel_addr.to_string();
        self.server_port = port.to_string();

        // Resolve tunnel address (synchronous for init)
        let tunnel_addr_str = self.tunnel_addr.clone();
        let tcp_addr: SocketAddr = std::net::ToSocketAddrs::to_socket_addrs(&tunnel_addr_str)
            .map_err(|e| anyhow::anyhow!("getAddress: resolveTCPAddr failed: {}", e))?
            .next()
            .ok_or_else(|| anyhow::anyhow!("getAddress: no addresses found"))?;

        self.tunnel_tcp_addr = Some(tcp_addr);
        self.tunnel_udp_addr = Some(tcp_addr);

        // Parse target addresses from path
        let path = self.parsed_url.path().trim_start_matches('/');
        if path.is_empty() {
            anyhow::bail!("getAddress: no valid target address found");
        }

        let addr_list: Vec<&str> = path.split(',').collect();
        let mut temp_tcp = Vec::new();
        let mut temp_udp = Vec::new();
        let mut temp_raw = Vec::new();

        for addr in addr_list {
            let addr = addr.trim();
            if addr.is_empty() {
                continue;
            }

            // Handle empty host like ":1002" → "0.0.0.0:1002"
            let addr = if addr.starts_with(':') {
                format!("0.0.0.0{}", addr)
            } else {
                addr.to_string()
            };
            let addr = addr.as_str();

            let resolved: SocketAddr = std::net::ToSocketAddrs::to_socket_addrs(addr)
                .map_err(|e| anyhow::anyhow!("getAddress: resolve failed for {}: {}", addr, e))?
                .next()
                .ok_or_else(|| anyhow::anyhow!("getAddress: no addresses found for {}", addr))?;

            temp_tcp.push(resolved);
            temp_udp.push(resolved);
            temp_raw.push(addr.to_string());
        }

        if temp_tcp.is_empty() {
            anyhow::bail!("getAddress: no valid target address found");
        }

        // Check port conflict
        let tunnel_port = tcp_addr.port();
        for target_addr in &temp_tcp {
            if target_addr.port() == tunnel_port
                && (target_addr.ip().is_loopback() || tcp_addr.ip().is_unspecified())
            {
                anyhow::bail!(
                    "getAddress: tunnel port {} conflicts with target address {}",
                    tunnel_port,
                    target_addr
                );
            }
        }

        self.target_addrs = temp_raw;
        self.target_tcp_addrs = temp_tcp;
        self.target_udp_addrs = temp_udp;
        self.target_idx.store(0, Ordering::SeqCst);

        Ok(())
    }

    fn get_tunnel_key(&mut self) {
        if let Some(password) = self.parsed_url.password() {
            self.tunnel_key = password.to_string();
        } else if let Ok(username) = urlencoding::decode(self.parsed_url.username()) {
            if !username.is_empty() {
                self.tunnel_key = username.to_string();
            } else {
                self.tunnel_key = self.generate_fnv_key();
            }
        } else {
            self.tunnel_key = self.generate_fnv_key();
        }
    }

    fn generate_fnv_key(&self) -> String {
        let mut hasher = DefaultHasher::new();
        self.server_port.hash(&mut hasher);
        let hash = hasher.finish() as u32;
        hex::encode(hash.to_be_bytes())
    }

    fn get_dns_ttl(&mut self) {
        if let Some(dns) = self.get_query("dns") {
            if let Some(ttl) = crate::config::parse_go_duration_pub(&dns) {
                if !ttl.is_zero() {
                    self.dns_cache = DnsCache::new(ttl);
                    return;
                }
            }
        }
        self.dns_cache = DnsCache::new(DEFAULT_DNS_TTL);
    }

    fn get_server_name(&mut self) {
        if let Some(sni) = self.get_query("sni") {
            if !sni.is_empty() {
                self.server_name = sni;
                return;
            }
        }
        if self.server_name.is_empty() || self.server_name.parse::<std::net::IpAddr>().is_ok() {
            self.server_name = DEFAULT_SERVER_NAME.to_string();
        }
    }

    fn get_lb_strategy(&mut self) {
        self.lb_strategy = self.get_query("lbs").unwrap_or_else(|| DEFAULT_LB_STRATEGY.to_string());
    }

    fn get_pool_capacity(&mut self) {
        if let Some(min) = self.get_query("min") {
            if let Ok(v) = min.parse::<usize>() {
                if v > 0 { self.min_pool_capacity = v; }
            }
        }
        if let Some(max) = self.get_query("max") {
            if let Ok(v) = max.parse::<usize>() {
                if v > 0 { self.max_pool_capacity = v; }
            }
        }
    }

    fn get_run_mode(&mut self) {
        self.run_mode = self.get_query("mode").unwrap_or_else(|| DEFAULT_RUN_MODE.to_string());
    }

    fn get_pool_type(&mut self) {
        self.pool_type = self.get_query("type").unwrap_or_else(|| DEFAULT_POOL_TYPE.to_string());
        if self.pool_type == "1" && self.tls_code == "0" {
            self.tls_code = "1".to_string();
        }
    }

    fn get_dialer_ip(&mut self) {
        if let Some(dial) = self.get_query("dial") {
            if dial != "auto" && !dial.is_empty() {
                if dial.parse::<std::net::IpAddr>().is_ok() {
                    self.dialer_ip = dial;
                    return;
                } else {
                    log_error!(self.logger, "getDialerIP: fallback to system auto due to invalid IP address: {}", dial);
                }
            }
        }
        self.dialer_ip = DEFAULT_DIALER_IP.to_string();
    }

    fn get_read_timeout(&mut self) {
        if let Some(timeout) = self.get_query("read") {
            if let Some(v) = crate::config::parse_go_duration_pub(&timeout) {
                if !v.is_zero() {
                    self.read_timeout = v;
                    return;
                }
            }
        }
        self.read_timeout = DEFAULT_READ_TIMEOUT;
    }

    fn get_rate_limit(&mut self) {
        if let Some(limit) = self.get_query("rate") {
            if let Ok(v) = limit.parse::<usize>() {
                if v > 0 {
                    self.rate_limit = v * 125000; // Mbps to bytes/sec
                    return;
                }
            }
        }
        self.rate_limit = DEFAULT_RATE_LIMIT;
    }

    fn get_slot_limit(&mut self) {
        if let Some(slot) = self.get_query("slot") {
            if let Ok(v) = slot.parse::<i32>() {
                if v > 0 {
                    self.slot_limit = v;
                    return;
                }
            }
        }
        self.slot_limit = DEFAULT_SLOT_LIMIT;
    }

    fn get_proxy_protocol(&mut self) {
        self.proxy_protocol = self.get_query("proxy").unwrap_or_else(|| DEFAULT_PROXY_PROTOCOL.to_string());
    }

    fn get_block_protocol(&mut self) {
        self.block_protocol = self.get_query("block").unwrap_or_else(|| DEFAULT_BLOCK_PROTOCOL.to_string());
        self.block_socks = self.block_protocol.contains('1');
        self.block_http = self.block_protocol.contains('2');
        self.block_tls = self.block_protocol.contains('3');
    }

    fn get_tcp_strategy(&mut self) {
        self.disable_tcp = self.get_query("notcp").unwrap_or_else(|| DEFAULT_TCP_STRATEGY.to_string());
    }

    fn get_udp_strategy(&mut self) {
        self.disable_udp = self.get_query("noudp").unwrap_or_else(|| DEFAULT_UDP_STRATEGY.to_string());
    }

    fn get_query(&self, key: &str) -> Option<String> {
        self.parsed_url.query_pairs()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.to_string())
    }

    pub fn init_rate_limiter(&mut self) {
        if self.rate_limit > 0 {
            self.rate_limiter = Some(Arc::new(RateLimiter::new(
                self.rate_limit as u64,
                self.rate_limit as u64,
            )));
        }
    }

    pub fn init_cancel(&mut self) {
        self.cancel = CancellationToken::new();

        // Recreate channels for the new start() cycle
        // Previous .take() calls leave these as None, so they must be rebuilt
        let (signal_tx, signal_rx) = mpsc::channel(SEMAPHORE_LIMIT());
        self.signal_tx = signal_tx;
        self.signal_rx = Some(signal_rx);

        let (write_tx, write_rx) = mpsc::channel(SEMAPHORE_LIMIT());
        self.write_tx = write_tx;
        self.write_rx = Some(write_rx);

        let (verify_tx, verify_rx) = mpsc::channel(1);
        self.verify_tx = verify_tx;
        self.verify_rx = Some(verify_rx);
    }

    pub fn generate_auth_token(&self) -> String {
        auth::generate_auth_token(&self.tunnel_key)
    }

    pub fn verify_auth_token(&self, token: &str) -> bool {
        auth::verify_auth_token(token, &self.tunnel_key)
    }

    pub fn encode(&self, data: &[u8]) -> Vec<u8> {
        signal_protocol::encode_signal(data, self.tunnel_key.as_bytes())
    }

    pub fn decode(&self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        signal_protocol::decode_signal(data, self.tunnel_key.as_bytes())
    }

    pub fn get_target_addrs_string(&self) -> String {
        self.target_tcp_addrs
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(",")
    }

    pub fn next_target_idx(&self) -> usize {
        if self.target_tcp_addrs.len() <= 1 {
            return 0;
        }
        (self.target_idx.fetch_add(1, Ordering::SeqCst) as usize) % self.target_tcp_addrs.len()
    }

    pub fn try_acquire_slot(&self, is_udp: bool) -> bool {
        if self.slot_limit == 0 {
            return true;
        }
        let current_total = self.tcp_slot.load(Ordering::SeqCst) + self.udp_slot.load(Ordering::SeqCst);
        if current_total >= self.slot_limit {
            return false;
        }
        if is_udp {
            self.udp_slot.fetch_add(1, Ordering::SeqCst);
        } else {
            self.tcp_slot.fetch_add(1, Ordering::SeqCst);
        }
        true
    }

    pub fn release_slot(&self, is_udp: bool) {
        if self.slot_limit == 0 {
            return;
        }
        if is_udp {
            let current = self.udp_slot.load(Ordering::SeqCst);
            if current > 0 {
                self.udp_slot.fetch_sub(1, Ordering::SeqCst);
            }
        } else {
            let current = self.tcp_slot.load(Ordering::SeqCst);
            if current > 0 {
                self.tcp_slot.fetch_sub(1, Ordering::SeqCst);
            }
        }
    }

    pub async fn dial_with_rotation(&self, is_tcp: bool) -> anyhow::Result<TcpStream> {
        let timeout = if is_tcp { TCP_DIAL_TIMEOUT() } else { UDP_DIAL_TIMEOUT() };
        let addr_count = self.target_addrs.len();

        if addr_count == 0 {
            anyhow::bail!("dialWithRotation: no target addresses");
        }

        let get_addr = |idx: usize| -> SocketAddr {
            self.target_tcp_addrs[idx]
        };

        if addr_count == 1 {
            let addr = get_addr(0);
            return tokio::time::timeout(timeout, TcpStream::connect(addr))
                .await
                .map_err(|_| anyhow::anyhow!("dialWithRotation: timeout"))?
                .map_err(|e| anyhow::anyhow!("dialWithRotation: connect failed: {}", e));
        }

        let start_idx = match self.lb_strategy.as_str() {
            "1" => (self.target_idx.load(Ordering::SeqCst) as usize) % addr_count,
            "2" => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u64;
                let last = self.last_fallback.load(Ordering::SeqCst);
                if now.saturating_sub(last) > FALLBACK_INTERVAL().as_nanos() as u64 {
                    self.last_fallback.store(now, Ordering::SeqCst);
                    self.target_idx.store(0, Ordering::SeqCst);
                }
                (self.target_idx.load(Ordering::SeqCst) as usize) % addr_count
            }
            _ => self.next_target_idx(),
        };

        let mut last_err = None;
        for i in 0..addr_count {
            let target_idx = (start_idx + i) % addr_count;
            let addr = get_addr(target_idx);

            match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => {
                    if i > 0 && (self.lb_strategy == "1" || self.lb_strategy == "2") {
                        self.target_idx.store(target_idx as u64, Ordering::SeqCst);
                    }
                    return Ok(stream);
                }
                Ok(Err(e)) => last_err = Some(e.to_string()),
                Err(_) => last_err = Some("timeout".to_string()),
            }
        }

        anyhow::bail!(
            "dialWithRotation: all {} targets failed: {}",
            addr_count,
            last_err.unwrap_or_default()
        )
    }

    pub async fn probe_best_target(&self) -> i32 {
        let count = self.target_tcp_addrs.len();
        if count == 0 {
            return 0;
        }

        let mut handles = Vec::new();
        for i in 0..count {
            let addr = self.target_tcp_addrs[i];
            handles.push(tokio::spawn(async move {
                let start = Instant::now();
                match tokio::time::timeout(
                    REPORT_INTERVAL(),
                    TcpStream::connect(addr),
                )
                .await
                {
                    Ok(Ok(stream)) => {
                        drop(stream);
                        (i, start.elapsed().as_millis() as i32)
                    }
                    _ => (i, 0),
                }
            }));
        }

        let mut best_idx = 0;
        let mut best_lat = 0;
        for handle in handles {
            if let Ok((idx, lat)) = handle.await {
                if lat > 0 && (best_lat == 0 || lat < best_lat) {
                    best_idx = idx;
                    best_lat = lat;
                }
            }
        }

        if best_lat > 0 {
            self.target_idx.store(best_idx as u64, Ordering::SeqCst);
            self.best_latency.store(best_lat, Ordering::SeqCst);
        }

        best_lat
    }

    pub fn stop(&mut self) {
        self.cancel.cancel();

        if let Some(ref pool) = self.tunnel_pool {
            let pool = pool.clone();
            tokio::spawn(async move {
                pool.close().await;
            });
        }
        self.tunnel_pool = None;

        self.target_udp_sessions.clear();

        if let Some(ref limiter) = self.rate_limiter {
            limiter.reset();
        }

        self.dns_cache.clear();
    }
}

