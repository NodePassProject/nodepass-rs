use dashmap::DashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::lookup_host;

struct CacheEntry {
    tcp_addr: SocketAddr,
    udp_addr: SocketAddr,
    expires_at: Instant,
}

pub struct DnsCache {
    entries: DashMap<String, CacheEntry>,
    ttl: Duration,
}

impl DnsCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: DashMap::new(),
            ttl,
        }
    }

    pub async fn resolve_tcp(&self, address: &str) -> anyhow::Result<SocketAddr> {
        self.resolve(address, true).await
    }

    pub async fn resolve_udp(&self, address: &str) -> anyhow::Result<SocketAddr> {
        self.resolve(address, false).await
    }

    async fn resolve(&self, address: &str, _is_tcp: bool) -> anyhow::Result<SocketAddr> {
        let now = Instant::now();

        // Check cache
        if let Some(entry) = self.entries.get(address) {
            if now < entry.expires_at {
                return Ok(entry.tcp_addr);
            }
            drop(entry);
            self.entries.remove(address);
        }

        // Resolve
        let addr = lookup_host(address)
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("resolve: no addresses found for {}", address))?;

        let entry = CacheEntry {
            tcp_addr: addr,
            udp_addr: addr,
            expires_at: now + self.ttl,
        };
        self.entries.insert(address.to_string(), entry);

        Ok(addr)
    }

    pub fn clear(&self) {
        self.entries.clear();
    }

    pub fn set_ttl(&mut self, ttl: Duration) {
        self.ttl = ttl;
    }

    pub fn ttl_display(&self) -> String {
        format!("{:?}", self.ttl)
    }
}

/// Resolve an address, using DNS cache only for hostnames (not raw IPs)
pub async fn resolve_addr(
    cache: &DnsCache,
    address: &str,
) -> anyhow::Result<SocketAddr> {
    // Split host and port
    let (host, _port) = split_host_port(address)?;

    // If it's an IP address (not a hostname), resolve directly without cache
    if host.is_empty() || host.parse::<std::net::IpAddr>().is_ok() {
        let addr = tokio::net::lookup_host(address)
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("resolve: no addresses found for {}", address))?;
        return Ok(addr);
    }

    cache.resolve_tcp(address).await
}

fn split_host_port(address: &str) -> anyhow::Result<(String, String)> {
    // Handle [IPv6]:port format
    if let Some(bracket_end) = address.find(']') {
        let host = address[1..bracket_end].to_string();
        let port = if address.len() > bracket_end + 2 {
            address[bracket_end + 2..].to_string()
        } else {
            String::new()
        };
        return Ok((host, port));
    }

    // Handle host:port format
    if let Some(colon_pos) = address.rfind(':') {
        let host = address[..colon_pos].to_string();
        let port = address[colon_pos + 1..].to_string();
        Ok((host, port))
    } else {
        anyhow::bail!("invalid address {}: missing port", address)
    }
}
