use std::env;
use std::time::Duration;

pub fn get_env_as_int(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default)
}

pub fn get_env_as_duration(name: &str, default: Duration) -> Duration {
    env::var(name)
        .ok()
        .and_then(|v| parse_go_duration(&v))
        .unwrap_or(default)
}

/// Parse Go-style duration strings like "5s", "100ms", "5m", "1h"
pub fn parse_go_duration_pub(s: &str) -> Option<Duration> {
    parse_go_duration(s)
}

fn parse_go_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    let mut total = Duration::ZERO;
    let mut remaining = s;

    while !remaining.is_empty() {
        // Find the numeric part
        let num_end = remaining
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(remaining.len());
        if num_end == 0 {
            return None;
        }
        let num: f64 = remaining[..num_end].parse().ok()?;
        remaining = &remaining[num_end..];

        // Find the unit part
        let unit_end = remaining
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(remaining.len());
        let unit = &remaining[..unit_end];
        remaining = &remaining[unit_end..];

        let dur = match unit {
            "ns" => Duration::from_nanos(num as u64),
            "us" | "µs" => Duration::from_micros(num as u64),
            "ms" => Duration::from_millis(num as u64),
            "s" => Duration::from_secs_f64(num),
            "m" => Duration::from_secs_f64(num * 60.0),
            "h" => Duration::from_secs_f64(num * 3600.0),
            _ => return None,
        };
        total += dur;
    }

    if total.is_zero() && s != "0s" && s != "0" {
        // Allow "0s" or "0" but not other zero-duration strings
    }

    Some(total)
}

lazy_static_config! {
    pub SEMAPHORE_LIMIT: usize = get_env_as_int("NP_SEMAPHORE_LIMIT", 65536);
    pub TCP_DATA_BUF_SIZE: usize = get_env_as_int("NP_TCP_DATA_BUF_SIZE", 16384);
    pub UDP_DATA_BUF_SIZE: usize = get_env_as_int("NP_UDP_DATA_BUF_SIZE", 16384);
    pub HANDSHAKE_TIMEOUT: Duration = get_env_as_duration("NP_HANDSHAKE_TIMEOUT", Duration::from_secs(5));
    pub TCP_DIAL_TIMEOUT: Duration = get_env_as_duration("NP_TCP_DIAL_TIMEOUT", Duration::from_secs(5));
    pub UDP_DIAL_TIMEOUT: Duration = get_env_as_duration("NP_UDP_DIAL_TIMEOUT", Duration::from_secs(5));
    pub UDP_READ_TIMEOUT: Duration = get_env_as_duration("NP_UDP_READ_TIMEOUT", Duration::from_secs(30));
    pub POOL_GET_TIMEOUT: Duration = get_env_as_duration("NP_POOL_GET_TIMEOUT", Duration::from_secs(5));
    pub MIN_POOL_INTERVAL: Duration = get_env_as_duration("NP_MIN_POOL_INTERVAL", Duration::from_millis(100));
    pub MAX_POOL_INTERVAL: Duration = get_env_as_duration("NP_MAX_POOL_INTERVAL", Duration::from_secs(1));
    pub REPORT_INTERVAL: Duration = get_env_as_duration("NP_REPORT_INTERVAL", Duration::from_secs(5));
    pub FALLBACK_INTERVAL: Duration = get_env_as_duration("NP_FALLBACK_INTERVAL", Duration::from_secs(300));
    pub SERVICE_COOLDOWN: Duration = get_env_as_duration("NP_SERVICE_COOLDOWN", Duration::from_secs(3));
    pub SHUTDOWN_TIMEOUT: Duration = get_env_as_duration("NP_SHUTDOWN_TIMEOUT", Duration::from_secs(5));
    pub RELOAD_INTERVAL: Duration = get_env_as_duration("NP_RELOAD_INTERVAL", Duration::from_secs(3600));
}

pub const CONTEXT_CHECK_INTERVAL: Duration = Duration::from_millis(50);
pub const DEFAULT_DNS_TTL: Duration = Duration::from_secs(300);
pub const DEFAULT_MIN_POOL: usize = 64;
pub const DEFAULT_MAX_POOL: usize = 1024;
pub const DEFAULT_SERVER_NAME: &str = "none";
pub const DEFAULT_LB_STRATEGY: &str = "0";
pub const DEFAULT_RUN_MODE: &str = "0";
pub const DEFAULT_POOL_TYPE: &str = "0";
pub const DEFAULT_DIALER_IP: &str = "auto";
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::ZERO;
pub const DEFAULT_RATE_LIMIT: usize = 0;
pub const DEFAULT_SLOT_LIMIT: i32 = 65536;
pub const DEFAULT_PROXY_PROTOCOL: &str = "0";
pub const DEFAULT_BLOCK_PROTOCOL: &str = "0";
pub const DEFAULT_TCP_STRATEGY: &str = "0";
pub const DEFAULT_UDP_STRATEGY: &str = "0";

#[macro_export]
macro_rules! lazy_static_config {
    ($($vis:vis $name:ident : $ty:ty = $init:expr;)*) => {
        $(
            #[allow(non_snake_case, dead_code)]
            $vis fn $name() -> $ty {
                use std::sync::OnceLock;
                static VALUE: OnceLock<$ty> = OnceLock::new();
                *VALUE.get_or_init(|| $init)
            }
        )*
    };
}
pub(crate) use lazy_static_config;
