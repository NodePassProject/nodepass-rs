use std::sync::atomic::AtomicU64;
use std::sync::Mutex;
use std::time::Instant;

/// Token bucket rate limiter
pub struct RateLimiter {
    rate: u64,        // tokens per second
    burst: u64,       // max burst size
    tokens: Mutex<f64>,
    last_time: Mutex<Instant>,
    _total: AtomicU64,
}

impl RateLimiter {
    pub fn new(rate: u64, burst: u64) -> Self {
        Self {
            rate,
            burst,
            tokens: Mutex::new(burst as f64),
            last_time: Mutex::new(Instant::now()),
            _total: AtomicU64::new(0),
        }
    }

    pub fn consume(&self, n: u64) {
        if self.rate == 0 {
            return;
        }

        let mut tokens = self.tokens.lock().unwrap();
        let mut last_time = self.last_time.lock().unwrap();

        let now = Instant::now();
        let elapsed = now.duration_since(*last_time).as_secs_f64();
        *tokens = (*tokens + elapsed * self.rate as f64).min(self.burst as f64);
        *last_time = now;

        *tokens -= n as f64;

        // If we've gone negative, we need to wait
        if *tokens < 0.0 {
            let wait_secs = (-*tokens) / self.rate as f64;
            std::thread::sleep(std::time::Duration::from_secs_f64(wait_secs));
            *tokens = 0.0;
        }
    }

    pub fn reset(&self) {
        let mut tokens = self.tokens.lock().unwrap();
        let mut last_time = self.last_time.lock().unwrap();
        *tokens = self.burst as f64;
        *last_time = Instant::now();
    }
}
