use chrono::Local;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum LogLevel {
    None = 0,
    Event = 1,
    Error = 2,
    Warn = 3,
    Info = 4,
    Debug = 5,
}

impl LogLevel {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => LogLevel::None,
            1 => LogLevel::Event,
            2 => LogLevel::Error,
            3 => LogLevel::Warn,
            4 => LogLevel::Info,
            5 => LogLevel::Debug,
            _ => LogLevel::Info,
        }
    }
}

#[derive(Clone)]
pub struct Logger {
    level: Arc<AtomicU8>,
    colored: bool,
}

impl Logger {
    pub fn new(level: LogLevel, colored: bool) -> Self {
        Self {
            level: Arc::new(AtomicU8::new(level as u8)),
            colored,
        }
    }

    pub fn set_level(&self, level: LogLevel) {
        self.level.store(level as u8, Ordering::Relaxed);
    }

    pub fn level(&self) -> LogLevel {
        LogLevel::from_u8(self.level.load(Ordering::Relaxed))
    }

    fn should_log(&self, level: LogLevel) -> bool {
        let current = self.level.load(Ordering::Relaxed);
        (level as u8) <= current
    }

    fn log(&self, level: LogLevel, msg: &str) {
        if !self.should_log(level) {
            return;
        }

        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");

        if self.colored {
            let (color, label) = match level {
                LogLevel::Debug => ("\x1b[36m", "DEBUG"),
                LogLevel::Info => ("\x1b[32m", "INFO"),
                LogLevel::Warn => ("\x1b[33m", "WARN"),
                LogLevel::Error => ("\x1b[31m", "ERROR"),
                LogLevel::Event => ("\x1b[35m", "EVENT"),
                LogLevel::None => return,
            };
            eprintln!("{}  {}{}\x1b[0m  {}", timestamp, color, label, msg);
        } else {
            let label = match level {
                LogLevel::Debug => "DEBUG",
                LogLevel::Info => "INFO",
                LogLevel::Warn => "WARN",
                LogLevel::Error => "ERROR",
                LogLevel::Event => "EVENT",
                LogLevel::None => return,
            };
            eprintln!("{}  {}  {}", timestamp, label, msg);
        }
    }

    pub fn debug(&self, msg: &str) {
        self.log(LogLevel::Debug, msg);
    }

    pub fn info(&self, msg: &str) {
        self.log(LogLevel::Info, msg);
    }

    pub fn warn(&self, msg: &str) {
        self.log(LogLevel::Warn, msg);
    }

    pub fn error(&self, msg: &str) {
        self.log(LogLevel::Error, msg);
    }

    pub fn event(&self, msg: &str) {
        self.log(LogLevel::Event, msg);
    }
}

/// Convenience macro for formatted logging
#[macro_export]
macro_rules! log_debug {
    ($logger:expr, $($arg:tt)*) => {
        $logger.debug(&format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_info {
    ($logger:expr, $($arg:tt)*) => {
        $logger.info(&format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_warn {
    ($logger:expr, $($arg:tt)*) => {
        $logger.warn(&format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_error {
    ($logger:expr, $($arg:tt)*) => {
        $logger.error(&format!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_event {
    ($logger:expr, $($arg:tt)*) => {
        $logger.event(&format!($($arg)*))
    };
}
