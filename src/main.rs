#![allow(dead_code)]

mod auth;
mod block;
mod client;
mod common;
mod config;
mod conn;
mod dns_cache;
mod logger;
mod master;
mod pool;
mod proxy;
mod server;
mod signal_protocol;
mod tls;

use logger::{LogLevel, Logger};
use std::sync::Arc;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let args: Vec<String> = std::env::args().collect();
    if let Err(err) = start(args).await {
        exit(err);
    }
}

async fn start(args: Vec<String>) -> anyhow::Result<()> {
    if args.len() != 2 {
        anyhow::bail!("start: empty URL command");
    }

    // Replace empty host (e.g. "server://:1001/:1002") with 0.0.0.0
    let url_str = {
        let s = &args[1];
        // Match pattern "scheme://:port" — insert 0.0.0.0 before the colon
        if let Some(scheme_end) = s.find("://") {
            let after_scheme = &s[scheme_end + 3..];
            if after_scheme.starts_with(':') {
                format!("{}://0.0.0.0{}", &s[..scheme_end], after_scheme)
            } else {
                s.clone()
            }
        } else {
            s.clone()
        }
    };
    let parsed_url = url::Url::parse(&url_str)
        .map_err(|e| anyhow::anyhow!("start: parse URL failed: {}", e))?;

    let logger = init_logger(
        parsed_url
            .query_pairs()
            .find(|(k, _)| k == "log")
            .map(|(_, v)| v.to_string())
            .as_deref(),
    );

    match parsed_url.scheme() {
        "server" => {
            let (tls_code, tls_config, cert_der) = get_tls_protocol(&parsed_url, &logger);
            let mut srv = server::Server::new(parsed_url, tls_code, tls_config, cert_der, logger)?;
            srv.run().await;
        }
        "client" => {
            let mut cli = client::Client::new(parsed_url, logger)?;
            cli.run().await;
        }
        "master" => {
            let (tls_code, tls_config, _cert_der) = get_tls_protocol(&parsed_url, &logger);
            let mut mst = master::Master::new(parsed_url, tls_code, tls_config, logger, VERSION.to_string())?;
            mst.run().await;
        }
        scheme => {
            anyhow::bail!("createCore: unknown core: {}", scheme);
        }
    }

    Ok(())
}

fn init_logger(level: Option<&str>) -> Logger {
    let logger = Logger::new(LogLevel::Info, true);
    match level {
        Some("none") => logger.set_level(LogLevel::None),
        Some("debug") => {
            logger.set_level(LogLevel::Debug);
            logger.debug("Init log level: DEBUG");
        }
        Some("warn") => {
            logger.set_level(LogLevel::Warn);
            logger.warn("Init log level: WARN");
        }
        Some("error") => {
            logger.set_level(LogLevel::Error);
            logger.error("Init log level: ERROR");
        }
        Some("event") => {
            logger.set_level(LogLevel::Event);
            logger.event("Init log level: EVENT");
        }
        _ => {}
    }
    logger
}

fn get_tls_protocol(parsed_url: &url::Url, logger: &Logger) -> (String, Option<Arc<rustls::ServerConfig>>, Option<Vec<u8>>) {
    let (tls_config, cert_der) = match tls::new_tls_config() {
        Ok((config, der)) => (config, der),
        Err(e) => {
            log_error!(logger, "Generate TLS config failed: {}", e);
            log_warn!(logger, "TLS code-0: nil cert");
            return ("0".to_string(), None, None);
        }
    };

    let tls_param = parsed_url
        .query_pairs()
        .find(|(k, _)| k == "tls")
        .map(|(_, v)| v.to_string());

    match tls_param.as_deref() {
        Some("1") => {
            log_info!(logger, "TLS code-1: RAM cert with TLS 1.3");
            ("1".to_string(), Some(tls_config), Some(cert_der))
        }
        Some("2") => {
            let crt_file = parsed_url
                .query_pairs()
                .find(|(k, _)| k == "crt")
                .map(|(_, v)| v.to_string())
                .unwrap_or_default();
            let key_file = parsed_url
                .query_pairs()
                .find(|(k, _)| k == "key")
                .map(|(_, v)| v.to_string())
                .unwrap_or_default();

            match tls::load_tls_config_reloading(&crt_file, &key_file) {
                Ok(config) => {
                    log_info!(logger, "TLS code-2: file cert with TLS 1.3");
                    ("2".to_string(), Some(config), None)
                }
                Err(e) => {
                    log_error!(logger, "Certificate load failed: {}", e);
                    log_warn!(logger, "TLS code-1: RAM cert with TLS 1.3");
                    ("1".to_string(), Some(tls_config), Some(cert_der))
                }
            }
        }
        _ => {
            // Check if pool type requires TLS
            let pool_type = parsed_url
                .query_pairs()
                .find(|(k, _)| k == "type")
                .map(|(_, v)| v.to_string());

            if pool_type.as_deref() == Some("1") || pool_type.as_deref() == Some("3") {
                log_info!(logger, "TLS code-1: RAM cert with TLS 1.3 for stream pool");
                ("1".to_string(), Some(tls_config), Some(cert_der))
            } else {
                log_warn!(logger, "TLS code-0: unencrypted");
                ("0".to_string(), None, None)
            }
        }
    }
}

fn exit(err: anyhow::Error) {
    eprintln!(
        "nodepass-{} {}/{} pid={} error={}\nvisit https://github.com/NodePassProject for more information",
        VERSION,
        std::env::consts::OS,
        std::env::consts::ARCH,
        std::process::id(),
        err,
    );
    std::process::exit(1);
}
