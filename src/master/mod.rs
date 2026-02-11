pub mod api;
pub mod instance;
pub mod state;
pub mod openapi;
pub mod sysinfo;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use dashmap::DashMap;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::config::*;
use crate::logger::Logger;
use crate::{log_error, log_info};

use instance::{Instance, InstanceEvent};

pub struct Master {
    pub mid: String,
    pub alias: String,
    pub prefix: String,
    pub version: String,
    pub hostname: String,
    pub log_level: String,
    pub crt_path: String,
    pub key_path: String,
    pub tls_code: String,
    pub tls_config: Option<Arc<rustls::ServerConfig>>,
    pub bind_addr: SocketAddr,
    pub instances: Arc<DashMap<String, Instance>>,
    pub state_path: String,
    pub event_tx: broadcast::Sender<InstanceEvent>,
    pub logger: Logger,
    pub start_time: Instant,
    pub cancel: CancellationToken,
}

const API_KEY_ID: &str = "********";
const SSE_RETRY_TIME: u32 = 3000;
const TCPING_SEM_LIMIT: usize = 10;
const BASE_DURATION: std::time::Duration = std::time::Duration::from_millis(100);
const GRACEFUL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const MAX_VALUE_LEN: usize = 256;
const OPENAPI_VERSION: &str = "v1";
const STATE_FILE_DIR: &str = "bincode";
const STATE_FILE_NAME: &str = "nodepass.bin";

impl Master {
    pub fn new(
        parsed_url: url::Url,
        tls_code: String,
        tls_config: Option<Arc<rustls::ServerConfig>>,
        logger: Logger,
        version: String,
    ) -> anyhow::Result<Self> {
        let host = parsed_url.host_str().unwrap_or("0.0.0.0");
        let port = parsed_url.port().unwrap_or(9090);
        let bind_addr: SocketAddr = format!("{}:{}", host, port).parse()
            .map_err(|e| anyhow::anyhow!("newMaster: resolve host failed: {}", e))?;

        let hostname = parsed_url.host_str().unwrap_or("localhost").to_string();

        let mut prefix = parsed_url.path().to_string();
        if prefix.is_empty() || prefix == "/" {
            prefix = "/api".to_string();
        } else {
            prefix = prefix.trim_end_matches('/').to_string();
        }
        let prefix = format!("{}/{}", prefix, OPENAPI_VERSION);

        let exec_path = std::env::current_exe().unwrap_or_default();
        let base_dir = exec_path.parent().unwrap_or(std::path::Path::new("."));
        let state_path = base_dir.join(STATE_FILE_DIR).join(STATE_FILE_NAME)
            .to_string_lossy().to_string();

        let (event_tx, _) = broadcast::channel(SEMAPHORE_LIMIT());

        let mut master = Self {
            mid: String::new(),
            alias: String::new(),
            prefix,
            version,
            hostname,
            log_level: parsed_url.query_pairs()
                .find(|(k, _)| k == "log")
                .map(|(_, v)| v.to_string())
                .unwrap_or_default(),
            crt_path: parsed_url.query_pairs()
                .find(|(k, _)| k == "crt")
                .map(|(_, v)| v.to_string())
                .unwrap_or_default(),
            key_path: parsed_url.query_pairs()
                .find(|(k, _)| k == "key")
                .map(|(_, v)| v.to_string())
                .unwrap_or_default(),
            tls_code,
            tls_config,
            bind_addr,
            instances: Arc::new(DashMap::new()),
            state_path,
            event_tx,
            logger,
            start_time: Instant::now(),
            cancel: CancellationToken::new(),
        };

        master.load_state();

        Ok(master)
    }

    pub async fn run(&mut self) {
        log_info!(self.logger, "Master started: {}{}", self.bind_addr, self.prefix);

        // API key management
        if let Some(api_key) = self.instances.get(API_KEY_ID) {
            self.alias = api_key.alias.clone();
            self.mid = api_key.config.clone();
            if self.mid.is_empty() {
                let mid = generate_mid();
                self.mid = mid.clone();
                let mut inst = api_key.clone();
                inst.config = mid;
                drop(api_key);
                self.instances.insert(API_KEY_ID.to_string(), inst);
                let _ = self.save_state();
                log_info!(self.logger, "Master ID created: {}", self.mid);
            } else {
                drop(api_key);
            }
            let api_key = self.instances.get(API_KEY_ID).unwrap();
            let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
            eprintln!("{}  \x1b[32mINFO\x1b[0m  API Key loaded: {}", timestamp, api_key.url);
        } else {
            let api_key = Instance {
                id: API_KEY_ID.to_string(),
                url: generate_api_key(),
                config: generate_mid(),
                meta: instance::Meta::default(),
                ..Instance::default()
            };
            self.mid = api_key.config.clone();
            let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
            eprintln!("{}  \x1b[32mINFO\x1b[0m  API Key created: {}", timestamp, api_key.url);
            self.instances.insert(API_KEY_ID.to_string(), api_key);
            let _ = self.save_state();
        }

        // Start REST API server
        let app = api::create_router(self);

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

        let listener = tokio::net::TcpListener::bind(self.bind_addr).await.unwrap();

        // Start periodic tasks
        let instances = self.instances.clone();
        let state_path = self.state_path.clone();
        let logger = self.logger.clone();
        let periodic_cancel = cancel.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(RELOAD_INTERVAL());
            loop {
                tokio::select! {
                    _ = periodic_cancel.cancelled() => return,
                    _ = interval.tick() => {
                        // Periodic backup
                        let backup_path = format!("{}.backup", state_path);
                        if let Err(e) = state::save_state_to_path(&instances, &backup_path) {
                            log_error!(logger, "performPeriodicBackup: backup state failed: {}", e);
                        } else {
                            log_info!(logger, "State backup saved: {}", backup_path);
                        }
                    }
                }
            }
        });

        // Auto-start instances with restart=true
        for entry in self.instances.iter() {
            if entry.key() != API_KEY_ID && entry.value().restart && entry.value().status == "stopped" {
                let mut inst = entry.value().clone();
                log_info!(self.logger, "Auto-starting instance: {} [{}]", inst.url, inst.id);
                instance::start_instance(&mut inst, &self.instances, &self.event_tx, &self.logger);
                self.instances.insert(inst.id.clone(), inst);
                tokio::time::sleep(BASE_DURATION).await;
            }
        }

        // Serve
        if let Some(ref tls_config) = self.tls_config {
            let acceptor = tokio_rustls::TlsAcceptor::from(tls_config.clone());
            tokio::select! {
                _ = cancel.cancelled() => {},
                _ = async {
                    loop {
                        let (stream, _) = match listener.accept().await {
                            Ok(s) => s,
                            Err(_) => continue,
                        };
                        let acceptor = acceptor.clone();
                        let app = app.clone();
                        tokio::spawn(async move {
                            if let Ok(tls_stream) = acceptor.accept(stream).await {
                                let io = hyper_util::rt::TokioIo::new(tls_stream);
                                let service = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                                    let app = app.clone();
                                    async move {
                                        let resp = tower::ServiceExt::oneshot(app, req.map(axum::body::Body::new))
                                            .await
                                            .unwrap_or_else(|e| match e {});
                                        Ok::<_, std::convert::Infallible>(resp)
                                    }
                                });
                                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                                    .serve_connection(io, service)
                                    .await
                                    .ok();
                            }
                        });
                    }
                } => {},
            }
        } else {
            tokio::select! {
                _ = cancel.cancelled() => {},
                result = axum::serve(listener, app) => {
                    if let Err(e) = result {
                        log_error!(self.logger, "run: listen failed: {}", e);
                    }
                }
            }
        }

        // Shutdown
        self.shutdown().await;
        log_info!(self.logger, "Master shutdown complete");
    }

    async fn shutdown(&mut self) {
        // Stop all running instances
        for entry in self.instances.iter() {
            let inst = entry.value();
            if inst.status != "stopped" {
                // Stop instance
            }
        }

        // Save state
        if let Err(e) = self.save_state() {
            log_error!(self.logger, "shutdown: save state failed: {}", e);
        } else {
            log_info!(self.logger, "Instances saved: {}", self.state_path);
        }
    }

    pub fn send_sse_event(&self, event_type: &str, instance: &Instance) {
        let event = InstanceEvent {
            event_type: event_type.to_string(),
            time: chrono::Utc::now(),
            instance: instance.clone(),
            logs: String::new(),
        };
        let _ = self.event_tx.send(event);
    }

    pub fn send_sse_event_with_log(&self, event_type: &str, instance: &Instance, log: &str) {
        let event = InstanceEvent {
            event_type: event_type.to_string(),
            time: chrono::Utc::now(),
            instance: instance.clone(),
            logs: log.to_string(),
        };
        let _ = self.event_tx.send(event);
    }

    fn save_state(&self) -> Result<(), String> {
        state::save_state_to_path(&self.instances, &self.state_path)
            .map_err(|e| e.to_string())
    }

    fn load_state(&mut self) {
        state::load_state(&self.instances, &self.state_path, &self.logger);
    }

    pub fn find_instance(&self, id: &str) -> Option<Instance> {
        self.instances.get(id).map(|v| v.clone())
    }

    pub fn enhance_url(&self, url: &str, instance_type: &str) -> String {
        let mut parsed = match url::Url::parse(url) {
            Ok(u) => u,
            Err(_) => return url.to_string(),
        };

        {
            let mut query_pairs: Vec<(String, String)> = parsed.query_pairs()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();

            if !self.log_level.is_empty() && !query_pairs.iter().any(|(k, _)| k == "log") {
                query_pairs.push(("log".to_string(), self.log_level.clone()));
            }

            if instance_type == "server" && self.tls_code != "0" {
                if !query_pairs.iter().any(|(k, _)| k == "tls") {
                    query_pairs.push(("tls".to_string(), self.tls_code.clone()));
                }
                if self.tls_code == "2" {
                    if !self.crt_path.is_empty() && !query_pairs.iter().any(|(k, _)| k == "crt") {
                        query_pairs.push(("crt".to_string(), self.crt_path.clone()));
                    }
                    if !self.key_path.is_empty() && !query_pairs.iter().any(|(k, _)| k == "key") {
                        query_pairs.push(("key".to_string(), self.key_path.clone()));
                    }
                }
            }

            let query_str = query_pairs.iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("&");
            parsed.set_query(if query_str.is_empty() { None } else { Some(&query_str) });
        }

        parsed.to_string()
    }
}

pub fn generate_id() -> String {
    let mut bytes = [0u8; 4];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    hex::encode(bytes)
}

pub fn generate_mid() -> String {
    let mut bytes = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    hex::encode(bytes)
}

pub fn generate_api_key() -> String {
    let mut bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    hex::encode(bytes)
}
