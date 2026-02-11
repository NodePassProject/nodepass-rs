use std::collections::HashMap;
use std::sync::Arc;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::logger::Logger;
use crate::{log_error, log_info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instance {
    pub id: String,
    pub alias: String,
    #[serde(rename = "type")]
    pub instance_type: String,
    pub status: String,
    pub url: String,
    pub config: String,
    pub restart: bool,
    pub meta: Meta,
    pub mode: i32,
    pub ping: i32,
    pub pool: i32,
    pub tcps: i32,
    pub udps: i32,
    pub tcprx: u64,
    pub tcptx: u64,
    pub udprx: u64,
    pub udptx: u64,
    #[serde(skip)]
    pub tcprx_base: u64,
    #[serde(skip)]
    pub tcptx_base: u64,
    #[serde(skip)]
    pub udprx_base: u64,
    #[serde(skip)]
    pub udptx_base: u64,
    #[serde(skip)]
    pub tcprx_reset: u64,
    #[serde(skip)]
    pub tcptx_reset: u64,
    #[serde(skip)]
    pub udprx_reset: u64,
    #[serde(skip)]
    pub udptx_reset: u64,
    #[serde(skip)]
    pub deleted: bool,
    #[serde(skip)]
    pub last_checkpoint: Option<std::time::Instant>,
    #[serde(skip)]
    pub child_pid: Option<u32>,
}

impl Default for Instance {
    fn default() -> Self {
        Self {
            id: String::new(),
            alias: String::new(),
            instance_type: String::new(),
            status: "stopped".to_string(),
            url: String::new(),
            config: String::new(),
            restart: false,
            meta: Meta::default(),
            mode: 0,
            ping: 0,
            pool: 0,
            tcps: 0,
            udps: 0,
            tcprx: 0,
            tcptx: 0,
            udprx: 0,
            udptx: 0,
            tcprx_base: 0,
            tcptx_base: 0,
            udprx_base: 0,
            udptx_base: 0,
            tcprx_reset: 0,
            tcptx_reset: 0,
            udprx_reset: 0,
            udptx_reset: 0,
            deleted: false,
            last_checkpoint: None,
            child_pid: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Meta {
    pub peer: Peer,
    pub tags: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Peer {
    pub sid: String,
    #[serde(rename = "type")]
    pub peer_type: String,
    pub alias: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub time: chrono::DateTime<chrono::Utc>,
    pub instance: Instance,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub logs: String,
}

/// Start an instance by spawning the current executable as a child process
pub fn start_instance(
    instance: &mut Instance,
    instances: &Arc<DashMap<String, Instance>>,
    event_tx: &broadcast::Sender<InstanceEvent>,
    logger: &Logger,
) {
    if instance.status != "stopped" {
        return;
    }

    instance.tcprx_base = instance.tcprx;
    instance.tcptx_base = instance.tcptx;
    instance.udprx_base = instance.udprx;
    instance.udptx_base = instance.udptx;

    let exec_path = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            log_error!(logger, "startInstance: get path failed: {} [{}]", e, instance.id);
            instance.status = "error".to_string();
            return;
        }
    };

    log_info!(logger, "Instance starting: {} [{}]", instance.url, instance.id);

    let mut cmd = std::process::Command::new(&exec_path);
    cmd.arg(&instance.url);
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    match cmd.spawn() {
        Ok(child) => {
            instance.child_pid = Some(child.id());
            instance.status = "running".to_string();

            // Monitor the child process in a background task
            let id = instance.id.clone();
            let instances_clone = instances.clone();
            let event_tx_clone = event_tx.clone();
            let logger_clone = logger.clone();
            let checkpoint_regex = regex::Regex::new(
                r"CHECK_POINT\|MODE=(\d+)\|PING=(\d+)ms\|POOL=(\d+)\|TCPS=(\d+)\|UDPS=(\d+)\|TCPRX=(\d+)\|TCPTX=(\d+)\|UDPRX=(\d+)\|UDPTX=(\d+)"
            ).unwrap();

            tokio::spawn(async move {
                monitor_child(child, id, instances_clone, event_tx_clone, logger_clone, checkpoint_regex).await;
            });
        }
        Err(e) => {
            log_error!(logger, "startInstance: instance error: {} [{}]", e, instance.id);
            instance.status = "error".to_string();
        }
    }
}

async fn monitor_child(
    mut child: std::process::Child,
    id: String,
    instances: Arc<DashMap<String, Instance>>,
    event_tx: broadcast::Sender<InstanceEvent>,
    logger: Logger,
    checkpoint_regex: regex::Regex,
) {
    use std::io::BufRead;

    // Read stderr in a separate thread (blocking I/O)
    let stderr = child.stderr.take();
    let _stdout = child.stdout.take();

    let id_clone = id.clone();
    let instances_clone = instances.clone();
    let event_tx_clone = event_tx.clone();
    let logger_clone = logger.clone();
    let regex_clone = checkpoint_regex.clone();

    // Process output in a blocking thread
    if let Some(stderr) = stderr {
        let id = id_clone.clone();
        let instances = instances_clone.clone();
        let event_tx = event_tx_clone.clone();
        let _logger = logger_clone.clone();
        let regex = regex_clone.clone();

        std::thread::spawn(move || {
            let reader = std::io::BufReader::new(stderr);
            for line in reader.lines() {
                let line = match line {
                    Ok(l) => l,
                    Err(_) => break,
                };

                // Parse CHECK_POINT lines
                if let Some(captures) = regex.captures(&line) {
                    if let Some(mut inst) = instances.get_mut(&id) {
                        if let Ok(v) = captures[1].parse::<i32>() { inst.mode = v; }
                        if let Ok(v) = captures[2].parse::<i32>() { inst.ping = v; }
                        if let Ok(v) = captures[3].parse::<i32>() { inst.pool = v; }
                        if let Ok(v) = captures[4].parse::<i32>() { inst.tcps = v; }
                        if let Ok(v) = captures[5].parse::<i32>() { inst.udps = v; }

                        // Update traffic stats with base/reset logic
                        let stat_fields = [6, 7, 8, 9];
                        let bases = [inst.tcprx_base, inst.tcptx_base, inst.udprx_base, inst.udptx_base];
                        let resets = [inst.tcprx_reset, inst.tcptx_reset, inst.udprx_reset, inst.udptx_reset];

                        for (i, &field_idx) in stat_fields.iter().enumerate() {
                            if let Ok(v) = captures[field_idx].parse::<u64>() {
                                let stat = if v >= resets[i] {
                                    bases[i] + v - resets[i]
                                } else {
                                    bases[i] + v
                                };
                                match i {
                                    0 => inst.tcprx = stat,
                                    1 => inst.tcptx = stat,
                                    2 => inst.udprx = stat,
                                    3 => inst.udptx = stat,
                                    _ => {}
                                }
                            }
                        }

                        inst.last_checkpoint = Some(std::time::Instant::now());
                        if inst.status == "error" {
                            inst.status = "running".to_string();
                        }

                        // Send SSE update
                        let event = InstanceEvent {
                            event_type: "update".to_string(),
                            time: chrono::Utc::now(),
                            instance: inst.clone(),
                            logs: String::new(),
                        };
                        let _ = event_tx.send(event);
                    }
                    continue;
                }

                // Check for error lines
                if line.contains("Server error:") || line.contains("Client error:") {
                    if let Some(mut inst) = instances.get_mut(&id) {
                        if inst.status != "error" {
                            inst.status = "error".to_string();
                            inst.ping = 0;
                            inst.pool = 0;
                            inst.tcps = 0;
                            inst.udps = 0;
                        }
                    }
                }

                // Forward log line
                eprintln!("{} [{}]", line, id);

                // Send log SSE event
                if let Some(inst) = instances.get(&id) {
                    let event = InstanceEvent {
                        event_type: "log".to_string(),
                        time: chrono::Utc::now(),
                        instance: inst.clone(),
                        logs: line,
                    };
                    let _ = event_tx.send(event);
                }
            }
        });
    }

    // Wait for child process
    let status = tokio::task::spawn_blocking(move || child.wait()).await;

    // Update instance status
    if let Some(mut inst) = instances.get_mut(&id) {
        if inst.status == "running" {
            match status {
                Ok(Ok(exit_status)) => {
                    if exit_status.success() {
                        inst.status = "stopped".to_string();
                    } else {
                        log_error!(logger, "monitorInstance: instance error: exit code {:?} [{}]", exit_status.code(), id);
                        inst.status = "error".to_string();
                    }
                }
                _ => {
                    inst.status = "error".to_string();
                }
            }

            let event = InstanceEvent {
                event_type: "update".to_string(),
                time: chrono::Utc::now(),
                instance: inst.clone(),
                logs: String::new(),
            };
            let _ = event_tx.send(event);
        }
    }
}

/// Stop an instance by sending SIGTERM then SIGKILL
pub fn stop_instance(
    instance: &mut Instance,
    logger: &Logger,
) {
    if instance.status == "stopped" {
        return;
    }

    if let Some(pid) = instance.child_pid {
        // Send SIGTERM
        #[cfg(unix)]
        {
            use std::process::Command;
            let _ = Command::new("kill").arg("-TERM").arg(pid.to_string()).output();
        }
        #[cfg(windows)]
        {
            use std::process::Command;
            let _ = Command::new("taskkill").arg("/PID").arg(pid.to_string()).output();
        }

        // Wait briefly then force kill
        std::thread::sleep(super::GRACEFUL_TIMEOUT);

        #[cfg(unix)]
        {
            use std::process::Command;
            let _ = Command::new("kill").arg("-9").arg(pid.to_string()).output();
        }

        log_info!(logger, "Instance stopped [{}]", instance.id);
    }

    instance.status = "stopped".to_string();
    instance.child_pid = None;
    instance.ping = 0;
    instance.pool = 0;
    instance.tcps = 0;
    instance.udps = 0;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TCPingResult {
    pub target: String,
    pub connected: bool,
    pub latency: i64,
    pub error: Option<String>,
}

pub async fn perform_tcping(target: &str) -> TCPingResult {
    let start = std::time::Instant::now();
    match tokio::time::timeout(
        crate::config::REPORT_INTERVAL(),
        tokio::net::TcpStream::connect(target),
    ).await {
        Ok(Ok(stream)) => {
            drop(stream);
            TCPingResult {
                target: target.to_string(),
                connected: true,
                latency: start.elapsed().as_millis() as i64,
                error: None,
            }
        }
        Ok(Err(e)) => {
            TCPingResult {
                target: target.to_string(),
                connected: false,
                latency: 0,
                error: Some(e.to_string()),
            }
        }
        Err(_) => {
            TCPingResult {
                target: target.to_string(),
                connected: false,
                latency: 0,
                error: Some("timeout".to_string()),
            }
        }
    }
}
