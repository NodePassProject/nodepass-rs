use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, Method, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Json,
    },
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};

use super::instance::{Instance, InstanceEvent, Meta, Peer, TCPingResult};
use super::{Master, API_KEY_ID, MAX_VALUE_LEN};
use crate::logger::Logger;

#[derive(Clone)]
pub struct AppState {
    pub instances: Arc<dashmap::DashMap<String, Instance>>,
    pub event_tx: tokio::sync::broadcast::Sender<InstanceEvent>,
    pub logger: Logger,
    pub master_info: Arc<tokio::sync::RwLock<MasterInfo>>,
    pub prefix: String,
    pub log_level: String,
    pub tls_code: String,
    pub crt_path: String,
    pub key_path: String,
}

#[derive(Clone, Serialize)]
pub struct MasterInfo {
    pub mid: String,
    pub alias: String,
    pub os: String,
    pub arch: String,
    pub cpu: i32,
    pub mem_total: u64,
    pub mem_used: u64,
    pub swap_total: u64,
    pub swap_used: u64,
    pub netrx: u64,
    pub nettx: u64,
    pub diskr: u64,
    pub diskw: u64,
    pub sysup: u64,
    pub ver: String,
    pub name: String,
    pub uptime: u64,
    pub log: String,
    pub tls: String,
    pub crt: String,
    pub key: String,
}

pub fn create_router(master: &Master) -> Router {
    let master_info = MasterInfo {
        mid: master.mid.clone(),
        alias: master.alias.clone(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        cpu: -1,
        mem_total: 0,
        mem_used: 0,
        swap_total: 0,
        swap_used: 0,
        netrx: 0,
        nettx: 0,
        diskr: 0,
        diskw: 0,
        sysup: 0,
        ver: master.version.clone(),
        name: master.hostname.clone(),
        uptime: 0,
        log: master.log_level.clone(),
        tls: master.tls_code.clone(),
        crt: master.crt_path.clone(),
        key: master.key_path.clone(),
    };

    let state = AppState {
        instances: master.instances.clone(),
        event_tx: master.event_tx.clone(),
        logger: master.logger.clone(),
        master_info: Arc::new(tokio::sync::RwLock::new(master_info)),
        prefix: master.prefix.clone(),
        log_level: master.log_level.clone(),
        tls_code: master.tls_code.clone(),
        crt_path: master.crt_path.clone(),
        key_path: master.key_path.clone(),
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::PATCH, Method::DELETE, Method::OPTIONS])
        .allow_headers(Any);

    let prefix = master.prefix.clone();

    Router::new()
        .route(&format!("{}/instances", prefix), get(list_instances).post(create_instance))
        .route(&format!("{}/instances/{{id}}", prefix), get(get_instance).patch(patch_instance).put(put_instance).delete(delete_instance))
        .route(&format!("{}/events", prefix), get(sse_handler))
        .route(&format!("{}/info", prefix), get(get_info).post(update_info))
        .route(&format!("{}/tcping", prefix), get(tcping_handler))
        .route(&format!("{}/openapi.json", prefix), get(openapi_spec))
        .route(&format!("{}/docs", prefix), get(swagger_ui))
        .layer(cors)
        .with_state(state)
}

// Middleware: check API key
fn check_api_key(state: &AppState, headers: &HeaderMap) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if let Some(api_key_inst) = state.instances.get(API_KEY_ID) {
        let api_key = &api_key_inst.url;
        if !api_key.is_empty() {
            let req_key = headers.get("X-API-Key")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if req_key.is_empty() {
                return Err((StatusCode::UNAUTHORIZED, Json(json!({"error": "Unauthorized: API key required"}))));
            }
            if req_key != api_key {
                return Err((StatusCode::UNAUTHORIZED, Json(json!({"error": "Unauthorized: Invalid API key"}))));
            }
        }
    }
    Ok(())
}

async fn list_instances(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<Instance>>, (StatusCode, Json<serde_json::Value>)> {
    check_api_key(&state, &headers)?;
    let instances: Vec<Instance> = state.instances.iter().map(|e| e.value().clone()).collect();
    Ok(Json(instances))
}

#[derive(Deserialize)]
struct CreateInstanceReq {
    alias: Option<String>,
    url: String,
}

async fn create_instance(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateInstanceReq>,
) -> Result<(StatusCode, Json<Instance>), (StatusCode, Json<serde_json::Value>)> {
    check_api_key(&state, &headers)?;

    let parsed = url::Url::parse(&req.url)
        .map_err(|_| (StatusCode::BAD_REQUEST, Json(json!({"error": "Invalid URL format"}))))?;

    let instance_type = parsed.scheme().to_string();
    if instance_type != "client" && instance_type != "server" {
        return Err((StatusCode::BAD_REQUEST, Json(json!({"error": "Invalid URL scheme"}))));
    }

    let id = super::generate_id();
    if state.instances.contains_key(&id) {
        return Err((StatusCode::CONFLICT, Json(json!({"error": "Instance ID already exists"}))));
    }

    let instance = Instance {
        id: id.clone(),
        alias: req.alias.unwrap_or_default(),
        instance_type,
        url: req.url,
        status: "stopped".to_string(),
        restart: true,
        meta: Meta::default(),
        ..Instance::default()
    };

    state.instances.insert(id, instance.clone());

    // Send SSE event
    let event = InstanceEvent {
        event_type: "create".to_string(),
        time: chrono::Utc::now(),
        instance: instance.clone(),
        logs: String::new(),
    };
    let _ = state.event_tx.send(event);

    Ok((StatusCode::CREATED, Json(instance)))
}

async fn get_instance(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Instance>, (StatusCode, Json<serde_json::Value>)> {
    check_api_key(&state, &headers)?;

    let instance = state.instances.get(&id)
        .map(|v| v.clone())
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(json!({"error": "Instance not found"}))))?;

    Ok(Json(instance))
}

#[derive(Deserialize)]
struct PatchInstanceReq {
    alias: Option<String>,
    action: Option<String>,
    restart: Option<bool>,
    meta: Option<PatchMeta>,
}

#[derive(Deserialize)]
struct PatchMeta {
    peer: Option<Peer>,
    tags: Option<HashMap<String, String>>,
}

async fn patch_instance(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<PatchInstanceReq>,
) -> Result<Json<Instance>, (StatusCode, Json<serde_json::Value>)> {
    check_api_key(&state, &headers)?;

    let mut instance = state.instances.get(&id)
        .map(|v| v.clone())
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(json!({"error": "Instance not found"}))))?;

    if let Some(alias) = req.alias {
        if alias.len() > MAX_VALUE_LEN {
            return Err((StatusCode::BAD_REQUEST, Json(json!({"error": format!("Alias exceeds maximum length {}", MAX_VALUE_LEN)}))));
        }
        instance.alias = alias;
    }

    if let Some(action) = req.action {
        match action.as_str() {
            "start" | "stop" | "restart" | "reset" => {
                if action == "reset" {
                    instance.tcprx_reset = instance.tcprx - instance.tcprx_base;
                    instance.tcptx_reset = instance.tcptx - instance.tcptx_base;
                    instance.udprx_reset = instance.udprx - instance.udprx_base;
                    instance.udptx_reset = instance.udptx - instance.udptx_base;
                    instance.tcprx = 0;
                    instance.tcptx = 0;
                    instance.udprx = 0;
                    instance.udptx = 0;
                    instance.tcprx_base = 0;
                    instance.tcptx_base = 0;
                    instance.udprx_base = 0;
                    instance.udptx_base = 0;
                }
                // For start/stop/restart: would call process management
            }
            _ => {
                return Err((StatusCode::BAD_REQUEST, Json(json!({"error": format!("Invalid action: {}", action)}))));
            }
        }
    }

    if let Some(restart) = req.restart {
        instance.restart = restart;
    }

    if let Some(meta) = req.meta {
        if let Some(peer) = meta.peer {
            instance.meta.peer = peer;
        }
        if let Some(tags) = meta.tags {
            instance.meta.tags = tags;
        }
    }

    state.instances.insert(id, instance.clone());

    let event = InstanceEvent {
        event_type: "update".to_string(),
        time: chrono::Utc::now(),
        instance: instance.clone(),
        logs: String::new(),
    };
    let _ = state.event_tx.send(event);

    Ok(Json(instance))
}

#[derive(Deserialize)]
struct PutInstanceReq {
    url: String,
}

async fn put_instance(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<PutInstanceReq>,
) -> Result<Json<Instance>, (StatusCode, Json<serde_json::Value>)> {
    check_api_key(&state, &headers)?;

    if id == API_KEY_ID {
        return Err((StatusCode::FORBIDDEN, Json(json!({"error": "Forbidden: API Key"}))));
    }

    let mut instance = state.instances.get(&id)
        .map(|v| v.clone())
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(json!({"error": "Instance not found"}))))?;

    let parsed = url::Url::parse(&req.url)
        .map_err(|_| (StatusCode::BAD_REQUEST, Json(json!({"error": "Invalid URL format"}))))?;

    let instance_type = parsed.scheme().to_string();
    if instance_type != "client" && instance_type != "server" {
        return Err((StatusCode::BAD_REQUEST, Json(json!({"error": "Invalid URL scheme"}))));
    }

    instance.url = req.url;
    instance.instance_type = instance_type;
    state.instances.insert(id, instance.clone());

    Ok(Json(instance))
}

async fn delete_instance(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    check_api_key(&state, &headers)?;

    if id == API_KEY_ID {
        return Err((StatusCode::FORBIDDEN, Json(json!({"error": "Forbidden: API Key"}))));
    }

    let instance = state.instances.remove(&id)
        .map(|(_, v)| v)
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(json!({"error": "Instance not found"}))))?;

    let event = InstanceEvent {
        event_type: "delete".to_string(),
        time: chrono::Utc::now(),
        instance,
        logs: String::new(),
    };
    let _ = state.event_tx.send(event);

    Ok(StatusCode::NO_CONTENT)
}

async fn sse_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>>, (StatusCode, Json<serde_json::Value>)> {
    check_api_key(&state, &headers)?;

    let mut rx = state.event_tx.subscribe();

    // First send all current instances as "initial" events
    let initial_events: Vec<InstanceEvent> = state.instances.iter()
        .map(|entry| InstanceEvent {
            event_type: "initial".to_string(),
            time: chrono::Utc::now(),
            instance: entry.value().clone(),
            logs: String::new(),
        })
        .collect();

    let stream = async_stream::stream! {
        // Send initial events
        for event in initial_events {
            if let Ok(data) = serde_json::to_string(&event) {
                yield Ok(Event::default().event("instance").data(data));
            }
        }

        // Stream ongoing events
        loop {
            match rx.recv().await {
                Ok(event) => {
                    if event.event_type == "shutdown" {
                        break;
                    }
                    if let Ok(data) = serde_json::to_string(&event) {
                        yield Ok(Event::default().event("instance").data(data));
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => break,
            }
        }
    };

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

async fn get_info(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<MasterInfo>, (StatusCode, Json<serde_json::Value>)> {
    check_api_key(&state, &headers)?;

    let mut info = state.master_info.read().await.clone();
    info.uptime = state.master_info.read().await.uptime; // Would calculate from start_time

    // Get system info on Linux
    #[cfg(target_os = "linux")]
    {
        let sys = super::sysinfo::get_linux_sys_info();
        info.cpu = sys.cpu;
        info.mem_total = sys.mem_total;
        info.mem_used = sys.mem_used;
        info.swap_total = sys.swap_total;
        info.swap_used = sys.swap_used;
        info.netrx = sys.netrx;
        info.nettx = sys.nettx;
        info.diskr = sys.diskr;
        info.diskw = sys.diskw;
        info.sysup = sys.sysup;
    }

    Ok(Json(info))
}

#[derive(Deserialize)]
struct UpdateInfoReq {
    alias: String,
}

async fn update_info(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<UpdateInfoReq>,
) -> Result<Json<MasterInfo>, (StatusCode, Json<serde_json::Value>)> {
    check_api_key(&state, &headers)?;

    if req.alias.len() > MAX_VALUE_LEN {
        return Err((StatusCode::BAD_REQUEST, Json(json!({"error": format!("Master alias exceeds maximum length {}", MAX_VALUE_LEN)}))));
    }

    let mut info = state.master_info.write().await;
    info.alias = req.alias.clone();

    // Update API key instance
    if let Some(mut api_key) = state.instances.get_mut(API_KEY_ID) {
        api_key.alias = req.alias;
    }

    Ok(Json(info.clone()))
}

#[derive(Deserialize)]
struct TCPingQuery {
    target: String,
}

async fn tcping_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<TCPingQuery>,
) -> Result<Json<TCPingResult>, (StatusCode, Json<serde_json::Value>)> {
    check_api_key(&state, &headers)?;

    if query.target.is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(json!({"error": "Target address required"}))));
    }

    let result = super::instance::perform_tcping(&query.target).await;
    Ok(Json(result))
}

async fn openapi_spec(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let spec = super::openapi::generate_openapi_spec(&state.prefix);
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        spec,
    )
}

async fn swagger_ui(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let spec = super::openapi::generate_openapi_spec(&state.prefix);
    let html = super::openapi::swagger_ui_html(&spec);
    (
        [(axum::http::header::CONTENT_TYPE, "text/html")],
        html,
    )
}
