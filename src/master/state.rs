use std::collections::HashMap;
use std::sync::Arc;
use dashmap::DashMap;

use super::instance::Instance;
use super::API_KEY_ID;
use crate::logger::Logger;
use crate::{log_error, log_info};

/// Save all instances to a file using bincode
pub fn save_state_to_path(
    instances: &Arc<DashMap<String, Instance>>,
    file_path: &str,
) -> anyhow::Result<()> {
    let mut data: HashMap<String, Instance> = HashMap::new();
    for entry in instances.iter() {
        data.insert(entry.key().clone(), entry.value().clone());
    }

    if data.is_empty() {
        if std::path::Path::new(file_path).exists() {
            std::fs::remove_file(file_path)?;
        }
        return Ok(());
    }

    // Ensure directory exists
    if let Some(parent) = std::path::Path::new(file_path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Write to temp file then rename
    let dir = std::path::Path::new(file_path).parent().unwrap_or(std::path::Path::new("."));
    let temp_path = dir.join(format!("np-{}.tmp", rand::random::<u32>()));

    let encoded = bincode::serialize(&data)?;
    std::fs::write(&temp_path, &encoded)?;
    std::fs::rename(&temp_path, file_path)?;

    Ok(())
}

/// Load instances from a file
pub fn load_state(
    instances: &Arc<DashMap<String, Instance>>,
    file_path: &str,
    logger: &Logger,
) {
    // Clean up temp files
    if let Some(parent) = std::path::Path::new(file_path).parent() {
        if let Ok(entries) = std::fs::read_dir(parent) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("np-") && name.ends_with(".tmp") {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
    }

    if !std::path::Path::new(file_path).exists() {
        return;
    }

    let data = match std::fs::read(file_path) {
        Ok(d) => d,
        Err(e) => {
            log_error!(logger, "loadState: open file failed: {}", e);
            return;
        }
    };

    let persistent_data: HashMap<String, Instance> = match bincode::deserialize(&data) {
        Ok(d) => d,
        Err(e) => {
            log_error!(logger, "loadState: decode file failed: {}", e);
            return;
        }
    };

    let count = persistent_data.len();
    for (id, mut instance) in persistent_data {
        if id != API_KEY_ID {
            instance.status = "stopped".to_string();
        }
        if instance.meta.tags.is_empty() {
            // tags already default initialized
        }
        instances.insert(id, instance);
    }

    log_info!(logger, "Loaded {} instances from {}", count, file_path);
}
