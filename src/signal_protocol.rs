use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signal {
    pub action: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub remote: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fp: String,
}

impl Signal {
    pub fn new(action: &str) -> Self {
        Self {
            action: action.to_string(),
            remote: String::new(),
            id: String::new(),
            fp: String::new(),
        }
    }

    pub fn with_id(action: &str, id: &str) -> Self {
        Self {
            action: action.to_string(),
            remote: String::new(),
            id: id.to_string(),
            fp: String::new(),
        }
    }

    pub fn tcp(remote: &str, id: &str) -> Self {
        Self {
            action: "tcp".to_string(),
            remote: remote.to_string(),
            id: id.to_string(),
            fp: String::new(),
        }
    }

    pub fn udp(remote: &str, id: &str) -> Self {
        Self {
            action: "udp".to_string(),
            remote: remote.to_string(),
            id: id.to_string(),
            fp: String::new(),
        }
    }

    pub fn verify(id: &str, fingerprint: &str) -> Self {
        Self {
            action: "verify".to_string(),
            remote: String::new(),
            id: id.to_string(),
            fp: fingerprint.to_string(),
        }
    }
}

pub fn xor_bytes(data: &mut [u8], key: &[u8]) {
    if key.is_empty() {
        return;
    }
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
}

pub fn encode_signal(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut buf = data.to_vec();
    xor_bytes(&mut buf, key);
    let mut encoded = BASE64.encode(&buf).into_bytes();
    encoded.push(b'\n');
    encoded
}

pub fn decode_signal(data: &[u8], key: &[u8]) -> anyhow::Result<Vec<u8>> {
    let trimmed = if data.last() == Some(&b'\n') {
        &data[..data.len() - 1]
    } else {
        data
    };
    let mut decoded = BASE64
        .decode(trimmed)
        .map_err(|e| anyhow::anyhow!("decode: base64 decode failed: {}", e))?;
    xor_bytes(&mut decoded, key);
    Ok(decoded)
}
