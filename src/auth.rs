use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub fn generate_auth_token(key: &str) -> String {
    let mac = HmacSha256::new_from_slice(key.as_bytes())
        .expect("HMAC can take key of any size");
    hex::encode(mac.finalize().into_bytes())
}

pub fn verify_auth_token(token: &str, key: &str) -> bool {
    let expected = generate_auth_token(key);
    constant_time_eq(token.as_bytes(), expected.as_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}
