
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BlockedProtocol {
    Socks4,
    Socks5,
    Http,
    Tls,
}

impl std::fmt::Display for BlockedProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockedProtocol::Socks4 => write!(f, "SOCKS4"),
            BlockedProtocol::Socks5 => write!(f, "SOCKS5"),
            BlockedProtocol::Http => write!(f, "HTTP"),
            BlockedProtocol::Tls => write!(f, "TLS"),
        }
    }
}

/// Peek at the first 8 bytes of a connection to detect blocked protocols.
/// Returns (detected_protocol, peeked_bytes).
/// The caller must prepend peeked_bytes to subsequent reads.
pub fn detect_block_protocol(
    buf: &[u8],
    block_socks: bool,
    block_http: bool,
    block_tls: bool,
) -> Option<BlockedProtocol> {
    if buf.is_empty() {
        return None;
    }

    // SOCKS detection
    if block_socks && buf.len() >= 2 {
        if buf[0] == 0x04 && (buf[1] == 0x01 || buf[1] == 0x02) {
            return Some(BlockedProtocol::Socks4);
        }
        if buf[0] == 0x05 && buf[1] >= 0x01 && buf[1] <= 0x03 {
            return Some(BlockedProtocol::Socks5);
        }
    }

    // HTTP detection
    if block_http && buf.len() >= 4 && buf[0] >= b'A' && buf[0] <= b'Z' {
        for (i, &c) in buf[1..].iter().enumerate() {
            if c == b' ' {
                return Some(BlockedProtocol::Http);
            }
            if c < b'A' || c > b'Z' || i >= 7 {
                break;
            }
        }
    }

    // TLS detection
    if block_tls && buf[0] == 0x16 {
        return Some(BlockedProtocol::Tls);
    }

    None
}
