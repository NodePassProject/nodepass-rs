use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;

/// Send a PROXY protocol v1 header
pub async fn send_proxy_v1_header<W: AsyncWriteExt + Unpin>(
    client_addr: &str,
    remote_addr: SocketAddr,
    writer: &mut W,
) -> anyhow::Result<()> {
    let client_sock: SocketAddr = client_addr
        .parse()
        .map_err(|e| anyhow::anyhow!("sendProxyV1Header: parse client addr failed: {}", e))?;

    let protocol = if client_sock.ip().to_string().contains(':') {
        if remote_addr.ip().to_string().contains(':') {
            "TCP6"
        } else {
            anyhow::bail!("sendProxyV1Header: unsupported IP protocol for PROXY v1");
        }
    } else if !remote_addr.ip().to_string().contains(':') {
        "TCP4"
    } else {
        anyhow::bail!("sendProxyV1Header: unsupported IP protocol for PROXY v1");
    };

    let header = format!(
        "PROXY {} {} {} {} {}\r\n",
        protocol,
        client_sock.ip(),
        remote_addr.ip(),
        client_sock.port(),
        remote_addr.port(),
    );

    writer.write_all(header.as_bytes()).await?;
    Ok(())
}
