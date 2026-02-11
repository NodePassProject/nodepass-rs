use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Bidirectional data exchange between two connections
/// Returns a string describing the result (matching Go's conn.DataExchange)
pub async fn data_exchange<A, B>(
    conn1: A,
    conn2: B,
    read_timeout: Duration,
    buf1: &mut [u8],
    buf2: &mut [u8],
) -> String
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut r1, mut w1) = tokio::io::split(conn1);
    let (mut r2, mut w2) = tokio::io::split(conn2);

    let copy1 = async {
        let result = if read_timeout.is_zero() {
            copy_with_buf(&mut r1, &mut w2, buf1).await
        } else {
            copy_with_buf_timeout(&mut r1, &mut w2, buf1, read_timeout).await
        };
        let _ = w2.shutdown().await;
        result
    };

    let copy2 = async {
        let result = if read_timeout.is_zero() {
            copy_with_buf(&mut r2, &mut w1, buf2).await
        } else {
            copy_with_buf_timeout(&mut r2, &mut w1, buf2, read_timeout).await
        };
        let _ = w1.shutdown().await;
        result
    };

    let (r1_result, r2_result) = tokio::join!(copy1, copy2);
    let tx = r1_result.unwrap_or(0);
    let rx = r2_result.unwrap_or(0);

    format!("TX={} RX={}", tx, rx)
}

async fn copy_with_buf<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    buf: &mut [u8],
) -> std::io::Result<u64> {
    let mut total = 0u64;
    loop {
        let n = reader.read(buf).await?;
        if n == 0 {
            return Ok(total);
        }
        writer.write_all(&buf[..n]).await?;
        total += n as u64;
    }
}

async fn copy_with_buf_timeout<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    buf: &mut [u8],
    timeout: Duration,
) -> std::io::Result<u64> {
    let mut total = 0u64;
    loop {
        let n = match tokio::time::timeout(timeout, reader.read(buf)).await {
            Ok(result) => result?,
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "read timeout",
                ))
            }
        };
        if n == 0 {
            return Ok(total);
        }
        writer.write_all(&buf[..n]).await?;
        total += n as u64;
    }
}
