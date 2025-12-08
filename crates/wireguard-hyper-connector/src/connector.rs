//! Custom connector for hyper that uses our userspace network stack.
//!
//! This module provides a tower::Service that creates TCP connections through
//! our WireGuard tunnel + smoltcp network stack.
//!
//! DNS resolution is performed using DNS-over-HTTPS through the WireGuard tunnel,
//! ensuring that DNS queries also go through the VPN.

use crate::error::{Error, Result};
use http::Uri;
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::client::legacy::connect::{Connected, Connection};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tower_service::Service;
use wireguard_netstack::{DohResolver, DohServerConfig, NetStack, TcpConnection};

/// A connector that creates TCP connections through our WireGuard tunnel.
///
/// DNS resolution is performed using DNS-over-HTTPS through the same WireGuard
/// tunnel, ensuring all traffic (including DNS) goes through the VPN.
///
/// # Example
///
/// ```no_run
/// use wireguard_hyper_connector::{WgConnector, ManagedTunnel, WgConfigFile, DohServerConfig};
/// use hyper_util::client::legacy::Client;
/// use hyper_util::rt::TokioExecutor;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = WgConfigFile::from_file("wg.conf")?
///     .into_wireguard_config()
///     .await?;
///
/// let tunnel = ManagedTunnel::connect(config).await?;
///
/// // Use default Cloudflare DNS through the tunnel
/// let connector = WgConnector::new(tunnel.netstack());
///
/// // Or use custom DNS through the tunnel
/// let connector = WgConnector::with_dns(tunnel.netstack(), DohServerConfig::google());
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct WgConnector {
    netstack: Arc<NetStack>,
    tls_connector: TlsConnector,
    /// DNS-over-HTTPS resolver that uses the WireGuard tunnel.
    doh_resolver: Arc<DohResolver>,
}

impl WgConnector {
    /// Create a new WireGuard connector with default Cloudflare DNS-over-HTTPS resolution.
    pub fn new(netstack: Arc<NetStack>) -> Self {
        Self::with_dns(netstack, DohServerConfig::default())
    }

    /// Create a new WireGuard connector with custom DNS-over-HTTPS configuration.
    ///
    /// # Arguments
    ///
    /// * `netstack` - The network stack to use for TCP connections.
    /// * `dns_config` - The DNS server configuration for resolving hostnames.
    pub fn with_dns(netstack: Arc<NetStack>, dns_config: DohServerConfig) -> Self {
        // Install ring as the crypto provider
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Set up rustls with webpki roots
        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let tls_connector = TlsConnector::from(Arc::new(tls_config));

        // Create the DoH resolver that uses the WireGuard tunnel with custom config
        let doh_resolver = Arc::new(DohResolver::new_tunneled_with_config(netstack.clone(), dns_config));

        Self {
            netstack,
            tls_connector,
            doh_resolver,
        }
    }

    /// Get the underlying DoH resolver.
    pub fn doh_resolver(&self) -> &Arc<DohResolver> {
        &self.doh_resolver
    }
}

impl Service<Uri> for WgConnector {
    type Response = WgTlsStream;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let netstack = self.netstack.clone();
        let tls_connector = self.tls_connector.clone();
        let doh_resolver = self.doh_resolver.clone();

        Box::pin(async move {
            let host = uri
                .host()
                .ok_or_else(|| Error::NoHost(uri.to_string()))?;

            let is_https = uri.scheme_str() == Some("https");

            let port = uri.port_u16().unwrap_or(if is_https { 443 } else { 80 });

            log::info!("Connecting to {}:{} (TLS: {})", host, port, is_https);

            // Resolve the hostname using DNS-over-HTTPS through WireGuard
            let addr = doh_resolver.resolve_addr(host, port).await?;
            log::info!("Resolved {} to {} via DoH", host, addr);

            // Create TCP connection through our network stack
            let tcp_conn = TcpConnection::connect(netstack, addr)
                .await
                .map_err(|e| Error::TcpConnect(e.to_string()))?;
            let tcp_stream = WgStream {
                conn: Arc::new(tcp_conn),
            };

            if is_https {
                // Wrap with TLS
                let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
                    .map_err(|e| Error::InvalidServerName(e.to_string()))?;

                log::debug!("Starting TLS handshake with {}", host);
                let tls_stream = tls_connector
                    .connect(server_name, tcp_stream)
                    .await
                    .map_err(|e| Error::TlsHandshake(e.to_string()))?;

                log::info!("TLS handshake completed with {}", host);
                Ok(WgTlsStream::Tls(Box::new(tls_stream)))
            } else {
                Ok(WgTlsStream::Plain(tcp_stream))
            }
        })
    }
}

/// A TCP stream through our WireGuard tunnel (raw TCP).
pub struct WgStream {
    conn: Arc<TcpConnection>,
}

/// A stream that can be either plain TCP or TLS-wrapped.
pub enum WgTlsStream {
    Plain(WgStream),
    Tls(Box<TlsStream<WgStream>>),
}

impl Connection for WgTlsStream {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl AsyncRead for WgStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let conn = self.conn.clone();
        let unfilled = buf.initialize_unfilled();

        // Try to read without blocking
        conn.netstack.poll();

        let can_recv = conn.netstack.can_recv(conn.handle);
        log::trace!(
            "WgStream poll_read: can_recv={}, buf_len={}",
            can_recv,
            unfilled.len()
        );

        if can_recv {
            match conn.netstack.recv(conn.handle, unfilled) {
                Ok(n) if n > 0 => {
                    log::debug!("WgStream read {} bytes", n);
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(_) => {
                    log::trace!("WgStream recv returned 0 bytes");
                }
                Err(e) => {
                    log::error!("WgStream recv error: {}", e);
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e.to_string())));
                }
            }
        }

        if !conn.netstack.may_recv(conn.handle) {
            log::debug!("WgStream: connection closed (may_recv=false)");
            // Connection closed
            return Poll::Ready(Ok(()));
        }

        // Schedule a wake-up
        let waker = cx.waker().clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            waker.wake();
        });

        Poll::Pending
    }
}

impl AsyncWrite for WgStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let conn = self.conn.clone();

        // Try to write without blocking
        conn.netstack.poll();

        if conn.netstack.can_send(conn.handle) {
            match conn.netstack.send(conn.handle, buf) {
                Ok(n) => {
                    conn.netstack.poll();
                    return Poll::Ready(Ok(n));
                }
                Err(e) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e.to_string())));
                }
            }
        }

        if !conn.netstack.may_send(conn.handle) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Connection closed",
            )));
        }

        // Schedule a wake-up
        let waker = cx.waker().clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            waker.wake();
        });

        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.conn.netstack.poll();
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.conn.shutdown();
        self.conn.netstack.poll();
        Poll::Ready(Ok(()))
    }
}

// AsyncRead for WgTlsStream
impl AsyncRead for WgTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            WgTlsStream::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            WgTlsStream::Tls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

// AsyncWrite for WgTlsStream
impl AsyncWrite for WgTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            WgTlsStream::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            WgTlsStream::Tls(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            WgTlsStream::Plain(stream) => Pin::new(stream).poll_flush(cx),
            WgTlsStream::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            WgTlsStream::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            WgTlsStream::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }
}

// Implement hyper's Read trait for WgTlsStream
impl Read for WgTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        // Use a temporary buffer for reading
        let mut temp_buf = [0u8; 8192];
        let unfilled_len = unsafe { buf.as_mut().len() };
        let read_len = temp_buf.len().min(unfilled_len);

        let mut read_buf = ReadBuf::new(&mut temp_buf[..read_len]);

        match <Self as AsyncRead>::poll_read(self, cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let filled = read_buf.filled();
                if !filled.is_empty() {
                    unsafe {
                        let unfilled = buf.as_mut();
                        for (i, byte) in filled.iter().enumerate() {
                            unfilled[i].write(*byte);
                        }
                        buf.advance(filled.len());
                    }
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

// Implement hyper's Write trait for WgTlsStream
impl Write for WgTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        <Self as AsyncWrite>::poll_write(self, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        <Self as AsyncWrite>::poll_flush(self, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        <Self as AsyncWrite>::poll_shutdown(self, cx)
    }
}
