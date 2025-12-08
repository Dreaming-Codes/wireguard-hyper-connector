//! Error types for wireguard-hyper-connector.

/// Result type alias for connector operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur in the WireGuard hyper connector.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("URI has no host: {0}")]
    NoHost(String),

    #[error("Invalid server name: {0}")]
    InvalidServerName(String),

    #[error("TLS handshake failed: {0}")]
    TlsHandshake(String),

    #[error("DNS resolution failed: {0}")]
    DnsResolution(#[from] wireguard_netstack::Error),

    #[error("TCP connection failed: {0}")]
    TcpConnect(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
