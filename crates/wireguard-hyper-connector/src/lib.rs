//! Hyper connector for making HTTP requests through a WireGuard tunnel.
//!
//! This crate provides `WgConnector`, a `tower::Service` implementation that
//! creates HTTP connections through a WireGuard tunnel.
//!
//! # DNS Configuration
//!
//! You can configure different DNS servers for pre-connection (endpoint resolution)
//! and post-connection (HTTP request DNS resolution) using `DohServerConfig`:
//!
//! ```no_run
//! use wireguard_hyper_connector::{WgConnector, ManagedTunnel, WgConfigFile, DohServerConfig};
//! use hyper_util::client::legacy::Client;
//! use hyper_util::rt::TokioExecutor;
//! use http_body_util::Empty;
//! use bytes::Bytes;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Use Google DNS for resolving WireGuard endpoint
//!     let config = WgConfigFile::from_file("wg.conf")?
//!         .into_wireguard_config_with_dns(DohServerConfig::google())
//!         .await?;
//!     
//!     let tunnel = ManagedTunnel::connect(config).await?;
//!     
//!     // Use Quad9 DNS for HTTP requests through the tunnel
//!     let connector = WgConnector::with_dns(tunnel.netstack(), DohServerConfig::quad9());
//!     
//!     let client: Client<WgConnector, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build(connector);
//!     
//!     // Make requests...
//!     
//!     tunnel.shutdown().await;
//!     Ok(())
//! }
//! ```
//!
//! # Example (Default DNS)
//!
//! ```no_run
//! use wireguard_hyper_connector::{WgConnector, ManagedTunnel, WgConfigFile};
//! use hyper_util::client::legacy::Client;
//! use hyper_util::rt::TokioExecutor;
//! use http_body_util::Empty;
//! use bytes::Bytes;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Load config and connect (uses Cloudflare DNS by default)
//!     let config = WgConfigFile::from_file("wg.conf")?
//!         .into_wireguard_config()
//!         .await?;
//!     
//!     let tunnel = ManagedTunnel::connect(config).await?;
//!     
//!     // Create the hyper connector (uses Cloudflare DNS by default)
//!     let connector = WgConnector::new(tunnel.netstack());
//!     
//!     // Create a hyper client
//!     let client: Client<WgConnector, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build(connector);
//!     
//!     // Make requests...
//!     
//!     tunnel.shutdown().await;
//!     Ok(())
//! }
//! ```

mod connector;
pub mod error;

// Re-export connector types
pub use connector::{WgConnector, WgStream, WgTlsStream};
pub use error::{Error, Result};

// Re-export wireguard-netstack types for convenience
pub use wireguard_netstack::{
    DnsConfig, DohResolver, DohServerConfig, ManagedTunnel, NetStack, TcpConnection, WgConfigFile,
    WireGuardConfig, WireGuardTunnel,
};
