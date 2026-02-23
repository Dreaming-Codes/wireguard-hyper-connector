//! Self-healing `reqwest` HTTP client over a WireGuard tunnel.
//!
//! This crate wraps [`wireguard-hyper-connector`] with automatic reconnection
//! logic. It produces a standard `reqwest::Client` that you can hand to **any**
//! library expecting one — the tunnel is managed transparently in the background.
//!
//! # Quick start (Cloudflare WARP)
//!
//! ```ignore
//! use wireguard_managed_client::{ManagedWgClient, RegistrationOptions, register_with_retry};
//!
//! // App owns credential loading/saving — library never touches the filesystem.
//! let creds = load_creds("warp-credentials.json")
//!     .unwrap_or(register_with_retry(RegistrationOptions::default()).await?);
//! save_creds("warp-credentials.json", &creds);
//!
//! let managed = ManagedWgClient::from_warp_credentials(creds).await?;
//! let client = managed.client();          // reqwest::Client
//! let resp = client.get("https://api.example.com/data").send().await?;
//! ```
//!
//! # Quick start (config file)
//!
//! ```ignore
//! use wireguard_managed_client::ManagedWgClient;
//!
//! let managed = ManagedWgClient::from_config_file("wg.conf").await?;
//! let client = managed.client();
//! ```
//!
//! # How it works
//!
//! 1. On creation, a WireGuard tunnel is established and a `reqwest::Client`
//!    using a custom hyper connector is built on top of it.
//! 2. A background supervisor task monitors the WireGuard handshake timer.
//! 3. When the tunnel goes stale (handshake age exceeds a configurable
//!    threshold, typically 180 s) the supervisor tears down the old tunnel,
//!    re-resolves the endpoint, and builds a fresh `reqwest::Client`.
//! 4. [`client()`](ManagedWgClient::client) always returns the latest healthy
//!    instance.

mod client;
pub mod config;
pub mod error;
#[cfg(feature = "warp")]
mod warp;

pub use client::{ManagedWgClient, TunnelStatus};
pub use config::ClientConfig;
pub use error::Error;

// Re-export types users might need for advanced configuration.
pub use wireguard_hyper_connector::{
    DohServerConfig, ManagedTunnel, WgConfigFile, WgConnector, WireGuardConfig,
};

#[cfg(feature = "warp")]
pub use warp_wireguard_gen::{self, RegistrationOptions, TeamsEnrollment, WarpCredentials};

#[cfg(feature = "warp")]
pub use warp::register_with_retry;

use crate::config::ConfigSource;

// ---------------------------------------------------------------------------
// Builder methods on ManagedWgClient
// ---------------------------------------------------------------------------

impl ManagedWgClient {
    /// Connect using a WireGuard `.conf` file with default settings.
    pub async fn from_config_file(path: &str) -> error::Result<Self> {
        Self::from_config_file_with(path, ClientConfig::default()).await
    }

    /// Connect using a WireGuard `.conf` file with custom settings.
    pub async fn from_config_file_with(path: &str, cfg: ClientConfig) -> error::Result<Self> {
        let wg = WgConfigFile::from_file(path)?;
        Self::start(ConfigSource::File(wg), cfg).await
    }

    /// Connect using an already-built [`WireGuardConfig`] with default settings.
    pub async fn from_wireguard_config(config: WireGuardConfig) -> error::Result<Self> {
        Self::from_wireguard_config_with(config, ClientConfig::default()).await
    }

    /// Connect using an already-built [`WireGuardConfig`] with custom settings.
    pub async fn from_wireguard_config_with(
        config: WireGuardConfig,
        cfg: ClientConfig,
    ) -> error::Result<Self> {
        Self::start(ConfigSource::Static(config), cfg).await
    }

    /// Connect through Cloudflare WARP using pre-existing credentials.
    ///
    /// Skips registration entirely. The caller is responsible for obtaining
    /// credentials via [`register_with_retry`] and for persisting them across
    /// restarts if desired.
    #[cfg(feature = "warp")]
    pub async fn from_warp_credentials(creds: WarpCredentials) -> error::Result<Self> {
        Self::from_warp_credentials_with(creds, ClientConfig::default()).await
    }

    /// Connect through Cloudflare WARP using pre-existing credentials with
    /// custom settings.
    #[cfg(feature = "warp")]
    pub async fn from_warp_credentials_with(
        creds: WarpCredentials,
        cfg: ClientConfig,
    ) -> error::Result<Self> {
        Self::start(ConfigSource::Warp(creds), cfg).await
    }
}
