//! Self-healing `reqwest` HTTP client over a WireGuard tunnel.
//!
//! This crate wraps [`wireguard-hyper-connector`] with automatic reconnection
//! logic. It produces a standard `reqwest::Client` that you can hand to **any**
//! library expecting one — the tunnel is managed transparently in the background.
//!
//! # Quick start (Cloudflare WARP)
//!
//! ```ignore
//! use wireguard_managed_client::ManagedWgClient;
//!
//! let managed = ManagedWgClient::warp().await?;
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

pub use client::ManagedWgClient;
pub use config::ClientConfig;
pub use error::Error;

// Re-export types users might need for advanced configuration.
pub use wireguard_hyper_connector::{
    DohServerConfig, ManagedTunnel, WgConfigFile, WgConnector, WireGuardConfig,
};

#[cfg(feature = "warp")]
pub use warp_wireguard_gen::{self, RegistrationOptions, TeamsEnrollment, WarpCredentials};

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

    /// Connect through Cloudflare WARP with default settings.
    ///
    /// Credentials are persisted to `warp-credentials.json` in the current
    /// directory so that subsequent runs skip registration.
    #[cfg(feature = "warp")]
    pub async fn warp() -> error::Result<Self> {
        Self::warp_with_options(RegistrationOptions::default(), ClientConfig::default()).await
    }

    /// Connect through Cloudflare WARP with full control over registration
    /// options and client tuning.
    ///
    /// # Arguments
    ///
    /// * `options` - WARP registration options (device name, license key, Teams enrollment).
    /// * `cfg` - Client configuration (timeouts, backoff, health thresholds).
    #[cfg(feature = "warp")]
    pub async fn warp_with_options(
        options: RegistrationOptions,
        cfg: ClientConfig,
    ) -> error::Result<Self> {
        let creds_path = std::path::PathBuf::from("warp-credentials.json");
        let creds =
            crate::warp::obtain_credentials(options, Some(&creds_path)).await?;
        Self::start(ConfigSource::Warp(creds), cfg).await
    }

    /// Connect through Cloudflare WARP using pre-existing credentials.
    ///
    /// Skips registration entirely. Useful when you manage credential
    /// persistence yourself.
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
