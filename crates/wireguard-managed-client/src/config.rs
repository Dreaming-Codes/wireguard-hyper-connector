use std::time::Duration;
use wireguard_hyper_connector::{WgConfigFile, WireGuardConfig};

#[cfg(feature = "warp")]
use warp_wireguard_gen::WarpCredentials;

use crate::error::Result;

/// How the managed client obtains a [`WireGuardConfig`] on each (re)connect.
pub(crate) enum ConfigSource {
    /// A static `.conf` file. Re-resolves the endpoint DNS on each reconnect.
    File(WgConfigFile),

    /// A pre-built [`WireGuardConfig`]. Used as-is on every reconnect.
    Static(WireGuardConfig),

    /// WARP credentials. Calls [`warp_wireguard_gen::get_config`] to fetch a
    /// fresh [`WireGuardConfig`] on each reconnect (handles endpoint rotation).
    #[cfg(feature = "warp")]
    Warp(WarpCredentials),
}

impl ConfigSource {
    pub async fn resolve(&self) -> Result<WireGuardConfig> {
        match self {
            Self::File(wg) => Ok(wg.clone().into_wireguard_config().await?),
            Self::Static(config) => Ok(config.clone()),
            #[cfg(feature = "warp")]
            Self::Warp(creds) => Ok(warp_wireguard_gen::get_config(creds).await?),
        }
    }
}

/// Tuning knobs for the managed client.
///
/// All fields have sensible defaults via [`Default`].
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Maximum time since last WireGuard handshake before declaring the tunnel stale.
    ///
    /// With Cloudflare WARP (25s keepalive), re-handshakes occur every ~25-30s.
    /// With standard WireGuard, every ~120s. The default of 180s is conservative
    /// enough for both cases.
    pub handshake_stale_threshold: Duration,

    /// How often to poll the tunnel health.
    pub health_check_interval: Duration,

    /// How many consecutive HTTP-level failures before forcing a reconnect.
    pub max_consecutive_failures: u32,

    /// Timeout for the WireGuard handshake during (re)connect.
    pub handshake_timeout: Duration,

    /// Per-request timeout applied to the inner `reqwest::Client`.
    pub request_timeout: Duration,

    /// Initial backoff duration after a failed connect attempt.
    pub initial_backoff: Duration,

    /// Maximum backoff duration between reconnect attempts.
    pub max_backoff: Duration,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            handshake_stale_threshold: Duration::from_secs(180),
            health_check_interval: Duration::from_secs(10),
            max_consecutive_failures: 3,
            handshake_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(15),
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(60),
        }
    }
}
