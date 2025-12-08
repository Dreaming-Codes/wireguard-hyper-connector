//! Generate WireGuard configurations by registering with Cloudflare WARP.
//!
//! This crate provides functionality to:
//! - Register a new device with Cloudflare WARP
//! - Retrieve WireGuard configuration for connecting through WARP
//! - Optionally apply a Warp+ license key
//!
//! # Example
//!
//! ```no_run
//! use warp_wireguard_gen::{register, RegistrationOptions};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Register with default options
//!     let (config, credentials) = register(RegistrationOptions::default()).await?;
//!     
//!     // Use config with wireguard-netstack...
//!     // Optionally save credentials for reuse...
//!     
//!     Ok(())
//! }
//! ```
//!
//! # Feature Flags
//!
//! - `serde`: Enables `Serialize` and `Deserialize` for `WarpCredentials`,
//!   allowing easy persistence to JSON, TOML, etc.
//!
//! # Credential Persistence
//!
//! The [`WarpCredentials`] struct returned by [`register`] contains all the
//! information needed to reconnect without re-registering. Enable the `serde`
//! feature to serialize credentials for storage.
//!
//! ```no_run
//! # #[cfg(feature = "serde")]
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use warp_wireguard_gen::{register, get_config, RegistrationOptions, WarpCredentials};
//!
//! // First run: register and save credentials
//! # tokio::runtime::Runtime::new().unwrap().block_on(async {
//! let (config, credentials) = register(RegistrationOptions::default()).await?;
//! let json = serde_json::to_string_pretty(&credentials)?;
//! std::fs::write("warp-credentials.json", &json)?;
//!
//! // Later: load credentials and get fresh config
//! let json = std::fs::read_to_string("warp-credentials.json")?;
//! let credentials: WarpCredentials = serde_json::from_str(&json)?;
//! let config = get_config(&credentials).await?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! # });
//! # Ok(())
//! # }
//! ```

pub mod api;
pub mod error;
pub mod keys;
pub mod types;

pub use error::{Error, Result};

use base64::{engine::general_purpose::STANDARD, Engine};
use wireguard_netstack::WireGuardConfig;

/// Options for registering a new WARP device.
#[derive(Debug, Clone)]
pub struct RegistrationOptions {
    /// Device model name displayed in the 1.1.1.1 app.
    ///
    /// Default: `"PC"`
    pub device_model: String,

    /// Optional Warp+ license key.
    ///
    /// Must be purchased through the official 1.1.1.1 app.
    /// Keys obtained by other means (including referrals) will not work.
    pub license_key: Option<String>,
}

impl Default for RegistrationOptions {
    fn default() -> Self {
        Self {
            device_model: "PC".to_string(),
            license_key: None,
        }
    }
}

/// Credentials for an existing WARP device registration.
///
/// Store these to avoid re-registering on each use. Use [`get_config`] to
/// obtain a fresh [`WireGuardConfig`] from existing credentials.
///
/// Enable the `serde` feature for JSON/TOML serialization support.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct WarpCredentials {
    /// Unique device identifier assigned by Cloudflare.
    pub device_id: String,

    /// Bearer token for API authentication.
    pub access_token: String,

    /// WireGuard private key (32 bytes).
    #[cfg_attr(feature = "serde", serde(with = "base64_serde"))]
    pub private_key: [u8; 32],

    /// Account license key.
    pub license_key: String,
}

/// Serde helper module for base64-encoding the private key.
#[cfg(feature = "serde")]
mod base64_serde {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = STANDARD
            .decode(&s)
            .map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid key length, expected 32 bytes"))
    }
}

impl WarpCredentials {
    /// Get the private key as a base64-encoded string.
    pub fn private_key_base64(&self) -> String {
        STANDARD.encode(self.private_key)
    }
}

/// Register a new device with Cloudflare WARP and get a WireGuard configuration.
///
/// This creates a new device registration with Cloudflare's WARP service and
/// returns both the WireGuard configuration and credentials for future use.
///
/// # Arguments
///
/// * `options` - Registration options including device model and optional license key.
///
/// # Returns
///
/// A tuple of `(WireGuardConfig, WarpCredentials)` on success.
///
/// # Example
///
/// ```no_run
/// use warp_wireguard_gen::{register, RegistrationOptions};
///
/// # async fn example() -> warp_wireguard_gen::Result<()> {
/// // Basic registration
/// let (config, creds) = register(RegistrationOptions::default()).await?;
///
/// // With custom device name
/// let (config, creds) = register(RegistrationOptions {
///     device_model: "MyApp/1.0".to_string(),
///     license_key: None,
/// }).await?;
///
/// // With Warp+ license
/// let (config, creds) = register(RegistrationOptions {
///     device_model: "PC".to_string(),
///     license_key: Some("xxxxxxxx-xxxxxxxx-xxxxxxxx".to_string()),
/// }).await?;
/// # Ok(())
/// # }
/// ```
pub async fn register(options: RegistrationOptions) -> Result<(WireGuardConfig, WarpCredentials)> {
    api::register(options).await
}

/// Get a WireGuard configuration using existing credentials.
///
/// Use this to refresh the configuration without creating a new registration.
/// This is useful when you have saved credentials from a previous [`register`] call.
///
/// # Arguments
///
/// * `credentials` - Previously obtained credentials from [`register`].
///
/// # Example
///
/// ```no_run
/// use warp_wireguard_gen::{get_config, WarpCredentials};
///
/// # async fn example(credentials: &WarpCredentials) -> warp_wireguard_gen::Result<()> {
/// let config = get_config(credentials).await?;
/// // Use config with wireguard-netstack...
/// # Ok(())
/// # }
/// ```
pub async fn get_config(credentials: &WarpCredentials) -> Result<WireGuardConfig> {
    api::get_config(credentials).await
}

/// Update the license key on an existing registration.
///
/// Use this to bind a Warp+ subscription to an existing device.
///
/// # Arguments
///
/// * `credentials` - Existing device credentials.
/// * `license_key` - Warp+ license key from the 1.1.1.1 app.
///
/// # Note
///
/// Only subscriptions purchased directly from the official 1.1.1.1 app are
/// supported. Keys obtained by other means (including referrals) will not work.
///
/// # Example
///
/// ```no_run
/// use warp_wireguard_gen::{update_license, WarpCredentials};
///
/// # async fn example(credentials: &WarpCredentials) -> warp_wireguard_gen::Result<()> {
/// update_license(credentials, "xxxxxxxx-xxxxxxxx-xxxxxxxx").await?;
/// # Ok(())
/// # }
/// ```
pub async fn update_license(credentials: &WarpCredentials, license_key: &str) -> Result<()> {
    api::update_license(credentials, license_key).await
}

/// Generate a new X25519 keypair.
///
/// This is exposed for advanced use cases where you want to provide your own key
/// during registration. Most users should use [`register`] which generates keys automatically.
///
/// # Returns
///
/// A tuple of `(private_key, public_key)` as 32-byte arrays.
pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    keys::generate_keypair()
}
