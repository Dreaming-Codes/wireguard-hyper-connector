//! API request and response types for the Cloudflare WARP API.

use serde::{Deserialize, Serialize};

/// Request body for device registration.
#[derive(Debug, Serialize)]
pub struct RegisterRequest {
    /// FCM token (empty for non-Android clients).
    pub fcm_token: String,
    /// Installation ID (empty for non-Android clients).
    pub install_id: String,
    /// Base64-encoded public key.
    pub key: String,
    /// Locale string (e.g., "en_US").
    pub locale: String,
    /// Device model name.
    pub model: String,
    /// TOS acceptance timestamp (RFC3339).
    pub tos: String,
    /// Device type (e.g., "Android").
    #[serde(rename = "type")]
    pub device_type: String,
}

/// Response from device registration.
#[derive(Debug, Deserialize)]
pub struct RegisterResponse {
    /// Unique device identifier.
    pub id: String,
    /// Authentication token for subsequent requests.
    pub token: String,
    /// Account information.
    pub account: Account,
    /// WireGuard configuration.
    pub config: Config,
}

/// Account information.
#[derive(Debug, Deserialize)]
pub struct Account {
    /// Account license key.
    pub license: String,
    /// Whether the account has Warp+ enabled.
    #[serde(default)]
    pub warp_plus: bool,
}

/// WireGuard configuration from the API.
#[derive(Debug, Deserialize)]
pub struct Config {
    /// Interface configuration.
    pub interface: Interface,
    /// Peer configurations.
    pub peers: Vec<Peer>,
}

/// Interface configuration.
#[derive(Debug, Deserialize)]
pub struct Interface {
    /// Assigned IP addresses.
    pub addresses: NetworkAddress,
}

/// Network addresses (IPv4 and IPv6).
#[derive(Debug, Deserialize)]
pub struct NetworkAddress {
    /// IPv4 address with CIDR notation.
    pub v4: String,
    /// IPv6 address with CIDR notation.
    pub v6: String,
}

/// Peer configuration.
#[derive(Debug, Deserialize)]
pub struct Peer {
    /// Base64-encoded public key.
    pub public_key: String,
    /// Endpoint information.
    pub endpoint: Endpoint,
}

/// Endpoint information.
#[derive(Debug, Deserialize)]
pub struct Endpoint {
    /// Hostname with port (e.g., "engage.cloudflareclient.com:2408").
    pub host: String,
    /// IPv4 address.
    pub v4: String,
    /// IPv6 address.
    pub v6: String,
}

/// Response from GetSourceDevice endpoint.
#[derive(Debug, Deserialize)]
pub struct GetSourceDeviceResponse {
    /// WireGuard configuration.
    pub config: Config,
    /// Account information.
    pub account: Account,
}

/// Request body for updating account license.
#[derive(Debug, Serialize)]
pub struct UpdateAccountRequest {
    /// New license key.
    pub license: String,
}
