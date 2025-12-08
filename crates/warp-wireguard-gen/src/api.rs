//! Cloudflare WARP API client implementation.

use std::net::SocketAddr;
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use reqwest::Client;

use crate::error::{Error, Result};
use crate::keys::generate_keypair;
use crate::types::*;
use crate::{RegistrationOptions, WarpCredentials};
use wireguard_netstack::{DohResolver, WireGuardConfig};

/// Cloudflare WARP API base URL.
const API_URL: &str = "https://api.cloudflareclient.com";

/// API version string (must match the official client).
const API_VERSION: &str = "v0a1922";

/// Create an HTTP client with required headers and TLS 1.2 configuration.
///
/// Cloudflare's WARP API requires TLS 1.2 specifically and rejects TLS 1.3.
fn create_client(auth_token: Option<&str>) -> Result<Client> {
    // Configure rustls to use TLS 1.2 only (Cloudflare API requirement)
    // Use ring crypto provider explicitly
    let tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS12])
    .map_err(|e| Error::Tls(e.to_string()))?
    .with_root_certificates(Arc::new(rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }))
    .with_no_client_auth();

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("CF-Client-Version", "a-6.3-1922".parse().unwrap());
    if let Some(token) = auth_token {
        headers.insert(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", token).parse().unwrap(),
        );
    }

    let builder = Client::builder()
        .use_preconfigured_tls(tls_config)
        .user_agent("okhttp/3.12.1")
        .default_headers(headers)
        .http1_only(); // No HTTP/2 to match official client behavior

    builder.build().map_err(Error::from)
}

/// Register a new device with Cloudflare WARP.
pub async fn register(options: RegistrationOptions) -> Result<(WireGuardConfig, WarpCredentials)> {
    let (private_key, public_key) = generate_keypair();
    let public_key_b64 = STANDARD.encode(public_key);
    let timestamp = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);

    let client = create_client(None)?;

    // Build registration request
    let register_req = RegisterRequest {
        fcm_token: String::new(),
        install_id: String::new(),
        key: public_key_b64,
        locale: "en_US".to_string(),
        model: options.device_model,
        tos: timestamp,
        device_type: "Android".to_string(),
    };

    log::info!("Registering new device with Cloudflare WARP...");

    let resp: RegisterResponse = client
        .post(format!("{}/{}/reg", API_URL, API_VERSION))
        .json(&register_req)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    log::info!("Device registered successfully with ID: {}", resp.id);

    let mut credentials = WarpCredentials {
        device_id: resp.id,
        access_token: resp.token,
        private_key,
        license_key: resp.account.license,
    };

    // Apply license key if provided
    if let Some(ref license) = options.license_key {
        log::info!("Applying Warp+ license key...");
        update_license(&credentials, license).await?;
        credentials.license_key = license.clone();
    }

    // Fetch full configuration
    let config = get_config(&credentials).await?;

    Ok((config, credentials))
}

/// Get WireGuard configuration from existing credentials.
pub async fn get_config(credentials: &WarpCredentials) -> Result<WireGuardConfig> {
    let client = create_client(Some(&credentials.access_token))?;

    log::info!("Fetching WARP configuration for device {}...", credentials.device_id);

    let resp: GetSourceDeviceResponse = client
        .get(format!(
            "{}/{}/reg/{}",
            API_URL, API_VERSION, credentials.device_id
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let peer = resp
        .config
        .peers
        .first()
        .ok_or_else(|| Error::InvalidResponse("No peers in config".to_string()))?;

    // Decode peer public key
    let peer_public_key: [u8; 32] = STANDARD
        .decode(&peer.public_key)
        .map_err(|e| Error::InvalidKey(e.to_string()))?
        .try_into()
        .map_err(|_| Error::InvalidKey("Invalid key length".to_string()))?;

    // Parse tunnel IP (v4), stripping CIDR notation
    let tunnel_ip = resp
        .config
        .interface
        .addresses
        .v4
        .split('/')
        .next()
        .unwrap_or(&resp.config.interface.addresses.v4)
        .parse()
        .map_err(|_| Error::InvalidAddress(resp.config.interface.addresses.v4.clone()))?;

    // Resolve endpoint hostname
    let peer_endpoint = resolve_endpoint(&peer.endpoint.host).await?;

    log::info!(
        "Configuration retrieved: tunnel_ip={}, endpoint={}",
        tunnel_ip,
        peer_endpoint
    );

    Ok(WireGuardConfig {
        private_key: credentials.private_key,
        peer_public_key,
        peer_endpoint,
        tunnel_ip,
        preshared_key: None,
        keepalive_seconds: Some(25),
    })
}

/// Update the license key on an existing registration.
pub async fn update_license(credentials: &WarpCredentials, license_key: &str) -> Result<()> {
    let client = create_client(Some(&credentials.access_token))?;

    let req = UpdateAccountRequest {
        license: license_key.to_string(),
    };

    client
        .put(format!(
            "{}/{}/reg/{}/account",
            API_URL, API_VERSION, credentials.device_id
        ))
        .json(&req)
        .send()
        .await?
        .error_for_status()?;

    log::info!("License key updated successfully");

    Ok(())
}

/// Resolve an endpoint hostname to a SocketAddr.
///
/// First tries to parse as a direct SocketAddr, then falls back to DNS-over-HTTPS resolution.
async fn resolve_endpoint(endpoint: &str) -> Result<SocketAddr> {
    // Try to parse directly as SocketAddr first
    if let Ok(addr) = endpoint.parse() {
        return Ok(addr);
    }

    // Parse host:port
    let (host, port) = endpoint
        .rsplit_once(':')
        .ok_or_else(|| Error::InvalidEndpoint(endpoint.to_string()))?;

    let port: u16 = port
        .parse()
        .map_err(|_| Error::InvalidEndpoint(format!("Invalid port in endpoint: {}", endpoint)))?;

    // Resolve via DoH (using Cloudflare DNS in direct mode)
    log::info!("Resolving WARP endpoint '{}' via DoH...", host);
    let resolver = DohResolver::new_direct();
    let addr = resolver
        .resolve_addr(host, port)
        .await
        .map_err(|e| Error::DnsResolution(format!("Failed to resolve '{}': {}", host, e)))?;

    log::info!("WARP endpoint resolved to: {}", addr);
    Ok(addr)
}
