//! Reliable HTTP client over Cloudflare WARP with connection status events.
//!
//! Demonstrates the recommended pattern: the **app** owns credential
//! loading/saving; the library only handles tunnel management.
//!
//! Usage: cargo run -p wireguard-managed-client --example reliable_warp

use std::path::Path;

use wireguard_managed_client::{
    register_with_retry, ManagedWgClient, RegistrationOptions, TunnelStatus, WarpCredentials,
};

// ---------------------------------------------------------------------------
// Credential helpers — the app owns persistence, not the library.
// ---------------------------------------------------------------------------

fn load_creds(path: &str) -> Option<WarpCredentials> {
    let data = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

fn save_creds(path: &str, creds: &WarpCredentials) {
    if let Ok(json) = serde_json::to_string_pretty(creds) {
        let _ = std::fs::write(path, json);
    }
}

// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let creds_path = "warp-credentials.json";

    // Load saved credentials or register a new device.
    let creds = if Path::new(creds_path).exists() {
        match load_creds(creds_path) {
            Some(c) => {
                log::info!("Loaded credentials for device {}", c.device_id);
                c
            }
            None => {
                log::warn!("Credential file unreadable — re-registering");
                let c = register_with_retry(RegistrationOptions::default()).await?;
                save_creds(creds_path, &c);
                c
            }
        }
    } else {
        log::info!("No credentials found — registering new device");
        let c = register_with_retry(RegistrationOptions::default()).await?;
        save_creds(creds_path, &c);
        c
    };

    // Build the managed client. The library handles reconnection from here.
    let managed = ManagedWgClient::from_warp_credentials(creds).await?;

    // Subscribe to tunnel status changes.
    let mut status_rx = managed.status_receiver();
    tokio::spawn(async move {
        while status_rx.changed().await.is_ok() {
            match &*status_rx.borrow() {
                TunnelStatus::Connected => log::info!("[status] Tunnel connected"),
                TunnelStatus::Disconnected => log::warn!("[status] Tunnel disconnected"),
                TunnelStatus::Reconnecting { attempt } => {
                    log::warn!("[status] Reconnecting (attempt {})", attempt)
                }
                TunnelStatus::Shutdown => {
                    log::info!("[status] Tunnel shut down");
                    break;
                }
            }
        }
    });

    // Get a reqwest::Client — pass this to any library that expects one.
    let client = managed.client();

    loop {
        match client.get("https://www.cloudflare.com/cdn-cgi/trace").send().await {
            Ok(resp) => {
                let body = resp.text().await?;
                log::info!("OK:\n{}", &body[..body.len().min(200)]);
            }
            Err(e) => {
                log::warn!("Request failed: {}", e);
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}
