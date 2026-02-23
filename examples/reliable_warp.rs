//! Reliable HTTP client over Cloudflare WARP — zero configuration.
//!
//! The managed client handles registration, credential persistence,
//! tunnel health monitoring, and automatic reconnection.
//!
//! Usage: cargo run --example reliable_warp

use wireguard_managed_client::ManagedWgClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    // One line: register (or reuse saved creds), connect tunnel, start supervisor.
    let managed = ManagedWgClient::warp().await?;

    // Get a reqwest::Client — pass it to any library that expects one.
    let client = managed.client();

    loop {
        match client.get("https://www.cloudflare.com/cdn-cgi/trace").send().await {
            Ok(resp) => {
                let body = resp.text().await?;
                let preview = &body[..body.len().min(200)];
                log::info!("OK:\n{}", preview);
            }
            Err(e) => {
                // Tunnel may be reconnecting — grab the latest client and retry.
                log::warn!("Request failed (tunnel may be reconnecting): {}", e);
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}
