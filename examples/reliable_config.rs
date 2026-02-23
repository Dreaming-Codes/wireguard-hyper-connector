//! Reliable HTTP client using a WireGuard config file.
//!
//! Usage: cargo run --example reliable_config -- <wireguard-config-file>

use wireguard_managed_client::ManagedWgClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let config_path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: reliable_config <wireguard-config-file>");
        std::process::exit(1);
    });

    let managed = ManagedWgClient::from_config_file(&config_path).await?;
    let client = managed.client();

    let resp = client.get("https://www.google.com").send().await?;
    log::info!("Status: {}", resp.status());

    managed.shutdown().await;
    Ok(())
}
