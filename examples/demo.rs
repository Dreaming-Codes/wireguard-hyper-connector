//! Demo application showing how to use wireguard-hyper-connector.
//!
//! Usage: cargo run --example demo -- <wireguard-config-file>

use http_body_util::BodyExt;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::time::Duration;
use wireguard_hyper_connector::{ManagedTunnel, WgConfigFile, WgConnector};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    let config_path = match args.get(1) {
        Some(path) => path.as_str(),
        None => {
            eprintln!("Usage: {} <wireguard-config-file>", args[0]);
            std::process::exit(1);
        }
    };

    log::info!("Starting WireGuard HTTP proxy demo");

    // Load configuration
    log::info!("Loading WireGuard configuration from: {}", config_path);
    let wg_config = WgConfigFile::from_file(config_path)?;
    let config = wg_config.into_wireguard_config().await?;

    // Connect using the managed tunnel (handles all background tasks)
    let tunnel = ManagedTunnel::connect_with_timeout(config, Duration::from_secs(10)).await?;

    // Create the hyper connector
    let connector = WgConnector::new(tunnel.netstack());

    // Create the hyper client
    let client = Client::builder(TokioExecutor::new()).build(connector);

    log::info!("Making HTTPS request to https://www.google.com/...");

    let uri: http::Uri = "https://www.google.com/".parse()?;

    let request = http::Request::builder()
        .method("GET")
        .uri(&uri)
        .header("Host", "www.google.com")
        .header("User-Agent", "wireguard-hyper-connector/0.1.0")
        .header("Accept", "*/*")
        .body(http_body_util::Empty::<bytes::Bytes>::new())?;

    match client.request(request).await {
        Ok(response) => {
            log::info!("Response status: {}", response.status());

            // Read body
            let body_bytes = response.into_body().collect().await?.to_bytes();
            let body_str = String::from_utf8_lossy(&body_bytes);
            let preview_len = std::cmp::min(500, body_str.len());

            println!();
            println!("{}", "=".repeat(70));
            println!("Response body (first {} chars):", preview_len);
            println!("{}", "=".repeat(70));
            println!("{}", &body_str[..preview_len]);
            if body_str.len() > preview_len {
                println!("... ({} more bytes)", body_str.len() - preview_len);
            }
            println!("{}", "=".repeat(70));
        }
        Err(e) => {
            log::error!("Request failed: {}", e);
            return Err(e.into());
        }
    }

    log::info!("Demo complete!");

    // Graceful shutdown
    tunnel.shutdown().await;

    Ok(())
}
