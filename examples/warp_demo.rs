//! Demo application showing how to use warp-wireguard-gen with wireguard-hyper-connector.
//!
//! This example registers with Cloudflare WARP, establishes a WireGuard tunnel,
//! and makes an HTTPS request through the tunnel.
//!
//! Usage: cargo run --example warp_demo

use http_body_util::BodyExt;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::time::Duration;
use warp_wireguard_gen::{register, RegistrationOptions};
use wireguard_hyper_connector::{ManagedTunnel, WgConnector};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    log::info!("Starting Cloudflare WARP demo");

    // Register with Cloudflare WARP and get WireGuard config
    log::info!("Registering with Cloudflare WARP...");
    let (config, credentials) = register(RegistrationOptions {
        device_model: "warp-demo/0.1.0".to_string(),
        license_key: None, // Set to Some("xxxx-xxxx-xxxx") for Warp+
        teams: None,       // Set to Some(TeamsEnrollment { ... }) for Zero Trust
    })
    .await?;

    log::info!("Registration successful!");
    log::info!("  Device ID: {}", credentials.device_id);
    log::info!("  Tunnel IP: {}", config.tunnel_ip);
    log::info!("  Endpoint: {}", config.peer_endpoint);

    // Connect using the managed tunnel (handles all background tasks)
    log::info!("Establishing WireGuard tunnel...");
    let tunnel = ManagedTunnel::connect_with_timeout(config, Duration::from_secs(10)).await?;
    log::info!("Tunnel established!");

    // Create the hyper connector
    let connector = WgConnector::new(tunnel.netstack());

    // Create the hyper client
    let client = Client::builder(TokioExecutor::new()).build(connector);

    // Make a request to verify we're going through WARP
    // The trace endpoint shows WARP connection status
    log::info!("Making request to https://www.cloudflare.com/cdn-cgi/trace ...");

    let uri: http::Uri = "https://www.cloudflare.com/cdn-cgi/trace".parse()?;

    let request = http::Request::builder()
        .method("GET")
        .uri(&uri)
        .header("Host", "www.cloudflare.com")
        .header("User-Agent", "warp-demo/0.1.0")
        .header("Accept", "*/*")
        .body(http_body_util::Empty::<bytes::Bytes>::new())?;

    match client.request(request).await {
        Ok(response) => {
            log::info!("Response status: {}", response.status());

            // Read body
            let body_bytes = response.into_body().collect().await?.to_bytes();
            let body_str = String::from_utf8_lossy(&body_bytes);

            println!();
            println!("{}", "=".repeat(70));
            println!("Cloudflare Trace Response:");
            println!("{}", "=".repeat(70));
            println!("{}", body_str);
            println!("{}", "=".repeat(70));

            // Check if WARP is active
            if body_str.contains("warp=on") {
                log::info!("WARP is active (free tier)");
            } else if body_str.contains("warp=plus") {
                log::info!("WARP+ is active (premium tier)");
            } else if body_str.contains("warp=off") {
                log::warn!("WARP appears to be off - connection may not be going through WARP");
            }
        }
        Err(e) => {
            log::error!("Request failed: {}", e);
            return Err(e.into());
        }
    }

    // Also make a request to a regular site
    log::info!("Making request to https://www.google.com/ ...");

    let uri: http::Uri = "https://www.google.com/".parse()?;

    let request = http::Request::builder()
        .method("GET")
        .uri(&uri)
        .header("Host", "www.google.com")
        .header("User-Agent", "warp-demo/0.1.0")
        .header("Accept", "*/*")
        .body(http_body_util::Empty::<bytes::Bytes>::new())?;

    match client.request(request).await {
        Ok(response) => {
            log::info!("Google response status: {}", response.status());

            let body_bytes = response.into_body().collect().await?.to_bytes();
            let body_str = String::from_utf8_lossy(&body_bytes);
            let preview_len = std::cmp::min(300, body_str.len());

            println!();
            println!("{}", "=".repeat(70));
            println!("Google response (first {} chars):", preview_len);
            println!("{}", "=".repeat(70));
            println!("{}", &body_str[..preview_len]);
            if body_str.len() > preview_len {
                println!("... ({} more bytes)", body_str.len() - preview_len);
            }
            println!("{}", "=".repeat(70));
        }
        Err(e) => {
            log::error!("Google request failed: {}", e);
        }
    }

    log::info!("Demo complete!");

    // Graceful shutdown
    tunnel.shutdown().await;

    Ok(())
}
